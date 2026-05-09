"""LLM-driven CTI report → STIX 2.1 bundle.

Two-step pipeline:

1. ``extract_entities(text, ...)`` — Vertex AI Gemini reads the article and
   returns a structured ``Extraction`` (entities + relationships) using
   short ``local_id`` aliases. The LLM does **not** generate UUIDs,
   timestamps, ``spec_version``, or any STIX wire format — those are
   mechanical and would just produce malformed output.

2. ``build_stix_bundle_from_extraction(extraction, source_url, ...)`` —
   TRACE assigns ``<type>--<uuid4>`` ids, a single ``created/modified``
   timestamp, and ``spec_version="2.1"`` to every object, translates
   ``relationships[*].{source,target}`` from local_ids to STIX ids, and
   stamps the bundle with the L4 ``x_trace_*`` metadata.

Anything ``relationships[*]`` references that doesn't appear in
``entities[*].local_id`` is dropped with a structured log warning. SAGE
ignores unknown ``x_*`` properties so the bundle envelope stays
forward-compatible.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

import structlog

from trace_engine.config import Config, load_config
from trace_engine.llm.client import TaskType, call_llm, load_prompt
from trace_engine.validate.schema import PIRDocument, PIRItem

logger = structlog.get_logger(__name__)

# "medium" (gemini-2.5-flash) is the default: fast enough for large CTI articles
# and accurate enough for STIX entity extraction.  Use "complex" only for reports
# with dense, ambiguous, or multi-language content.
_DEFAULT_TASK: TaskType = "medium"

_VALID_ENTITY_TYPES: frozenset[str] = frozenset(
    {
        "threat-actor",
        "intrusion-set",
        "attack-pattern",
        "malware",
        "tool",
        "vulnerability",
        "indicator",
    }
)

_VALID_RELATIONSHIP_TYPES: frozenset[str] = frozenset({"uses", "exploits", "indicates"})


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ExtractedEntity:
    local_id: str
    type: str
    properties: dict  # raw fields from the LLM (name, description, …)


@dataclass
class ExtractedRelationship:
    source: str  # local_id
    target: str  # local_id
    relationship_type: str


@dataclass
class Extraction:
    entities: list[ExtractedEntity] = field(default_factory=list)
    relationships: list[ExtractedRelationship] = field(default_factory=list)


# ---------------------------------------------------------------------------
# JSON salvage (LLM responses)
# ---------------------------------------------------------------------------


def _extract_json_from_text(raw: str) -> list | dict | None:
    """Extract a JSON value from a possibly noisy LLM response.

    Strategies tried in order:
      1. Parse the full response as-is.
      2. Extract the first ```json ... ``` Markdown block.
      3. Find the first '[' or '{' and parse from there.
      4. Bracket-balanced salvage of ``entities`` / ``relationships`` arrays
         when the outer JSON is truncated mid-stream (Gemini hits
         ``max_output_tokens`` on dense reports even after chunking).
    """
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    block = re.search(r"```(?:json)?\s*\n([\s\S]+?)\n```", raw)
    if block:
        try:
            return json.loads(block.group(1))
        except json.JSONDecodeError:
            pass

    start = min(
        (raw.find("[") if raw.find("[") != -1 else len(raw)),
        (raw.find("{") if raw.find("{") != -1 else len(raw)),
    )
    if start < len(raw):
        try:
            return json.loads(raw[start:])
        except json.JSONDecodeError:
            pass

    salvaged = _salvage_truncated_extraction(raw)
    if salvaged is not None:
        return salvaged

    return None


def _salvage_truncated_extraction(raw: str) -> dict | None:
    """Recover ``{entities, relationships}`` from a truncated LLM response.

    When Gemini hits ``max_output_tokens`` mid-array we lose the closing
    ``]}``, but the entity / relationship objects written so far are still
    well-formed JSON. Walk each ``"entities":`` / ``"relationships":`` array
    and extract whatever complete ``{...}`` records we can with bracket
    balancing.
    """
    entities = _scan_object_array(raw, "entities")
    relationships = _scan_object_array(raw, "relationships")
    if not entities and not relationships:
        return None
    return {"entities": entities, "relationships": relationships}


def _scan_object_array(raw: str, key: str) -> list[dict]:
    pattern = re.compile(rf'"{re.escape(key)}"\s*:\s*\[')
    match = pattern.search(raw)
    if not match:
        return []
    i = match.end()
    out: list[dict] = []
    n = len(raw)
    while i < n:
        while i < n and raw[i] in " \t\r\n,":
            i += 1
        if i >= n or raw[i] == "]":
            break
        if raw[i] != "{":
            break
        depth = 0
        in_str = False
        escape = False
        start = i
        while i < n:
            ch = raw[i]
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif in_str:
                if ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    i += 1
                    try:
                        out.append(json.loads(raw[start:i]))
                    except json.JSONDecodeError:
                        return out
                    break
            i += 1
        else:
            return out
    return out


# ---------------------------------------------------------------------------
# PIR context injection (L3 hint, not a filter)
# ---------------------------------------------------------------------------


def _render_pir_context_block(pir_doc: PIRDocument | None) -> str:
    if pir_doc is None or not pir_doc.root:
        return ""
    lines: list[str] = [
        "## PIR Context",
        "",
        (
            "Use the following organizational PIRs as hints when deciding which "
            "entities to surface. They are *guidance only* — do not invent "
            "entities that are not in the report just to satisfy a PIR."
        ),
        "",
    ]
    for item in pir_doc.root:
        lines.append(f"### {item.pir_id}")
        if item.intelligence_level:
            lines.append(f"- intelligence_level: {item.intelligence_level}")
        if item.description:
            lines.append(f"- description: {item.description}")
        if item.threat_actor_tags:
            lines.append(f"- threat_actor_tags: {', '.join(item.threat_actor_tags)}")
        notable_groups = _safe_list_field(item, "notable_groups")
        if notable_groups:
            lines.append(f"- notable_groups: {', '.join(notable_groups)}")
        collection_focus = _safe_list_field(item, "collection_focus")
        if collection_focus:
            lines.append(f"- collection_focus: {', '.join(collection_focus)}")
        if item.asset_weight_rules:
            tags = sorted({r.tag for r in item.asset_weight_rules})
            lines.append(f"- prioritized_asset_tags: {', '.join(tags)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _safe_list_field(item: PIRItem, name: str) -> list[str]:
    raw = item.model_dump(exclude_none=True).get(name)
    if not isinstance(raw, list):
        return []
    return [str(v) for v in raw]


# ---------------------------------------------------------------------------
# L3: LLM extraction (entities + relationships only)
# ---------------------------------------------------------------------------


def extract_entities(
    text: str,
    task: TaskType = _DEFAULT_TASK,
    config: Config | None = None,
    *,
    pir_doc: PIRDocument | None = None,
) -> Extraction:
    """Ask the LLM to return ``{entities: [...], relationships: [...]}``.

    The LLM produces only domain knowledge — names, descriptions,
    relationship_types — keyed by short ``local_id`` aliases it picks. STIX
    wire format (ids, timestamps, spec_version, ref translation) is the
    job of ``build_stix_bundle_from_extraction``.

    Long articles are split into paragraph-aligned chunks
    (``Config.extraction_chunk_chars``) so a single LLM call does not blow
    past ``max_output_tokens``. Each chunk is extracted independently and
    the results are merged: entities are deduplicated by
    ``(type, normalized_name|pattern)``, list-valued properties are
    unioned, and relationship endpoints are rewritten through the merged
    ``local_id`` map. Chunk-level parse failures are logged and skipped —
    other chunks still contribute their entities.

    Returns an empty ``Extraction`` only when *every* chunk fails. CLIs
    surface this as a 0-object bundle (and crawl_batch records
    ``decision="extraction_failed"`` in state).
    """
    cfg = config or load_config()
    chunks = _chunk_text(text, max_chars=cfg.extraction_chunk_chars)

    if len(chunks) == 1:
        logger.info("extracting_entities", chars=len(text), task=task)
        return _extract_chunk(chunks[0], task=task, config=cfg, pir_doc=pir_doc)

    logger.info(
        "extracting_entities_chunked",
        total_chars=len(text),
        chunks=len(chunks),
        chunk_chars=cfg.extraction_chunk_chars,
        task=task,
    )
    parts: list[Extraction] = []
    for index, chunk in enumerate(chunks):
        part = _extract_chunk(chunk, task=task, config=cfg, pir_doc=pir_doc, chunk_index=index)
        logger.info(
            "chunk_extracted",
            chunk_index=index,
            chars=len(chunk),
            entities=len(part.entities),
            relationships=len(part.relationships),
        )
        parts.append(part)

    return _merge_extractions(parts)


def _extract_chunk(
    text: str,
    *,
    task: TaskType,
    config: Config,
    pir_doc: PIRDocument | None,
    chunk_index: int | None = None,
) -> Extraction:
    template = load_prompt("stix_extraction.md")
    prompt = template.replace("{{REPORT_TEXT}}", text).replace(
        "{{PIR_CONTEXT_BLOCK}}", _render_pir_context_block(pir_doc)
    )

    # Per-chunk output ceiling: Gemini 2.5 flash supports up to 65,535 output
    # tokens. Each entity's nested structure (kill_chain_phases, external
    # references, labels) is verbose, so 8192 tokens runs out mid-array on
    # dense reports. 32768 leaves comfortable headroom while still bounding
    # cost. Truncated responses past this limit fall through to
    # `_extract_json_from_text`'s bracket-balanced salvage.
    raw = call_llm(task, prompt, config=config, json_mode=True, max_output_tokens=32768)

    parsed = _extract_json_from_text(raw)
    if not isinstance(parsed, dict):
        logger.warning(
            "extraction_response_not_object",
            chunk_index=chunk_index,
            response_type=type(parsed).__name__ if parsed is not None else "None",
            raw_chars=len(raw),
            preview=raw[:200],
            tail=raw[-200:] if len(raw) > 200 else "",
        )
        return Extraction()

    entities = _coerce_entities(parsed.get("entities"))
    relationships = _coerce_relationships(parsed.get("relationships"))

    # Namespace local_ids per chunk so identical aliases from different
    # chunks (e.g. "actor_1") don't collide before merge.
    if chunk_index is not None:
        prefix = f"c{chunk_index}_"
        entities = [
            ExtractedEntity(local_id=prefix + e.local_id, type=e.type, properties=e.properties)
            for e in entities
        ]
        relationships = [
            ExtractedRelationship(
                source=prefix + r.source,
                target=prefix + r.target,
                relationship_type=r.relationship_type,
            )
            for r in relationships
        ]
    return Extraction(entities=entities, relationships=relationships)


# ---------------------------------------------------------------------------
# Chunking + merging
# ---------------------------------------------------------------------------


def _chunk_text(text: str, *, max_chars: int) -> list[str]:
    """Split ``text`` into paragraph-aligned chunks no larger than ``max_chars``.

    Paragraphs are detected by blank-line separators (``\\n\\n``). A
    paragraph that on its own exceeds ``max_chars`` is hard-cut at the
    boundary — the model still sees coherent prose, just clipped.
    """
    if max_chars <= 0:
        raise ValueError("max_chars must be positive")
    if len(text) <= max_chars:
        return [text]

    paragraphs = re.split(r"\n\s*\n", text)
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0
    for para in paragraphs:
        para_len = len(para)
        if para_len > max_chars:
            if current:
                chunks.append("\n\n".join(current))
                current, current_len = [], 0
            for start in range(0, para_len, max_chars):
                chunks.append(para[start : start + max_chars])
            continue
        added = para_len + (2 if current else 0)
        if current_len + added > max_chars:
            chunks.append("\n\n".join(current))
            current, current_len = [para], para_len
        else:
            current.append(para)
            current_len += added
    if current:
        chunks.append("\n\n".join(current))
    return chunks


def _entity_merge_key(entity: ExtractedEntity) -> tuple[str, str] | None:
    """Stable dedupe key. Falls back to None when the entity has no
    distinguishing field — those records are kept as-is (no merging)."""
    props = entity.properties
    if entity.type == "indicator":
        pattern = props.get("pattern")
        if isinstance(pattern, str) and pattern.strip():
            return (entity.type, pattern.strip())
        return None
    name = props.get("name")
    if isinstance(name, str) and name.strip():
        return (entity.type, name.strip().lower())
    return None


_LIST_UNION_FIELDS: frozenset[str] = frozenset(
    {"labels", "aliases", "kill_chain_phases", "external_references", "malware_types", "tool_types"}
)


def _merge_entity_properties(into: dict, other: dict) -> None:
    for key, value in other.items():
        if key not in into:
            into[key] = value
            continue
        if key in _LIST_UNION_FIELDS and isinstance(into[key], list) and isinstance(value, list):
            seen = {json.dumps(v, sort_keys=True) for v in into[key]}
            for v in value:
                marker = json.dumps(v, sort_keys=True)
                if marker not in seen:
                    into[key].append(v)
                    seen.add(marker)


def _merge_extractions(parts: list[Extraction]) -> Extraction:
    """Merge per-chunk extractions: dedupe entities, remap relationship endpoints."""
    merged_entities: list[ExtractedEntity] = []
    by_key: dict[tuple[str, str], int] = {}
    alias_to_canonical: dict[str, str] = {}

    for part in parts:
        for entity in part.entities:
            key = _entity_merge_key(entity)
            if key is not None and key in by_key:
                canonical = merged_entities[by_key[key]]
                _merge_entity_properties(canonical.properties, entity.properties)
                alias_to_canonical[entity.local_id] = canonical.local_id
                continue
            merged_entities.append(
                ExtractedEntity(
                    local_id=entity.local_id,
                    type=entity.type,
                    properties=dict(entity.properties),
                )
            )
            alias_to_canonical[entity.local_id] = entity.local_id
            if key is not None:
                by_key[key] = len(merged_entities) - 1

    merged_relationships: list[ExtractedRelationship] = []
    rel_seen: set[tuple[str, str, str]] = set()
    dropped = 0
    for part in parts:
        for rel in part.relationships:
            src = alias_to_canonical.get(rel.source)
            tgt = alias_to_canonical.get(rel.target)
            if src is None or tgt is None:
                dropped += 1
                continue
            marker = (src, tgt, rel.relationship_type)
            if marker in rel_seen:
                continue
            rel_seen.add(marker)
            merged_relationships.append(
                ExtractedRelationship(
                    source=src, target=tgt, relationship_type=rel.relationship_type
                )
            )

    raw_entity_count = sum(len(p.entities) for p in parts)
    raw_rel_count = sum(len(p.relationships) for p in parts)
    logger.info(
        "extractions_merged",
        chunks=len(parts),
        raw_entities=raw_entity_count,
        merged_entities=len(merged_entities),
        raw_relationships=raw_rel_count,
        merged_relationships=len(merged_relationships),
        dropped_relationships=dropped,
    )
    return Extraction(entities=merged_entities, relationships=merged_relationships)


def _coerce_entities(raw: object) -> list[ExtractedEntity]:
    if not isinstance(raw, list):
        return []
    out: list[ExtractedEntity] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        local_id = item.get("local_id")
        stix_type = item.get("type")
        if not isinstance(local_id, str) or not local_id:
            continue
        if not isinstance(stix_type, str) or stix_type not in _VALID_ENTITY_TYPES:
            continue
        properties = {k: v for k, v in item.items() if k not in ("local_id", "type")}
        out.append(ExtractedEntity(local_id=local_id, type=stix_type, properties=properties))
    return out


def _coerce_relationships(raw: object) -> list[ExtractedRelationship]:
    if not isinstance(raw, list):
        return []
    out: list[ExtractedRelationship] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        source = item.get("source")
        target = item.get("target")
        rtype = item.get("relationship_type")
        if not (isinstance(source, str) and isinstance(target, str) and isinstance(rtype, str)):
            continue
        if rtype not in _VALID_RELATIONSHIP_TYPES:
            continue
        out.append(ExtractedRelationship(source=source, target=target, relationship_type=rtype))
    return out


# ---------------------------------------------------------------------------
# L4: TRACE-built STIX 2.1 bundle
# ---------------------------------------------------------------------------


def build_stix_bundle_from_extraction(
    extraction: Extraction,
    *,
    source_url: str | None = None,
    collected_at: str | None = None,
    matched_pir_ids: list[str] | None = None,
    relevance_score: float | None = None,
    relevance_rationale: str | None = None,
    now: datetime | None = None,
) -> dict:
    """Construct a STIX 2.1 bundle from an ``Extraction``.

    All STIX wire-format details (UUIDv4 ids, ISO-8601 millisecond
    timestamps, ``spec_version``, cross-reference resolution) are produced
    here in code; the LLM never has a chance to malform them.

    Unresolved relationship endpoints (LLM hallucinated a local_id that
    doesn't exist in ``entities``) are dropped with a structured log
    warning rather than emitting a dangling reference SAGE would later
    fail on.
    """
    ts = (now or datetime.now(tz=UTC)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    objects: list[dict] = []
    local_to_stix: dict[str, str] = {}

    for entity in extraction.entities:
        stix_id = f"{entity.type}--{uuid.uuid4()}"
        local_to_stix[entity.local_id] = stix_id
        obj = {
            "type": entity.type,
            "id": stix_id,
            "spec_version": "2.1",
            "created": ts,
            "modified": ts,
        }
        # Copy LLM-supplied properties (name, description, labels, …) but never
        # let them override the wire-format fields above.
        for key, value in entity.properties.items():
            if key in obj:
                continue
            obj[key] = value
        # STIX 2.1 type-specific required-property defaults. The LLM is asked
        # for domain knowledge only — it does not know which STIX wire-format
        # fields are mandatory per type, so the bundle assembler fills them in.
        _apply_required_property_defaults(obj, ts)
        objects.append(obj)

    dropped = 0
    for rel in extraction.relationships:
        src_id = local_to_stix.get(rel.source)
        tgt_id = local_to_stix.get(rel.target)
        if src_id is None or tgt_id is None:
            dropped += 1
            continue
        objects.append(
            {
                "type": "relationship",
                "id": f"relationship--{uuid.uuid4()}",
                "spec_version": "2.1",
                "created": ts,
                "modified": ts,
                "relationship_type": rel.relationship_type,
                "source_ref": src_id,
                "target_ref": tgt_id,
            }
        )
    if dropped:
        logger.warning("stix_relationships_dropped", count=dropped)

    bundle: dict = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "created": ts,
        "objects": objects,
    }
    if source_url is not None:
        bundle["x_trace_source_url"] = source_url
        bundle["x_trace_collected_at"] = collected_at or ts
    if matched_pir_ids is not None:
        bundle["x_trace_matched_pir_ids"] = list(matched_pir_ids)
    if relevance_score is not None:
        bundle["x_trace_relevance_score"] = relevance_score
    if relevance_rationale:
        bundle["x_trace_relevance_rationale"] = relevance_rationale
    return bundle


def _apply_required_property_defaults(obj: dict, ts: str) -> None:
    """Fill in STIX 2.1 type-specific required properties the LLM didn't emit.

    Defaults are chosen conservatively — ``setdefault`` so anything the LLM
    explicitly supplied wins. Only mandatory properties per the STIX 2.1
    spec are added here; vocabulary corrections, optional metadata, and
    best-practice fields are left to the validator's warning level.
    """
    stype = obj.get("type")
    if stype == "malware":
        # Required by STIX 2.1 §4.7. `is_family` is a boolean discriminator
        # between malware family and instance — default to False (instance)
        # since incident reports usually describe a single deployment.
        obj.setdefault("is_family", False)
    elif stype == "indicator":
        # Required by STIX 2.1 §4.7. `valid_from` defaults to the bundle
        # timestamp (the report's collection time is the earliest known
        # validity). `pattern_type` defaults to "stix" — STIX patterning
        # is the only language reliably emitted by the L3 prompt.
        obj.setdefault("valid_from", ts)
        obj.setdefault("pattern_type", "stix")
