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
            return None

    return None


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
    config=None,
    *,
    pir_doc: PIRDocument | None = None,
) -> Extraction:
    """Ask the LLM to return ``{entities: [...], relationships: [...]}``.

    The LLM produces only domain knowledge — names, descriptions,
    relationship_types — keyed by short ``local_id`` aliases it picks. STIX
    wire format (ids, timestamps, spec_version, ref translation) is the
    job of ``build_stix_bundle_from_extraction``.

    Returns an empty ``Extraction`` if the response can't be parsed; the
    caller can decide how to surface that (CLIs log + exit, batch records
    `extraction_failed`).
    """
    template = load_prompt("stix_extraction.md")
    prompt = template.replace("{{REPORT_TEXT}}", text).replace(
        "{{PIR_CONTEXT_BLOCK}}", _render_pir_context_block(pir_doc)
    )

    logger.info("extracting_entities", chars=len(text), task=task)
    raw = call_llm(task, prompt, config=config, json_mode=True, max_output_tokens=8192)

    parsed = _extract_json_from_text(raw)
    if not isinstance(parsed, dict):
        logger.warning(
            "extraction_response_not_object",
            response_type=type(parsed).__name__ if parsed is not None else "None",
            preview=raw[:200],
        )
        return Extraction()

    entities = _coerce_entities(parsed.get("entities"))
    relationships = _coerce_relationships(parsed.get("relationships"))
    logger.info(
        "entities_extracted",
        entities=len(entities),
        relationships=len(relationships),
    )
    return Extraction(entities=entities, relationships=relationships)


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
