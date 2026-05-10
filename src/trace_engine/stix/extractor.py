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
from pathlib import Path

import structlog

from trace_engine.config import Config, load_config
from trace_engine.llm.client import TaskType, call_llm, load_prompt
from trace_engine.stix.asset_resolver import resolve_asset_reference
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
        "identity",  # 1.0.0 — credential / org-targeting graph node, paired with SAGE 0.5.0
        # 1.3.0 / Initiative B — STIX 2.1 §6.4 user-account SCO + §4.10
        # observed-data SDO. The L3 prompt emits user-account observations
        # wrapped in observed-data; the bundle assembler synthesizes
        # x-asset-internal references for AccountOnAsset edges.
        "user-account",
        "observed-data",
    }
)

# `targets` added in 1.0.0 alongside identity. STIX 2.1 §4.13 source
# vocabulary: attack-pattern, campaign, intrusion-set, malware, threat-actor,
# tool. Target vocabulary: identity, location, vulnerability, infrastructure.
#
# `x-trace-has-access` added in 1.1.0 (Initiative A): identity → asset
# (resolved to a SAGE asset_id at TRACE-side via the 4-tier matching
# ladder in `resolve_asset_reference`). The relationship target_ref points
# at a synthesized `x-asset-internal--<asset_id>` STIX object that the
# bundle assembler creates per referenced asset.
#
# `x-trace-valids-on` added in 1.3.0 (Initiative B): user-account → asset.
# Same `x-asset-internal--<uuid5>` target convention as has-access; SAGE
# 0.7.0 maps it to the AccountOnAsset edge.
_VALID_RELATIONSHIP_TYPES: frozenset[str] = frozenset(
    {"uses", "exploits", "indicates", "targets", "x-trace-has-access", "x-trace-valids-on"}
)

# STIX 2.1 §6.7 `identity-class-ov` open vocabulary. Demote LLM values
# outside this set to `labels` (open vocab) — same pattern as the 0.5.1
# malware_types / tool_types handling.
_STIX21_IDENTITY_CLASS_OV: frozenset[str] = frozenset(
    {
        "individual",
        "group",
        "system",
        "organization",
        "class",
        "unspecified",
    }
)

# STIX 2.1 §6.6 `industry-sector-ov` open vocabulary. Same demote-to-labels
# pattern for `identity.sectors` values outside this set ({215} warning).
# 1.0.1 added when real-URL extraction emitted "fintech" / "electronic money"
# / "card-payments" etc. that the validator flagged.
_STIX21_INDUSTRY_SECTOR_OV: frozenset[str] = frozenset(
    {
        "agriculture",
        "aerospace",
        "automotive",
        "chemical",
        "commercial",
        "communications",
        "construction",
        "defense",
        "education",
        "energy",
        "entertainment",
        "financial-services",
        "government",
        "emergency-services",
        "government-local",
        "government-national",
        "government-public-services",
        "government-regional",
        "healthcare",
        "hospitality-leisure",
        "infrastructure",
        "dams",
        "nuclear",
        "water",
        "manufacturing",
        "mining",
        "non-profit",
        "pharmaceuticals",
        "retail",
        "technology",
        "telecommunications",
        "transportation",
        "utilities",
    }
)

# STIX 2.1 §4.13 relationship type table — `(source_type, relationship_type)`
# → suggested target types. Drop relationships whose source/target combination
# is outside the suggested set. Two TRACE-specific accept exceptions retained
# from 0.5.2: `tool uses malware` and `tool uses tool` (semantically valid in
# incident reports; major STIX consumers accept them).
_RELATIONSHIP_TYPE_TABLE: dict[tuple[str, str], frozenset[str]] = {
    # uses
    ("attack-pattern", "uses"): frozenset({"attack-pattern", "infrastructure", "malware", "tool"}),
    ("campaign", "uses"): frozenset({"attack-pattern", "infrastructure", "malware", "tool"}),
    ("intrusion-set", "uses"): frozenset({"attack-pattern", "infrastructure", "malware", "tool"}),
    ("malware", "uses"): frozenset({"attack-pattern", "infrastructure", "malware", "tool"}),
    ("threat-actor", "uses"): frozenset({"attack-pattern", "infrastructure", "malware", "tool"}),
    # `tool` → {malware, tool} are 0.5.2 accept exceptions (out of spec but
    # documented; see docs/data-model.md "Accepted OASIS validator warnings").
    ("tool", "uses"): frozenset({"attack-pattern", "infrastructure", "malware", "tool"}),
    # exploits — STIX 2.1 §4.13 lists `malware` as the only suggested source.
    # Actor-side "exploits vulnerability" semantics are expressed via
    # `targets` (intrusion-set / threat-actor / campaign targets
    # vulnerability), which is already in the table below. LLM-emitted
    # `intrusion-set exploits vulnerability` falls through the
    # relationship_type_mismatch_dropped guard. (Tightened in 1.0.2.)
    ("malware", "exploits"): frozenset({"vulnerability"}),
    # indicates — only indicator can indicate; broad target set excluding indicator itself
    ("indicator", "indicates"): frozenset(
        {
            "attack-pattern",
            "campaign",
            "infrastructure",
            "intrusion-set",
            "malware",
            "threat-actor",
            "tool",
        }
    ),
    # targets (1.0.0) — STIX 2.1 §4.13. Source: attack-pattern, campaign,
    # intrusion-set, malware, threat-actor, tool. Target: identity,
    # location, vulnerability, infrastructure. SAGE 0.5.0 only stores
    # actor-source edges (threat-actor / intrusion-set → identity);
    # other source/target pairs survive bundle validation but get
    # dropped in SAGE's mapper with a structured-log warning.
    ("attack-pattern", "targets"): frozenset(
        {"identity", "location", "vulnerability", "infrastructure"}
    ),
    ("campaign", "targets"): frozenset({"identity", "location", "vulnerability", "infrastructure"}),
    ("intrusion-set", "targets"): frozenset(
        {"identity", "location", "vulnerability", "infrastructure"}
    ),
    ("malware", "targets"): frozenset({"identity", "location", "vulnerability", "infrastructure"}),
    ("threat-actor", "targets"): frozenset(
        {"identity", "location", "vulnerability", "infrastructure"}
    ),
    ("tool", "targets"): frozenset({"identity", "location", "vulnerability", "infrastructure"}),
    # x-trace-has-access (1.1.0 / Initiative A) — identity → internal asset.
    # The target type `x-asset-internal` is a TRACE-synthesized STIX object
    # created by the bundle assembler whenever the resolver maps an LLM-
    # supplied asset reference to a SAGE asset_id. SAGE 0.6.0+ consumes
    # these as `HasAccess` rows.
    ("identity", "x-trace-has-access"): frozenset({"x-asset-internal"}),
    # x-trace-valids-on (1.3.0 / Initiative B) — user-account → internal
    # asset. Same x-asset-internal target convention as has-access; SAGE
    # 0.7.0 routes to the AccountOnAsset edge.
    ("user-account", "x-trace-valids-on"): frozenset({"x-asset-internal"}),
}


# stix2patterns is a transitive dep of stix2-validator. Imported lazily at
# module load so missing-dep environments still load extractor (the indicator
# pattern check just becomes a no-op).
try:
    from stix2patterns.v21.pattern import Pattern as _StixPattern  # noqa: I001
except ImportError:  # pragma: no cover
    _StixPattern = None  # type: ignore[assignment]

# STIX 2.1 §7.3 toplevel-property extension definition for TRACE-emitted
# bundle metadata (``x_trace_source_url``, ``x_trace_collected_at``,
# ``x_trace_matched_pir_ids``, ``x_trace_relevance_score``,
# ``x_trace_relevance_rationale``). The id is **stable across emissions** —
# every bundle TRACE produces references the same extension definition so
# downstream STIX consumers can recognise the extension without per-bundle
# discovery. Generated once via uuid4() and pinned; never regenerate.
_TRACE_EXTENSION_ID: str = "extension-definition--c1e4d6a7-2f3b-4e8c-9a5f-1b8d7e6c4a3f"
_TRACE_EXTENSION_SCHEMA_URL: str = (
    "https://github.com/sw33t-b1u/sage/blob/main/TRACE/docs/data-model.md#"
    "trace-bundle-metadata-extension"
)
_TRACE_EXTENSION_VERSION: str = "1.0"

# Property names introduced by the TRACE bundle metadata extension. Listed in
# `extension-definition.extension_properties` per STIX 2.1 §7.3 (SHOULD)
# so consumers know exactly which keys the extension defines.
_TRACE_EXTENSION_PROPERTIES: list[str] = [
    "x_trace_source_url",
    "x_trace_collected_at",
    "x_trace_matched_pir_ids",
    "x_trace_relevance_score",
    "x_trace_relevance_rationale",
]

# STIX 2.1 §6.5 `tool-type-ov` open vocabulary. Anything the LLM emits in
# `tool_types` outside this set is demoted to `labels` (open vocab) so the
# information survives but the validator's {222} warning goes away.
_STIX21_TOOL_TYPE_OV: frozenset[str] = frozenset(
    {
        "denial-of-service",
        "exploitation",
        "information-gathering",
        "network-capture",
        "credential-exploitation",
        "remote-access",
        "vulnerability-scanning",
        "unknown",
    }
)

# STIX 2.1 §6.4 `malware-type-ov` open vocabulary. Same demotion to `labels`
# for any LLM-emitted value outside this set ({216} warning).
_STIX21_MALWARE_TYPE_OV: frozenset[str] = frozenset(
    {
        "adware",
        "backdoor",
        "bot",
        "bootkit",
        "ddos",
        "downloader",
        "dropper",
        "exploit-kit",
        "keylogger",
        "ransomware",
        "remote-access-trojan",
        "resource-exploitation",
        "rogue-security-software",
        "rootkit",
        "screen-capture",
        "spyware",
        "trojan",
        "unknown",
        "virus",
        "webshell",
        "wiper",
        "worm",
    }
)


# STIX 2.1 §6.2 attack-motivation-ov. Demote LLM values outside this set to
# `labels` (same pattern as identity_class / sectors / sophistication).
# Spec list: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
# section 10.2 (open vocab `attack-motivation-ov`).
_STIX21_ATTACK_MOTIVATION_OV: frozenset[str] = frozenset(
    {
        "accidental",
        "coercion",
        "dominance",
        "ideology",
        "notoriety",
        "organizational-gain",
        "personal-gain",
        "personal-satisfaction",
        "revenge",
        "unpredictable",
    }
)


# CVE identifier format per CVE Numbering Authority rules:
# CVE-YYYY-NNNN where YYYY ≥ 1999 (CVE program start), NNNN ≥ 4 digits with
# arbitrary trailing digits (no upper bound — high-volume years exceed 6).
# Used to validate vulnerability `name` and external_reference external_id.
_CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


# 1.2.1: UUIDv5 namespace for synthetic ``x-asset-internal`` STIX ids.
# STIX 2.1 §2.7 requires `<type>--<UUIDv4|v5>` for any identifier referenced
# by a relationship. Using the asset_id directly (e.g. `asset-CA-001`)
# violated the format and the stix2 library rejected the relationship at
# SAGE's parser. UUIDv5 keeps the id deterministic per asset_id (the same
# SAGE asset always produces the same STIX id across runs) while staying
# spec-compliant. The actual asset_id lives in the `asset_id` property of
# the x-asset-internal object — SAGE reads from there, not from the id.
_X_ASSET_INTERNAL_NAMESPACE = uuid.UUID("d41d8cd9-8f00-b204-e980-0998ecf8427e")


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
class IdentityAssetEdge:
    """LLM-extracted identity → asset edge (Initiative A).

    Distinct from ``ExtractedRelationship`` because the target is not
    another extracted entity but a free-form asset reference that
    requires TRACE-side resolution against ``assets.json``. Resolution
    happens at bundle assembly time; unresolved edges are dropped.
    """

    source: str  # identity local_id
    asset_reference: str  # LLM-supplied free-form asset hint
    description: str = ""


@dataclass
class Extraction:
    entities: list[ExtractedEntity] = field(default_factory=list)
    relationships: list[ExtractedRelationship] = field(default_factory=list)
    identity_asset_edges: list[IdentityAssetEdge] = field(default_factory=list)


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
        "## PIR Context (priority hint, NOT a filter)",
        "",
        (
            "**Read this carefully.** The PIRs below describe what the "
            "organization most cares about — they help you decide which "
            "entities are *most relevant*, but they are NOT a filter on "
            "what to extract."
        ),
        "",
        "**Required behaviour:**",
        "",
        (
            "- Extract every threat-actor, intrusion-set, malware, tool, "
            "attack-pattern, vulnerability, and indicator that is *named* "
            "or *clearly described* in the report, regardless of whether "
            "it overlaps with any PIR below."
        ),
        (
            "- Treat the PIRs as ranking input only: when the report is "
            "long and you must choose what to describe in detail, prefer "
            "entities that align with the PIRs."
        ),
        (
            "- Do **not** drop a real entity just because no PIR mentions "
            "it. Empty PIR coverage is acceptable; an under-extracted "
            "bundle is not."
        ),
        ("- Do **not** invent entities that are not in the report just to satisfy a PIR."),
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
    identity_asset_edges = _coerce_identity_asset_edges(parsed.get("identity_asset_edges"))

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
        identity_asset_edges = [
            IdentityAssetEdge(
                source=prefix + e.source,
                asset_reference=e.asset_reference,
                description=e.description,
            )
            for e in identity_asset_edges
        ]
    return Extraction(
        entities=entities,
        relationships=relationships,
        identity_asset_edges=identity_asset_edges,
    )


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

    # Identity-asset edges (1.2.0): same alias remap + de-dup. Edges that
    # reference an unknown identity local_id (LLM hallucination) are dropped.
    merged_iae: list[IdentityAssetEdge] = []
    iae_seen: set[tuple[str, str]] = set()
    iae_dropped = 0
    for part in parts:
        for edge in part.identity_asset_edges:
            src = alias_to_canonical.get(edge.source)
            if src is None:
                iae_dropped += 1
                continue
            marker = (src, edge.asset_reference.strip().lower())
            if marker in iae_seen:
                continue
            iae_seen.add(marker)
            merged_iae.append(
                IdentityAssetEdge(
                    source=src,
                    asset_reference=edge.asset_reference,
                    description=edge.description,
                )
            )

    raw_entity_count = sum(len(p.entities) for p in parts)
    raw_rel_count = sum(len(p.relationships) for p in parts)
    raw_iae_count = sum(len(p.identity_asset_edges) for p in parts)
    logger.info(
        "extractions_merged",
        chunks=len(parts),
        raw_entities=raw_entity_count,
        merged_entities=len(merged_entities),
        raw_relationships=raw_rel_count,
        merged_relationships=len(merged_relationships),
        dropped_relationships=dropped,
        raw_identity_asset_edges=raw_iae_count,
        merged_identity_asset_edges=len(merged_iae),
        dropped_identity_asset_edges=iae_dropped,
    )
    return Extraction(
        entities=merged_entities,
        relationships=merged_relationships,
        identity_asset_edges=merged_iae,
    )


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


def _coerce_identity_asset_edges(raw: object) -> list[IdentityAssetEdge]:
    """Parse the LLM's ``identity_asset_edges`` array (TRACE 1.2.0+).

    Distinct from ``relationships`` because the target is a free-form
    asset reference string, not another extracted entity. Resolution
    against ``assets.json`` happens at bundle assembly time.
    """
    if not isinstance(raw, list):
        return []
    out: list[IdentityAssetEdge] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        source = item.get("source")
        asset_reference = item.get("asset_reference")
        description = item.get("description") or ""
        if not (isinstance(source, str) and source.strip()):
            continue
        if not (isinstance(asset_reference, str) and asset_reference.strip()):
            continue
        out.append(
            IdentityAssetEdge(
                source=source,
                asset_reference=asset_reference,
                description=description if isinstance(description, str) else "",
            )
        )
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
    config: Config | None = None,
    assets: list[dict] | None = None,
) -> dict:
    """Construct a STIX 2.1 bundle from an ``Extraction``.

    All STIX wire-format details (UUIDv4 ids, ISO-8601 millisecond
    timestamps, ``spec_version``, cross-reference resolution) are produced
    here in code; the LLM never has a chance to malform them.

    Unresolved relationship endpoints (LLM hallucinated a local_id that
    doesn't exist in ``entities``) are dropped with a structured log
    warning rather than emitting a dangling reference SAGE would later
    fail on.

    ``assets`` (1.2.0): list of ``assets.json[*].assets[]`` entries used
    to resolve ``identity_asset_edges`` against. When omitted, no
    identity-asset edges are emitted (the LLM may have extracted them
    but resolution requires the analyst's asset inventory). When
    supplied, each edge is run through the 4-tier
    ``resolve_asset_reference`` ladder; resolved edges produce a
    synthetic ``x-asset-internal--<asset_id>`` STIX object (one per
    referenced asset) plus an ``x-trace-has-access`` relationship.
    """
    ts = (now or datetime.now(tz=UTC)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    objects: list[dict] = []
    local_to_stix: dict[str, str] = {}
    local_to_type: dict[str, str] = {}

    indicators_dropped_invalid_pattern = 0
    vulnerabilities_dropped_no_cve = 0
    for entity in extraction.entities:
        stix_id = f"{entity.type}--{uuid.uuid4()}"
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
        # Strip empty list properties before validator sees them. STIX 2.1
        # disallows `aliases: []`, `labels: []`, etc.; the LLM occasionally
        # emits them when nothing is known.
        _scrub_empty_arrays(obj)
        # Validate STIX patterning syntax for indicators; drop the indicator
        # outright if the pattern is missing or fails to parse. Relationships
        # pointing at the dropped indicator fall through the dangling-ref
        # guard below.
        if entity.type == "indicator" and not _validate_indicator_pattern(obj):
            indicators_dropped_invalid_pattern += 1
            logger.warning(
                "indicator_dropped_invalid_pattern",
                local_id=entity.local_id,
                pattern=obj.get("pattern"),
            )
            continue
        # Drop vulnerability entries the LLM hallucinated from generic prose
        # mentions (e.g. name="Common Vulnerabilities and Exposures (CVEs)").
        # SAGE indexes vulnerabilities by CVE id with a STRING(32) column;
        # entries without a parseable CVE both break the schema and provide
        # no analytical value. (1.0.3 fix.)
        if entity.type == "vulnerability":
            cve_id = _extract_cve_id(obj)
            if cve_id is None:
                vulnerabilities_dropped_no_cve += 1
                logger.warning(
                    "vulnerability_dropped_no_cve",
                    local_id=entity.local_id,
                    name=obj.get("name"),
                )
                continue
            # Normalize the entity name to the canonical CVE id so downstream
            # consumers (SAGE mapper, validator) see a clean identifier even
            # when the LLM wrote a longer descriptive name.
            obj["name"] = cve_id
        local_to_stix[entity.local_id] = stix_id
        local_to_type[entity.local_id] = entity.type
        objects.append(obj)
    if indicators_dropped_invalid_pattern:
        logger.warning(
            "indicators_dropped_invalid_pattern_total",
            count=indicators_dropped_invalid_pattern,
        )
    if vulnerabilities_dropped_no_cve:
        logger.warning(
            "vulnerabilities_dropped_no_cve_total",
            count=vulnerabilities_dropped_no_cve,
        )

    dropped_unresolved = 0
    dropped_type_mismatch = 0
    for rel in extraction.relationships:
        src_id = local_to_stix.get(rel.source)
        tgt_id = local_to_stix.get(rel.target)
        if src_id is None or tgt_id is None:
            dropped_unresolved += 1
            continue
        src_type = local_to_type[rel.source]
        tgt_type = local_to_type[rel.target]
        if not _is_relationship_suggested(src_type, rel.relationship_type, tgt_type):
            dropped_type_mismatch += 1
            logger.warning(
                "relationship_type_mismatch_dropped",
                source_type=src_type,
                relationship_type=rel.relationship_type,
                target_type=tgt_type,
            )
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
    if dropped_unresolved:
        logger.warning("stix_relationships_dropped", count=dropped_unresolved)
    if dropped_type_mismatch:
        logger.warning("stix_relationships_type_mismatch_dropped", count=dropped_type_mismatch)

    # 1.2.0 — Identity-asset edges (Initiative A).
    # Each LLM-extracted edge references an identity by local_id and
    # carries a free-form asset hint string. Resolution against the
    # supplied ``assets`` list happens here at the bundle assembler;
    # unresolved edges drop entirely (analyst manual review is not an
    # acceptable fallback per the design decision 2026-05-10).
    iae_emitted = 0
    iae_dropped_unresolved_source = 0
    iae_dropped_no_assets_supplied = 0
    iae_dropped_unresolved_asset = 0
    asset_internal_ids: dict[str, str] = {}  # asset_id → x-asset-internal STIX id (1:1)
    has_identity_asset_edges = False
    if extraction.identity_asset_edges:
        for edge in extraction.identity_asset_edges:
            src_stix = local_to_stix.get(edge.source)
            src_type = local_to_type.get(edge.source)
            if src_stix is None or src_type != "identity":
                iae_dropped_unresolved_source += 1
                logger.warning(
                    "identity_asset_edge_unresolved_source",
                    source_local=edge.source,
                    asset_reference=edge.asset_reference,
                )
                continue
            if not assets:
                iae_dropped_no_assets_supplied += 1
                continue
            resolution = resolve_asset_reference(edge.asset_reference, assets)
            if resolution is None:
                iae_dropped_unresolved_asset += 1
                continue
            asset_internal_id = asset_internal_ids.get(resolution.asset_id)
            if asset_internal_id is None:
                # 1.2.1: STIX 2.1 §2.7 requires <type>--<UUIDv4|v5> for the
                # identifier of any object referenced by a relationship.
                # ``x-asset-internal--asset-CA-001`` failed validation in
                # the stix2 library used by SAGE's parser. Switch to a
                # UUIDv5 derived deterministically from ``asset_id`` so
                # the same SAGE asset always produces the same STIX id;
                # the actual asset_id moves into a property on the object.
                asset_uuid = uuid.uuid5(_X_ASSET_INTERNAL_NAMESPACE, resolution.asset_id)
                asset_internal_id = f"x-asset-internal--{asset_uuid}"
                asset_internal_ids[resolution.asset_id] = asset_internal_id
                # Synthetic STIX object — `asset_id` carries the SAGE-side
                # primary key separately from the STIX id. SAGE 0.6.2's
                # parser/worker reads `asset_id` from this object when
                # resolving x-trace-has-access relationships.
                objects.append(
                    {
                        "type": "x-asset-internal",
                        "id": asset_internal_id,
                        "spec_version": "2.1",
                        "created": ts,
                        "modified": ts,
                        "asset_id": resolution.asset_id,
                    }
                )
            objects.append(
                {
                    "type": "relationship",
                    "id": f"relationship--{uuid.uuid4()}",
                    "spec_version": "2.1",
                    "created": ts,
                    "modified": ts,
                    "relationship_type": "x-trace-has-access",
                    "source_ref": src_stix,
                    "target_ref": asset_internal_id,
                    "description": edge.description or None,
                    "confidence": resolution.confidence,
                }
            )
            iae_emitted += 1
            has_identity_asset_edges = True
    if iae_emitted or extraction.identity_asset_edges:
        logger.info(
            "identity_asset_edges_processed",
            extracted=len(extraction.identity_asset_edges),
            emitted=iae_emitted,
            dropped_unresolved_source=iae_dropped_unresolved_source,
            dropped_no_assets_supplied=iae_dropped_no_assets_supplied,
            dropped_unresolved_asset=iae_dropped_unresolved_asset,
            asset_internal_objects=len(asset_internal_ids),
        )

    has_trace_metadata = (
        source_url is not None
        or matched_pir_ids is not None
        or relevance_score is not None
        or bool(relevance_rationale)
        or has_identity_asset_edges
    )

    # Prepend the TRACE extension definition object so the bundle can carry
    # `x_trace_*` properties without tripping STIX 2.1 §7.3 {401} warnings.
    # The definition is stable (fixed id), self-contained, and only emitted
    # when at least one `x_trace_*` field would be present.
    if has_trace_metadata:
        objects.insert(0, _build_trace_extension_definition(ts))

    # STIX 2.1 deprecated `spec_version` and `created` on the bundle envelope
    # (per-object only). SAGE's parser iterates `bundle.objects[]` and reads
    # per-object spec_version, so the removal is safe.
    bundle: dict = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
    if has_trace_metadata:
        bundle["extensions"] = {
            _TRACE_EXTENSION_ID: {"extension_type": "toplevel-property-extension"}
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

    # 0.5.0: augment external_references[*].hashes (SHA-256) for entries
    # that have a URL but no hash, removing the OASIS {302} warnings.
    cfg = config or load_config()
    if cfg.external_ref_hash_enabled:
        from trace_engine.stix.external_ref_hash import augment_external_references

        augment_external_references(
            objects,
            cache_path=Path(cfg.external_ref_hash_cache_path),
            ttl_days=cfg.external_ref_hash_ttl_days,
            user_agent=cfg.crawl_user_agent,
        )
    return bundle


def _build_trace_extension_definition(ts: str) -> dict:
    """Construct the STIX 2.1 extension-definition object for TRACE metadata.

    Same id every time (see ``_TRACE_EXTENSION_ID``). ``created`` /
    ``modified`` mirror the bundle timestamp so all objects share one
    timestamp — the validator does not require extension-definition to be
    immutable across emissions, only that the id is stable.
    """
    return {
        "type": "extension-definition",
        "id": _TRACE_EXTENSION_ID,
        "spec_version": "2.1",
        "created": ts,
        "modified": ts,
        "name": "TRACE bundle metadata extension",
        "description": (
            "TRACE-emitted top-level bundle properties: source URL, "
            "collection timestamp, matched PIR ids, relevance score, and "
            "relevance rationale. Consumers without the extension can "
            "ignore these fields safely."
        ),
        "schema": _TRACE_EXTENSION_SCHEMA_URL,
        "version": _TRACE_EXTENSION_VERSION,
        "extension_types": ["toplevel-property-extension"],
        "extension_properties": list(_TRACE_EXTENSION_PROPERTIES),
    }


def _apply_required_property_defaults(obj: dict, ts: str) -> None:
    """Fill in STIX 2.1 type-specific required properties the LLM didn't emit,
    and demote vocabulary-violation values from open-vocab fields into
    ``labels`` (also open-vocab) so information survives without tripping
    the OASIS validator's {216}/{222} warnings.

    Defaults are conservative — ``setdefault`` so anything the LLM
    explicitly supplied wins.
    """
    stype = obj.get("type")
    if stype == "malware":
        # Required by STIX 2.1 §4.7. `is_family` is a boolean discriminator
        # between malware family and instance — default to False (instance)
        # since incident reports usually describe a single deployment.
        obj.setdefault("is_family", False)
        _filter_open_vocab(obj, "malware_types", _STIX21_MALWARE_TYPE_OV)
    elif stype == "indicator":
        # Required by STIX 2.1 §4.7. `valid_from` defaults to the bundle
        # timestamp (the report's collection time is the earliest known
        # validity). `pattern_type` defaults to "stix" — STIX patterning
        # is the only language reliably emitted by the L3 prompt.
        obj.setdefault("valid_from", ts)
        obj.setdefault("pattern_type", "stix")
        # STIX 2.1 §4.7 SHOULD: indicator must include both `name` and
        # `description`. The L3 LLM commonly returns `pattern` only.
        # Synthesise a short name from the pattern and a generic
        # description. (Validator {303} fix in 1.0.1.)
        if "name" not in obj:
            obj["name"] = _derive_indicator_name(obj.get("pattern", ""))
        obj.setdefault("description", "Indicator extracted from CTI report")
    elif stype == "tool":
        _filter_open_vocab(obj, "tool_types", _STIX21_TOOL_TYPE_OV)
    elif stype == "intrusion-set":
        # STIX 2.1 §4.5 does not define `sophistication` for intrusion-set
        # (it lives on `threat-actor` only). When the LLM puts it here,
        # demote to `labels` (open vocab) — same pattern as the open-vocab
        # demotion in 0.5.1.
        _demote_property_to_labels(obj, "sophistication")
        # STIX 2.1 §6.2 attack-motivation-ov is open vocab; `primary_motivation`
        # / `secondary_motivations` outside the spec list trip {211}. Same
        # demote-to-labels pattern as identity_class / sectors. (1.0.3 fix.)
        _demote_scalar_to_labels_if_outside(obj, "primary_motivation", _STIX21_ATTACK_MOTIVATION_OV)
        _filter_open_vocab(obj, "secondary_motivations", _STIX21_ATTACK_MOTIVATION_OV)
    elif stype == "threat-actor":
        # STIX 2.1 §4.17 threat-actor uses the same attack-motivation-ov for
        # primary_motivation / secondary_motivations / goals (goals stays
        # free-form per spec). Same demote pattern. (1.0.3 fix.)
        _demote_scalar_to_labels_if_outside(obj, "primary_motivation", _STIX21_ATTACK_MOTIVATION_OV)
        _filter_open_vocab(obj, "secondary_motivations", _STIX21_ATTACK_MOTIVATION_OV)
    elif stype == "identity":
        # STIX 2.1 §6.7 `identity-class-ov` is open vocab but the
        # validator emits {2xx} on out-of-vocab values. Demote to
        # `labels` (open vocab) when the LLM picks something exotic.
        _demote_scalar_to_labels_if_outside(obj, "identity_class", _STIX21_IDENTITY_CLASS_OV)
        # STIX 2.1 §6.6 `industry-sector-ov` — same pattern as
        # tool_types / malware_types. Out-of-vocab `sectors` values
        # ("fintech", "card-payments", etc.) move to `labels`.
        _filter_open_vocab(obj, "sectors", _STIX21_INDUSTRY_SECTOR_OV)
    elif stype == "vulnerability":
        # STIX 2.1 §4.18 vulnerability does not define `aliases`. The L3
        # LLM occasionally puts CVE alternate names there ("EternalBlue",
        # "ProxyLogon"). Demote to `labels` (open vocab on the common
        # SDO properties) so the alternate names survive without the
        # {401} custom-property flag. (1.0.2 fix.)
        _demote_list_to_labels(obj, "aliases")


def _demote_list_to_labels(obj: dict, field_name: str) -> None:
    """Move a list-valued property entirely into ``labels``.

    Used when the LLM puts a list under a key the STIX object type
    does not define (e.g. ``aliases`` on ``vulnerability``). The field
    is removed; non-empty string values join ``labels`` (deduped,
    order-preserving).
    """
    raw = obj.pop(field_name, None)
    if not isinstance(raw, list):
        return
    cleaned = [v for v in raw if isinstance(v, str) and v.strip()]
    if not cleaned:
        return
    existing = obj.get("labels")
    merged: list[str] = list(existing) if isinstance(existing, list) else []
    seen = set(merged)
    for v in cleaned:
        if v not in seen:
            merged.append(v)
            seen.add(v)
    obj["labels"] = merged


def _derive_indicator_name(pattern: str) -> str:
    """Synthesise a short indicator name from a STIX pattern.

    STIX 2.1 §4.7 SHOULD that indicators carry both `name` and
    `description`. The L3 LLM frequently emits indicators with only
    `pattern`. This function picks a readable label out of the
    pattern's main SCO so the validator stops flagging {303} and
    downstream consumers see something meaningful.
    """
    if not isinstance(pattern, str) or not pattern.strip():
        return "Indicator"
    # `[type:property = 'value']` — extract `type` and the first
    # quoted value if present.
    match = re.search(r"\[\s*([\w-]+)\s*:[\w.\-]+\s*=\s*'([^']{1,80})'", pattern)
    if match is None:
        # No quoted value (e.g. integer literal); fall back to type only.
        type_match = re.search(r"\[\s*([\w-]+)\s*:", pattern)
        if type_match is not None:
            return f"Indicator: {type_match.group(1)}"
        return "Indicator"
    sco_type = match.group(1)
    value = match.group(2)
    return f"{sco_type}: {value}"


def _demote_scalar_to_labels_if_outside(obj: dict, field_name: str, vocab: frozenset[str]) -> None:
    """Demote a scalar property to ``labels`` only when its value is
    outside the supplied open-vocab set. Conforming values stay put.

    Used for identity_class (STIX 2.1 §6.7) — the validator tolerates
    out-of-vocab values but flags them; we keep the information in
    `labels` and clear the misused field.
    """
    raw = obj.get(field_name)
    if not isinstance(raw, str):
        return
    if raw in vocab:
        return
    _demote_property_to_labels(obj, field_name)


def _demote_property_to_labels(obj: dict, field_name: str) -> None:
    """Move a single LLM-supplied scalar property into ``labels``.

    Used for properties the LLM emits on a STIX type that does not define
    them (e.g. ``sophistication`` on ``intrusion-set``). The original
    field is removed; the value joins ``labels`` (deduped, order-preserving)
    so the information survives without tripping {401}.
    """
    raw = obj.pop(field_name, None)
    if not isinstance(raw, str):
        return
    raw = raw.strip()
    if not raw:
        return
    existing = obj.get("labels")
    if isinstance(existing, list):
        if raw not in existing:
            existing.append(raw)
    else:
        obj["labels"] = [raw]


def _scrub_empty_arrays(obj: dict) -> None:
    """Strip keys whose value is an empty list. STIX 2.1 disallows empty
    arrays for `labels`, `aliases`, `kill_chain_phases`, `external_references`
    and most other list-valued fields; the LLM occasionally emits `[]` when
    nothing is known. Removing the key entirely satisfies the validator.
    """
    for key in list(obj.keys()):
        value = obj.get(key)
        if isinstance(value, list) and len(value) == 0:
            del obj[key]


def _validate_indicator_pattern(obj: dict) -> bool:
    """Return True when the indicator's `pattern` parses as STIX 2.1
    patterning syntax (or the pattern is in another language).

    Returning False causes the caller to drop the indicator entirely;
    relationships pointing at it fall through the dangling-ref guard.

    Drop conditions:
    - `pattern` missing or empty → required by STIX 2.1 §4.7. The L3 LLM
      sometimes emits "indicator" entities for prose descriptions of
      patterns ("Newly Registered Domains") without an actual pattern;
      these have no operational value to SAGE and would only generate
      validator errors. (1.0.3 fix.)
    - `pattern` present but does not parse as STIX patterning syntax
      and `pattern_type == "stix"`. Other pattern types (YARA, Snort,
      PCRE) are passed through untouched.

    Pattern parsing uses ``stix2patterns.v21.pattern.Pattern`` which is a
    transitive dependency of ``stix2-validator``. When the parser is not
    installed, only the missing-pattern check applies.
    """
    pattern = obj.get("pattern")
    if not isinstance(pattern, str) or not pattern.strip():
        return False
    if _StixPattern is None:
        return True
    if obj.get("pattern_type", "stix") != "stix":
        return True
    try:
        _StixPattern(pattern)
    except Exception:  # noqa: BLE001 — stix2patterns raises ParseException; be defensive
        return False
    return True


def _extract_cve_id(obj: dict) -> str | None:
    """Return a normalized CVE-YYYY-NNNN identifier for a vulnerability
    object, or ``None`` when no CVE id can be derived.

    Resolution order, matching STIX 2.1 §4.18 conventions:

    1. Each entry in ``external_references`` whose ``source_name`` equals
       ``"cve"`` (case-insensitive). The ``external_id`` is checked first,
       then ``url`` for the trailing CVE token. The first match wins.
    2. The vulnerability's ``name`` itself, when it parses as a CVE id.

    Used to drop vulnerability entries that the LLM hallucinated from
    generic CVE references in prose (e.g. ``name="Common Vulnerabilities
    and Exposures (CVEs)"``). Such entries break SAGE's
    ``Vulnerability.cve_id STRING(32)`` constraint and have no analytical
    value because no actual CVE is identified. (1.0.3 fix.)
    """
    refs = obj.get("external_references") or []
    if isinstance(refs, list):
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            if (ref.get("source_name") or "").lower() != "cve":
                continue
            ext_id = ref.get("external_id")
            if isinstance(ext_id, str) and _CVE_ID_PATTERN.fullmatch(ext_id.strip()):
                return ext_id.strip()
            url = ref.get("url")
            if isinstance(url, str):
                # MITRE / NVD URLs end with `/CVE-YYYY-NNNN` or `?name=CVE-...`
                m = re.search(r"CVE-\d{4}-\d{4,}", url)
                if m and _CVE_ID_PATTERN.fullmatch(m.group()):
                    return m.group()
    name = obj.get("name")
    if isinstance(name, str) and _CVE_ID_PATTERN.fullmatch(name.strip()):
        return name.strip()
    return None


def _is_relationship_suggested(src_type: str, rel_type: str, tgt_type: str) -> bool:
    """Check `(src_type, rel_type, tgt_type)` against the STIX 2.1 §4.13
    suggested-relationship table. See `_RELATIONSHIP_TYPE_TABLE` for the
    exact entries (including the two TRACE 0.5.2 accept exceptions for
    `tool uses {malware,tool}`).
    """
    allowed = _RELATIONSHIP_TYPE_TABLE.get((src_type, rel_type))
    if allowed is None:
        return False
    return tgt_type in allowed


def _filter_open_vocab(obj: dict, field_name: str, vocab: frozenset[str]) -> None:
    """Split ``obj[field_name]`` into vocab-conforming and non-conforming
    values. Conforming stays in place; the rest is appended to ``labels``
    (deduped, order-preserving). Empty conforming list removes the field
    entirely so the bundle does not carry an empty array.
    """
    raw = obj.get(field_name)
    if not isinstance(raw, list) or not raw:
        return
    conforming: list[str] = []
    extras: list[str] = []
    for v in raw:
        if not isinstance(v, str):
            continue
        if v in vocab:
            conforming.append(v)
        else:
            extras.append(v)
    if conforming:
        obj[field_name] = conforming
    else:
        obj.pop(field_name, None)
    if extras:
        existing = obj.get("labels")
        merged: list[str] = list(existing) if isinstance(existing, list) else []
        seen = set(merged)
        for e in extras:
            if e not in seen:
                merged.append(e)
                seen.add(e)
        obj["labels"] = merged
