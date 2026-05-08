"""Extract STIX 2.1 objects from CTI report text using LLM.

The LLM (Vertex AI Gemini) reads a CTI report and returns a JSON array of
STIX 2.1 objects (intrusion-set, attack-pattern, malware, tool, vulnerability,
indicator, relationship).  The bundle can then be fed directly to SAGE ETL.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime

import structlog

from trace_engine.llm.client import TaskType, call_llm, load_prompt
from trace_engine.validate.schema import PIRDocument, PIRItem

logger = structlog.get_logger(__name__)

# "medium" (gemini-2.5-flash) is the default: fast enough for large CTI articles
# and accurate enough for STIX entity extraction.  Use "complex" only for reports
# with dense, ambiguous, or multi-language content.
_DEFAULT_TASK: TaskType = "medium"

_VALID_STIX_TYPES: frozenset[str] = frozenset(
    {
        "threat-actor",
        "intrusion-set",
        "attack-pattern",
        "malware",
        "tool",
        "vulnerability",
        "indicator",
        "relationship",
    }
)


def _extract_json_from_text(raw: str) -> list | dict | None:
    """Extract a JSON value from a plain-text LLM response.

    The model may wrap the JSON in a Markdown code block (```json ... ```) or
    return it inline.  This function tries, in order:
      1. Parse the full response as-is (already valid JSON)
      2. Extract the content of the first ```json ... ``` block
      3. Find the first '[' or '{' and parse from there
      4. Repair a truncated JSON array by closing after the last complete '}'

    Returns the parsed value, or None if all strategies fail.
    """
    # Strategy 1: verbatim parse
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # Strategy 2: markdown code block  ```json\n...\n```
    block = re.search(r"```(?:json)?\s*\n([\s\S]+?)\n```", raw)
    if block:
        try:
            return json.loads(block.group(1))
        except json.JSONDecodeError:
            pass

    # Strategy 3: find first '[' or '{' and parse from there
    start = min(
        (raw.find("[") if raw.find("[") != -1 else len(raw)),
        (raw.find("{") if raw.find("{") != -1 else len(raw)),
    )
    if start < len(raw):
        try:
            return json.loads(raw[start:])
        except json.JSONDecodeError:
            candidate = raw[start:]

            # Strategy 4: repair truncated array — close after last complete '}'
            last = None
            for m in re.finditer(r"\}", candidate):
                last = m
            if last is not None:
                repaired = re.sub(r",\s*$", "", candidate[: last.end()]) + "\n]"
                try:
                    result = json.loads(repaired)
                    if isinstance(result, list):
                        logger.warning(
                            "truncated_json_repaired",
                            original_chars=len(raw),
                            repaired_objects=len(result),
                        )
                        return result
                except json.JSONDecodeError:
                    pass

    return None


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


def extract_stix_objects(
    text: str,
    task: TaskType = _DEFAULT_TASK,
    config=None,
    *,
    pir_doc: PIRDocument | None = None,
) -> list[dict]:
    """Call LLM to extract STIX 2.1 objects from CTI report text.

    Uses plain-text mode (json_mode=False) to avoid Gemini's constrained JSON
    decoding, which can truncate output prematurely for complex STIX structures.
    JSON is extracted from the response with _extract_json_from_text().

    Args:
        text: Plain text of a CTI report (PDF, web article, etc.).
        task: LLM complexity tier. "medium" (gemini-2.5-flash) is the default
              and handles typical CTI blog posts and reports well.
              Use "complex" (gemini-2.5-pro) only for dense or ambiguous content.
        config: TRACE Config. Uses load_config() if None.
        pir_doc: Optional ``PIRDocument`` whose summary is appended to the
            prompt as a "## PIR Context" section (L3). Hint to the model only;
            does not filter the output.

    Returns:
        List of STIX 2.1 object dicts filtered to known STIX types.
    """
    template = load_prompt("stix_extraction.md")
    prompt = template.replace("{{REPORT_TEXT}}", text).replace(
        "{{PIR_CONTEXT_BLOCK}}", _render_pir_context_block(pir_doc)
    )

    logger.info("extracting_stix_objects", chars=len(text), task=task)
    raw = call_llm(task, prompt, config=config, json_mode=False, max_output_tokens=65536)

    parsed = _extract_json_from_text(raw)
    if parsed is None:
        logger.warning("llm_json_extract_failed", chars=len(raw))
        return []

    # LLM may return a bare list or a wrapped {"objects": [...]}
    if isinstance(parsed, dict):
        objects: list = parsed.get("objects", [])
    elif isinstance(parsed, list):
        objects = parsed
    else:
        logger.warning("unexpected_llm_response_format", response_type=type(parsed).__name__)
        objects = []

    valid = [o for o in objects if isinstance(o, dict) and o.get("type") in _VALID_STIX_TYPES]
    logger.info("stix_objects_extracted", total=len(objects), valid=len(valid))
    return valid


def build_stix_bundle(
    objects: list[dict],
    *,
    source_url: str | None = None,
    collected_at: str | None = None,
    matched_pir_ids: list[str] | None = None,
    relevance_score: float | None = None,
    relevance_rationale: str | None = None,
) -> dict:
    """Wrap extracted STIX objects in a STIX 2.1 bundle.

    L4 metadata: ``x_trace_source_url``, ``x_trace_collected_at``, and
    (when supplied) ``x_trace_matched_pir_ids`` / ``x_trace_relevance_score`` /
    ``x_trace_relevance_rationale``. SAGE ignores unknown ``x_*`` properties
    so adding them is backward-compatible.

    Args:
        objects: List of STIX 2.1 object dicts from extract_stix_objects().
        source_url: Origin URL or file path of the report.
        collected_at: ISO-8601 timestamp of when the article was fetched.
            Defaults to "now (UTC)" if omitted.
        matched_pir_ids: PIR ids judged relevant by the L2 gate, if any.
        relevance_score: 0.0–1.0 score from the L2 gate, if any.
        relevance_rationale: Short LLM-authored justification, if any.

    Returns:
        A STIX 2.1 bundle dict ready for JSON serialization or SAGE ETL.
    """
    now = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    bundle: dict = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "created": now,
        "objects": objects,
    }
    if source_url is not None:
        bundle["x_trace_source_url"] = source_url
        bundle["x_trace_collected_at"] = collected_at or now
    if matched_pir_ids is not None:
        bundle["x_trace_matched_pir_ids"] = list(matched_pir_ids)
    if relevance_score is not None:
        bundle["x_trace_relevance_score"] = relevance_score
    if relevance_rationale:
        bundle["x_trace_relevance_rationale"] = relevance_rationale
    return bundle
