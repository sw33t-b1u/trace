"""PIR-driven L2 relevance gate.

Given an article and a ``PIRDocument``, ask a lightweight LLM whether the
article is worth running L3 STIX extraction on. The verdict is small and
JSON-shaped so it can be embedded directly in ``crawl_state.json`` and the
output bundle's ``x_trace_*`` metadata.

Failure semantics: any LLM/parse error returns
``RelevanceVerdict(decision="extraction_failed", ...)``. The caller is
expected to fail-open and proceed with extraction in that case (see HLD §6.3
for rationale).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

import structlog

from trace_engine.config import Config, load_config
from trace_engine.llm.client import call_llm, load_prompt
from trace_engine.stix.extractor import _extract_json_from_text
from trace_engine.validate.schema import PIRDocument, PIRItem

logger = structlog.get_logger(__name__)

_RELEVANCE_INPUT_MAX_CHARS = 3000
_PIR_DESCRIPTION_MAX_CHARS = 240
_PIR_LIST_FIELD_MAX_ITEMS = 8
# Verdict JSON is small (score + ids + short rationale) but Gemini occasionally
# truncates at 512; 1024 leaves comfortable headroom without inviting prose.
_RELEVANCE_MAX_OUTPUT_TOKENS = 1024


@dataclass(frozen=True)
class RelevanceVerdict:
    score: float
    matched_pir_ids: list[str] = field(default_factory=list)
    rationale: str = ""
    failed: bool = False  # True when extraction itself failed (fail-open)

    def keep(self, threshold: float) -> bool:
        """Return True if the caller should proceed with L3 extraction."""
        if self.failed:
            return True  # fail-open
        return self.score >= threshold


def _summarise_pir(item: PIRItem) -> dict:
    """Compact PIR summary for the L2 prompt.

    Long descriptions and unbounded `notable_groups` / `collection_focus`
    arrays were causing the JSON verdict to get truncated at the model's
    output limit. Keep the surface area small and predictable.
    """
    extra = item.model_dump(exclude_none=True)
    notable_groups = _trim_list(extra.get("notable_groups"))
    collection_focus = _trim_list(extra.get("collection_focus"))
    description = item.description or ""
    if len(description) > _PIR_DESCRIPTION_MAX_CHARS:
        description = description[:_PIR_DESCRIPTION_MAX_CHARS].rstrip() + "…"
    summary = {
        "pir_id": item.pir_id,
        "intelligence_level": item.intelligence_level,
        "description": description or None,
        "threat_actor_tags": list(item.threat_actor_tags),
        "asset_weight_rules": [
            {"tag": r.tag, "criticality_multiplier": r.criticality_multiplier}
            for r in item.asset_weight_rules
        ],
    }
    if notable_groups:
        summary["notable_groups"] = notable_groups
    if collection_focus:
        summary["collection_focus"] = collection_focus
    return summary


def _trim_list(raw: object) -> list[str]:
    if not isinstance(raw, list):
        return []
    return [str(v) for v in raw[:_PIR_LIST_FIELD_MAX_ITEMS]]


def _build_pir_context(doc: PIRDocument, *, restrict_to: list[str] | None = None) -> str:
    items = doc.root
    if restrict_to:
        wanted = set(restrict_to)
        items = [i for i in items if i.pir_id in wanted]
    return json.dumps([_summarise_pir(i) for i in items], indent=2, ensure_ascii=False)


def evaluate(
    text: str,
    pir_doc: PIRDocument,
    *,
    config: Config | None = None,
    restrict_to: list[str] | None = None,
    max_chars: int = _RELEVANCE_INPUT_MAX_CHARS,
) -> RelevanceVerdict:
    """Ask the L2 LLM whether ``text`` is relevant to any PIR in ``pir_doc``.

    ``restrict_to`` (optional) is a list of pir_ids — when supplied, only those
    PIRs are passed to the LLM. Used by ``sources.yaml`` per-source pinning.
    """
    cfg = config or load_config()
    template = load_prompt("relevance_check.md")
    prompt = template.replace(
        "{{PIR_CONTEXT}}", _build_pir_context(pir_doc, restrict_to=restrict_to)
    ).replace(
        "{{ARTICLE_TEXT}}",
        text if len(text) <= max_chars else text[:max_chars] + "\n\n[...truncated]",
    )

    logger.info(
        "relevance_call_start",
        chars=len(text),
        truncated=len(text) > max_chars,
        tier=cfg.relevance_model_tier,
    )

    try:
        raw = call_llm(
            cfg.relevance_model_tier,
            prompt,
            config=cfg,
            json_mode=True,
            max_output_tokens=_RELEVANCE_MAX_OUTPUT_TOKENS,
        )
    except (RuntimeError, ValueError) as exc:
        logger.warning("relevance_call_failed", error=str(exc))
        return RelevanceVerdict(score=0.0, failed=True, rationale=f"call_failed: {exc}")

    parsed = _extract_json_from_text(raw)
    if isinstance(parsed, dict):
        return _verdict_from_dict(parsed)

    # Full JSON parse failed — try the salvage path. Truncation typically
    # happens inside `rationale`, after `score` and `matched_pir_ids` have
    # already been emitted. We can still record a real verdict.
    salvaged = _salvage_partial_verdict(raw)
    if salvaged is not None:
        logger.info(
            "relevance_salvaged_partial_json",
            score=salvaged.score,
            matched_pir_ids=salvaged.matched_pir_ids,
        )
        return salvaged

    logger.warning(
        "relevance_parse_failed",
        response_type=type(parsed).__name__ if parsed is not None else "None",
        preview=raw[:200],
    )
    return RelevanceVerdict(
        score=0.0,
        failed=True,
        rationale=f"parse_failed: {raw[:120]!r}",
    )


def _verdict_from_dict(parsed: dict) -> RelevanceVerdict:
    score = _coerce_score(parsed.get("score"))
    matched_raw = parsed.get("matched_pir_ids") or []
    matched = [str(m) for m in matched_raw] if isinstance(matched_raw, list) else []
    rationale = (parsed.get("rationale") or "").strip()
    if len(rationale) > 200:
        rationale = rationale[:200]
    logger.info("relevance_call_done", score=score, matched_pir_ids=matched)
    return RelevanceVerdict(score=score, matched_pir_ids=matched, rationale=rationale)


_SCORE_RE = re.compile(r'"score"\s*:\s*([0-9]+(?:\.[0-9]+)?)')
_MATCHED_RE = re.compile(r'"matched_pir_ids"\s*:\s*\[([^\]]*)\]', re.DOTALL)
_PIR_ID_RE = re.compile(r'"([^"]+)"')


def _salvage_partial_verdict(raw: str) -> RelevanceVerdict | None:
    """Recover ``score`` and ``matched_pir_ids`` from a truncated JSON string.

    The model sometimes runs out of output budget mid-``rationale``. Score
    and matched_pir_ids are emitted earlier in the response, so a regex
    scrape can still produce a usable verdict. Rationale falls back to
    ``"(truncated)"`` so callers see why it's empty.
    """
    score_match = _SCORE_RE.search(raw)
    if score_match is None:
        return None
    score = _coerce_score(score_match.group(1))

    matched_match = _MATCHED_RE.search(raw)
    matched: list[str] = []
    if matched_match is not None:
        matched = [m for m in _PIR_ID_RE.findall(matched_match.group(1)) if m]

    return RelevanceVerdict(
        score=score,
        matched_pir_ids=matched,
        rationale="(truncated)",
    )


def _coerce_score(value: object) -> float:
    try:
        f = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, f))
