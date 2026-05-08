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
from dataclasses import dataclass, field

import structlog

from trace_engine.config import Config, load_config
from trace_engine.llm.client import call_llm, load_prompt
from trace_engine.validate.schema import PIRDocument, PIRItem

logger = structlog.get_logger(__name__)

_RELEVANCE_INPUT_MAX_CHARS = 3000


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
    extra = item.model_dump(exclude_none=True)
    notable_groups = extra.get("notable_groups") or []
    collection_focus = extra.get("collection_focus") or []
    return {
        "pir_id": item.pir_id,
        "intelligence_level": item.intelligence_level,
        "description": item.description,
        "threat_actor_tags": list(item.threat_actor_tags),
        "notable_groups": list(notable_groups) if isinstance(notable_groups, list) else [],
        "collection_focus": (list(collection_focus) if isinstance(collection_focus, list) else []),
        "asset_weight_rules": [
            {"tag": r.tag, "criticality_multiplier": r.criticality_multiplier}
            for r in item.asset_weight_rules
        ],
    }


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
            max_output_tokens=512,
        )
        parsed = json.loads(raw)
    except (json.JSONDecodeError, RuntimeError, ValueError) as exc:
        logger.warning("relevance_extraction_failed", error=str(exc))
        return RelevanceVerdict(score=0.0, failed=True, rationale=f"extraction_failed: {exc}")

    score = _coerce_score(parsed.get("score"))
    matched = parsed.get("matched_pir_ids") or []
    if not isinstance(matched, list):
        matched = []
    rationale = (parsed.get("rationale") or "").strip()
    if len(rationale) > 500:
        rationale = rationale[:500]

    logger.info(
        "relevance_call_done",
        score=score,
        matched_pir_ids=matched,
    )
    return RelevanceVerdict(
        score=score,
        matched_pir_ids=[str(m) for m in matched],
        rationale=rationale,
    )


def _coerce_score(value: object) -> float:
    try:
        f = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, f))
