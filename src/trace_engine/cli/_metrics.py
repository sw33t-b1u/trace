"""Per-run metrics collection for TRACE CLI entry points.

A ``MetricsCollector`` is registered as a structlog processor (see
``cli/_logging.py``). The processor inspects each log record and updates
counters / latencies for the events that matter to operators (LLM calls,
chunk extraction outcomes, defense activations, fetch outcomes). The
collector is process-local — one ``MetricsCollector`` per CLI invocation.

CLI entry points wrap their work in ``start_run(...)`` /
``finish_run(...)``. ``finish_run`` emits a per-run JSON file
(``output/run_metrics_<ts>_<run_id8>.json``) and a short human-readable
summary on stdout. ``crawl_batch`` calls ``start_run`` once per source URL
so each URL gets its own metrics record; the batch driver collects all
records into a single ``run_metrics_batch_<ts>.json``.

The collector ignores log records it does not understand, so adding new
log events elsewhere does not break the metrics layer — operators just
get the existing counters until they extend ``MetricsCollector`` here.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

# Singleton collector — one per process. CLI helpers register / clear it.
_active_collector: MetricsCollector | None = None
_collector_lock = threading.Lock()


@dataclass
class _LLMTotals:
    calls: int = 0
    output_chars_total: int = 0


@dataclass
class _RunMetrics:
    run_id: str
    started_at: datetime
    ended_at: datetime | None = None

    input_url_or_path: str | None = None
    input_chars: int | None = None
    body_chars: int | None = None

    # L2 verdict (last value wins — only one verdict per run)
    l2_model_tier: str | None = None
    l2_score: float | None = None
    l2_matched_pir_ids: list[str] = field(default_factory=list)
    l2_salvaged: bool = False
    l2_failed: bool = False

    # L3 extraction
    l3_model: str | None = None
    l3_task: str | None = None
    l3_chunks: int = 0
    l3_chunk_chars_max: int | None = None
    l3_llm_calls: int = 0
    l3_llm_output_chars_total: int = 0
    l3_parse_failures: int = 0
    l3_raw_entities: int = 0
    l3_merged_entities: int = 0
    l3_raw_relationships: int = 0
    l3_merged_relationships: int = 0

    # Defenses (0.6.1, 0.5.0/0.5.1/0.5.2)
    indicators_dropped_invalid_pattern: int = 0
    relationships_dropped_unresolved: int = 0
    relationships_dropped_type_mismatch: int = 0
    external_ref_fetched: int = 0
    external_ref_fetch_failed: int = 0

    # Bundle output
    bundle_path: str | None = None
    bundle_entities: int | None = None
    bundle_relationships: int | None = None
    bundle_object_count: int | None = None

    # Per-LLM-tier latency (rolling totals)
    llm_totals: dict[str, _LLMTotals] = field(default_factory=dict)


class MetricsCollector:
    """Aggregate structured-log events for CLI invocations.

    Acts as a structlog processor — it looks at each log record's
    ``event`` field and updates the **active run for the current
    thread**. Records with no active run on the current thread are
    passed through untouched.

    The per-thread design (TRACE 0.8.0) lets concurrent batch crawls
    keep one ``_RunMetrics`` per worker without the runs interfering.
    """

    def __init__(self) -> None:
        self._runs: dict[int, _RunMetrics] = {}
        self._runs_lock = threading.Lock()

    # ---- run lifecycle ----

    def start_run(
        self,
        *,
        input_url_or_path: str | None = None,
    ) -> str:
        run_id = uuid.uuid4().hex
        run = _RunMetrics(
            run_id=run_id,
            started_at=datetime.now(tz=UTC),
            input_url_or_path=input_url_or_path,
        )
        with self._runs_lock:
            self._runs[threading.get_ident()] = run
        return run_id

    def finish_run(self) -> _RunMetrics | None:
        tid = threading.get_ident()
        with self._runs_lock:
            run = self._runs.pop(tid, None)
        if run is None:
            return None
        run.ended_at = datetime.now(tz=UTC)
        return run

    # ---- structlog processor ----

    def __call__(self, logger, method_name: str, event_dict: dict) -> dict:
        tid = threading.get_ident()
        with self._runs_lock:
            run = self._runs.get(tid)
        if run is not None:
            self._observe(event_dict, run)
        return event_dict

    def _observe(self, event_dict: dict, run: _RunMetrics) -> None:
        event = event_dict.get("event")
        if not isinstance(event, str):
            return

        if event == "url_converted":
            run.input_chars = _to_int(event_dict.get("chars"))
            run.body_chars = _to_int(event_dict.get("body_chars"))
            return

        if event == "relevance_call_start":
            run.l2_model_tier = event_dict.get("tier") or run.l2_model_tier
            return

        if event == "relevance_call_done":
            run.l2_score = _to_float(event_dict.get("score"))
            matched = event_dict.get("matched_pir_ids")
            if isinstance(matched, list):
                run.l2_matched_pir_ids = [str(m) for m in matched]
            return

        if event == "relevance_salvaged_partial_json":
            run.l2_salvaged = True
            run.l2_score = _to_float(event_dict.get("score")) or run.l2_score
            matched = event_dict.get("matched_pir_ids")
            if isinstance(matched, list):
                run.l2_matched_pir_ids = [str(m) for m in matched]
            return

        if event in ("relevance_call_failed", "relevance_parse_failed"):
            run.l2_failed = True
            return

        if event == "extracting_entities":
            run.l3_task = event_dict.get("task") or run.l3_task
            run.l3_chunks = max(run.l3_chunks, 1)
            run.l3_chunk_chars_max = _to_int(event_dict.get("chars"))
            return

        if event == "extracting_entities_chunked":
            run.l3_task = event_dict.get("task") or run.l3_task
            run.l3_chunks = _to_int(event_dict.get("chunks")) or run.l3_chunks
            run.l3_chunk_chars_max = _to_int(event_dict.get("chunk_chars"))
            return

        if event == "chunk_extracted":
            # Per-chunk results merge into raw_* totals via the merge log,
            # so don't double-count here. We only track the count of chunks
            # processed for resilience (some chunks fail).
            return

        if event == "extraction_response_not_object":
            run.l3_parse_failures += 1
            return

        if event == "extractions_merged":
            run.l3_raw_entities = _to_int(event_dict.get("raw_entities")) or 0
            run.l3_merged_entities = _to_int(event_dict.get("merged_entities")) or 0
            run.l3_raw_relationships = _to_int(event_dict.get("raw_relationships")) or 0
            run.l3_merged_relationships = _to_int(event_dict.get("merged_relationships")) or 0
            return

        if event == "llm_call_start":
            tier = event_dict.get("task") or "unknown"
            run.llm_totals.setdefault(tier, _LLMTotals())
            return

        if event == "llm_call_done":
            tier = event_dict.get("task") or "unknown"
            totals = run.llm_totals.setdefault(tier, _LLMTotals())
            totals.calls += 1
            chars = _to_int(event_dict.get("chars")) or 0
            totals.output_chars_total += chars
            # L3-specific aggregate (medium / complex tier)
            if tier in ("medium", "complex"):
                run.l3_llm_calls += 1
                run.l3_llm_output_chars_total += chars
                if not run.l3_model:
                    run.l3_model = event_dict.get("model")
            return

        if event == "indicator_dropped_invalid_pattern":
            run.indicators_dropped_invalid_pattern += 1
            return

        if event == "stix_relationships_dropped":
            run.relationships_dropped_unresolved += _to_int(event_dict.get("count")) or 0
            return

        if event == "stix_relationships_type_mismatch_dropped":
            run.relationships_dropped_type_mismatch += _to_int(event_dict.get("count")) or 0
            return

        if event == "external_ref_hashed":
            run.external_ref_fetched += 1
            return

        if event == "external_ref_fetch_failed":
            run.external_ref_fetch_failed += 1
            return

        if event == "stix_bundle_written":
            run.bundle_path = event_dict.get("path")
            run.bundle_entities = _to_int(event_dict.get("entities"))
            run.bundle_relationships = _to_int(event_dict.get("relationships"))
            run.bundle_object_count = _to_int(event_dict.get("object_count"))
            return


# ---------------------------------------------------------------------------
# Singleton helpers
# ---------------------------------------------------------------------------


def get_collector() -> MetricsCollector | None:
    """Return the process-active collector, if any."""
    with _collector_lock:
        return _active_collector


def install_collector() -> MetricsCollector:
    """Create and register a fresh collector. Idempotent within a process —
    re-installing replaces the previous one."""
    global _active_collector
    with _collector_lock:
        _active_collector = MetricsCollector()
        return _active_collector


def clear_collector() -> None:
    global _active_collector
    with _collector_lock:
        _active_collector = None


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


def to_dict(run: _RunMetrics) -> dict:
    duration = None
    if run.ended_at is not None:
        duration = (run.ended_at - run.started_at).total_seconds()
    return {
        "run_id": run.run_id,
        "started_at": run.started_at.isoformat(timespec="seconds"),
        "ended_at": (
            run.ended_at.isoformat(timespec="seconds") if run.ended_at is not None else None
        ),
        "duration_seconds": duration,
        "input": {
            "url_or_path": run.input_url_or_path,
            "chars": run.input_chars,
            "body_chars": run.body_chars,
        },
        "l2": {
            "model_tier": run.l2_model_tier,
            "score": run.l2_score,
            "matched_pir_ids": list(run.l2_matched_pir_ids),
            "salvaged": run.l2_salvaged,
            "failed": run.l2_failed,
        },
        "l3": {
            "model": run.l3_model,
            "task": run.l3_task,
            "chunks": run.l3_chunks,
            "chunk_chars_max": run.l3_chunk_chars_max,
            "llm_calls": run.l3_llm_calls,
            "llm_output_chars_total": run.l3_llm_output_chars_total,
            "parse_failures": run.l3_parse_failures,
            "raw_entities": run.l3_raw_entities,
            "merged_entities": run.l3_merged_entities,
            "raw_relationships": run.l3_raw_relationships,
            "merged_relationships": run.l3_merged_relationships,
        },
        "defenses": {
            "indicators_dropped_invalid_pattern": run.indicators_dropped_invalid_pattern,
            "relationships_dropped_unresolved": run.relationships_dropped_unresolved,
            "relationships_dropped_type_mismatch": run.relationships_dropped_type_mismatch,
            "external_ref_fetched": run.external_ref_fetched,
            "external_ref_fetch_failed": run.external_ref_fetch_failed,
        },
        "bundle": {
            "path": run.bundle_path,
            "entities": run.bundle_entities,
            "relationships": run.bundle_relationships,
            "object_count": run.bundle_object_count,
        },
        "llm_totals_by_tier": {
            tier: {"calls": tt.calls, "output_chars_total": tt.output_chars_total}
            for tier, tt in run.llm_totals.items()
        },
    }


def write_run_json(run: _RunMetrics, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = run.started_at.strftime("%Y%m%dT%H%M%SZ")
    suffix = run.run_id[:8]
    path = output_dir / f"run_metrics_{ts}_{suffix}.json"
    payload = to_dict(run)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=output_dir, delete=False, suffix=".tmp"
    ) as tmp:
        json.dump(payload, tmp, indent=2, ensure_ascii=False, sort_keys=False)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)
    return path


def write_batch_json(runs: list[_RunMetrics], output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    started = min((r.started_at for r in runs), default=datetime.now(tz=UTC))
    ts = started.strftime("%Y%m%dT%H%M%SZ")
    path = output_dir / f"run_metrics_batch_{ts}.json"
    payload = {
        "runs": [to_dict(r) for r in runs],
        "summary": {
            "run_count": len(runs),
            "merged_entities_total": sum(r.l3_merged_entities for r in runs),
            "merged_relationships_total": sum(r.l3_merged_relationships for r in runs),
            "llm_calls_total": sum(r.l3_llm_calls for r in runs),
            "llm_output_chars_total": sum(r.l3_llm_output_chars_total for r in runs),
            "indicators_dropped_invalid_pattern_total": sum(
                r.indicators_dropped_invalid_pattern for r in runs
            ),
            "relationships_dropped_total": sum(
                r.relationships_dropped_unresolved + r.relationships_dropped_type_mismatch
                for r in runs
            ),
            "external_ref_fetched_total": sum(r.external_ref_fetched for r in runs),
        },
    }
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=output_dir, delete=False, suffix=".tmp"
    ) as tmp:
        json.dump(payload, tmp, indent=2, ensure_ascii=False, sort_keys=False)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)
    return path


# ---------------------------------------------------------------------------
# Human-readable CLI summary
# ---------------------------------------------------------------------------


def render_summary(run: _RunMetrics) -> str:
    duration = None
    if run.ended_at is not None:
        duration = (run.ended_at - run.started_at).total_seconds()
    lines: list[str] = ["=== Run summary ==="]
    if run.input_url_or_path:
        chars_part = (
            f" ({run.body_chars:,} body / {run.input_chars:,} raw chars)"
            if run.input_chars and run.body_chars
            else f" ({run.input_chars:,} chars)"
            if run.input_chars
            else ""
        )
        lines.append(f"Input:        {run.input_url_or_path}{chars_part}")
    if run.l2_score is not None:
        verdict = "kept" if (run.l2_score is not None and run.l2_score >= 0.5) else "skipped"
        salvaged = " (salvaged)" if run.l2_salvaged else ""
        failed = " (failed → fail-open)" if run.l2_failed else ""
        matched = " matched=" + ",".join(run.l2_matched_pir_ids) if run.l2_matched_pir_ids else ""
        lines.append(
            f"L2:           score={run.l2_score:.2f} → {verdict}{salvaged}{failed}{matched}"
        )
    if run.l3_chunks:
        lines.append(
            f"L3:           {run.l3_chunks} chunks, "
            f"{run.l3_llm_calls} LLM calls, "
            f"{run.l3_llm_output_chars_total:,} output chars, "
            f"{run.l3_parse_failures} parse failures"
        )
        lines.append(
            f"              raw {run.l3_raw_entities}/{run.l3_raw_relationships} → "
            f"merged {run.l3_merged_entities}/{run.l3_merged_relationships} "
            f"(entities/relationships)"
        )
    if run.bundle_path:
        lines.append(
            f"Bundle:       {run.bundle_object_count} objects "
            f"({run.bundle_entities} entities, {run.bundle_relationships} relationships) "
            f"→ {run.bundle_path}"
        )
    defense_bits = []
    if run.external_ref_fetched:
        defense_bits.append(f"{run.external_ref_fetched} ATT&CK URLs hashed")
    if run.external_ref_fetch_failed:
        defense_bits.append(f"{run.external_ref_fetch_failed} fetch fails")
    if run.indicators_dropped_invalid_pattern:
        defense_bits.append(
            f"{run.indicators_dropped_invalid_pattern} indicators dropped (bad pattern)"
        )
    if run.relationships_dropped_unresolved:
        defense_bits.append(f"{run.relationships_dropped_unresolved} rels dropped (unresolved)")
    if run.relationships_dropped_type_mismatch:
        defense_bits.append(
            f"{run.relationships_dropped_type_mismatch} rels dropped (type mismatch)"
        )
    if defense_bits:
        lines.append(f"Defenses:     {', '.join(defense_bits)}")
    if duration is not None:
        lines.append(f"Duration:     {duration:.1f}s")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Coercion helpers (tolerate mixed types in log payloads)
# ---------------------------------------------------------------------------


def _to_int(value: object) -> int | None:
    if isinstance(value, bool):  # bool is subtype of int — treat False/True as None
        return None
    if isinstance(value, int):
        return value
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _to_float(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
