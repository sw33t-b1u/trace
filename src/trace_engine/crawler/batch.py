"""Batch crawl orchestration.

Reads ``input/sources.yaml`` and, for each source URL:

1. Fetches raw bytes (httpx) and computes ``content_sha256``.
2. If the URL is unchanged AND the PIR set hasn't changed
   (or ``--recheck-on-pir-change`` is off), skips it.
3. Otherwise converts URL → text via ``ingest.report_reader.read_report``.
4. Runs the L2 PIR relevance gate when ``pir_doc`` is supplied. Below the
   threshold → records ``skipped_below_threshold`` and continues.
5. Runs L3 STIX extraction with PIR context, builds the L4 bundle with
   ``x_trace_*`` metadata, writes it to disk, and updates state.

The driver is structured as a generator of per-source ``BatchOutcome``
records so the CLI can format a summary without re-running anything.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import structlog

from trace_engine.config import Config, load_config
from trace_engine.crawler.fetcher import FetchError, fetch
from trace_engine.crawler.state import (
    CrawlState,
    RelevanceRecord,
    content_sha256,
)
from trace_engine.ingest.report_reader import read_report
from trace_engine.pir import relevance as pir_relevance
from trace_engine.stix.extractor import build_stix_bundle_from_extraction, extract_entities
from trace_engine.validate.schema import PIRDocument, SourcesDocument

logger = structlog.get_logger(__name__)

OutcomeKind = Literal[
    "extracted",
    "skipped_unchanged",
    "skipped_below_threshold",
    "fetch_failed",
    "extraction_failed",
    "no_objects",
]


@dataclass
class BatchOutcome:
    url: str
    label: str | None
    kind: OutcomeKind
    bundle_path: str | None = None
    relevance_score: float | None = None
    matched_pir_ids: list[str] | None = None
    error: str | None = None
    # Per-URL metrics run, populated by `crawl_batch` when a metrics
    # collector is registered. The CLI driver uses this to render per-URL
    # summaries; tests / library callers can ignore it.
    metrics: object | None = None


def _slug(url: str) -> str:
    """Compress a URL to a filesystem-safe stub for the bundle filename."""
    s = re.sub(r"^https?://", "", url)
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-")
    return s[:80] if s else "bundle"


def crawl_batch(
    sources: SourcesDocument,
    *,
    state: CrawlState,
    output_dir: Path,
    pir_doc: PIRDocument | None = None,
    pir_set_hash: str | None = None,
    threshold: float | None = None,
    recheck_on_pir_change: bool = False,
    dry_run: bool = False,
    config: Config | None = None,
    write_bundle=None,
    max_workers: int | None = None,
) -> Iterator[BatchOutcome]:
    """Yield one ``BatchOutcome`` per source. Caller is responsible for
    calling ``state.save()`` after iteration if it wants to persist.

    ``write_bundle`` is an injection point for tests (``write_bundle(path, data)``);
    by default the function writes JSON to disk.

    ``max_workers`` controls per-URL concurrency (TRACE 0.8.0). When
    omitted, ``Config.crawl_concurrency`` is used. ``max_workers <= 1``
    keeps the legacy sequential generator behaviour. ``> 1`` dispatches
    sources to a ``ThreadPoolExecutor``; outcomes are yielded in
    completion order, not source order.
    """
    cfg = config or load_config()
    threshold = cfg.relevance_threshold if threshold is None else threshold
    output_dir.mkdir(parents=True, exist_ok=True)
    workers = max_workers if max_workers is not None else cfg.crawl_concurrency

    if workers <= 1 or len(sources.sources) <= 1:
        for source in sources.sources:
            yield _process_source(
                source,
                state=state,
                output_dir=output_dir,
                pir_doc=pir_doc,
                pir_set_hash=pir_set_hash,
                threshold=threshold,
                recheck_on_pir_change=recheck_on_pir_change,
                dry_run=dry_run,
                cfg=cfg,
                write_bundle=write_bundle,
            )
        return

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [
            ex.submit(
                _process_source,
                source,
                state=state,
                output_dir=output_dir,
                pir_doc=pir_doc,
                pir_set_hash=pir_set_hash,
                threshold=threshold,
                recheck_on_pir_change=recheck_on_pir_change,
                dry_run=dry_run,
                cfg=cfg,
                write_bundle=write_bundle,
            )
            for source in sources.sources
        ]
        for fut in as_completed(futures):
            yield fut.result()


def _process_source(
    source,
    *,
    state: CrawlState,
    output_dir: Path,
    pir_doc: PIRDocument | None,
    pir_set_hash: str | None,
    threshold: float,
    recheck_on_pir_change: bool,
    dry_run: bool,
    cfg: Config,
    write_bundle,
) -> BatchOutcome:
    """Process a single source URL end-to-end (fetch → L2 → L3 → bundle).

    Returns a ``BatchOutcome`` that, if a metrics collector is active,
    carries the run's ``_RunMetrics`` in ``BatchOutcome.metrics``.
    """
    # Lazy import to avoid circular dependency on cli._metrics for
    # non-CLI callers (tests, library use).
    from trace_engine.cli._metrics import get_collector

    collector = get_collector()
    if collector is not None:
        collector.start_run(input_url_or_path=source.url)

    try:
        outcome = _process_source_body(
            source,
            state=state,
            output_dir=output_dir,
            pir_doc=pir_doc,
            pir_set_hash=pir_set_hash,
            threshold=threshold,
            recheck_on_pir_change=recheck_on_pir_change,
            dry_run=dry_run,
            cfg=cfg,
            write_bundle=write_bundle,
        )
    finally:
        if collector is not None:
            run = collector.finish_run()
            if run is not None:
                # outcome may not exist yet on early failure; guard.
                try:
                    outcome.metrics = run  # type: ignore[union-attr]
                except (UnboundLocalError, AttributeError):
                    pass
    return outcome


def _process_source_body(
    source,
    *,
    state: CrawlState,
    output_dir: Path,
    pir_doc: PIRDocument | None,
    pir_set_hash: str | None,
    threshold: float,
    recheck_on_pir_change: bool,
    dry_run: bool,
    cfg: Config,
    write_bundle,
) -> BatchOutcome:
    prev = state.get(source.url)
    if dry_run:
        return BatchOutcome(url=source.url, label=source.label, kind="extracted", bundle_path=None)

    try:
        fetched = fetch(source.url, config=cfg)
    except FetchError as exc:
        logger.warning("source_fetch_failed", url=source.url, error=str(exc))
        return BatchOutcome(url=source.url, label=source.label, kind="fetch_failed", error=str(exc))

    sha = content_sha256(fetched.content)
    if (
        prev is not None
        and prev.content_sha256 == sha
        and (not recheck_on_pir_change or prev.relevance.pir_set_hash == pir_set_hash)
    ):
        return BatchOutcome(
            url=source.url,
            label=source.label,
            kind="skipped_unchanged",
            bundle_path=prev.bundle_path,
        )

    try:
        text = read_report(source.url, max_chars=source.max_chars or 30_000)
    except Exception as exc:  # markitdown surfaces many runtime errors
        logger.warning("source_read_failed", url=source.url, error=str(exc))
        return BatchOutcome(
            url=source.url,
            label=source.label,
            kind="extraction_failed",
            error=str(exc),
        )

    if not text.strip():
        return BatchOutcome(
            url=source.url,
            label=source.label,
            kind="extraction_failed",
            error="empty article text",
        )

    verdict = None
    if pir_doc is not None:
        verdict = pir_relevance.evaluate(
            text,
            pir_doc,
            config=cfg,
            restrict_to=source.pir_ids or None,
        )
        if not verdict.keep(threshold):
            state.upsert(
                source.url,
                content_sha256=sha,
                bundle_path=None,
                relevance=RelevanceRecord(
                    decision="skipped_below_threshold",
                    score=verdict.score,
                    matched_pir_ids=verdict.matched_pir_ids,
                    rationale=verdict.rationale,
                    pir_set_hash=pir_set_hash,
                ),
            )
            return BatchOutcome(
                url=source.url,
                label=source.label,
                kind="skipped_below_threshold",
                relevance_score=verdict.score,
                matched_pir_ids=verdict.matched_pir_ids,
            )

    extraction = extract_entities(text, task=source.task, config=cfg, pir_doc=pir_doc)
    if not extraction.entities:
        decision: Literal["extraction_failed", "no_pir", "kept"] = "extraction_failed"
        state.upsert(
            source.url,
            content_sha256=sha,
            bundle_path=None,
            relevance=RelevanceRecord(
                decision=decision,
                score=verdict.score if verdict else None,
                matched_pir_ids=(verdict.matched_pir_ids if verdict else []),
                rationale=verdict.rationale if verdict else None,
                pir_set_hash=pir_set_hash,
            ),
        )
        return BatchOutcome(
            url=source.url,
            label=source.label,
            kind="no_objects",
            relevance_score=verdict.score if verdict else None,
        )

    bundle = build_stix_bundle_from_extraction(
        extraction,
        source_url=source.url,
        matched_pir_ids=verdict.matched_pir_ids if verdict else None,
        relevance_score=verdict.score if verdict else None,
        relevance_rationale=verdict.rationale if verdict else None,
    )
    bundle_path = output_dir / f"stix_bundle_{_slug(source.url)}.json"
    if write_bundle is None:
        _write_json(bundle_path, bundle)
    else:
        write_bundle(bundle_path, bundle)

    state.upsert(
        source.url,
        content_sha256=sha,
        bundle_path=str(bundle_path),
        relevance=RelevanceRecord(
            decision="kept" if verdict else "no_pir",
            score=verdict.score if verdict else None,
            matched_pir_ids=verdict.matched_pir_ids if verdict else [],
            rationale=verdict.rationale if verdict else None,
            pir_set_hash=pir_set_hash,
        ),
    )
    return BatchOutcome(
        url=source.url,
        label=source.label,
        kind="extracted",
        bundle_path=str(bundle_path),
        relevance_score=verdict.score if verdict else None,
        matched_pir_ids=verdict.matched_pir_ids if verdict else None,
    )


def _write_json(path: Path, data: dict) -> None:
    import json

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def filter_unchanged(outcomes: list[BatchOutcome]) -> list[BatchOutcome]:
    return [o for o in outcomes if o.kind != "skipped_unchanged"]
