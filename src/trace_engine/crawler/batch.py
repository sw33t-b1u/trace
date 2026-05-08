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


@dataclass(frozen=True)
class BatchOutcome:
    url: str
    label: str | None
    kind: OutcomeKind
    bundle_path: str | None = None
    relevance_score: float | None = None
    matched_pir_ids: list[str] | None = None
    error: str | None = None


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
) -> Iterator[BatchOutcome]:
    """Yield one ``BatchOutcome`` per source. Caller is responsible for
    calling ``state.save()`` after iteration if it wants to persist.

    ``write_bundle`` is an injection point for tests (``write_bundle(path, data)``);
    by default the function writes JSON to disk.
    """
    cfg = config or load_config()
    threshold = cfg.relevance_threshold if threshold is None else threshold
    output_dir.mkdir(parents=True, exist_ok=True)

    for source in sources.sources:
        prev = state.get(source.url)
        if dry_run:
            yield BatchOutcome(
                url=source.url, label=source.label, kind="extracted", bundle_path=None
            )
            continue

        try:
            fetched = fetch(source.url, config=cfg)
        except FetchError as exc:
            logger.warning("source_fetch_failed", url=source.url, error=str(exc))
            yield BatchOutcome(
                url=source.url, label=source.label, kind="fetch_failed", error=str(exc)
            )
            continue

        sha = content_sha256(fetched.content)
        if (
            prev is not None
            and prev.content_sha256 == sha
            and (not recheck_on_pir_change or prev.relevance.pir_set_hash == pir_set_hash)
        ):
            yield BatchOutcome(
                url=source.url,
                label=source.label,
                kind="skipped_unchanged",
                bundle_path=prev.bundle_path,
            )
            continue

        try:
            text = read_report(source.url, max_chars=source.max_chars or 30_000)
        except Exception as exc:  # markitdown surfaces many runtime errors
            logger.warning("source_read_failed", url=source.url, error=str(exc))
            yield BatchOutcome(
                url=source.url,
                label=source.label,
                kind="extraction_failed",
                error=str(exc),
            )
            continue

        if not text.strip():
            yield BatchOutcome(
                url=source.url,
                label=source.label,
                kind="extraction_failed",
                error="empty article text",
            )
            continue

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
                yield BatchOutcome(
                    url=source.url,
                    label=source.label,
                    kind="skipped_below_threshold",
                    relevance_score=verdict.score,
                    matched_pir_ids=verdict.matched_pir_ids,
                )
                continue

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
            yield BatchOutcome(
                url=source.url,
                label=source.label,
                kind="no_objects",
                relevance_score=verdict.score if verdict else None,
            )
            continue

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
        yield BatchOutcome(
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
