"""Batch crawl URLs listed in ``input/sources.yaml``.

Per source:
  - fetch via httpx (UA / timeout from TRACE config)
  - dedupe by (url, content_sha256) against output/crawl_state.json
  - run the L2 PIR relevance gate (if --pir is given) and skip below threshold
  - extract STIX 2.1 objects (L3) with PIR context
  - emit a bundle with x_trace_* metadata (L4) and update state

Usage:
    uv run python cmd/crawl_batch.py --sources input/sources.yaml \\
        --pir ../BEACON/output/pir_output.json
    uv run python cmd/crawl_batch.py --dry-run
    uv run python cmd/crawl_batch.py --pir ... --recheck-on-pir-change

Exit codes: 0 success / 1 if any source produced fetch_failed or
extraction_failed / 2 input/argument error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import structlog
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from trace_engine.cli._logging import configure as configure_logging  # noqa: E402
from trace_engine.config import load_config  # noqa: E402
from trace_engine.crawler.batch import crawl_batch  # noqa: E402
from trace_engine.crawler.sources import load_sources  # noqa: E402
from trace_engine.crawler.state import CrawlState  # noqa: E402
from trace_engine.pir.loader import load_pir  # noqa: E402

load_dotenv()
configure_logging()
logger = structlog.get_logger(__name__)

_ROOT = Path(__file__).parent.parent
_DEFAULT_SOURCES = _ROOT / "input" / "sources.yaml"
_DEFAULT_OUTPUT = _ROOT / "output"


def main() -> None:
    cfg = load_config()
    parser = argparse.ArgumentParser(description="Batch crawl URLs into STIX bundles")
    parser.add_argument(
        "--sources",
        type=Path,
        default=_DEFAULT_SOURCES,
        help=f"Path to sources.yaml (default: {_DEFAULT_SOURCES.relative_to(_ROOT)})",
    )
    parser.add_argument(
        "--pir",
        type=Path,
        default=None,
        help="Path to BEACON pir_output.json. Enables the L2 relevance gate.",
    )
    parser.add_argument(
        "--state",
        type=Path,
        default=Path(cfg.state_path),
        help=f"Path to crawl_state.json (default: {cfg.state_path})",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_DEFAULT_OUTPUT,
        help=f"Directory for emitted bundles (default: {_DEFAULT_OUTPUT.relative_to(_ROOT)})",
    )
    parser.add_argument(
        "--relevance-threshold",
        type=float,
        default=None,
        help=(
            f"Override TRACE_RELEVANCE_THRESHOLD ({cfg.relevance_threshold}). 0.0 keeps everything."
        ),
    )
    parser.add_argument(
        "--recheck-on-pir-change",
        action="store_true",
        help="Re-evaluate URLs whose PIR-set hash differs from the recorded one.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print sources without fetching or extracting.",
    )
    args = parser.parse_args()

    if not args.sources.exists():
        logger.error("sources_not_found", path=str(args.sources))
        sys.exit(2)

    try:
        sources = load_sources(args.sources)
    except Exception as exc:
        logger.error("sources_invalid", path=str(args.sources), error=str(exc))
        sys.exit(2)

    pir_doc = None
    pir_set_hash = None
    if args.pir is not None:
        if not args.pir.exists():
            logger.error("pir_not_found", path=str(args.pir))
            sys.exit(2)
        try:
            pir_doc, pir_set_hash = load_pir(args.pir)
        except Exception as exc:
            logger.error("pir_invalid", path=str(args.pir), error=str(exc))
            sys.exit(2)

    state = CrawlState.load(args.state)

    failures = 0
    counts = {
        "extracted": 0,
        "skipped_unchanged": 0,
        "skipped_below_threshold": 0,
        "fetch_failed": 0,
        "extraction_failed": 0,
        "no_objects": 0,
    }

    for outcome in crawl_batch(
        sources,
        state=state,
        output_dir=args.output_dir,
        pir_doc=pir_doc,
        pir_set_hash=pir_set_hash,
        threshold=args.relevance_threshold,
        recheck_on_pir_change=args.recheck_on_pir_change,
        dry_run=args.dry_run,
        config=cfg,
    ):
        counts[outcome.kind] = counts.get(outcome.kind, 0) + 1
        log = logger.bind(url=outcome.url, label=outcome.label, kind=outcome.kind)
        if outcome.kind == "extracted":
            log.info("source_extracted", bundle=outcome.bundle_path)
        elif outcome.kind == "skipped_unchanged":
            log.info("source_skipped_unchanged")
        elif outcome.kind == "skipped_below_threshold":
            log.info(
                "source_skipped_below_threshold",
                score=outcome.relevance_score,
                matched=outcome.matched_pir_ids,
            )
        elif outcome.kind in ("fetch_failed", "extraction_failed"):
            failures += 1
            log.warning("source_failed", error=outcome.error)
        elif outcome.kind == "no_objects":
            log.warning("source_no_objects", score=outcome.relevance_score)

    if not args.dry_run:
        state.save()

    summary = " ".join(f"{k}={v}" for k, v in counts.items() if v)
    logger.info("crawl_batch_done", **counts, failures=failures)
    print(f"Crawl batch summary: {summary or '(no sources)'}")

    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
