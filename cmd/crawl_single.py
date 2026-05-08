"""Convert a PDF or web article to a STIX 2.1 bundle via LLM extraction.

Uses Vertex AI Gemini (via TRACE's LLM client) to extract threat actors, TTPs,
malware, tools, vulnerabilities, indicators, and relationships from a CTI report.

Usage:
    # From a PDF report
    uv run python cmd/crawl_single.py --input report.pdf

    # From a web article (quote the URL to prevent shell glob expansion)
    uv run python cmd/crawl_single.py --input 'https://example.com/apt-report?id=1'

    # Specify output path
    uv run python cmd/crawl_single.py --input report.pdf --output output/bundle.json

    # Use the more powerful (but slower) model for dense reports
    uv run python cmd/crawl_single.py --input report.pdf --task complex

    # Increase input size for long technical reports (default: 30000 chars)
    uv run python cmd/crawl_single.py --input report.pdf --max-chars 60000

The resulting STIX bundle can be fed directly to SAGE ETL after passing
TRACE's validate_stix gate.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import structlog
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from trace_engine.cli._logging import configure as configure_logging  # noqa: E402
from trace_engine.config import load_config  # noqa: E402
from trace_engine.ingest.report_reader import _MAX_CHARS, read_report  # noqa: E402
from trace_engine.pir import relevance as pir_relevance  # noqa: E402
from trace_engine.pir.loader import load_pir  # noqa: E402
from trace_engine.stix.extractor import build_stix_bundle, extract_stix_objects  # noqa: E402

load_dotenv()
configure_logging()
logger = structlog.get_logger(__name__)

_OUTPUT_DIR = Path(__file__).parent.parent / "output"


def _default_output(bundle_id: str) -> Path:
    """Return output/stix_bundle_<last-12-chars-of-bundle-id>.json."""
    suffix = bundle_id.replace("bundle--", "")[-12:]
    return _OUTPUT_DIR / f"stix_bundle_{suffix}.json"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract STIX 2.1 bundle from a PDF or web article"
    )
    parser.add_argument(
        "--input",
        required=True,
        metavar="PATH_OR_URL",
        help=(
            "Path to a PDF/text file, or a https:// URL of a CTI article. "
            "Wrap URLs in single quotes in zsh/bash to prevent glob expansion."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=(
            "Output path for the STIX bundle JSON "
            "(default: output/stix_bundle_<bundle-id-last-12>.json)"
        ),
    )
    parser.add_argument(
        "--task",
        choices=["simple", "medium", "complex"],
        default="medium",
        help=(
            "LLM complexity tier (default: medium = gemini-2.5-flash). "
            "Use 'complex' (gemini-2.5-pro) for dense or multi-language reports — "
            "expect 2–5 minutes per call."
        ),
    )
    parser.add_argument(
        "--max-chars",
        type=int,
        default=_MAX_CHARS,
        metavar="N",
        help=f"Maximum characters of report text to send to the LLM (default: {_MAX_CHARS})",
    )
    parser.add_argument(
        "--pir",
        type=Path,
        default=None,
        help=(
            "Path to BEACON pir_output.json. Enables the L2 relevance gate: "
            "articles below the threshold are not extracted. The PIR context is "
            "also injected into the L3 prompt and recorded in the bundle's "
            "x_trace_* metadata."
        ),
    )
    parser.add_argument(
        "--relevance-threshold",
        type=float,
        default=None,
        help="Override TRACE_RELEVANCE_THRESHOLD. Ignored when --pir is not set.",
    )
    args = parser.parse_args()
    cfg = load_config()

    try:
        text = read_report(args.input, max_chars=args.max_chars)
    except FileNotFoundError as exc:
        logger.error("input_not_found", error=str(exc))
        sys.exit(1)

    if not text.strip():
        logger.error("empty_report_text", input=args.input)
        sys.exit(1)

    pir_doc = None
    verdict = None
    if args.pir is not None:
        if not args.pir.exists():
            logger.error("pir_not_found", path=str(args.pir))
            sys.exit(2)
        pir_doc, _ = load_pir(args.pir)
        threshold = (
            args.relevance_threshold
            if args.relevance_threshold is not None
            else cfg.relevance_threshold
        )
        verdict = pir_relevance.evaluate(text, pir_doc, config=cfg)
        if not verdict.keep(threshold):
            logger.info(
                "skipped_below_threshold",
                score=verdict.score,
                threshold=threshold,
                rationale=verdict.rationale,
            )
            print(f"Skipped (relevance score {verdict.score:.2f} < threshold {threshold:.2f})")
            sys.exit(0)

    objects = extract_stix_objects(text, task=args.task, config=cfg, pir_doc=pir_doc)
    bundle = build_stix_bundle(
        objects,
        source_url=str(args.input),
        matched_pir_ids=verdict.matched_pir_ids if verdict else None,
        relevance_score=verdict.score if verdict else None,
        relevance_rationale=verdict.rationale if verdict else None,
    )

    out = args.output if args.output is not None else _default_output(bundle["id"])
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(bundle, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    logger.info("stix_bundle_written", path=str(out), object_count=len(objects))
    print(
        f"STIX bundle written: {out} ({len(objects)} objects)\n"
        f"Validate before feeding SAGE:\n"
        f"  uv run python cmd/validate_stix.py --bundle {out}"
    )


if __name__ == "__main__":
    main()
