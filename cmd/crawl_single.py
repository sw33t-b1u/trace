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

.. deprecated:: TRACE 1.12.0

    Direct invocation as ``python -m cmd.crawl_single`` /
    ``python cmd/crawl_single.py`` is deprecated. Use the unified
    ``trace crawl-single`` entry (Initiative H Phase 6). Removal is
    scheduled for TRACE 2.0.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import structlog
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from trace_engine.cli import _metrics  # noqa: E402
from trace_engine.cli._logging import configure as configure_logging  # noqa: E402
from trace_engine.config import load_config  # noqa: E402
from trace_engine.crawler.taxonomy_sync import ensure_taxonomy_fresh  # noqa: E402
from trace_engine.ingest.report_reader import _MAX_CHARS, read_report  # noqa: E402
from trace_engine.io.inputs import resolve_input  # noqa: E402
from trace_engine.pir import relevance as pir_relevance  # noqa: E402
from trace_engine.pir.loader import load_pir_text  # noqa: E402
from trace_engine.stix.extractor import (  # noqa: E402
    build_stix_bundle_from_extraction,
    extract_entities,
)

load_dotenv()
_metrics.install_collector()
configure_logging()
logger = structlog.get_logger(__name__)

_OUTPUT_DIR = Path(__file__).parent.parent / "output"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract STIX 2.1 bundle from a PDF or web article"
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        metavar="PATH_OR_URL",
        help=(
            "Path to a PDF/text file, or a https:// URL of a CTI article. "
            "Wrap URLs in single quotes in zsh/bash to prevent glob expansion."
        ),
    )
    parser.add_argument(
        "--output",
        "-o",
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
        "-p",
        default=None,
        help=(
            "Path, gs:// URI, or pir/ storage key for BEACON pir_output.json. "
            "Enables the L2 relevance gate: "
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
    parser.add_argument(
        "--it-assets",
        "--ita",
        default=None,
        help=(
            "Path, gs:// URI, or assets/ storage key for BEACON assets.json. "
            "Enables identity-asset edge "
            "extraction (Initiative A): the L3 prompt asks the LLM to "
            "emit identity_asset_edges, and the bundle assembler resolves "
            "each free-form asset reference against this assets file via "
            "the 4-tier matching ladder (name exact → substring → tag). "
            "Unresolved edges are dropped. Without --it-assets, no identity-"
            "asset edges are emitted (the LLM may extract them but they "
            "cannot be resolved to known asset_ids)."
        ),
    )
    parser.add_argument(
        "--identity-assets",
        "--ida",
        default=None,
        help=(
            "Path, gs:// URI, or assets/ storage key for BEACON identity_assets.json. "
            "Initiative C Phase 2 "
            "(TRACE 1.6.0): identities flagged "
            "is_high_value_impersonation_target=true contribute a +0.2 "
            "boost to the L2 relevance score when their name appears in "
            "the crawled document, prioritising extraction of articles "
            "that touch high-value impersonation targets."
        ),
    )
    parser.add_argument(
        "--no-sync-taxonomy",
        action="store_true",
        help=(
            "Skip the automatic taxonomy cache sync at startup. "
            "Use in CI or air-gapped environments where BEACON is not available."
        ),
    )
    args = parser.parse_args()
    cfg = load_config()

    if not args.no_sync_taxonomy:
        try:
            ensure_taxonomy_fresh(cfg)
        except Exception as exc:
            logger.warning("taxonomy_sync_failed", error=str(exc))

    collector = _metrics.get_collector()
    if collector is not None:
        collector.start_run(input_url_or_path=str(args.input))

    try:
        text = read_report(args.input, max_chars=args.max_chars, config=cfg)
    except FileNotFoundError as exc:
        logger.error("input_not_found", error=str(exc))
        sys.exit(1)

    if not text.strip():
        logger.error("empty_report_text", input=args.input)
        sys.exit(1)

    pir_doc = None
    verdict = None
    if args.pir is not None:
        try:
            pir_input = resolve_input(cfg, "pir", args.pir)
        except FileNotFoundError:
            logger.error("pir_not_found", path=str(args.pir))
            sys.exit(2)
        pir_doc, _ = load_pir_text(pir_input.text)
        threshold = (
            args.relevance_threshold
            if args.relevance_threshold is not None
            else cfg.relevance_threshold
        )
        high_value_identity_names: list[str] | None = None
        if args.identity_assets is not None:
            try:
                identity_assets_input = resolve_input(cfg, "assets", args.identity_assets)
            except FileNotFoundError:
                logger.error("identity_assets_not_found", path=str(args.identity_assets))
                sys.exit(2)
            ia_payload = json.loads(identity_assets_input.text)
            high_value_identity_names = [
                entry["name"]
                for entry in ia_payload.get("identities", [])
                if entry.get("is_high_value_impersonation_target") and entry.get("name")
            ]
        verdict = pir_relevance.evaluate(
            text,
            pir_doc,
            config=cfg,
            high_value_identity_names=high_value_identity_names,
        )
        if not verdict.keep(threshold):
            logger.info(
                "skipped_below_threshold",
                score=verdict.score,
                threshold=threshold,
                rationale=verdict.rationale,
            )
            print(f"Skipped (relevance score {verdict.score:.2f} < threshold {threshold:.2f})")
            sys.exit(0)

    # Initiative A: load --assets when supplied so identity_asset_edges
    # can be resolved to known asset_ids during bundle assembly.
    assets_list: list[dict] | None = None
    if args.it_assets is not None:
        try:
            assets_input = resolve_input(cfg, "assets", args.it_assets)
        except FileNotFoundError:
            logger.error("assets_not_found", path=str(args.it_assets))
            sys.exit(2)
        assets_payload = json.loads(assets_input.text)
        assets_list = assets_payload.get("assets") if isinstance(assets_payload, dict) else None
        if assets_list is None:
            logger.error("assets_missing_assets_key", path=str(args.it_assets))
            sys.exit(2)

    extraction = extract_entities(text, task=args.task, config=cfg, pir_doc=pir_doc)
    bundle = build_stix_bundle_from_extraction(
        extraction,
        source_url=str(args.input),
        matched_pir_ids=verdict.matched_pir_ids if verdict else None,
        relevance_score=verdict.score if verdict else None,
        relevance_rationale=verdict.rationale if verdict else None,
        assets=assets_list,
    )

    bundle_json = json.dumps(bundle, indent=2, ensure_ascii=False)
    object_count = len(bundle["objects"])

    if args.output is not None:
        # Explicit --output: bypass StorageBackend for backward compatibility.
        out = args.output
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(bundle_json, encoding="utf-8")
        out_display = str(out)
    else:
        # No --output: use StorageBackend (local or GCS per TRACE_STORAGE).
        from trace_engine.storage import create_storage_backend  # noqa: E402

        storage = create_storage_backend(cfg)
        suffix = bundle["id"].replace("bundle--", "")[-12:]
        bundle_filename = f"stix_bundle_{suffix}.json"
        storage.save("stix", bundle_filename, bundle_json)
        out_display = f"stix/{bundle_filename}"

    logger.info(
        "stix_bundle_written",
        path=out_display,
        entities=len(extraction.entities),
        relationships=len(extraction.relationships),
        object_count=object_count,
    )
    print(
        f"STIX bundle written: {out_display} ({object_count} objects)\n"
        f"Validate before feeding SAGE:\n"
        f"  uv run python cmd/validate_stix.py --bundle {out_display}"
    )

    if collector is not None:
        run = collector.finish_run()
        if run is not None:
            print()
            print(_metrics.render_summary(run))
            metrics_path = _metrics.write_run_json(run, _OUTPUT_DIR)
            print(f"Metrics:      {metrics_path}")
