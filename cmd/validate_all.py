"""Aggregate validation runner — runs every applicable validator and emits
a single Markdown report.

At least one of ``--assets``, ``--pir``, or ``--bundle`` must be supplied.
When both ``--pir`` and ``--assets`` are supplied, the PIR ``asset_weight_rules``
tag-match check runs against the assets file.

Default output path is ``output/validation_report_<UTC-iso-compact>.md``.

Usage:
    uv run python cmd/validate_all.py --assets a.json --pir p.json --bundle b.json

.. deprecated:: TRACE 1.12.0

    Direct invocation as ``python -m cmd.validate_all`` /
    ``python cmd/validate_all.py`` is deprecated. Use the unified
    ``trace validate-all`` entry (Initiative H Phase 6). Removal is
    scheduled for TRACE 2.0.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

import structlog
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from trace_engine.cli._logging import configure as configure_logging  # noqa: E402
from trace_engine.config import load_config  # noqa: E402
from trace_engine.io.inputs import resolve_json_input  # noqa: E402
from trace_engine.review.markdown_report import render_report  # noqa: E402
from trace_engine.validate.schema import AssetsDocument, PIRDocument  # noqa: E402
from trace_engine.validate.semantic.assets import check_assets  # noqa: E402
from trace_engine.validate.semantic.findings import (  # noqa: E402
    ValidationFinding,
    has_errors,
)
from trace_engine.validate.semantic.pir import check_pir  # noqa: E402
from trace_engine.validate.stix import (  # noqa: E402
    check_stix_bundle,
    run_stix2_validator,
)

configure_logging()
logger = structlog.get_logger(__name__)

_DEFAULT_REPORT_DIR = Path(__file__).parent.parent / "output"


def _schema_findings(exc: ValidationError, code: str) -> list[ValidationFinding]:
    return [
        ValidationFinding(
            severity="error",
            code=code,
            location=".".join(str(p) for p in err["loc"]),
            message=err["msg"],
        )
        for err in exc.errors()
    ]


def _validate_assets(payload: object) -> tuple[AssetsDocument | None, list[ValidationFinding]]:
    try:
        doc = AssetsDocument.model_validate(payload)
    except ValidationError as exc:
        return None, _schema_findings(exc, "ASSETS_SCHEMA")
    return doc, check_assets(doc)


def _validate_pir(
    payload: object, assets: AssetsDocument | None, *, location: str
) -> tuple[PIRDocument | None, list[ValidationFinding]]:
    try:
        doc = PIRDocument.from_payload(payload)
    except ValidationError as exc:
        return None, _schema_findings(exc, "PIR_SCHEMA")
    except ValueError as exc:
        return None, [
            ValidationFinding(
                severity="error",
                code="PIR_SCHEMA_ENVELOPE",
                location=location,
                message=str(exc),
            )
        ]
    return doc, check_pir(doc, assets=assets)


def _validate_bundle(bundle: object, *, strict: bool) -> list[ValidationFinding]:
    return [*run_stix2_validator(bundle, strict=strict), *check_stix_bundle(bundle)]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run every TRACE validator and emit a report")
    parser.add_argument("--it-assets", "--ita", default=None)
    parser.add_argument("--pir", "-p", default=None)
    parser.add_argument("--bundle", "-b", default=None)
    parser.add_argument("--strict", action="store_true", help="Promote STIX warnings to errors")
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Output Markdown path (default: output/validation_report_<ts>.md)",
    )
    args = parser.parse_args()
    cfg = load_config()

    if not (args.it_assets or args.pir or args.bundle):
        parser.error("at least one of --it-assets / --pir / --bundle is required")

    sections: list[tuple[str, list[ValidationFinding]]] = []
    assets_doc: AssetsDocument | None = None
    if args.it_assets:
        try:
            assets_payload, assets_input = resolve_json_input(cfg, "assets", args.it_assets)
        except FileNotFoundError:
            logger.error("file_not_found", path=str(args.it_assets))
            sys.exit(1)
        assets_doc, findings = _validate_assets(assets_payload)
        sections.append((f"Assets: {assets_input.display_name}", findings))

    if args.pir:
        try:
            pir_payload, pir_input = resolve_json_input(cfg, "pir", args.pir)
        except FileNotFoundError:
            logger.error("file_not_found", path=str(args.pir))
            sys.exit(1)
        _, findings = _validate_pir(pir_payload, assets_doc, location=str(args.pir))
        sections.append((f"PIR: {pir_input.display_name}", findings))

    if args.bundle:
        try:
            bundle_payload, bundle_input = resolve_json_input(cfg, "stix", args.bundle)
        except FileNotFoundError:
            logger.error("file_not_found", path=str(args.bundle))
            sys.exit(1)
        findings = _validate_bundle(bundle_payload, strict=args.strict)
        sections.append((f"STIX bundle: {bundle_input.display_name}", findings))

    now = datetime.now(tz=UTC)
    text = render_report(sections, timestamp=now)

    report_path = args.report
    if report_path is None:
        ts = now.strftime("%Y%m%dT%H%M%SZ")
        report_path = _DEFAULT_REPORT_DIR / f"validation_report_{ts}.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(text, encoding="utf-8")

    all_findings = [f for _, fs in sections for f in fs]
    errors = sum(1 for f in all_findings if f.severity == "error")
    warnings = sum(1 for f in all_findings if f.severity == "warning")
    print(f"validation report: {report_path} (errors={errors} warnings={warnings})")
    sys.exit(1 if has_errors(all_findings) else 0)
