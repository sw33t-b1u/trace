"""Aggregate validation runner — runs every applicable validator and emits
a single Markdown report.

At least one of ``--assets``, ``--pir``, or ``--bundle`` must be supplied.
When both ``--pir`` and ``--assets`` are supplied, the PIR ``asset_weight_rules``
tag-match check runs against the assets file.

Default output path is ``output/validation_report_<UTC-iso-compact>.md``.

Usage:
    uv run python cmd/validate_all.py --assets a.json --pir p.json --bundle b.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import structlog
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from trace_engine.cli._logging import configure as configure_logging  # noqa: E402
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


def _validate_assets(path: Path) -> tuple[AssetsDocument | None, list[ValidationFinding]]:
    with path.open() as f:
        payload = json.load(f)
    try:
        doc = AssetsDocument.model_validate(payload)
    except ValidationError as exc:
        return None, _schema_findings(exc, "ASSETS_SCHEMA")
    return doc, check_assets(doc)


def _validate_pir(
    path: Path, assets: AssetsDocument | None
) -> tuple[PIRDocument | None, list[ValidationFinding]]:
    with path.open() as f:
        payload = json.load(f)
    try:
        doc = PIRDocument.from_payload(payload)
    except ValidationError as exc:
        return None, _schema_findings(exc, "PIR_SCHEMA")
    return doc, check_pir(doc, assets=assets)


def _validate_bundle(path: Path, *, strict: bool) -> list[ValidationFinding]:
    with path.open() as f:
        bundle = json.load(f)
    return [*run_stix2_validator(bundle, strict=strict), *check_stix_bundle(bundle)]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run every TRACE validator and emit a report")
    parser.add_argument("--assets", type=Path, default=None)
    parser.add_argument("--pir", type=Path, default=None)
    parser.add_argument("--bundle", type=Path, default=None)
    parser.add_argument("--strict", action="store_true", help="Promote STIX warnings to errors")
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Output Markdown path (default: output/validation_report_<ts>.md)",
    )
    args = parser.parse_args()

    if not (args.assets or args.pir or args.bundle):
        parser.error("at least one of --assets / --pir / --bundle is required")

    sections: list[tuple[str, list[ValidationFinding]]] = []
    assets_doc: AssetsDocument | None = None

    if args.assets:
        if not args.assets.exists():
            logger.error("file_not_found", path=str(args.assets))
            sys.exit(1)
        assets_doc, findings = _validate_assets(args.assets)
        sections.append((f"Assets: {args.assets.name}", findings))

    if args.pir:
        if not args.pir.exists():
            logger.error("file_not_found", path=str(args.pir))
            sys.exit(1)
        _, findings = _validate_pir(args.pir, assets_doc)
        sections.append((f"PIR: {args.pir.name}", findings))

    if args.bundle:
        if not args.bundle.exists():
            logger.error("file_not_found", path=str(args.bundle))
            sys.exit(1)
        findings = _validate_bundle(args.bundle, strict=args.strict)
        sections.append((f"STIX bundle: {args.bundle.name}", findings))

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


if __name__ == "__main__":
    main()
