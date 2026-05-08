"""Validate ``assets.json`` against SAGE's input contract.

Layers run, in order:
  1. Pydantic schema check (``AssetsDocument``).
  2. Referential-integrity checks (id uniqueness, segment / control / asset
     refs all resolve).

Exit code is 0 on success and 1 on any error-severity finding. Warnings do
not block. Findings are also written to ``output/validation_report_<ts>.md``
when ``--report`` is supplied.

Usage:
    uv run python cmd/validate_assets.py --assets path/to/assets.json
    uv run python cmd/validate_assets.py --assets a.json --report output/report.md
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
from trace_engine.validate.schema import AssetsDocument  # noqa: E402
from trace_engine.validate.semantic.assets import check_assets  # noqa: E402
from trace_engine.validate.semantic.findings import (  # noqa: E402
    ValidationFinding,
    has_errors,
)

configure_logging()
logger = structlog.get_logger(__name__)


def validate_assets_file(path: Path) -> tuple[AssetsDocument | None, list[ValidationFinding]]:
    findings: list[ValidationFinding] = []
    with path.open() as f:
        payload = json.load(f)
    try:
        doc = AssetsDocument.model_validate(payload)
    except ValidationError as exc:
        for err in exc.errors():
            findings.append(
                ValidationFinding(
                    severity="error",
                    code="SCHEMA",
                    location=".".join(str(p) for p in err["loc"]),
                    message=err["msg"],
                )
            )
        return None, findings

    findings.extend(check_assets(doc))
    return doc, findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate assets.json before SAGE ingestion")
    parser.add_argument("--assets", required=True, type=Path, help="Path to assets.json")
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Optional Markdown report output path",
    )
    args = parser.parse_args()

    if not args.assets.exists():
        logger.error("file_not_found", path=str(args.assets))
        sys.exit(1)

    _, findings = validate_assets_file(args.assets)

    for f in findings:
        log_method = logger.error if f.severity == "error" else logger.warning
        log_method(f.code, location=f.location, message=f.message)

    if args.report:
        text = render_report(
            [(f"Assets: {args.assets.name}", findings)],
            timestamp=datetime.now(tz=UTC),
        )
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text, encoding="utf-8")
        print(f"Report written: {args.report}")

    errors = sum(1 for f in findings if f.severity == "error")
    warnings = sum(1 for f in findings if f.severity == "warning")
    print(f"assets validation: errors={errors} warnings={warnings}")
    sys.exit(1 if has_errors(findings) else 0)


if __name__ == "__main__":
    main()
