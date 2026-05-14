"""Validate ``pir_output.json`` against SAGE's PIR contract.

Layers:
  1. Pydantic schema check (``PIRDocument``) — pir_id, threat_actor_tags,
     asset_weight_rules, valid_from/until, with ``valid_from < valid_until``.
  2. Semantic checks — pir_id uniqueness, taxonomy presence (warning),
     and asset-tag match for ``asset_weight_rules`` when ``--assets`` is
     supplied.

Supersedes the schema-only ``BEACON/cmd/validate_pir.py``, which shipped as
a deprecation stub in BEACON 0.9.x and was deleted in BEACON 0.10.0.

Usage:
    uv run python cmd/validate_pir.py --pir pir_output.json
    uv run python cmd/validate_pir.py --pir pir.json --assets assets.json
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
from trace_engine.validate.semantic.findings import (  # noqa: E402
    ValidationFinding,
    has_errors,
)
from trace_engine.validate.semantic.pir import check_pir  # noqa: E402

configure_logging()
logger = structlog.get_logger(__name__)


def validate_pir_file(
    pir_path: Path,
    assets_path: Path | None,
) -> tuple[PIRDocument | None, list[ValidationFinding]]:
    findings: list[ValidationFinding] = []

    with pir_path.open() as f:
        payload = json.load(f)
    try:
        pir_doc = PIRDocument.from_payload(payload)
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

    assets_doc: AssetsDocument | None = None
    if assets_path:
        with assets_path.open() as f:
            assets_payload = json.load(f)
        try:
            assets_doc = AssetsDocument.model_validate(assets_payload)
        except ValidationError as exc:
            for err in exc.errors():
                findings.append(
                    ValidationFinding(
                        severity="error",
                        code="ASSETS_SCHEMA",
                        location=".".join(str(p) for p in err["loc"]),
                        message=err["msg"],
                    )
                )
            return pir_doc, findings

    findings.extend(check_pir(pir_doc, assets=assets_doc))
    return pir_doc, findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate pir_output.json before SAGE ingestion")
    parser.add_argument("--pir", required=True, type=Path, help="Path to pir_output.json")
    parser.add_argument(
        "--assets",
        type=Path,
        default=None,
        help="Optional assets.json — enables asset_weight_rules.tag match check",
    )
    parser.add_argument("--report", type=Path, default=None, help="Markdown report output path")
    args = parser.parse_args()

    if not args.pir.exists():
        logger.error("file_not_found", path=str(args.pir))
        sys.exit(1)
    if args.assets and not args.assets.exists():
        logger.error("file_not_found", path=str(args.assets))
        sys.exit(1)

    _, findings = validate_pir_file(args.pir, args.assets)

    for f in findings:
        log_method = logger.error if f.severity == "error" else logger.warning
        log_method(f.code, location=f.location, message=f.message)

    if args.report:
        text = render_report(
            [(f"PIR: {args.pir.name}", findings)],
            timestamp=datetime.now(tz=UTC),
        )
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text, encoding="utf-8")
        print(f"Report written: {args.report}")

    errors = sum(1 for f in findings if f.severity == "error")
    warnings = sum(1 for f in findings if f.severity == "warning")
    print(f"pir validation: errors={errors} warnings={warnings}")
    sys.exit(1 if has_errors(findings) else 0)


if __name__ == "__main__":
    main()
