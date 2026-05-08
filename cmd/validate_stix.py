"""Validate a STIX 2.1 bundle before SAGE ingests it.

Layers:
  1. OASIS ``stix2-validator`` — schema + value conformance.
  2. TRACE-local checks — id uniqueness, ``relationship.{source_ref,target_ref}``
     resolution, ``kill_chain_name == "mitre-attack"``, and
     ``bundle.spec_version == "2.1"``.

``--strict`` promotes OASIS warnings to errors. Without it, warnings are
recorded but do not block ingestion.

Usage:
    uv run python cmd/validate_stix.py --bundle output/stix_bundle_<...>.json
    uv run python cmd/validate_stix.py --bundle b.json --strict
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import structlog

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from trace_engine.cli._logging import configure as configure_logging  # noqa: E402
from trace_engine.review.markdown_report import render_report  # noqa: E402
from trace_engine.validate.semantic.findings import (  # noqa: E402
    ValidationFinding,
    has_errors,
)
from trace_engine.validate.stix import (  # noqa: E402
    check_stix_bundle,
    run_stix2_validator,
)

configure_logging()
logger = structlog.get_logger(__name__)


def validate_bundle_file(path: Path, *, strict: bool) -> list[ValidationFinding]:
    with path.open() as f:
        bundle = json.load(f)
    findings: list[ValidationFinding] = []
    findings.extend(run_stix2_validator(bundle, strict=strict))
    findings.extend(check_stix_bundle(bundle))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate a STIX 2.1 bundle")
    parser.add_argument("--bundle", required=True, type=Path, help="Path to STIX bundle JSON")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Promote OASIS validator warnings to errors",
    )
    parser.add_argument("--report", type=Path, default=None, help="Markdown report output path")
    args = parser.parse_args()

    if not args.bundle.exists():
        logger.error("file_not_found", path=str(args.bundle))
        sys.exit(1)

    findings = validate_bundle_file(args.bundle, strict=args.strict)

    for f in findings:
        log_method = logger.error if f.severity == "error" else logger.warning
        log_method(f.code, location=f.location, message=f.message)

    if args.report:
        text = render_report(
            [(f"STIX bundle: {args.bundle.name}", findings)],
            timestamp=datetime.now(tz=UTC),
        )
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text, encoding="utf-8")
        print(f"Report written: {args.report}")

    errors = sum(1 for f in findings if f.severity == "error")
    warnings = sum(1 for f in findings if f.severity == "warning")
    print(f"stix validation: errors={errors} warnings={warnings}")
    sys.exit(1 if has_errors(findings) else 0)


if __name__ == "__main__":
    main()
