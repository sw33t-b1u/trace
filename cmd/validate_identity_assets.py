"""Validate ``identity_assets.json`` against SAGE's input contract.

Initiative A — TRACE 1.1.0 §6.1. ``--assets`` is **required** because
``has_access[*].asset_id`` must be cross-referenced against the assets
inventory; independent validation is not supported (Initiative A
2026-05-10 design decision).

Layers run, in order:
  1. Pydantic schema check (``IdentityAssetsDocument``).
  2. Pydantic schema check on the supplied ``assets.json``
     (``AssetsDocument``) — needed for the cross-ref lookup.
  3. Cross-reference checks (id uniqueness, identity_id / asset_id
     resolution, duplicate (identity_id, asset_id) pair detection).

Exit code is 0 on success and 1 on any error-severity finding.
Warnings (e.g. duplicate access pair) do not block.

Usage:
    uv run python cmd/validate_identity_assets.py \\
        --identity-assets ../BEACON/output/identity_assets.json \\
        --assets ../BEACON/output/assets.json
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
from trace_engine.validate.schema import (  # noqa: E402
    AssetsDocument,
    IdentityAssetsDocument,
)
from trace_engine.validate.semantic.findings import (  # noqa: E402
    ValidationFinding,
    has_errors,
)
from trace_engine.validate.semantic.identity_assets import (  # noqa: E402
    check_identity_assets,
)

configure_logging()
logger = structlog.get_logger(__name__)


def _load_and_validate_schema(
    path: Path,
    model_cls: type,
    findings: list[ValidationFinding],
):
    """Load JSON at ``path`` and validate against ``model_cls``.

    Returns the validated model on success or ``None`` when schema
    validation fails (with findings appended in-place).
    """
    with path.open() as f:
        payload = json.load(f)
    try:
        return model_cls.model_validate(payload)
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
        return None


def validate_identity_assets_files(
    identity_assets_path: Path,
    assets_path: Path,
) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    ia_doc = _load_and_validate_schema(identity_assets_path, IdentityAssetsDocument, findings)
    a_doc = _load_and_validate_schema(assets_path, AssetsDocument, findings)
    if ia_doc is None or a_doc is None:
        return findings
    findings.extend(check_identity_assets(ia_doc, a_doc))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate identity_assets.json before SAGE ingestion"
    )
    parser.add_argument(
        "--identity-assets",
        required=True,
        type=Path,
        help="Path to identity_assets.json",
    )
    parser.add_argument(
        "--assets",
        required=True,
        type=Path,
        help=("Path to assets.json (REQUIRED for cross-reference of has_access[*].asset_id)"),
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Optional Markdown report output path",
    )
    args = parser.parse_args()

    for label, path in (("identity-assets", args.identity_assets), ("assets", args.assets)):
        if not path.exists():
            logger.error("file_not_found", role=label, path=str(path))
            sys.exit(1)

    findings = validate_identity_assets_files(args.identity_assets, args.assets)

    for f in findings:
        log_method = logger.error if f.severity == "error" else logger.warning
        log_method(f.code, location=f.location, message=f.message)

    if args.report:
        text = render_report(
            [(f"IdentityAssets: {args.identity_assets.name}", findings)],
            timestamp=datetime.now(tz=UTC),
        )
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text, encoding="utf-8")
        print(f"Report written: {args.report}")

    errors = sum(1 for f in findings if f.severity == "error")
    warnings = sum(1 for f in findings if f.severity == "warning")
    print(f"identity_assets validation: errors={errors} warnings={warnings}")
    sys.exit(1 if has_errors(findings) else 0)


if __name__ == "__main__":
    main()
