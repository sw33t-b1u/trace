"""Validate ``user_accounts.json`` against SAGE's input contract.

Initiative B — TRACE 1.3.0 §6.1. ``--assets`` is **required**;
``--identity-assets`` is optional but enables an extra cross-ref pass
(``user_accounts[*].identity_id`` → identities).

Layers run, in order:
  1. Pydantic schema check (``UserAccountsDocument``).
  2. Pydantic schema check on supplied ``assets.json``
     (``AssetsDocument``).
  3. Pydantic schema check on supplied ``identity_assets.json`` if
     ``--identity-assets`` is provided.
  4. Cross-reference checks (id uniqueness, user_account_id / asset_id
     resolution, optional identity_id resolution, duplicate
     (user_account_id, asset_id) pair detection).

Exit code is 0 on success and 1 on any error-severity finding.
Warnings (e.g. duplicate access pair) do not block.

Usage:
    uv run python cmd/validate_user_accounts.py \\
        --user-accounts ../BEACON/output/user_accounts.json \\
        --assets ../BEACON/output/assets.json
    # Optional identity cross-ref
    uv run python cmd/validate_user_accounts.py \\
        --user-accounts ../BEACON/output/user_accounts.json \\
        --assets ../BEACON/output/assets.json \\
        --identity-assets ../BEACON/output/identity_assets.json

.. deprecated:: TRACE 1.12.0

    Direct invocation as ``python -m cmd.validate_user_accounts`` /
    ``python cmd/validate_user_accounts.py`` is deprecated. Use the
    unified ``trace validate-accounts`` entry (Initiative H Phase 6).
    Removal is scheduled for TRACE 2.0.
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
from trace_engine.config import load_config  # noqa: E402
from trace_engine.io.inputs import resolve_json_input  # noqa: E402
from trace_engine.review.markdown_report import render_report  # noqa: E402
from trace_engine.validate.schema import (  # noqa: E402
    AssetsDocument,
    IdentityAssetsDocument,
    UserAccountsDocument,
)
from trace_engine.validate.semantic.findings import (  # noqa: E402
    ValidationFinding,
    has_errors,
)
from trace_engine.validate.semantic.user_accounts import (  # noqa: E402
    check_user_accounts,
)

configure_logging()
logger = structlog.get_logger(__name__)


def _load_and_validate_schema(
    path: Path,
    model_cls: type,
    findings: list[ValidationFinding],
):
    with path.open() as f:
        payload = json.load(f)
    return _validate_schema_payload(payload, model_cls, findings)


def _validate_schema_payload(payload: object, model_cls: type, findings: list[ValidationFinding]):
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


def validate_user_accounts_files(
    user_accounts_path: Path,
    assets_path: Path,
    identity_assets_path: Path | None = None,
) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    ua_doc = _load_and_validate_schema(user_accounts_path, UserAccountsDocument, findings)
    a_doc = _load_and_validate_schema(assets_path, AssetsDocument, findings)
    ia_doc = None
    if identity_assets_path is not None:
        ia_doc = _load_and_validate_schema(identity_assets_path, IdentityAssetsDocument, findings)
    if ua_doc is None or a_doc is None:
        return findings
    findings.extend(check_user_accounts(ua_doc, a_doc, ia_doc))
    return findings


def validate_user_accounts_payloads(
    user_accounts_payload: object,
    assets_payload: object,
    identity_assets_payload: object | None = None,
) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    ua_doc = _validate_schema_payload(user_accounts_payload, UserAccountsDocument, findings)
    a_doc = _validate_schema_payload(assets_payload, AssetsDocument, findings)
    ia_doc = None
    if identity_assets_payload is not None:
        ia_doc = _validate_schema_payload(identity_assets_payload, IdentityAssetsDocument, findings)
    if ua_doc is None or a_doc is None:
        return findings
    findings.extend(check_user_accounts(ua_doc, a_doc, ia_doc))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate user_accounts.json before SAGE ingestion"
    )
    parser.add_argument(
        "--user-accounts",
        "--ua",
        required=True,
        help="Path, gs:// URI, or assets/ storage key for user_accounts.json",
    )
    parser.add_argument(
        "--it-assets",
        "--ita",
        required=True,
        help=(
            "Path, gs:// URI, or assets/ storage key for assets.json "
            "(REQUIRED for cross-reference of account_on_asset[*].asset_id)"
        ),
    )
    parser.add_argument(
        "--identity-assets",
        "--ida",
        default=None,
        help=(
            "Optional path, gs:// URI, or assets/ storage key for identity_assets.json. "
            "When provided, validates "
            "user_accounts[*].identity_id against identities[*].id."
        ),
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Optional Markdown report output path",
    )
    args = parser.parse_args()
    cfg = load_config()

    try:
        user_accounts_payload, user_accounts_input = resolve_json_input(
            cfg, "assets", args.user_accounts
        )
    except FileNotFoundError:
        logger.error("file_not_found", role="user-accounts", path=str(args.user_accounts))
        sys.exit(1)
    try:
        assets_payload, _ = resolve_json_input(cfg, "assets", args.it_assets)
    except FileNotFoundError:
        logger.error("file_not_found", role="it-assets", path=str(args.it_assets))
        sys.exit(1)
    identity_assets_payload = None
    if args.identity_assets is not None:
        try:
            identity_assets_payload, _ = resolve_json_input(cfg, "assets", args.identity_assets)
        except FileNotFoundError:
            logger.error("file_not_found", role="identity-assets", path=str(args.identity_assets))
            sys.exit(1)

    findings = validate_user_accounts_payloads(
        user_accounts_payload,
        assets_payload,
        identity_assets_payload,
    )

    for f in findings:
        log_method = logger.error if f.severity == "error" else logger.warning
        log_method(f.code, location=f.location, message=f.message)

    if args.report:
        text = render_report(
            [(f"UserAccounts: {user_accounts_input.display_name}", findings)],
            timestamp=datetime.now(tz=UTC),
        )
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text, encoding="utf-8")
        print(f"Report written: {args.report}")

    errors = sum(1 for f in findings if f.severity == "error")
    warnings = sum(1 for f in findings if f.severity == "warning")
    print(f"user_accounts validation: errors={errors} warnings={warnings}")
    sys.exit(1 if has_errors(findings) else 0)
