"""Cross-reference checks for ``user_accounts.json`` (Initiative B).

Schema validation (``UserAccountsDocument``) handles shape and value
bounds. This module enforces:

- ``user_accounts[*].id`` uniqueness
- ``account_on_asset[*].user_account_id`` resolves to
  ``user_accounts[*].id``
- ``account_on_asset[*].asset_id`` resolves to a supplied
  ``assets.json``'s ``assets[*].id`` (``--assets`` is REQUIRED at the
  CLI level)
- (Optional) ``user_accounts[*].identity_id`` resolves to a supplied
  ``identity_assets.json``'s ``identities[*].id`` when
  ``--identity-assets`` is also passed

Pair-uniqueness on ``(user_account_id, asset_id)`` is also enforced: SAGE
upserts on the composite key so duplicates would silently collapse to
the last entry, but the analyst should know.
"""

from __future__ import annotations

from collections import Counter

from trace_engine.validate.schema.models import (
    AssetsDocument,
    IdentityAssetsDocument,
    UserAccountsDocument,
)
from trace_engine.validate.semantic.findings import ValidationFinding


def check_user_accounts(
    doc: UserAccountsDocument,
    assets_doc: AssetsDocument,
    identity_assets_doc: IdentityAssetsDocument | None = None,
) -> list[ValidationFinding]:
    """Validate cross-references against the supplied assets document.

    ``assets_doc`` is required (Initiative B §6.1 decision: validator
    cross-ref is non-optional). ``identity_assets_doc`` is optional —
    when supplied, validates `user_accounts[*].identity_id` → known
    identity ids.
    """
    findings: list[ValidationFinding] = []

    findings.extend(_check_unique_user_account_ids(doc))
    findings.extend(_check_unique_account_asset_pairs(doc))

    user_account_ids = {ua.id for ua in doc.user_accounts}
    asset_ids = {a.id for a in assets_doc.assets}
    identity_ids: set[str] | None = None
    if identity_assets_doc is not None:
        identity_ids = {ident.id for ident in identity_assets_doc.identities}

    for i, ua in enumerate(doc.user_accounts):
        if ua.identity_id and identity_ids is not None and ua.identity_id not in identity_ids:
            findings.append(
                ValidationFinding(
                    severity="error",
                    code="USER_ACCOUNT_REF_IDENTITY",
                    location=f"user_accounts[{i}]",
                    message=(
                        f"identity_id {ua.identity_id!r} does not resolve to any "
                        "identities[*].id in the supplied identity_assets.json"
                    ),
                )
            )

    for i, edge in enumerate(doc.account_on_asset):
        loc = f"account_on_asset[{i}]"
        if edge.user_account_id not in user_account_ids:
            findings.append(
                ValidationFinding(
                    severity="error",
                    code="ACCOUNT_ON_ASSET_REF_USER_ACCOUNT",
                    location=loc,
                    message=(
                        f"user_account_id {edge.user_account_id!r} does not "
                        "resolve to any user_accounts[*].id"
                    ),
                )
            )
        if edge.asset_id not in asset_ids:
            findings.append(
                ValidationFinding(
                    severity="error",
                    code="ACCOUNT_ON_ASSET_REF_ASSET",
                    location=loc,
                    message=(
                        f"asset_id {edge.asset_id!r} does not resolve to any "
                        "assets[*].id in the supplied assets.json"
                    ),
                )
            )

    return findings


def _check_unique_user_account_ids(doc: UserAccountsDocument) -> list[ValidationFinding]:
    ids = [ua.id for ua in doc.user_accounts]
    dupes = [k for k, n in Counter(ids).items() if n > 1]
    return [
        ValidationFinding(
            severity="error",
            code="USER_ACCOUNT_ID_NOT_UNIQUE",
            location="user_accounts",
            message=f"id {dup!r} appears more than once in user_accounts",
        )
        for dup in dupes
    ]


def _check_unique_account_asset_pairs(doc: UserAccountsDocument) -> list[ValidationFinding]:
    pairs = [(edge.user_account_id, edge.asset_id) for edge in doc.account_on_asset]
    dupes = [pair for pair, n in Counter(pairs).items() if n > 1]
    return [
        ValidationFinding(
            severity="warning",
            code="ACCOUNT_ON_ASSET_DUPLICATE_PAIR",
            location="account_on_asset",
            message=(
                f"(user_account_id={pair[0]!r}, asset_id={pair[1]!r}) appears "
                "more than once; SAGE upsert will collapse duplicates to the "
                "last entry"
            ),
        )
        for pair in dupes
    ]
