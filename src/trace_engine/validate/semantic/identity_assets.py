"""Cross-reference checks for ``identity_assets.json`` (Initiative A).

Schema validation (``IdentityAssetsDocument``) handles shape and value
bounds. This module enforces:

- ``identities[*].id`` uniqueness
- ``has_access[*].identity_id`` resolves to ``identities[*].id``
- ``has_access[*].asset_id`` resolves to a supplied ``assets.json``'s
  ``assets[*].id``  (``--assets`` is REQUIRED at the CLI level — see
  ``cmd/validate_identity_assets.py``; this module asserts on the
  invariant when the assets doc is supplied).

Pair-uniqueness on (identity_id, asset_id) is enforced as well: SAGE
upserts on the composite key so duplicates would silently collapse to
the last entry, but the analyst should know.
"""

from __future__ import annotations

from collections import Counter

from trace_engine.validate.schema.models import (
    AssetsDocument,
    IdentityAssetsDocument,
)
from trace_engine.validate.semantic.findings import ValidationFinding


def check_identity_assets(
    doc: IdentityAssetsDocument,
    assets_doc: AssetsDocument,
) -> list[ValidationFinding]:
    """Validate cross-references against the supplied assets document.

    ``assets_doc`` is required (Initiative A §6.1 decision: validator
    cross-ref is non-optional). Callers that obtain
    ``IdentityAssetsDocument`` without a paired ``AssetsDocument`` should
    fail at the CLI layer rather than reach this function.
    """
    findings: list[ValidationFinding] = []

    findings.extend(_check_unique_identity_ids(doc))
    findings.extend(_check_unique_access_pairs(doc))

    identity_ids = {ident.id for ident in doc.identities}
    asset_ids = {a.id for a in assets_doc.assets}

    for i, edge in enumerate(doc.has_access):
        loc = f"has_access[{i}]"
        if edge.identity_id not in identity_ids:
            findings.append(
                ValidationFinding(
                    severity="error",
                    code="HAS_ACCESS_REF_IDENTITY",
                    location=loc,
                    message=(
                        f"identity_id {edge.identity_id!r} does not resolve to any identities[*].id"
                    ),
                )
            )
        if edge.asset_id not in asset_ids:
            findings.append(
                ValidationFinding(
                    severity="error",
                    code="HAS_ACCESS_REF_ASSET",
                    location=loc,
                    message=(
                        f"asset_id {edge.asset_id!r} does not resolve to any "
                        "assets[*].id in the supplied assets.json"
                    ),
                )
            )

    return findings


def _check_unique_identity_ids(doc: IdentityAssetsDocument) -> list[ValidationFinding]:
    ids = [ident.id for ident in doc.identities]
    dupes = [k for k, n in Counter(ids).items() if n > 1]
    return [
        ValidationFinding(
            severity="error",
            code="IDENTITY_ID_NOT_UNIQUE",
            location="identities",
            message=f"id {dup!r} appears more than once in identities",
        )
        for dup in dupes
    ]


def _check_unique_access_pairs(doc: IdentityAssetsDocument) -> list[ValidationFinding]:
    pairs = [(edge.identity_id, edge.asset_id) for edge in doc.has_access]
    dupes = [pair for pair, n in Counter(pairs).items() if n > 1]
    return [
        ValidationFinding(
            severity="warning",
            code="HAS_ACCESS_DUPLICATE_PAIR",
            location="has_access",
            message=(
                f"(identity_id={pair[0]!r}, asset_id={pair[1]!r}) appears more "
                "than once; SAGE upsert will collapse duplicates to the last "
                "entry"
            ),
        )
        for pair in dupes
    ]
