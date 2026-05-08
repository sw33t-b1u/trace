"""Referential-integrity checks for ``assets.json``.

Schema validation (``trace_engine.validate.schema.AssetsDocument``) handles
shape and value bounds; this module enforces cross-reference invariants:

- id uniqueness within ``network_segments``, ``security_controls``, ``assets``
- ``Asset.network_segment_id`` must resolve to a known segment when set
- ``Asset.security_control_ids`` entries must resolve to known controls
- ``asset_connections.{src,dst}`` must resolve to known assets
- ``asset_vulnerabilities.asset_id`` must resolve to a known asset
- ``actor_targets.asset_id`` must resolve to a known asset
"""

from __future__ import annotations

from collections import Counter

from trace_engine.validate.schema.models import AssetsDocument
from trace_engine.validate.semantic.findings import ValidationFinding


def check_assets(doc: AssetsDocument) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []

    findings.extend(_check_unique_ids(doc))

    seg_ids = {s.id for s in doc.network_segments}
    ctrl_ids = {c.id for c in doc.security_controls}
    asset_ids = {a.id for a in doc.assets}

    for i, asset in enumerate(doc.assets):
        loc = f"assets[{i}] id={asset.id}"
        if asset.network_segment_id and asset.network_segment_id not in seg_ids:
            findings.append(
                ValidationFinding(
                    severity="error",
                    code="ASSET_REF_SEGMENT",
                    location=loc,
                    message=(
                        f"network_segment_id {asset.network_segment_id!r} "
                        "does not resolve to any network_segments[*].id"
                    ),
                )
            )
        for j, ctrl_id in enumerate(asset.security_control_ids):
            if ctrl_id not in ctrl_ids:
                findings.append(
                    ValidationFinding(
                        severity="error",
                        code="ASSET_REF_CONTROL",
                        location=f"{loc}.security_control_ids[{j}]",
                        message=(
                            f"security_control_id {ctrl_id!r} does not "
                            "resolve to any security_controls[*].id"
                        ),
                    )
                )

    for i, conn in enumerate(doc.asset_connections):
        for side, value in (("src", conn.src), ("dst", conn.dst)):
            if value not in asset_ids:
                findings.append(
                    ValidationFinding(
                        severity="error",
                        code="CONNECTION_REF_ASSET",
                        location=f"asset_connections[{i}].{side}",
                        message=f"{side}={value!r} does not resolve to any assets[*].id",
                    )
                )

    for i, av in enumerate(doc.asset_vulnerabilities):
        if av.asset_id not in asset_ids:
            findings.append(
                ValidationFinding(
                    severity="error",
                    code="VULN_REF_ASSET",
                    location=f"asset_vulnerabilities[{i}]",
                    message=f"asset_id {av.asset_id!r} does not resolve to any assets[*].id",
                )
            )

    for i, t in enumerate(doc.actor_targets):
        if t.asset_id not in asset_ids:
            findings.append(
                ValidationFinding(
                    severity="error",
                    code="ACTOR_TARGET_REF_ASSET",
                    location=f"actor_targets[{i}]",
                    message=f"asset_id {t.asset_id!r} does not resolve to any assets[*].id",
                )
            )

    return findings


def _check_unique_ids(doc: AssetsDocument) -> list[ValidationFinding]:
    out: list[ValidationFinding] = []
    for kind, ids in (
        ("network_segments", [s.id for s in doc.network_segments]),
        ("security_controls", [c.id for c in doc.security_controls]),
        ("assets", [a.id for a in doc.assets]),
    ):
        dupes = [k for k, n in Counter(ids).items() if n > 1]
        for dup in dupes:
            out.append(
                ValidationFinding(
                    severity="error",
                    code="ID_NOT_UNIQUE",
                    location=kind,
                    message=f"id {dup!r} appears more than once in {kind}",
                )
            )
    return out
