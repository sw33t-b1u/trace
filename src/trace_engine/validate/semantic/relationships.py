"""Semantic checks for STIX 2.1 relationship source/target type compliance.

Initiative C Phase 1: verifies that ``attributed-to`` and ``impersonates``
SROs in a bundle use source/target combinations from the §3.4 emit-ready
matrix. Combinations outside the matrix are flagged with
``RELATIONSHIP_TYPE_MATCH`` (error). Unresolved identity references in
``x-identity-internal`` objects are flagged with ``IDENTITY_REF_RESOLUTION``
(warning).
"""

from __future__ import annotations

from trace_engine.validate.semantic.findings import ValidationFinding

# §3.4 emit-ready matrix: (source_type, relationship_type) → allowed target types.
# Source: OASIS cti-stix-validator/v21/enums.py RELATIONSHIPS dict.
_EMIT_READY_MATRIX: dict[tuple[str, str], frozenset[str]] = {
    ("campaign", "attributed-to"): frozenset({"intrusion-set", "threat-actor"}),
    ("intrusion-set", "attributed-to"): frozenset({"threat-actor"}),
    ("threat-actor", "attributed-to"): frozenset({"identity", "x-identity-internal"}),
    ("threat-actor", "impersonates"): frozenset({"identity", "x-identity-internal"}),
}

_ATTRIBUTION_IMPERSONATION_TYPES: frozenset[str] = frozenset({"attributed-to", "impersonates"})


def check_relationship_type_match(bundle: dict) -> list[ValidationFinding]:
    """Check attributed-to / impersonates SROs against the §3.4 emit-ready matrix.

    ``bundle`` is a parsed STIX 2.1 bundle dict with an ``objects`` list.
    Returns a ``RELATIONSHIP_TYPE_MATCH`` error for every out-of-spec triple
    and an ``IDENTITY_REF_RESOLUTION`` warning for every ``x-identity-internal``
    whose ``identity_id`` is not in the supplied identity_ids set.
    """
    objects = bundle.get("objects") or []
    id_to_type: dict[str, str] = {}
    for obj in objects:
        stix_id = obj.get("id")
        stix_type = obj.get("type")
        if stix_id and stix_type:
            id_to_type[stix_id] = stix_type

    findings: list[ValidationFinding] = []
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        rel_type = obj.get("relationship_type", "")
        if rel_type not in _ATTRIBUTION_IMPERSONATION_TYPES:
            continue
        src_ref = obj.get("source_ref", "")
        tgt_ref = obj.get("target_ref", "")
        src_type = id_to_type.get(src_ref, src_ref.split("--")[0] if "--" in src_ref else "")
        tgt_type = id_to_type.get(tgt_ref, tgt_ref.split("--")[0] if "--" in tgt_ref else "")
        allowed = _EMIT_READY_MATRIX.get((src_type, rel_type))
        if allowed is None or tgt_type not in allowed:
            findings.append(
                ValidationFinding(
                    severity="error",
                    code="RELATIONSHIP_TYPE_MATCH",
                    location=f"relationship id={obj.get('id', '?')}",
                    message=(
                        f"({src_type}, {rel_type}, {tgt_type}) is not in the "
                        "§3.4 emit-ready matrix — drop per §3.1.1"
                    ),
                )
            )
    return findings


def check_identity_ref_resolution(
    bundle: dict,
    known_identity_ids: set[str],
) -> list[ValidationFinding]:
    """Warn when x-identity-internal.identity_id is not in known_identity_ids.

    ``known_identity_ids`` is the set of id-* slugs from
    ``identity_assets.json[*].identities[*].id``. A missing entry means the
    identity reference couldn't be resolved at bundle-assembly time (tier-4
    drop) and the analyst should investigate.
    """
    objects = bundle.get("objects") or []
    findings: list[ValidationFinding] = []
    for obj in objects:
        if obj.get("type") != "x-identity-internal":
            continue
        identity_id = obj.get("identity_id", "")
        if identity_id and identity_id not in known_identity_ids:
            findings.append(
                ValidationFinding(
                    severity="warning",
                    code="IDENTITY_REF_RESOLUTION",
                    location=f"x-identity-internal id={obj.get('id', '?')}",
                    message=(
                        f"identity_id {identity_id!r} not found in "
                        "identity_assets.json — tier-4 resolver miss"
                    ),
                )
            )
    return findings
