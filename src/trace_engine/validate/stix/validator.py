"""STIX bundle validation.

Two layers:

1. ``run_stix2_validator`` — wraps the OASIS ``stix2-validator`` library and
   normalizes its ``ObjectValidationResults`` into ``ValidationFinding`` records.
2. ``check_stix_bundle`` — TRACE-local checks the OASIS validator does not
   cover: object-id uniqueness within the bundle,
   ``relationship.{source_ref,target_ref}`` resolution, and
   ``kill_chain_name == "mitre-attack"`` for any STIX object that carries
   kill chain phases.

As of TRACE 0.4.0 the bundle envelope no longer carries ``spec_version`` or
``created`` (STIX 2.1 deprecated those at the envelope level — they live on
each object instead). The previous ``BUNDLE_SPEC_VERSION`` local check was
removed in lockstep. SAGE's parser (``SAGE/src/sage/stix/parser.py``)
iterates ``bundle.objects[]`` and reads per-object ``spec_version``, so the
removal is safe.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from stix2validator import ValidationOptions, validate_parsed_json

from trace_engine.validate.semantic.findings import ValidationFinding


def run_stix2_validator(
    bundle: dict[str, Any],
    *,
    strict: bool = False,
) -> list[ValidationFinding]:
    """Run the OASIS validator and return findings.

    ``strict=True`` promotes warnings to errors. Non-strict mode keeps the
    OASIS warning severity intact so analysts see the spec deviations
    without blocking ingestion.
    """
    opts = ValidationOptions(version="2.1")
    result = validate_parsed_json(bundle, opts)

    findings: list[ValidationFinding] = []
    for err in result.errors:
        findings.append(
            ValidationFinding(
                severity="error",
                code="STIX2_VALIDATOR",
                location=getattr(result, "object_id", "bundle"),
                message=str(err),
            )
        )
    for warn in result.warnings:
        findings.append(
            ValidationFinding(
                severity="error" if strict else "warning",
                code="STIX2_VALIDATOR",
                location=getattr(result, "object_id", "bundle"),
                message=str(warn),
            )
        )
    return findings


def check_stix_bundle(bundle: dict[str, Any]) -> list[ValidationFinding]:
    """TRACE-local refchecks beyond what the OASIS validator covers."""
    findings: list[ValidationFinding] = []

    if bundle.get("type") != "bundle":
        findings.append(
            ValidationFinding(
                severity="error",
                code="BUNDLE_TYPE",
                location="bundle.type",
                message=f"expected 'bundle', got {bundle.get('type')!r}",
            )
        )

    objects = bundle.get("objects") or []
    findings.extend(_check_object_id_uniqueness(objects))
    findings.extend(_check_relationship_refs(objects))
    findings.extend(_check_kill_chain_name(objects))

    return findings


def _check_object_id_uniqueness(objects: list[dict[str, Any]]) -> list[ValidationFinding]:
    ids = [obj.get("id") for obj in objects if isinstance(obj.get("id"), str)]
    out: list[ValidationFinding] = []
    for dup, n in Counter(ids).items():
        if n > 1:
            out.append(
                ValidationFinding(
                    severity="error",
                    code="STIX_ID_NOT_UNIQUE",
                    location=f"objects[*].id={dup}",
                    message=f"id appears {n} times within the bundle",
                )
            )
    return out


def _check_relationship_refs(objects: list[dict[str, Any]]) -> list[ValidationFinding]:
    object_ids: set[str] = {obj["id"] for obj in objects if isinstance(obj.get("id"), str)}
    out: list[ValidationFinding] = []
    for i, obj in enumerate(objects):
        if obj.get("type") != "relationship":
            continue
        loc_base = f"objects[{i}] id={obj.get('id')}"
        for field in ("source_ref", "target_ref"):
            ref = obj.get(field)
            if not isinstance(ref, str):
                out.append(
                    ValidationFinding(
                        severity="error",
                        code="REL_REF_MISSING",
                        location=f"{loc_base}.{field}",
                        message=f"relationship is missing {field}",
                    )
                )
                continue
            if ref not in object_ids:
                out.append(
                    ValidationFinding(
                        severity="error",
                        code="REL_REF_UNRESOLVED",
                        location=f"{loc_base}.{field}",
                        message=f"{field}={ref!r} does not resolve within the bundle",
                    )
                )
    return out


def _check_kill_chain_name(objects: list[dict[str, Any]]) -> list[ValidationFinding]:
    out: list[ValidationFinding] = []
    for i, obj in enumerate(objects):
        phases = obj.get("kill_chain_phases")
        if not isinstance(phases, list):
            continue
        for j, phase in enumerate(phases):
            if not isinstance(phase, dict):
                continue
            name = phase.get("kill_chain_name")
            if name != "mitre-attack":
                out.append(
                    ValidationFinding(
                        severity="error",
                        code="KILL_CHAIN_NAME",
                        location=f"objects[{i}].kill_chain_phases[{j}].kill_chain_name",
                        message=(
                            f"expected 'mitre-attack', got {name!r} — SAGE's "
                            "ETL only consumes the MITRE ATT&CK kill chain"
                        ),
                    )
                )
    return out
