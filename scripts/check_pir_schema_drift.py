#!/usr/bin/env python3
"""Detect drift between BEACON producer-canonical and TRACE consumer-canonical
PIR JSON schemas.

This script is co-authored in TRACE and copied (byte-identical) into BEACON
as a follow-up. Standard library only — no DeepDiff, no jsondiff.

Usage:
    python scripts/check_pir_schema_drift.py BEACON.schema.json TRACE.schema.json

Drift rules (per plan §2.2):

    1. TRACE.required ⊄ BEACON.required               → ERROR
    2. Field type mismatch on a shared property        → ERROR
    3. BEACON.properties ⊋ TRACE.properties AND
       TRACE additionalProperties == false             → ERROR
    4. BEACON.properties ⊋ TRACE.properties AND
       TRACE additionalProperties == true              → WARNING
    5. TRACE.properties ⊋ BEACON.properties            → WARNING

Exit codes:
    0  no ERROR drift detected (WARNINGs may have been emitted to stderr)
    1  one or more ERROR rules hit
    2  CLI / IO failure
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _normalize_types(spec: dict) -> set[str]:
    """Return the set of JSON-Schema primitive types for a property spec.

    Handles three forms:
      - ``{"type": "string"}``                 → {"string"}
      - ``{"type": ["string", "null"]}``       → {"string", "null"}
      - ``{"anyOf": [{"type": "string"}, ...]}`` → union of sub-types
      - ``{"$ref": "#/$defs/Foo"}``            → {"$ref:Foo"} (opaque token)
    Returns an empty set if no type can be determined (schema is permissive).
    """
    types: set[str] = set()
    t = spec.get("type")
    if isinstance(t, str):
        types.add(t)
    elif isinstance(t, list):
        for sub in t:
            if isinstance(sub, str):
                types.add(sub)
    ref = spec.get("$ref")
    if isinstance(ref, str):
        types.add(f"$ref:{ref.rsplit('/', 1)[-1]}")
    for sub in spec.get("anyOf", []) or []:
        types |= _normalize_types(sub)
    for sub in spec.get("oneOf", []) or []:
        types |= _normalize_types(sub)
    return types


def _comparable_types(spec: dict) -> set[str]:
    """Return type set with ``"null"`` removed for cross-schema comparison.

    BEACON tends to omit explicit nullability while TRACE encodes it via
    ``anyOf: [{"type": "string"}, {"type": "null"}]``. Stripping ``null``
    avoids spurious rule-2 ERRORs on optional-vs-required modeling.
    """
    return _normalize_types(spec) - {"null"}


def _additional_properties(schema: dict) -> bool:
    """Read ``additionalProperties`` with the Pydantic default of True."""
    val = schema.get("additionalProperties", True)
    if isinstance(val, bool):
        return val
    return True  # dict form (constrained subschema) — treat as permissive


def check_drift(beacon: dict, trace: dict) -> tuple[list[str], list[str]]:
    """Return ``(errors, warnings)`` strings for rendering."""
    errors: list[str] = []
    warnings: list[str] = []

    beacon_props: dict = beacon.get("properties", {}) or {}
    trace_props: dict = trace.get("properties", {}) or {}
    beacon_required = set(beacon.get("required", []) or [])
    trace_required = set(trace.get("required", []) or [])
    trace_additional = _additional_properties(trace)

    # Rule 1: TRACE.required ⊄ BEACON.required
    missing = sorted(trace_required - beacon_required)
    if missing:
        errors.append(
            "RULE 1 (required-set drift): TRACE requires fields not in BEACON.required: "
            + ", ".join(missing)
        )

    # Rule 2: type mismatch on shared properties
    shared = sorted(set(beacon_props) & set(trace_props))
    for field in shared:
        b_types = _comparable_types(beacon_props[field])
        t_types = _comparable_types(trace_props[field])
        if not b_types or not t_types:
            continue  # one side is fully permissive; skip
        if b_types.isdisjoint(t_types):
            errors.append(
                f"RULE 2 (type drift on '{field}'): BEACON={sorted(b_types)} "
                f"vs TRACE={sorted(t_types)}"
            )

    # Rules 3 / 4: BEACON.properties ⊋ TRACE.properties
    beacon_only = sorted(set(beacon_props) - set(trace_props))
    if beacon_only:
        msg = "BEACON emits properties TRACE does not declare: " + ", ".join(beacon_only)
        if trace_additional:
            warnings.append(f"RULE 4 (silent-accept drift): {msg}")
        else:
            errors.append(f"RULE 3 (strict-reject drift): {msg}")

    # Rule 5: TRACE.properties ⊋ BEACON.properties
    trace_only = sorted(set(trace_props) - set(beacon_props))
    if trace_only:
        warnings.append(
            "RULE 5 (TRACE-only optional drift): TRACE declares properties BEACON "
            "does not emit: " + ", ".join(trace_only)
        )

    return errors, warnings


def _render_report(
    errors: list[str], warnings: list[str], beacon_path: Path, trace_path: Path
) -> str:
    lines = [
        "# PIR schema drift report",
        f"- BEACON: {beacon_path}",
        f"- TRACE:  {trace_path}",
        "",
    ]
    if not errors and not warnings:
        lines.append("OK — no drift detected.")
        return "\n".join(lines)
    if errors:
        lines.append("## ERRORS")
        lines.extend(f"- {e}" for e in errors)
        lines.append("")
    if warnings:
        lines.append("## WARNINGS")
        lines.extend(f"- {w}" for w in warnings)
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("beacon_schema", type=Path, help="BEACON producer schema path")
    parser.add_argument("trace_schema", type=Path, help="TRACE consumer schema path")
    args = parser.parse_args(argv)

    try:
        beacon = json.loads(args.beacon_schema.read_text(encoding="utf-8"))
        trace = json.loads(args.trace_schema.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        print(f"error: schema file not found: {exc.filename}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON: {exc}", file=sys.stderr)
        return 2

    errors, warnings = check_drift(beacon, trace)
    report = _render_report(errors, warnings, args.beacon_schema, args.trace_schema)
    print(report)
    if warnings:
        for w in warnings:
            print(f"WARNING: {w}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
