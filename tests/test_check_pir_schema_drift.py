"""Unit tests for ``scripts/check_pir_schema_drift.py``.

Each §2.2 rule of the plan
``/Users/test/Projects/claude_pj/.plans/2026-05-13-pir-schema-diff-ci.md``
is exercised with a synthetic minimal 2-schema pair.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_SCRIPT_PATH = Path(__file__).parent.parent / "scripts" / "check_pir_schema_drift.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("check_pir_schema_drift", _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


drift = _load_module()


def _trace_schema(properties: dict, required: list[str], additional: bool = True) -> dict:
    return {
        "type": "object",
        "additionalProperties": additional,
        "properties": properties,
        "required": required,
    }


def _beacon_schema(properties: dict, required: list[str]) -> dict:
    return {
        "type": "object",
        "properties": properties,
        "required": required,
    }


class TestRule1RequiredDrift:
    def test_trace_requires_field_beacon_omits(self):
        beacon = _beacon_schema({"pir_id": {"type": "string"}}, required=["pir_id"])
        trace = _trace_schema(
            {"pir_id": {"type": "string"}, "valid_from": {"type": "string"}},
            required=["pir_id", "valid_from"],
        )
        errors, _ = drift.check_drift(beacon, trace)
        assert any("RULE 1" in e and "valid_from" in e for e in errors)

    def test_required_subset_no_error(self):
        beacon = _beacon_schema(
            {"pir_id": {"type": "string"}, "valid_from": {"type": "string"}},
            required=["pir_id", "valid_from"],
        )
        trace = _trace_schema(
            {"pir_id": {"type": "string"}, "valid_from": {"type": "string"}},
            required=["pir_id"],
        )
        errors, _ = drift.check_drift(beacon, trace)
        assert not any("RULE 1" in e for e in errors)


class TestRule2TypeDrift:
    def test_string_vs_integer_is_error(self):
        beacon = _beacon_schema({"pir_id": {"type": "integer"}}, required=["pir_id"])
        trace = _trace_schema({"pir_id": {"type": "string"}}, required=["pir_id"])
        errors, _ = drift.check_drift(beacon, trace)
        assert any("RULE 2" in e and "pir_id" in e for e in errors)

    def test_nullable_string_matches_string(self):
        """TRACE encodes optionality via anyOf+null; BEACON omits it.

        Stripping ``null`` from the comparison avoids spurious ERRORs.
        """
        beacon = _beacon_schema(
            {"description": {"type": "string"}},
            required=["description"],
        )
        trace = _trace_schema(
            {
                "description": {
                    "anyOf": [{"type": "string"}, {"type": "null"}],
                    "default": None,
                }
            },
            required=[],
        )
        errors, _ = drift.check_drift(beacon, trace)
        assert not any("RULE 2" in e for e in errors)

    def test_format_mismatch_alone_not_error(self):
        """BEACON `valid_from: string` vs TRACE `valid_from: string/format=date`
        is tolerated per §2.3 known drift — base type matches, no Rule-2 ERROR."""
        beacon = _beacon_schema({"valid_from": {"type": "string"}}, required=[])
        trace = _trace_schema(
            {"valid_from": {"type": "string", "format": "date"}},
            required=[],
        )
        errors, _ = drift.check_drift(beacon, trace)
        assert not any("RULE 2" in e for e in errors)


class TestRule6FormatDrift:
    def test_format_mismatch_emits_warning(self):
        """BEACON `valid_from: string` vs TRACE `valid_from: string/format=date`
        surfaces as a Rule-6 WARNING (per §2.3)."""
        beacon = _beacon_schema({"valid_from": {"type": "string"}}, required=[])
        trace = _trace_schema(
            {"valid_from": {"type": "string", "format": "date"}},
            required=[],
        )
        _, warnings = drift.check_drift(beacon, trace)
        assert any("RULE 6" in w and "valid_from" in w for w in warnings)

    def test_format_match_no_warning(self):
        """Both sides declare the same format — no Rule-6 WARNING."""
        beacon = _beacon_schema(
            {"valid_from": {"type": "string", "format": "date"}}, required=[]
        )
        trace = _trace_schema(
            {"valid_from": {"type": "string", "format": "date"}}, required=[]
        )
        _, warnings = drift.check_drift(beacon, trace)
        assert not any("RULE 6" in w for w in warnings)

    def test_format_drift_inside_anyof(self):
        """TRACE optional `valid_until: anyOf(string/format=date, null)` vs BEACON
        `valid_until: string` surfaces Rule-6 from inside the anyOf branch."""
        beacon = _beacon_schema({"valid_until": {"type": "string"}}, required=[])
        trace = _trace_schema(
            {
                "valid_until": {
                    "anyOf": [{"type": "string", "format": "date"}, {"type": "null"}]
                }
            },
            required=[],
        )
        _, warnings = drift.check_drift(beacon, trace)
        assert any("RULE 6" in w and "valid_until" in w for w in warnings)


class TestRule3StrictRejectDrift:
    def test_strict_trace_with_beacon_extra_field_is_error(self):
        beacon = _beacon_schema(
            {
                "pir_id": {"type": "string"},
                "rationale": {"type": "string"},
            },
            required=["pir_id"],
        )
        trace = _trace_schema({"pir_id": {"type": "string"}}, required=["pir_id"], additional=False)
        errors, warnings = drift.check_drift(beacon, trace)
        assert any("RULE 3" in e and "rationale" in e for e in errors)
        assert not any("RULE 4" in w for w in warnings)


class TestRule4SilentAcceptDrift:
    def test_permissive_trace_with_beacon_extra_field_is_warning(self):
        beacon = _beacon_schema(
            {
                "pir_id": {"type": "string"},
                "rationale": {"type": "string"},
            },
            required=["pir_id"],
        )
        trace = _trace_schema({"pir_id": {"type": "string"}}, required=["pir_id"], additional=True)
        errors, warnings = drift.check_drift(beacon, trace)
        assert any("RULE 4" in w and "rationale" in w for w in warnings)
        assert not any("RULE 3" in e for e in errors)


class TestRule5TraceOnlyOptional:
    def test_trace_optional_not_in_beacon_is_warning(self):
        beacon = _beacon_schema({"pir_id": {"type": "string"}}, required=["pir_id"])
        trace = _trace_schema(
            {
                "pir_id": {"type": "string"},
                "organizational_scope": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            },
            required=["pir_id"],
        )
        errors, warnings = drift.check_drift(beacon, trace)
        assert any("RULE 5" in w and "organizational_scope" in w for w in warnings)
        assert errors == []


class TestExitCodes:
    def test_no_drift_exits_zero(self, tmp_path):
        b = tmp_path / "b.json"
        t = tmp_path / "t.json"
        schema = _beacon_schema({"pir_id": {"type": "string"}}, required=["pir_id"])
        b.write_text(json.dumps(schema))
        t.write_text(json.dumps(_trace_schema({"pir_id": {"type": "string"}}, required=["pir_id"])))
        rc = drift.main([str(b), str(t)])
        assert rc == 0

    def test_error_drift_exits_one(self, tmp_path):
        b = tmp_path / "b.json"
        t = tmp_path / "t.json"
        b.write_text(
            json.dumps(_beacon_schema({"pir_id": {"type": "string"}}, required=["pir_id"]))
        )
        t.write_text(
            json.dumps(
                _trace_schema(
                    {"pir_id": {"type": "string"}, "valid_from": {"type": "string"}},
                    required=["pir_id", "valid_from"],
                )
            )
        )
        rc = drift.main([str(b), str(t)])
        assert rc == 1

    def test_warning_only_exits_zero(self, tmp_path):
        b = tmp_path / "b.json"
        t = tmp_path / "t.json"
        b.write_text(
            json.dumps(
                _beacon_schema(
                    {"pir_id": {"type": "string"}, "extra": {"type": "string"}},
                    required=["pir_id"],
                )
            )
        )
        t.write_text(
            json.dumps(
                _trace_schema(
                    {"pir_id": {"type": "string"}},
                    required=["pir_id"],
                    additional=True,
                )
            )
        )
        rc = drift.main([str(b), str(t)])
        assert rc == 0

    def test_missing_file_exits_two(self, tmp_path, capsys):
        rc = drift.main([str(tmp_path / "nope.json"), str(tmp_path / "also-nope.json")])
        assert rc == 2

    def test_invalid_json_exits_two(self, tmp_path):
        b = tmp_path / "b.json"
        t = tmp_path / "t.json"
        b.write_text("{not json")
        t.write_text("{}")
        rc = drift.main([str(b), str(t)])
        assert rc == 2


@pytest.mark.parametrize(
    "trace_additional,expect_rule",
    [(False, "RULE 3"), (True, "RULE 4")],
)
def test_beacon_extra_rule_branches(trace_additional, expect_rule):
    beacon = _beacon_schema(
        {"pir_id": {"type": "string"}, "x": {"type": "string"}},
        required=["pir_id"],
    )
    trace = _trace_schema(
        {"pir_id": {"type": "string"}}, required=["pir_id"], additional=trace_additional
    )
    errors, warnings = drift.check_drift(beacon, trace)
    combined = errors + warnings
    assert any(expect_rule in entry for entry in combined)


def test_real_schemas_no_error(tmp_path):
    """Real BEACON ⇄ TRACE canonical schemas should drift to WARNING-only."""
    repo_root = Path(__file__).parent.parent
    beacon_path = repo_root.parent / "BEACON" / "schema" / "pir_output.schema.json"
    trace_path = repo_root / "schema" / "pir.schema.json"
    if not beacon_path.exists():
        pytest.skip("BEACON sibling repo not checked out")
    beacon = json.loads(beacon_path.read_text())
    trace = json.loads(trace_path.read_text())
    errors, _ = drift.check_drift(beacon, trace)
    assert errors == [], f"unexpected drift errors: {errors}"


# Make pytest-runner happy when invoked via uv run
_ = sys
