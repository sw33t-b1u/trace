"""Tests for STIX bundle validation (OASIS wrapper + local refchecks)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from trace_engine.validate.stix import check_stix_bundle, run_stix2_validator

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def valid_bundle() -> dict:
    with (FIXTURES / "valid_bundle.json").open() as f:
        return json.load(f)


def test_valid_bundle_local_checks_clean(valid_bundle: dict) -> None:
    assert check_stix_bundle(valid_bundle) == []


def test_wrong_spec_version_caught(valid_bundle: dict) -> None:
    bundle = copy.deepcopy(valid_bundle)
    bundle["spec_version"] = "2.0"
    findings = check_stix_bundle(bundle)
    assert any(f.code == "BUNDLE_SPEC_VERSION" for f in findings)


def test_wrong_bundle_type_caught(valid_bundle: dict) -> None:
    bundle = copy.deepcopy(valid_bundle)
    bundle["type"] = "envelope"
    assert any(f.code == "BUNDLE_TYPE" for f in check_stix_bundle(bundle))


def test_duplicate_object_id_caught(valid_bundle: dict) -> None:
    bundle = copy.deepcopy(valid_bundle)
    bundle["objects"].append(copy.deepcopy(bundle["objects"][0]))
    assert any(f.code == "STIX_ID_NOT_UNIQUE" for f in check_stix_bundle(bundle))


def test_dangling_relationship_source_caught(valid_bundle: dict) -> None:
    bundle = copy.deepcopy(valid_bundle)
    rel = next(o for o in bundle["objects"] if o["type"] == "relationship")
    rel["source_ref"] = "threat-actor--ffffffff-ffff-4fff-bfff-ffffffffffff"
    findings = check_stix_bundle(bundle)
    assert any(f.code == "REL_REF_UNRESOLVED" and "source_ref" in f.location for f in findings)


def test_dangling_relationship_target_caught(valid_bundle: dict) -> None:
    bundle = copy.deepcopy(valid_bundle)
    rel = next(o for o in bundle["objects"] if o["type"] == "relationship")
    rel["target_ref"] = "attack-pattern--ffffffff-ffff-4fff-bfff-ffffffffffff"
    findings = check_stix_bundle(bundle)
    assert any(f.code == "REL_REF_UNRESOLVED" and "target_ref" in f.location for f in findings)


def test_non_mitre_kill_chain_caught(valid_bundle: dict) -> None:
    bundle = copy.deepcopy(valid_bundle)
    ap = next(o for o in bundle["objects"] if o["type"] == "attack-pattern")
    ap["kill_chain_phases"][0]["kill_chain_name"] = "lockheed-martin"
    assert any(f.code == "KILL_CHAIN_NAME" for f in check_stix_bundle(bundle))


def test_oasis_validator_no_errors_on_valid_bundle(valid_bundle: dict) -> None:
    findings = run_stix2_validator(valid_bundle)
    errors = [f for f in findings if f.severity == "error"]
    assert errors == [], f"unexpected errors: {errors}"


def test_strict_mode_promotes_warnings_to_errors(valid_bundle: dict) -> None:
    lenient = run_stix2_validator(valid_bundle, strict=False)
    strict = run_stix2_validator(valid_bundle, strict=True)
    lenient_warns = sum(1 for f in lenient if f.severity == "warning")
    strict_warns = sum(1 for f in strict if f.severity == "warning")
    assert strict_warns < lenient_warns or lenient_warns == 0
