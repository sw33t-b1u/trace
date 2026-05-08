"""Tests for the assets validator (schema + semantic)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from trace_engine.validate.schema import AssetsDocument
from trace_engine.validate.semantic.assets import check_assets

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def valid_payload() -> dict:
    with (FIXTURES / "valid_assets.json").open() as f:
        return json.load(f)


def test_valid_assets_passes_schema_and_semantic(valid_payload: dict) -> None:
    doc = AssetsDocument.model_validate(valid_payload)
    assert check_assets(doc) == []


def test_criticality_above_ten_fails_schema(valid_payload: dict) -> None:
    payload = copy.deepcopy(valid_payload)
    payload["assets"][0]["criticality"] = 99.0
    with pytest.raises(ValidationError) as exc:
        AssetsDocument.model_validate(payload)
    assert "criticality" in str(exc.value)


def test_negative_criticality_fails_schema(valid_payload: dict) -> None:
    payload = copy.deepcopy(valid_payload)
    payload["assets"][0]["criticality"] = -1.0
    with pytest.raises(ValidationError):
        AssetsDocument.model_validate(payload)


def test_unknown_segment_id_caught_by_semantic(valid_payload: dict) -> None:
    payload = copy.deepcopy(valid_payload)
    payload["assets"][0]["network_segment_id"] = "seg-does-not-exist"
    doc = AssetsDocument.model_validate(payload)
    findings = check_assets(doc)
    codes = {f.code for f in findings}
    assert "ASSET_REF_SEGMENT" in codes


def test_unknown_control_id_caught_by_semantic(valid_payload: dict) -> None:
    payload = copy.deepcopy(valid_payload)
    payload["assets"][0]["security_control_ids"] = ["ctrl-missing"]
    doc = AssetsDocument.model_validate(payload)
    assert any(f.code == "ASSET_REF_CONTROL" for f in check_assets(doc))


def test_duplicate_asset_id_caught_by_semantic(valid_payload: dict) -> None:
    payload = copy.deepcopy(valid_payload)
    payload["assets"].append(dict(payload["assets"][0]))
    doc = AssetsDocument.model_validate(payload)
    assert any(f.code == "ID_NOT_UNIQUE" for f in check_assets(doc))


def test_dangling_connection_ref_caught(valid_payload: dict) -> None:
    payload = copy.deepcopy(valid_payload)
    payload["asset_connections"][0]["dst"] = "asset-ghost"
    doc = AssetsDocument.model_validate(payload)
    assert any(f.code == "CONNECTION_REF_ASSET" for f in check_assets(doc))


def test_dangling_vuln_ref_caught(valid_payload: dict) -> None:
    payload = copy.deepcopy(valid_payload)
    payload["asset_vulnerabilities"][0]["asset_id"] = "asset-ghost"
    doc = AssetsDocument.model_validate(payload)
    assert any(f.code == "VULN_REF_ASSET" for f in check_assets(doc))


def test_dangling_actor_target_ref_caught(valid_payload: dict) -> None:
    payload = copy.deepcopy(valid_payload)
    payload["actor_targets"][0]["asset_id"] = "asset-ghost"
    doc = AssetsDocument.model_validate(payload)
    assert any(f.code == "ACTOR_TARGET_REF_ASSET" for f in check_assets(doc))


def test_top_level_extra_keys_tolerated(valid_payload: dict) -> None:
    payload = copy.deepcopy(valid_payload)
    payload["_comment"] = "documentation only"
    AssetsDocument.model_validate(payload)
