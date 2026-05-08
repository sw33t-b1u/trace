"""Tests for the PIR validator (schema + semantic)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from trace_engine.validate.schema import AssetsDocument, PIRDocument
from trace_engine.validate.semantic.pir import check_pir

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def valid_pir() -> list:
    with (FIXTURES / "valid_pir.json").open() as f:
        return json.load(f)


@pytest.fixture
def valid_assets_doc() -> AssetsDocument:
    with (FIXTURES / "valid_assets.json").open() as f:
        return AssetsDocument.model_validate(json.load(f))


def test_valid_pir_passes_schema(valid_pir: list) -> None:
    doc = PIRDocument.from_payload(valid_pir)
    assert len(doc.root) == 1
    assert doc.root[0].pir_id == "PIR-TEST-001"


def test_single_object_payload_normalized_to_list(valid_pir: list) -> None:
    doc = PIRDocument.from_payload(valid_pir[0])
    assert len(doc.root) == 1


def test_inverted_validity_window_fails_schema(valid_pir: list) -> None:
    payload = copy.deepcopy(valid_pir)
    payload[0]["valid_from"] = "2026-01-01"
    payload[0]["valid_until"] = "2025-01-01"
    with pytest.raises(ValidationError) as exc:
        PIRDocument.from_payload(payload)
    assert "valid_from" in str(exc.value)


def test_equal_validity_dates_fails_schema(valid_pir: list) -> None:
    payload = copy.deepcopy(valid_pir)
    payload[0]["valid_from"] = "2025-06-01"
    payload[0]["valid_until"] = "2025-06-01"
    with pytest.raises(ValidationError):
        PIRDocument.from_payload(payload)


def test_known_taxonomy_tag_produces_no_warning(valid_pir: list) -> None:
    doc = PIRDocument.from_payload(valid_pir)
    findings = check_pir(doc)
    assert all(f.code != "PIR_TAG_NOT_IN_TAXONOMY" for f in findings)


def test_unknown_taxonomy_tag_warns(valid_pir: list) -> None:
    payload = copy.deepcopy(valid_pir)
    payload[0]["threat_actor_tags"] = ["totally-made-up-tag"]
    doc = PIRDocument.from_payload(payload)
    findings = check_pir(doc)
    assert any(f.code == "PIR_TAG_NOT_IN_TAXONOMY" and f.severity == "warning" for f in findings)


def test_asset_tag_match_passes_when_tag_used(
    valid_pir: list, valid_assets_doc: AssetsDocument
) -> None:
    doc = PIRDocument.from_payload(valid_pir)
    findings = check_pir(doc, assets=valid_assets_doc)
    assert all(f.code != "PIR_RULE_TAG_UNUSED" for f in findings)


def test_asset_tag_match_errors_on_unused_tag(
    valid_pir: list, valid_assets_doc: AssetsDocument
) -> None:
    payload = copy.deepcopy(valid_pir)
    payload[0]["asset_weight_rules"].append(
        {"tag": "tag-no-asset-has", "criticality_multiplier": 3.0}
    )
    doc = PIRDocument.from_payload(payload)
    findings = check_pir(doc, assets=valid_assets_doc)
    assert any(f.code == "PIR_RULE_TAG_UNUSED" and f.severity == "error" for f in findings)


def test_duplicate_pir_id_caught(valid_pir: list) -> None:
    payload = copy.deepcopy(valid_pir)
    payload.append(copy.deepcopy(payload[0]))
    doc = PIRDocument.from_payload(payload)
    findings = check_pir(doc)
    assert any(f.code == "PIR_ID_NOT_UNIQUE" for f in findings)


def test_zero_or_negative_multiplier_fails_schema(valid_pir: list) -> None:
    payload = copy.deepcopy(valid_pir)
    payload[0]["asset_weight_rules"][0]["criticality_multiplier"] = 0
    with pytest.raises(ValidationError):
        PIRDocument.from_payload(payload)
