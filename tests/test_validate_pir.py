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
def valid_pir() -> dict:
    """Load the canonical wrapped 1.0.0 PIR payload as a dict.

    Initiative H (TRACE 1.12.0) tightened ``PIRDocument.from_payload``
    to require the ``{"schema_version": "1.0.0", "pirs": [...]}``
    envelope; the bare-list and single-object forms no longer load.
    """
    with (FIXTURES / "valid_pir.json").open() as f:
        return json.load(f)


@pytest.fixture
def valid_assets_doc() -> AssetsDocument:
    with (FIXTURES / "valid_assets.json").open() as f:
        return AssetsDocument.model_validate(json.load(f))


def test_valid_pir_passes_schema(valid_pir: dict) -> None:
    doc = PIRDocument.from_payload(valid_pir)
    assert len(doc.root) == 1
    assert doc.root[0].pir_id == "PIR-TEST-001"


def test_bare_list_payload_rejected(valid_pir: dict) -> None:
    """Phase 3 carry-over: bare-list payloads raise a migration ValueError."""
    bare_list = valid_pir["pirs"]
    with pytest.raises(ValueError) as exc:
        PIRDocument.from_payload(bare_list)
    msg = str(exc.value)
    assert "Bare-list PIR input is no longer supported" in msg
    assert "TRACE 1.12.0" in msg


def test_single_object_payload_rejected(valid_pir: dict) -> None:
    """A single bare PIRItem dict is also rejected — no ``pirs`` key."""
    bare_object = valid_pir["pirs"][0]
    with pytest.raises(ValueError) as exc:
        PIRDocument.from_payload(bare_object)
    assert "Bare-list PIR input is no longer supported" in str(exc.value)


def test_inverted_validity_window_fails_schema(valid_pir: dict) -> None:
    payload = copy.deepcopy(valid_pir)
    payload["pirs"][0]["valid_from"] = "2026-01-01"
    payload["pirs"][0]["valid_until"] = "2025-01-01"
    with pytest.raises(ValidationError) as exc:
        PIRDocument.from_payload(payload)
    assert "valid_from" in str(exc.value)


def test_equal_validity_dates_fails_schema(valid_pir: dict) -> None:
    payload = copy.deepcopy(valid_pir)
    payload["pirs"][0]["valid_from"] = "2025-06-01"
    payload["pirs"][0]["valid_until"] = "2025-06-01"
    with pytest.raises(ValidationError):
        PIRDocument.from_payload(payload)


def test_known_taxonomy_tag_produces_no_warning(valid_pir: dict) -> None:
    doc = PIRDocument.from_payload(valid_pir)
    findings = check_pir(doc)
    assert all(f.code != "PIR_TAG_NOT_IN_TAXONOMY" for f in findings)


def test_unknown_taxonomy_tag_warns(valid_pir: dict) -> None:
    payload = copy.deepcopy(valid_pir)
    payload["pirs"][0]["threat_actor_tags"] = ["totally-made-up-tag"]
    doc = PIRDocument.from_payload(payload)
    findings = check_pir(doc)
    assert any(f.code == "PIR_TAG_NOT_IN_TAXONOMY" and f.severity == "warning" for f in findings)


def test_asset_tag_match_passes_when_tag_used(
    valid_pir: dict, valid_assets_doc: AssetsDocument
) -> None:
    doc = PIRDocument.from_payload(valid_pir)
    findings = check_pir(doc, assets=valid_assets_doc)
    assert all(f.code != "PIR_RULE_TAG_UNUSED" for f in findings)


def test_asset_tag_match_errors_on_unused_tag(
    valid_pir: dict, valid_assets_doc: AssetsDocument
) -> None:
    payload = copy.deepcopy(valid_pir)
    payload["pirs"][0]["asset_weight_rules"].append(
        {"tag": "tag-no-asset-has", "criticality_multiplier": 3.0}
    )
    doc = PIRDocument.from_payload(payload)
    findings = check_pir(doc, assets=valid_assets_doc)
    assert any(f.code == "PIR_RULE_TAG_UNUSED" and f.severity == "error" for f in findings)


def test_duplicate_pir_id_caught(valid_pir: dict) -> None:
    payload = copy.deepcopy(valid_pir)
    payload["pirs"].append(copy.deepcopy(payload["pirs"][0]))
    doc = PIRDocument.from_payload(payload)
    findings = check_pir(doc)
    assert any(f.code == "PIR_ID_NOT_UNIQUE" for f in findings)


def test_zero_or_negative_multiplier_fails_schema(valid_pir: dict) -> None:
    payload = copy.deepcopy(valid_pir)
    payload["pirs"][0]["asset_weight_rules"][0]["criticality_multiplier"] = 0
    with pytest.raises(ValidationError):
        PIRDocument.from_payload(payload)
