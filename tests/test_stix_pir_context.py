"""Tests for L3 PIR context injection and L4 bundle metadata (post-refactor)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from trace_engine.stix.extractor import (
    Extraction,
    build_stix_bundle_from_extraction,
    extract_entities,
)
from trace_engine.validate.schema import PIRDocument

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def pir_doc() -> PIRDocument:
    with (FIXTURES / "valid_pir.json").open() as f:
        return PIRDocument.from_payload(json.load(f))


def test_pir_context_appended_to_prompt(pir_doc: PIRDocument) -> None:
    captured: dict[str, str] = {}

    def fake_call(task, prompt, **_kw):
        captured["prompt"] = prompt
        return "{}"

    with patch("trace_engine.stix.extractor.call_llm", side_effect=fake_call):
        extract_entities("CTI report body", pir_doc=pir_doc)

    p = captured["prompt"]
    assert "## PIR Context" in p
    assert "PIR-TEST-001" in p
    assert "apt-china" in p
    assert "external-facing" in p


def test_pir_context_block_omitted_when_no_pir() -> None:
    captured: dict[str, str] = {}

    def fake_call(task, prompt, **_kw):
        captured["prompt"] = prompt
        return "{}"

    with patch("trace_engine.stix.extractor.call_llm", side_effect=fake_call):
        extract_entities("CTI report body", pir_doc=None)

    assert "## PIR Context" not in captured["prompt"]
    assert "{{PIR_CONTEXT_BLOCK}}" not in captured["prompt"]


def test_bundle_metadata_includes_x_trace_fields() -> None:
    bundle = build_stix_bundle_from_extraction(
        Extraction(),
        source_url="https://example.com/post",
        matched_pir_ids=["PIR-TEST-001"],
        relevance_score=0.82,
        relevance_rationale="actor named in report",
    )
    assert bundle["x_trace_source_url"] == "https://example.com/post"
    assert bundle["x_trace_collected_at"]
    assert bundle["x_trace_matched_pir_ids"] == ["PIR-TEST-001"]
    assert bundle["x_trace_relevance_score"] == 0.82
    assert bundle["x_trace_relevance_rationale"] == "actor named in report"
    # 0.4.0: bundle envelope no longer carries spec_version. The
    # extension-definition object inside `objects` declares STIX 2.1 conformance.
    assert "spec_version" not in bundle
    ext_obj = next(o for o in bundle["objects"] if o["type"] == "extension-definition")
    assert ext_obj["spec_version"] == "2.1"


def test_bundle_without_metadata_is_legacy_shape() -> None:
    bundle = build_stix_bundle_from_extraction(Extraction())
    assert "x_trace_source_url" not in bundle
    assert "x_trace_matched_pir_ids" not in bundle
    # No metadata → no extension-definition object emitted.
    assert all(o["type"] != "extension-definition" for o in bundle["objects"])
