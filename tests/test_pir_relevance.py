"""Tests for the L2 PIR relevance gate."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from trace_engine.config import Config
from trace_engine.pir import relevance as pir_relevance
from trace_engine.validate.schema import PIRDocument

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def pir_doc() -> PIRDocument:
    with (FIXTURES / "valid_pir.json").open() as f:
        return PIRDocument.from_payload(json.load(f))


@pytest.fixture
def cfg() -> Config:
    return Config(
        gcp_project_id="test-project",
        relevance_model_tier="simple",
        relevance_threshold=0.5,
    )


def test_score_above_threshold_keeps(pir_doc: PIRDocument, cfg: Config) -> None:
    payload = json.dumps(
        {"score": 0.82, "matched_pir_ids": ["PIR-TEST-001"], "rationale": "matches"}
    )
    with patch("trace_engine.pir.relevance.call_llm", return_value=payload):
        v = pir_relevance.evaluate("article body", pir_doc, config=cfg)
    assert v.score == pytest.approx(0.82)
    assert v.matched_pir_ids == ["PIR-TEST-001"]
    assert v.keep(0.5) is True
    assert v.failed is False


def test_score_below_threshold_skips(pir_doc: PIRDocument, cfg: Config) -> None:
    payload = json.dumps({"score": 0.1, "matched_pir_ids": [], "rationale": "no match"})
    with patch("trace_engine.pir.relevance.call_llm", return_value=payload):
        v = pir_relevance.evaluate("unrelated", pir_doc, config=cfg)
    assert v.score == pytest.approx(0.1)
    assert v.keep(0.5) is False


def test_extraction_failed_fails_open(pir_doc: PIRDocument, cfg: Config) -> None:
    with patch("trace_engine.pir.relevance.call_llm", return_value="not json at all"):
        v = pir_relevance.evaluate("article", pir_doc, config=cfg)
    assert v.failed is True
    assert v.keep(0.5) is True  # fail-open


def test_score_clamped_to_unit_range(pir_doc: PIRDocument, cfg: Config) -> None:
    payload = json.dumps({"score": 9.9, "matched_pir_ids": []})
    with patch("trace_engine.pir.relevance.call_llm", return_value=payload):
        v = pir_relevance.evaluate("article", pir_doc, config=cfg)
    assert v.score == 1.0


def test_restrict_to_filters_pir_context(pir_doc: PIRDocument, cfg: Config) -> None:
    captured: dict[str, str] = {}

    def fake_call(tier, prompt, **_kw):
        captured["prompt"] = prompt
        return json.dumps({"score": 0.7, "matched_pir_ids": ["PIR-TEST-001"]})

    with patch("trace_engine.pir.relevance.call_llm", side_effect=fake_call):
        pir_relevance.evaluate("article", pir_doc, config=cfg, restrict_to=["PIR-NOT-IN-DOC"])
    # No PIR ids in scope → empty PIR context array in prompt.
    assert "PIR-TEST-001" not in captured["prompt"]
