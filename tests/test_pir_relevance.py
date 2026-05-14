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


def test_truncated_rationale_salvages_decision(pir_doc: PIRDocument, cfg: Config) -> None:
    """Gemini cuts the rationale string mid-token; score and matched_pir_ids
    have already been emitted, so the verdict is recoverable."""
    truncated = '{\n  "score": 0.0,\n  "matched_pir_ids": [],\n  "rationale": "The'
    with patch("trace_engine.pir.relevance.call_llm", return_value=truncated):
        v = pir_relevance.evaluate("article", pir_doc, config=cfg)
    assert v.failed is False
    assert v.score == 0.0
    assert v.matched_pir_ids == []
    assert v.rationale == "(truncated)"
    assert v.keep(0.5) is False  # below threshold → skip


def test_truncated_with_matches_preserves_ids(pir_doc: PIRDocument, cfg: Config) -> None:
    truncated = (
        '{\n  "score": 0.7,\n  "matched_pir_ids": ["PIR-TEST-001", "PIR-X"],\n'
        '  "rationale": "Active campaign by FIN'
    )
    with patch("trace_engine.pir.relevance.call_llm", return_value=truncated):
        v = pir_relevance.evaluate("article", pir_doc, config=cfg)
    assert v.failed is False
    assert v.score == 0.7
    assert v.matched_pir_ids == ["PIR-TEST-001", "PIR-X"]
    assert v.keep(0.5) is True


def test_completely_unparseable_response_fails_open(pir_doc: PIRDocument, cfg: Config) -> None:
    """No score in the response at all → fail-open."""
    with patch("trace_engine.pir.relevance.call_llm", return_value='garbage with "no" score'):
        v = pir_relevance.evaluate("article", pir_doc, config=cfg)
    assert v.failed is True
    assert v.keep(0.5) is True


def test_markdown_fenced_response_parses(pir_doc: PIRDocument, cfg: Config) -> None:
    """Gemini sometimes wraps JSON in ```json ... ``` even with json_mode=True."""
    fenced = '```json\n{\n  "score": 0.7,\n  "matched_pir_ids": ["PIR-TEST-001"]\n}\n```'
    with patch("trace_engine.pir.relevance.call_llm", return_value=fenced):
        v = pir_relevance.evaluate("article body", pir_doc, config=cfg)
    assert v.failed is False
    assert v.score == pytest.approx(0.7)
    assert v.matched_pir_ids == ["PIR-TEST-001"]


def test_response_with_leading_prose_parses(pir_doc: PIRDocument, cfg: Config) -> None:
    """Tolerate ``Here is the JSON: {...}`` prefix."""
    raw = 'Here is the JSON:\n{"score": 0.9, "matched_pir_ids": []}'
    with patch("trace_engine.pir.relevance.call_llm", return_value=raw):
        v = pir_relevance.evaluate("article", pir_doc, config=cfg)
    assert v.failed is False
    assert v.score == pytest.approx(0.9)


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


def test_summarise_truncates_long_description() -> None:
    from trace_engine.pir.relevance import _PIR_DESCRIPTION_MAX_CHARS, _summarise_pir
    from trace_engine.validate.schema import PIRItem

    long = "x" * 1000
    item = PIRItem(
        pir_id="PIR-X",
        threat_actor_tags=[],
        asset_weight_rules=[],
        valid_from="2025-01-01",
        valid_until="2026-01-01",
        description=long,
    )
    s = _summarise_pir(item)
    assert s["description"] is not None
    # truncated, plus the ellipsis suffix
    assert len(s["description"]) <= _PIR_DESCRIPTION_MAX_CHARS + 1


def test_summarise_caps_notable_groups() -> None:
    from trace_engine.pir.relevance import _PIR_LIST_FIELD_MAX_ITEMS, _summarise_pir
    from trace_engine.validate.schema import PIRItem

    item = PIRItem.model_validate(
        {
            "pir_id": "PIR-X",
            "threat_actor_tags": [],
            "asset_weight_rules": [],
            "valid_from": "2025-01-01",
            "valid_until": "2026-01-01",
            "notable_groups": [f"APT{i}" for i in range(50)],
        }
    )
    s = _summarise_pir(item)
    assert len(s["notable_groups"]) == _PIR_LIST_FIELD_MAX_ITEMS


def test_max_output_tokens_uses_constant(pir_doc: PIRDocument, cfg: Config) -> None:
    """Regression: NPR run truncated at 512. We now request 1024."""
    captured: dict[str, int] = {}

    def fake_call(tier, prompt, **kw):
        captured["max_output_tokens"] = kw.get("max_output_tokens")
        return json.dumps({"score": 0.5, "matched_pir_ids": []})

    with patch("trace_engine.pir.relevance.call_llm", side_effect=fake_call):
        pir_relevance.evaluate("article", pir_doc, config=cfg)
    assert captured["max_output_tokens"] == 1024


# ---------------------------------------------------------------------------
# Initiative C Phase 2 (TRACE 1.6.0): high-value identity boost
# ---------------------------------------------------------------------------


class TestHighValueIdentityBoost:
    def test_boost_applied_when_flagged_name_present(
        self, pir_doc: PIRDocument, cfg: Config
    ) -> None:
        payload = json.dumps({"score": 0.5, "matched_pir_ids": [], "rationale": "neutral"})
        with patch("trace_engine.pir.relevance.call_llm", return_value=payload):
            v = pir_relevance.evaluate(
                "Sample Victim CFO was the target of a phishing attempt.",
                pir_doc,
                config=cfg,
                high_value_identity_names=["Sample Victim CFO"],
            )
        assert v.score == pytest.approx(0.7)

    def test_no_boost_when_flagged_name_absent(self, pir_doc: PIRDocument, cfg: Config) -> None:
        payload = json.dumps({"score": 0.5, "matched_pir_ids": []})
        with patch("trace_engine.pir.relevance.call_llm", return_value=payload):
            v = pir_relevance.evaluate(
                "Generic phishing report with no specific identity match.",
                pir_doc,
                config=cfg,
                high_value_identity_names=["Sample Victim CFO"],
            )
        assert v.score == pytest.approx(0.5)

    def test_boost_caps_at_one(self, pir_doc: PIRDocument, cfg: Config) -> None:
        payload = json.dumps({"score": 0.95, "matched_pir_ids": []})
        with patch("trace_engine.pir.relevance.call_llm", return_value=payload):
            v = pir_relevance.evaluate(
                "Article references Sample Victim CFO.",
                pir_doc,
                config=cfg,
                high_value_identity_names=["Sample Victim CFO"],
            )
        assert v.score == pytest.approx(1.0)

    def test_case_insensitive_match(self, pir_doc: PIRDocument, cfg: Config) -> None:
        payload = json.dumps({"score": 0.4, "matched_pir_ids": []})
        with patch("trace_engine.pir.relevance.call_llm", return_value=payload):
            v = pir_relevance.evaluate(
                "article mentions sample victim cfo in lowercase",
                pir_doc,
                config=cfg,
                high_value_identity_names=["Sample Victim CFO"],
            )
        assert v.score == pytest.approx(0.6)

    def test_no_boost_when_verdict_failed(self, pir_doc: PIRDocument, cfg: Config) -> None:
        """Failed verdicts (LLM call/parse error) preserve fail-open semantics
        and are not boosted."""
        with patch("trace_engine.pir.relevance.call_llm", return_value="not json at all"):
            v = pir_relevance.evaluate(
                "Article mentions Sample Victim CFO multiple times.",
                pir_doc,
                config=cfg,
                high_value_identity_names=["Sample Victim CFO"],
            )
        assert v.failed is True
        assert v.score == pytest.approx(0.0)

    def test_empty_names_list_is_noop(self, pir_doc: PIRDocument, cfg: Config) -> None:
        payload = json.dumps({"score": 0.5, "matched_pir_ids": []})
        with patch("trace_engine.pir.relevance.call_llm", return_value=payload):
            v = pir_relevance.evaluate(
                "Article mentions Sample Victim CFO.",
                pir_doc,
                config=cfg,
                high_value_identity_names=[],
            )
        assert v.score == pytest.approx(0.5)

    def test_none_names_list_is_noop(self, pir_doc: PIRDocument, cfg: Config) -> None:
        payload = json.dumps({"score": 0.5, "matched_pir_ids": []})
        with patch("trace_engine.pir.relevance.call_llm", return_value=payload):
            v = pir_relevance.evaluate(
                "Article mentions Sample Victim CFO.",
                pir_doc,
                config=cfg,
                high_value_identity_names=None,
            )
        assert v.score == pytest.approx(0.5)
