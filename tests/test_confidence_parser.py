"""Tests for _confidence_from_hedge_phrase (Initiative C §3.5)."""

from __future__ import annotations

from trace_engine.stix.extractor import _confidence_from_hedge_phrase


class TestConfidenceFromHedgePhrase:
    """8 cases: one per ICD 203 band + absent hedge → None + substring match."""

    def test_almost_certain_returns_95(self):
        assert _confidence_from_hedge_phrase("The attribution is almost certain.") == 95

    def test_very_likely_returns_85(self):
        assert _confidence_from_hedge_phrase("The actor is very likely APT29.") == 85

    def test_high_confidence_returns_85(self):
        assert _confidence_from_hedge_phrase("We assess with high confidence that ...") == 85

    def test_likely_returns_70(self):
        assert _confidence_from_hedge_phrase("It is likely that FIN7 is responsible.") == 70

    def test_roughly_even_returns_50(self):
        assert _confidence_from_hedge_phrase("We assess with roughly even chance.") == 50

    def test_unlikely_returns_30(self):
        assert _confidence_from_hedge_phrase("Attribution is unlikely given evidence.") == 30

    def test_very_unlikely_returns_15(self):
        assert _confidence_from_hedge_phrase("This is very unlikely based on TTPs.") == 15

    def test_no_evidence_returns_5(self):
        assert _confidence_from_hedge_phrase("There is no evidence of APT involvement.") == 5

    def test_absent_hedge_returns_none(self):
        assert _confidence_from_hedge_phrase("APT29 was responsible for the breach.") is None

    def test_empty_string_returns_none(self):
        assert _confidence_from_hedge_phrase("") is None

    def test_high_confidence_preferred_over_plain_confidence(self):
        # "high confidence" (→85) must not be consumed by a shorter match
        assert _confidence_from_hedge_phrase("high confidence assessment") == 85

    def test_case_insensitive_matching(self):
        assert _confidence_from_hedge_phrase("VERY LIKELY attributed to SVR") == 85
