"""Tests for the BEACON 1.0.0 wrapped pir_output gate (TRACE 1.12.0).

Initiative H locks ``SUPPORTED_PIR_SCHEMA_VERSIONS`` to ``{"1.0.0"}`` and
tightens ``PIRDocument.from_payload`` to accept ONLY the wrapped
``{"schema_version": "1.0.0", "pirs": [...]}`` envelope. The pre-1.0
normaliser (recency rename, IR-factor cross-version contamination gate)
and the bare-list dispatch are removed; ``test_per_version_reject_message``
covers the H-12b per-version error message for rejected pre-1.0 values.

Covered here:
  - ``SUPPORTED_PIR_SCHEMA_VERSIONS`` is a single-element ``set[str]`` of
    ``"1.0.0"``.
  - ``PIROutputDocument`` requires ``schema_version`` and accepts only
    ``"1.0.0"``; missing / future-version payloads raise ValidationError.
  - The canonical 1.0.0 fixture (with ``prioritized_actors``,
    ``ir_observed_*`` factors, ``ir_boost_skipped``) round-trips through
    both ``PIROutputDocument`` and ``PIRDocument.from_payload``.
  - ``ScoreComponent`` strict mode still rejects unknown sub-factor keys
    both directly and via a wrapped fixture.
  - Bare-list / single-object payloads are rejected with the migration
    ValueError naming TRACE 1.12.0.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from trace_engine.validate.schema import (
    SUPPORTED_PIR_SCHEMA_VERSIONS,
    PIRDocument,
    PIROutputDocument,
    ScoreComponent,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Module-level shape: SUPPORTED_PIR_SCHEMA_VERSIONS == {"1.0.0"}.
# ---------------------------------------------------------------------------


class TestSupportedVersionsContainer:
    def test_supported_versions_is_set_of_str(self):
        assert isinstance(SUPPORTED_PIR_SCHEMA_VERSIONS, set)
        assert all(isinstance(v, str) for v in SUPPORTED_PIR_SCHEMA_VERSIONS)

    def test_supported_versions_contains_only_1_0_0(self):
        assert SUPPORTED_PIR_SCHEMA_VERSIONS == {"1.0.0"}

    @pytest.mark.parametrize("legacy", ["0.16.0", "0.17.0", "0.18.0"])
    def test_pre_1_0_versions_not_in_supported_set(self, legacy):
        assert legacy not in SUPPORTED_PIR_SCHEMA_VERSIONS


# ---------------------------------------------------------------------------
# Positive case — 1.0.0 canonical fixture validates end-to-end.
# ---------------------------------------------------------------------------


class TestValid100Payload:
    def test_canonical_fixture_validates_via_pir_output_document(self):
        payload = _load("valid_pir_100_canonical.json")
        doc = PIROutputDocument.model_validate(payload)
        assert doc.schema_version == "1.0.0"
        assert len(doc.pirs) == 1
        assert len(doc.pirs[0].prioritized_actors) == 1

    def test_canonical_fixture_validates_via_from_payload(self):
        payload = _load("valid_pir_100_canonical.json")
        doc = PIRDocument.from_payload(payload)
        assert len(doc.root) == 1
        assert doc.root[0].pir_id == "PIR-H-001"

    def test_ir_boost_factors_round_trip(self):
        """The IR-boost factors are now committed surface on 1.0.0."""
        payload = _load("valid_pir_100_canonical.json")
        doc = PIRDocument.from_payload(payload)
        actor = doc.root[0].prioritized_actors[0]
        cap = actor.score_breakdown.capability
        opp = actor.score_breakdown.opportunity
        assert cap.ir_observed_capability == pytest.approx(1.0)
        assert opp.ir_observed_opportunity == pytest.approx(0.7)
        assert actor.score_breakdown.data_quality.ir_boost_skipped is False

    def test_capability_sub_factors_round_trip(self):
        payload = _load("valid_pir_100_canonical.json")
        cap = (
            PIRDocument.from_payload(payload)
            .root[0]
            .prioritized_actors[0]
            .score_breakdown.capability
        )
        assert cap.recency_active_campaigns == pytest.approx(0.25)
        assert cap.tool_sophistication == pytest.approx(0.4)
        assert cap.evasion_capability == pytest.approx(0.6)
        assert cap.depth == pytest.approx(0.62)
        assert cap.breadth == pytest.approx(0.48)


# ---------------------------------------------------------------------------
# Negative cases — missing / unsupported version.
# ---------------------------------------------------------------------------


class TestSchemaVersionGate:
    def test_missing_schema_version_rejected(self):
        payload = _load("invalid_pir_missing_schema_version.json")
        with pytest.raises(ValidationError) as exc:
            PIROutputDocument.model_validate(payload)
        err = str(exc.value).lower()
        assert "schema_version" in err
        # Pydantic v2 missing-field error code/message.
        assert "field required" in err or "missing" in err

    def test_missing_schema_version_rejected_via_from_payload(self):
        payload = _load("invalid_pir_missing_schema_version.json")
        with pytest.raises(ValidationError):
            PIRDocument.from_payload(payload)

    def test_unknown_lower_version_rejected_with_generic_message(self):
        """0.15.0 is unknown to ``_REJECTED_VERSION_HISTORY`` (pre-Initiative E),
        so the gate falls through to the generic future-version message."""
        payload = _load("invalid_pir_unsupported_version.json")
        with pytest.raises(ValidationError) as exc:
            PIROutputDocument.model_validate(payload)
        msg = str(exc.value)
        assert '"0.15.0"' in msg
        assert "TRACE 1.12.0" in msg
        assert "supported: {1.0.0}" in msg

    def test_unsupported_higher_version_rejected(self):
        """Any value beyond 1.0.0 (e.g. ``"1.1.0"``) is rejected with the
        generic future-version message naming the TRACE version + supported set."""
        payload = _load("invalid_pir_unsupported_version_110.json")
        with pytest.raises(ValidationError) as exc:
            PIROutputDocument.model_validate(payload)
        msg = str(exc.value)
        assert '"1.1.0"' in msg
        assert "TRACE 1.12.0" in msg
        assert "supported: {1.0.0}" in msg

    def test_unsupported_version_rejected_via_from_payload(self):
        payload = _load("invalid_pir_unsupported_version.json")
        with pytest.raises(ValidationError):
            PIRDocument.from_payload(payload)


# ---------------------------------------------------------------------------
# ScoreComponent strict mode (still enforced under 1.0.0).
# ---------------------------------------------------------------------------


class TestScoreComponentStrict:
    def test_extra_field_in_fixture_rejected(self):
        payload = _load("invalid_pir_extra_score_component_field.json")
        with pytest.raises(ValidationError) as exc:
            PIROutputDocument.model_validate(payload)
        assert "made_up_field" in str(exc.value)

    def test_extra_field_rejected_via_from_payload(self):
        payload = _load("invalid_pir_extra_score_component_field.json")
        with pytest.raises(ValidationError) as exc:
            PIRDocument.from_payload(payload)
        assert "made_up_field" in str(exc.value)

    def test_direct_score_component_extra_field_rejected(self):
        with pytest.raises(ValidationError) as exc:
            ScoreComponent.model_validate({"score": 0.5, "made_up_field": 0.1})
        msg = str(exc.value).lower()
        assert "made_up_field" in msg
        assert "not permitted" in msg or "extra" in msg

    def test_legacy_recency_key_rejected_directly(self):
        """``recency_active_campaigns_90d`` was the pre-Initiative F name.
        After Initiative H removed the rename normaliser, the bare model
        treats it as an extra (forbidden) field."""
        with pytest.raises(ValidationError) as exc:
            ScoreComponent.model_validate({"score": 0.5, "recency_active_campaigns_90d": 0.25})
        assert "recency_active_campaigns_90d" in str(exc.value)


# ---------------------------------------------------------------------------
# Bare-list / single-object payload — rejected as of Initiative H Phase 3.
# ---------------------------------------------------------------------------


class TestBareListPayloadRejected:
    def test_bare_list_payload_raises_migration_value_error(self):
        wrapped = _load("valid_pir.json")
        bare_list = wrapped["pirs"]
        with pytest.raises(ValueError) as exc:
            PIRDocument.from_payload(bare_list)
        msg = str(exc.value)
        assert "Bare-list PIR input is no longer supported" in msg
        assert "TRACE 1.12.0" in msg
        assert '"schema_version": "1.0.0"' in msg

    def test_bare_single_object_payload_raises_migration_value_error(self):
        wrapped = _load("valid_pir.json")
        bare_object = wrapped["pirs"][0]
        with pytest.raises(ValueError) as exc:
            PIRDocument.from_payload(bare_object)
        assert "Bare-list PIR input is no longer supported" in str(exc.value)
