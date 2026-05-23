"""Tests for the BEACON 0.16.0 wrapped pir_output gate (TRACE 1.9.0 — Phase 4).

Covers:
  - ``SUPPORTED_PIR_SCHEMA_VERSIONS`` is a ``set[str]`` (forward-compat handle
    for Initiative F adding ``"0.17.0"`` without refactoring).
  - ``PIROutputDocument`` requires ``schema_version`` and rejects values
    outside ``SUPPORTED_PIR_SCHEMA_VERSIONS``.
  - Wrapped payloads with ``prioritized_actors`` missing, empty, or populated
    all pass when ``schema_version="0.16.0"``.
  - ``ScoreComponent`` strict mode rejects unknown sub-factor keys both when
    invoked directly and when fed through a wrapped PIR fixture.
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
# Module-level shape: SUPPORTED_PIR_SCHEMA_VERSIONS must remain a set[str]
# so plan §6 Phase 4 forward-compat with Initiative F holds.
# ---------------------------------------------------------------------------


class TestSupportedVersionsContainer:
    def test_supported_versions_is_set_of_str(self):
        assert isinstance(SUPPORTED_PIR_SCHEMA_VERSIONS, set)
        assert all(isinstance(v, str) for v in SUPPORTED_PIR_SCHEMA_VERSIONS)

    def test_supported_versions_contains_0_16_0(self):
        assert "0.16.0" in SUPPORTED_PIR_SCHEMA_VERSIONS


# ---------------------------------------------------------------------------
# Positive cases — wrapped payload with schema_version="0.16.0" passes.
# ---------------------------------------------------------------------------


class TestValidWrappedPayload:
    def test_fixture_with_actor_triage_passes(self):
        payload = _load("valid_pir_with_actor_triage.json")
        doc = PIROutputDocument.model_validate(payload)
        assert doc.schema_version == "0.16.0"
        assert len(doc.pirs) == 1
        assert len(doc.pirs[0].prioritized_actors) == 1
        actor = doc.pirs[0].prioritized_actors[0]
        # Newly-enumerated Capability sub-factors round-trip via ScoreComponent.
        cap = actor.score_breakdown.capability
        assert cap.tool_sophistication == pytest.approx(0.4)
        assert cap.depth == pytest.approx(0.55)
        assert cap.breadth == pytest.approx(0.48)

    def test_fixture_loads_through_pir_document_from_payload(self):
        payload = _load("valid_pir_with_actor_triage.json")
        doc = PIRDocument.from_payload(payload)
        assert len(doc.root) == 1
        assert doc.root[0].pir_id == "PIR-TRIAGE-001"

    def test_wrapped_payload_without_prioritized_actors_passes(self):
        # Additive field — pre-Actor-Triage PIRs (no prioritized_actors key)
        # remain valid under the strict gate.
        payload = {
            "schema_version": "0.16.0",
            "pirs": [
                {
                    "pir_id": "PIR-NO-ACTORS-001",
                    "threat_actor_tags": ["apt-china"],
                    "asset_weight_rules": [
                        {"tag": "external-facing", "criticality_multiplier": 2.0}
                    ],
                    "valid_from": "2026-05-22",
                    "valid_until": "2027-05-22",
                }
            ],
        }
        doc = PIROutputDocument.model_validate(payload)
        assert doc.pirs[0].prioritized_actors == []

    def test_wrapped_payload_with_empty_prioritized_actors_passes(self):
        payload = {
            "schema_version": "0.16.0",
            "pirs": [
                {
                    "pir_id": "PIR-EMPTY-ACTORS-001",
                    "threat_actor_tags": ["apt-china"],
                    "asset_weight_rules": [
                        {"tag": "external-facing", "criticality_multiplier": 2.0}
                    ],
                    "valid_from": "2026-05-22",
                    "valid_until": "2027-05-22",
                    "prioritized_actors": [],
                }
            ],
        }
        doc = PIROutputDocument.model_validate(payload)
        assert doc.pirs[0].prioritized_actors == []


# ---------------------------------------------------------------------------
# Negative cases — missing / unsupported version, unknown ScoreComponent field.
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

    def test_unsupported_lower_version_rejected(self):
        payload = _load("invalid_pir_unsupported_version.json")
        with pytest.raises(ValidationError) as exc:
            PIROutputDocument.model_validate(payload)
        msg = str(exc.value)
        assert "unsupported schema version" in msg
        assert "'0.15.0'" in msg

    def test_unsupported_higher_version_rejected(self):
        payload = {
            "schema_version": "0.17.0",
            "pirs": [
                {
                    "pir_id": "PIR-FUTURE-001",
                    "threat_actor_tags": ["apt-china"],
                    "asset_weight_rules": [
                        {"tag": "external-facing", "criticality_multiplier": 2.0}
                    ],
                    "valid_from": "2026-05-22",
                    "valid_until": "2027-05-22",
                }
            ],
        }
        with pytest.raises(ValidationError) as exc:
            PIROutputDocument.model_validate(payload)
        msg = str(exc.value)
        assert "unsupported schema version" in msg
        assert "'0.17.0'" in msg

    def test_unsupported_version_rejected_via_from_payload(self):
        payload = _load("invalid_pir_unsupported_version.json")
        with pytest.raises(ValidationError):
            PIRDocument.from_payload(payload)


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
        # Pydantic v2 phrases the strict-mode failure as "extra inputs are not
        # permitted" / "Extra inputs are not permitted".
        msg = str(exc.value).lower()
        assert "made_up_field" in msg
        assert "not permitted" in msg or "extra" in msg


# ---------------------------------------------------------------------------
# Backward compat — legacy (non-wrapped) payloads bypass the gate so existing
# fixtures and producers that pre-date BEACON 0.16.0 keep loading.
# ---------------------------------------------------------------------------


class TestLegacyPayloadCompat:
    def test_legacy_list_payload_loads(self):
        payload = _load("valid_pir.json")
        doc = PIRDocument.from_payload(payload)
        assert len(doc.root) == 1

    def test_legacy_single_object_payload_loads(self):
        payload = _load("valid_pir.json")[0]
        doc = PIRDocument.from_payload(payload)
        assert len(doc.root) == 1
