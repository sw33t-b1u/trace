"""Tests for Initiative G Phase 7 — schema_version 0.18.0 acceptance.

Covers:

- ``SUPPORTED_PIR_SCHEMA_VERSIONS`` now contains ``"0.18.0"`` alongside
  the existing ``"0.16.0"`` (E) and ``"0.17.0"`` (F). 0.19.0 remains
  rejected as the forward-bound for unannounced producer bumps.
- 0.18.0 payloads carry the new IR-boost factors:
    * ``score_breakdown.capability.ir_observed_capability``
    * ``score_breakdown.opportunity.ir_observed_opportunity``
    * ``score_breakdown.data_quality.ir_boost_skipped``
  Plus the rationale mirrors:
    * ``rationale.capability_factors.ir_observed_capability``
    * ``rationale.opportunity_factors.ir_observed_opportunity``
- Cross-version contamination is rejected: each IR field placed under
  schema_version 0.16.0 / 0.17.0 raises ValidationError with a clear
  message naming both the field and the offending version (same
  "clean transition" pattern as Phase 6's recency rename).
- 0.16.0 + 0.17.0 fixtures continue to validate unchanged so the
  existing producers are not broken by the new gate.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from trace_engine.validate.schema import PIRDocument
from trace_engine.validate.schema.models import (
    SUPPORTED_PIR_SCHEMA_VERSIONS,
    PIROutputDocument,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


class TestSupportedVersionSet:
    def test_set_contains_018(self):
        assert "0.18.0" in SUPPORTED_PIR_SCHEMA_VERSIONS

    def test_set_contains_all_three_supported_versions(self):
        assert {"0.16.0", "0.17.0", "0.18.0"}.issubset(SUPPORTED_PIR_SCHEMA_VERSIONS)

    def test_019_remains_rejected(self):
        assert "0.19.0" not in SUPPORTED_PIR_SCHEMA_VERSIONS


class TestValid018Payload:
    def test_fixture_validates(self):
        payload = _load("valid_pir_018_ir_factors.json")
        doc = PIRDocument.from_payload(payload)
        actor = doc.root[0].prioritized_actors[0]
        cap = actor.score_breakdown.capability
        opp = actor.score_breakdown.opportunity
        assert cap.ir_observed_capability == pytest.approx(1.0)
        assert opp.ir_observed_opportunity == pytest.approx(0.7)
        assert actor.score_breakdown.data_quality.ir_boost_skipped is False

    def test_existing_capability_fields_still_accepted(self):
        """The IR field additions are additive — 0.16.0/0.17.0 factors still pass."""
        payload = _load("valid_pir_018_ir_factors.json")
        doc = PIRDocument.from_payload(payload)
        cap = doc.root[0].prioritized_actors[0].score_breakdown.capability
        assert cap.tool_sophistication == pytest.approx(0.4)
        assert cap.evasion_capability == pytest.approx(0.6)
        assert cap.recency_active_campaigns == pytest.approx(0.25)

    def test_ir_factor_out_of_range_rejected(self):
        """ScoreComponent enforces [0,1] on the IR factors."""
        payload = _load("valid_pir_018_ir_factors.json")
        payload["pirs"][0]["prioritized_actors"][0]["score_breakdown"]["capability"][
            "ir_observed_capability"
        ] = 1.5
        with pytest.raises(ValidationError):
            PIRDocument.from_payload(payload)

    def test_ir_boost_skipped_true_accepted(self):
        payload = _load("valid_pir_018_ir_factors.json")
        payload["pirs"][0]["prioritized_actors"][0]["score_breakdown"]["data_quality"][
            "ir_boost_skipped"
        ] = True
        doc = PIRDocument.from_payload(payload)
        dq = doc.root[0].prioritized_actors[0].score_breakdown.data_quality
        assert dq.ir_boost_skipped is True


class TestCrossVersionContamination:
    """0.18.0 fields must NOT appear under 0.16.0 / 0.17.0 schema_version."""

    def _payload_with_version(self, version: str) -> dict:
        """0.18.0 fixture rewritten to a different schema_version + recency key.

        Returns a payload that — apart from ``schema_version`` and the
        recency-key shape required by Phase 6's normaliser — is
        identical to ``valid_pir_018_ir_factors.json``. Used to drive
        cross-version contamination scenarios.
        """
        p = copy.deepcopy(_load("valid_pir_018_ir_factors.json"))
        p["schema_version"] = version
        if version == "0.16.0":
            # Phase 6 normaliser: 0.16.0 must use the legacy recency key.
            cap = p["pirs"][0]["prioritized_actors"][0]["score_breakdown"]["capability"]
            cap["recency_active_campaigns_90d"] = cap.pop("recency_active_campaigns")
            factors = p["pirs"][0]["prioritized_actors"][0]["rationale"]["capability_factors"]
            factors["recency_active_campaigns_90d"] = factors.pop("recency_active_campaigns")
        return p

    @pytest.mark.parametrize("version", ["0.16.0", "0.17.0"])
    def test_ir_observed_capability_in_score_breakdown_rejected(self, version):
        payload = self._payload_with_version(version)
        with pytest.raises(ValidationError) as exc:
            PIRDocument.from_payload(payload)
        msg = str(exc.value)
        assert "ir_observed_capability" in msg
        assert version in msg

    @pytest.mark.parametrize("version", ["0.16.0", "0.17.0"])
    def test_ir_observed_opportunity_in_score_breakdown_rejected(self, version):
        payload = self._payload_with_version(version)
        # Remove the capability IR factor to isolate the opportunity error.
        del payload["pirs"][0]["prioritized_actors"][0]["score_breakdown"]["capability"][
            "ir_observed_capability"
        ]
        del payload["pirs"][0]["prioritized_actors"][0]["rationale"]["capability_factors"][
            "ir_observed_capability"
        ]
        with pytest.raises(ValidationError) as exc:
            PIRDocument.from_payload(payload)
        msg = str(exc.value)
        assert "ir_observed_opportunity" in msg
        assert version in msg

    @pytest.mark.parametrize("version", ["0.16.0", "0.17.0"])
    def test_ir_boost_skipped_in_data_quality_rejected(self, version):
        payload = self._payload_with_version(version)
        # Strip the other IR fields so the data_quality check is the
        # first one to fire.
        sb = payload["pirs"][0]["prioritized_actors"][0]["score_breakdown"]
        sb["capability"].pop("ir_observed_capability", None)
        sb["opportunity"].pop("ir_observed_opportunity", None)
        rationale = payload["pirs"][0]["prioritized_actors"][0]["rationale"]
        rationale["capability_factors"].pop("ir_observed_capability", None)
        rationale["opportunity_factors"].pop("ir_observed_opportunity", None)
        with pytest.raises(ValidationError) as exc:
            PIRDocument.from_payload(payload)
        msg = str(exc.value)
        assert "ir_boost_skipped" in msg
        assert version in msg

    @pytest.mark.parametrize("version", ["0.16.0", "0.17.0"])
    def test_ir_field_in_rationale_factors_rejected(self, version):
        """Cross-version contamination via the free-form rationale dicts."""
        # Start from a minimal valid payload for the version, then sneak
        # the IR field in via capability_factors only.
        if version == "0.17.0":
            payload = copy.deepcopy(_load("valid_pir_017_renamed_recency.json"))
        else:
            payload = copy.deepcopy(_load("valid_pir_with_actor_triage.json"))
        payload["pirs"][0]["prioritized_actors"][0]["rationale"]["capability_factors"][
            "ir_observed_capability"
        ] = 1.0
        with pytest.raises(ValidationError) as exc:
            PIRDocument.from_payload(payload)
        msg = str(exc.value)
        assert "ir_observed_capability" in msg
        assert "rationale.capability_factors" in msg


class TestExistingVersionsUnaffected:
    """0.16.0 + 0.17.0 fixtures must keep validating after Phase 7."""

    def test_016_fixture_still_passes(self):
        payload = _load("valid_pir_with_actor_triage.json")
        doc = PIRDocument.from_payload(payload)
        assert len(doc.root[0].prioritized_actors) == 1

    def test_017_fixture_still_passes(self):
        payload = _load("valid_pir_017_renamed_recency.json")
        doc = PIRDocument.from_payload(payload)
        assert len(doc.root[0].prioritized_actors) == 1


class TestMinimalBeaconRoundTrip:
    """Smoke-test that a minimal BEACON-shaped 0.18.0 payload validates.

    Mirrors the Phase 6 round-trip test so producer drift is caught
    without a cross-repo dependency.
    """

    def test_minimal_beacon_018_payload_validates(self):
        payload = {
            "schema_version": "0.18.0",
            "pirs": [
                {
                    "pir_id": "PIR-RT-G-001",
                    "intelligence_level": "operational",
                    "threat_actor_tags": ["apt-finance"],
                    "asset_weight_rules": [
                        {"tag": "external-facing", "criticality_multiplier": 2.0}
                    ],
                    "valid_from": "2026-05-24",
                    "valid_until": "2027-05-24",
                    "prioritized_actors": [
                        {
                            "actor_id": "threat-actor--00000000-0000-4000-8000-00000000000a",
                            "name": "TestActorGamma",
                            "aliases": [],
                            "likelihood": 0.05,
                            "score_breakdown": {
                                "intent": {
                                    "score": 0.4,
                                    "motivation_alignment": 0.5,
                                    "industry_match": 0.3,
                                },
                                "capability": {
                                    "score": 0.6,
                                    "ttp_count_norm": 0.7,
                                    "sophistication_score": 0.5,
                                    "recency_active_campaigns": 0.4,
                                    "ir_observed_capability": 1.0,
                                },
                                "opportunity": {
                                    "score": 0.21,
                                    "victimology_match": 0.7,
                                    "geographic_match": 0.5,
                                    "surface_ttp_coverage": 0.6,
                                    "ir_observed_opportunity": 1.0,
                                },
                                "data_quality": {
                                    "degraded": False,
                                    "missing_sources": [],
                                    "ir_boost_skipped": False,
                                },
                            },
                            "rationale": {
                                "text": "minimal",
                                "intent_factors": {},
                                "capability_factors": {
                                    "recency_active_campaigns": 0.4,
                                    "ir_observed_capability": 1.0,
                                },
                                "opportunity_factors": {
                                    "ir_observed_opportunity": 1.0,
                                },
                            },
                        }
                    ],
                }
            ],
        }
        doc = PIRDocument.from_payload(payload)
        assert len(doc.root) == 1
        cap = doc.root[0].prioritized_actors[0].score_breakdown.capability
        opp = doc.root[0].prioritized_actors[0].score_breakdown.opportunity
        assert cap.ir_observed_capability == pytest.approx(1.0)
        assert opp.ir_observed_opportunity == pytest.approx(1.0)


class TestNormaliserSkipsUnsupportedVersion:
    """When schema_version is outside the supported set, the normaliser
    bows out — the user sees the version-gate error, not a stray
    field-name error."""

    def test_019_payload_with_ir_fields_reports_version_error(self):
        payload = copy.deepcopy(_load("valid_pir_018_ir_factors.json"))
        payload["schema_version"] = "0.19.0"
        with pytest.raises(ValidationError) as exc:
            PIROutputDocument.model_validate(payload)
        msg = str(exc.value)
        assert "0.19.0" in msg
        assert "unsupported schema version" in msg
