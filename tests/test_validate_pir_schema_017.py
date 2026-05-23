"""Tests for Initiative F Phase 6 — schema_version 0.17.0 acceptance.

Covers:

- ``SUPPORTED_PIR_SCHEMA_VERSIONS`` carries both ``"0.16.0"`` (E) and
  ``"0.17.0"`` (F); ``"0.18.0"`` is rejected by the gate.
- 0.17.0 payloads use the renamed ``recency_active_campaigns`` Capability
  sub-factor and pass straight through ``ScoreComponent``.
- 0.16.0 payloads continue to use the legacy ``recency_active_campaigns_90d``
  key; the per-version normaliser on ``PIROutputDocument`` rewrites the
  key to the canonical name before per-item validation.
- Cross-version contamination is rejected on both sides:
    0.17.0 + legacy key  → ValidationError
    0.16.0 + current key → ValidationError
  This is the "clean transition" enforcement per plan §3.
- The same rule applies to ``rationale.capability_factors`` (a free-form
  dict whose keys would otherwise pass unchecked).
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
    def test_set_contains_016_and_017(self):
        assert "0.16.0" in SUPPORTED_PIR_SCHEMA_VERSIONS
        assert "0.17.0" in SUPPORTED_PIR_SCHEMA_VERSIONS

    def test_set_excludes_unsupported_future(self):
        assert "0.18.0" not in SUPPORTED_PIR_SCHEMA_VERSIONS

    def test_016_fixture_still_validates_with_legacy_key(self):
        payload = _load("valid_pir_with_actor_triage.json")
        doc = PIRDocument.from_payload(payload)
        actor = doc.root[0].prioritized_actors[0]
        # Per-version normaliser rewrote the legacy key to the
        # canonical attribute name.
        assert actor.score_breakdown.capability.recency_active_campaigns == pytest.approx(0.25)

    def test_017_fixture_validates_with_renamed_key(self):
        payload = _load("valid_pir_017_renamed_recency.json")
        doc = PIRDocument.from_payload(payload)
        actor = doc.root[0].prioritized_actors[0]
        assert actor.score_breakdown.capability.recency_active_campaigns == pytest.approx(0.25)
        assert actor.score_breakdown.capability.tool_sophistication == pytest.approx(0.4)

    def test_unsupported_018_rejected(self):
        payload = _load("invalid_pir_unsupported_version_018.json")
        with pytest.raises(ValidationError) as exc:
            PIRDocument.from_payload(payload)
        assert "0.18.0" in str(exc.value)


class TestCrossVersionFieldNameEnforcement:
    """The schema_version gate enforces clean transition — no aliasing."""

    def test_017_payload_with_legacy_key_rejected(self):
        payload = _load("valid_pir_017_renamed_recency.json")
        cap = payload["pirs"][0]["prioritized_actors"][0]["score_breakdown"]["capability"]
        cap["recency_active_campaigns_90d"] = cap.pop("recency_active_campaigns")
        with pytest.raises(ValidationError) as exc:
            PIRDocument.from_payload(payload)
        msg = str(exc.value)
        assert "recency_active_campaigns_90d" in msg
        assert "0.17.0" in msg

    def test_016_payload_with_current_key_rejected(self):
        payload = _load("valid_pir_with_actor_triage.json")
        cap = payload["pirs"][0]["prioritized_actors"][0]["score_breakdown"]["capability"]
        # Swap legacy → current; schema_version stays 0.16.0.
        cap["recency_active_campaigns"] = cap.pop("recency_active_campaigns_90d")
        with pytest.raises(ValidationError) as exc:
            PIRDocument.from_payload(payload)
        msg = str(exc.value)
        assert "recency_active_campaigns" in msg
        assert "0.16.0" in msg

    def test_017_capability_factors_with_legacy_key_rejected(self):
        payload = _load("valid_pir_017_renamed_recency.json")
        factors = payload["pirs"][0]["prioritized_actors"][0]["rationale"]["capability_factors"]
        factors["recency_active_campaigns_90d"] = factors.pop("recency_active_campaigns")
        with pytest.raises(ValidationError) as exc:
            PIRDocument.from_payload(payload)
        assert "capability_factors" in str(exc.value)

    def test_016_capability_factors_with_current_key_rejected(self):
        payload = _load("valid_pir_with_actor_triage.json")
        factors = payload["pirs"][0]["prioritized_actors"][0]["rationale"]["capability_factors"]
        factors["recency_active_campaigns"] = factors.pop("recency_active_campaigns_90d")
        with pytest.raises(ValidationError) as exc:
            PIRDocument.from_payload(payload)
        assert "capability_factors" in str(exc.value)


class TestNormaliserNonInvasive:
    """The 0.16.0 → canonical rewrite must not touch unrelated payload."""

    def test_legacy_key_rewrite_preserves_other_capability_factors(self):
        payload = _load("valid_pir_with_actor_triage.json")
        # Add unrelated sub-factors to confirm they survive normalisation.
        cap = payload["pirs"][0]["prioritized_actors"][0]["score_breakdown"]["capability"]
        cap["tool_sophistication"] = 0.4
        doc = PIRDocument.from_payload(payload)
        c = doc.root[0].prioritized_actors[0].score_breakdown.capability
        assert c.tool_sophistication == pytest.approx(0.4)
        assert c.recency_active_campaigns == pytest.approx(0.25)

    def test_normaliser_skips_unsupported_version(self):
        """When schema_version is outside the supported set, the
        normaliser bows out and the schema_version gate fires the
        rejection — so the user sees the version error, not a stray
        field-name error."""
        payload = copy.deepcopy(_load("valid_pir_017_renamed_recency.json"))
        payload["schema_version"] = "0.18.0"
        with pytest.raises(ValidationError) as exc:
            PIROutputDocument.model_validate(payload)
        assert "0.18.0" in str(exc.value)


class TestRoundTripDrift:
    """Ensure pir_output.json BEACON 0.17.0 emit ↔ TRACE validate works.

    Constructs a minimal BEACON-shaped 0.17.0 payload from scratch (no
    cross-repo dependency) and asserts validation succeeds.
    """

    def test_minimal_beacon_017_payload_validates(self):
        payload = {
            "schema_version": "0.17.0",
            "pirs": [
                {
                    "pir_id": "PIR-RT-F-001",
                    "intelligence_level": "operational",
                    "threat_actor_tags": ["apt-finance"],
                    "asset_weight_rules": [
                        {"tag": "external-facing", "criticality_multiplier": 2.0}
                    ],
                    "valid_from": "2026-05-23",
                    "valid_until": "2027-05-23",
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
                                },
                                "opportunity": {
                                    "score": 0.21,
                                    "victimology_match": 0.7,
                                    "geographic_match": 0.5,
                                    "surface_ttp_coverage": 0.6,
                                },
                            },
                            "rationale": {
                                "text": "minimal",
                                "intent_factors": {},
                                "capability_factors": {
                                    "recency_active_campaigns": 0.4,
                                },
                                "opportunity_factors": {},
                            },
                        }
                    ],
                }
            ],
        }
        doc = PIRDocument.from_payload(payload)
        assert len(doc.root) == 1
        assert doc.root[0].prioritized_actors[
            0
        ].score_breakdown.capability.recency_active_campaigns == pytest.approx(0.4)
