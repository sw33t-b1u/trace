"""Tests for ``prioritized_actors[]`` validation under PIR schema_version 2.0.0.

Initiative H (TRACE 1.12.0) tightened ``prioritized_actors`` from
optional-with-default-list to a required field — the pre-0.15.0 PIR
backward-compat shim is gone. PIRs without actor triage now declare
``"prioritized_actors": []`` explicitly.

Verifies:
  - PIR with empty ``prioritized_actors`` passes.
  - Valid ``prioritized_actors[]`` entries pass.
  - Malformed entries are rejected (likelihood out of range, missing fields, wrong type).
  - Integration smoke test: full BEACON-shaped PIR with ActorTriageEntry passes.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from trace_engine.validate.schema import ActorTriageEntry, PIRDocument

FIXTURES = Path(__file__).parent / "fixtures"


def _wrap(pirs: list[dict]) -> dict:
    """Wrap a list of PIRItem dicts in the 2.0.0 envelope required by
    ``PIRDocument.from_payload`` after TRACE 2.0.0."""
    return {"schema_version": "2.0.0", "pirs": pirs}


# ---------------------------------------------------------------------------
# Minimal valid BEACON-shaped PIR (no prioritized_actors) — legacy baseline
# ---------------------------------------------------------------------------

_BASE_PIR = {
    "pir_id": "PIR-BASE-001",
    "intelligence_level": "operational",
    "threat_actor_tags": ["apt-china"],
    "asset_weight_rules": [{"tag": "external-facing", "criticality_multiplier": 2.0}],
    "valid_from": "2025-01-01",
    "valid_until": "2025-12-31",
    "prioritized_actors": [],
}

# ---------------------------------------------------------------------------
# Minimal valid ActorTriageEntry dict (placeholder IDs — no invented actor names)
# ---------------------------------------------------------------------------

_VALID_ACTOR_ENTRY = {
    "actor_id": "threat-actor--00000000-0000-4000-8000-000000000001",
    "name": "TestActorAlpha",
    "aliases": ["test-alias-1", "test-alias-2"],
    "likelihood": 0.07,
    "score_breakdown": {
        "intent": {
            "score": 0.25,
            "motivation_alignment": 0.5,
            "industry_match": 0.5,
        },
        "capability": {
            "score": 0.15,
            "sophistication_score": 0.667,
            "ttp_count_norm": 0.66,
            "recency_active_campaigns": 0.25,
        },
        "opportunity": {
            "score": 0.03,
            "victimology_match": 1.0,
            "geographic_match": 0.05,
            "surface_ttp_coverage": 0.62,
        },
        "data_quality": {
            "degraded": False,
            "missing_sources": [],
        },
    },
    "rationale": {
        "text": "Likelihood = Intent(0.250) × Capability(0.155) × Opportunity(0.029) = 0.0019",
        "intent_factors": {"motivation_alignment": 0.5, "industry_match": 0.5},
        "capability_factors": {
            "sophistication_score": 0.667,
            "ttp_count_norm": 0.66,
            "recency_active_campaigns": 0.25,
        },
        "opportunity_factors": {
            "victimology_match": 1.0,
            "geographic_match": 0.05,
            "surface_ttp_coverage": 0.62,
        },
    },
}

_PIR_WITH_ACTORS = {
    **_BASE_PIR,
    "pir_id": "PIR-TRIAGE-001",
    "prioritized_actors": [_VALID_ACTOR_ENTRY],
}


# ---------------------------------------------------------------------------
# prioritized_actors is required as of TRACE 1.12.0 (Initiative H).
# Empty list is the canonical "no triage data" value.
# ---------------------------------------------------------------------------


class TestPrioritizedActorsRequired:
    def test_pir_with_empty_prioritized_actors_passes(self):
        doc = PIRDocument.from_payload(_wrap([_BASE_PIR]))
        assert len(doc.root) == 1
        assert doc.root[0].pir_id == "PIR-BASE-001"
        assert doc.root[0].prioritized_actors == []

    def test_wrapped_fixture_with_empty_prioritized_actors_passes(self):
        data = json.loads((FIXTURES / "valid_pir.json").read_text())
        doc = PIRDocument.from_payload(data)
        assert doc.root[0].prioritized_actors == []

    def test_pir_missing_prioritized_actors_rejected(self):
        """The pre-0.15.0 ``default_factory=list`` shim was removed in
        Initiative H — payloads must declare ``prioritized_actors`` explicitly."""
        from copy import deepcopy

        pir = deepcopy(_BASE_PIR)
        del pir["prioritized_actors"]
        with pytest.raises(ValidationError) as exc:
            PIRDocument.from_payload(_wrap([pir]))
        msg = str(exc.value).lower()
        assert "prioritized_actors" in msg
        assert "field required" in msg or "missing" in msg


# ---------------------------------------------------------------------------
# Valid prioritized_actors[] passes
# ---------------------------------------------------------------------------


class TestValidActors:
    def test_single_valid_actor_entry_passes(self):
        doc = PIRDocument.from_payload(_wrap([_PIR_WITH_ACTORS]))
        actors = doc.root[0].prioritized_actors
        assert len(actors) == 1
        assert actors[0].actor_id == "threat-actor--00000000-0000-4000-8000-000000000001"
        assert actors[0].name == "TestActorAlpha"
        assert actors[0].likelihood == pytest.approx(0.07)

    def test_likelihood_boundary_zero_passes(self):
        entry = copy.deepcopy(_VALID_ACTOR_ENTRY)
        entry["likelihood"] = 0.0
        doc = PIRDocument.from_payload(_wrap([{**_PIR_WITH_ACTORS, "prioritized_actors": [entry]}]))
        assert doc.root[0].prioritized_actors[0].likelihood == 0.0

    def test_likelihood_boundary_one_passes(self):
        entry = copy.deepcopy(_VALID_ACTOR_ENTRY)
        entry["likelihood"] = 1.0
        doc = PIRDocument.from_payload(_wrap([{**_PIR_WITH_ACTORS, "prioritized_actors": [entry]}]))
        assert doc.root[0].prioritized_actors[0].likelihood == 1.0

    def test_multiple_actors_sorted_by_likelihood(self):
        entry2 = copy.deepcopy(_VALID_ACTOR_ENTRY)
        entry2["actor_id"] = "threat-actor--00000000-0000-4000-8000-000000000002"
        entry2["name"] = "TestActorBeta"
        entry2["likelihood"] = 0.001
        doc = PIRDocument.from_payload(
            _wrap([{**_PIR_WITH_ACTORS, "prioritized_actors": [_VALID_ACTOR_ENTRY, entry2]}])
        )
        assert len(doc.root[0].prioritized_actors) == 2

    def test_unknown_score_component_subfactor_rejected(self):
        """TRACE 1.9.0 strict mode — unknown ScoreComponent sub-factors fail.

        Replaces the prior ``extra='allow'`` forward-compat carve-out: adding
        a new sub-factor now requires bumping ``SUPPORTED_PIR_SCHEMA_VERSIONS``
        and extending ``ScoreComponent``.
        """
        entry = copy.deepcopy(_VALID_ACTOR_ENTRY)
        entry["score_breakdown"]["intent"]["future_sub_factor"] = 0.99
        with pytest.raises(ValidationError) as exc:
            PIRDocument.from_payload(_wrap([{**_PIR_WITH_ACTORS, "prioritized_actors": [entry]}]))
        assert "future_sub_factor" in str(exc.value)

    def test_empty_prioritized_actors_list_passes(self):
        doc = PIRDocument.from_payload(_wrap([{**_PIR_WITH_ACTORS, "prioritized_actors": []}]))
        assert doc.root[0].prioritized_actors == []


# ---------------------------------------------------------------------------
# Rejection — likelihood out of [0, 1]
# ---------------------------------------------------------------------------


class TestLikelihoodBounds:
    def _make_pir(self, likelihood: float) -> dict:
        entry = copy.deepcopy(_VALID_ACTOR_ENTRY)
        entry["likelihood"] = likelihood
        return _wrap([{**_PIR_WITH_ACTORS, "prioritized_actors": [entry]}])

    def test_likelihood_above_one_rejected(self):
        with pytest.raises(ValidationError) as exc:
            PIRDocument.from_payload(self._make_pir(1.001))
        err_str = str(exc.value).lower()
        assert "likelihood" in err_str or "less than or equal" in err_str

    def test_likelihood_negative_rejected(self):
        with pytest.raises(ValidationError):
            PIRDocument.from_payload(self._make_pir(-0.001))

    def test_likelihood_non_numeric_rejected(self):
        entry = copy.deepcopy(_VALID_ACTOR_ENTRY)
        entry["likelihood"] = "high"
        with pytest.raises(ValidationError):
            PIRDocument.from_payload(_wrap([{**_PIR_WITH_ACTORS, "prioritized_actors": [entry]}]))


# ---------------------------------------------------------------------------
# Rejection — missing required fields
# ---------------------------------------------------------------------------


class TestMissingRequiredFields:
    def _drop(self, field: str) -> dict:
        entry = copy.deepcopy(_VALID_ACTOR_ENTRY)
        del entry[field]
        return _wrap([{**_PIR_WITH_ACTORS, "prioritized_actors": [entry]}])

    def test_missing_actor_id_rejected(self):
        with pytest.raises(ValidationError):
            PIRDocument.from_payload(self._drop("actor_id"))

    def test_missing_name_rejected(self):
        with pytest.raises(ValidationError):
            PIRDocument.from_payload(self._drop("name"))

    def test_missing_likelihood_rejected(self):
        with pytest.raises(ValidationError):
            PIRDocument.from_payload(self._drop("likelihood"))

    def test_missing_score_breakdown_rejected(self):
        with pytest.raises(ValidationError):
            PIRDocument.from_payload(self._drop("score_breakdown"))

    def test_missing_rationale_rejected(self):
        with pytest.raises(ValidationError):
            PIRDocument.from_payload(self._drop("rationale"))

    def test_empty_actor_id_rejected(self):
        entry = copy.deepcopy(_VALID_ACTOR_ENTRY)
        entry["actor_id"] = ""
        with pytest.raises(ValidationError):
            PIRDocument.from_payload(_wrap([{**_PIR_WITH_ACTORS, "prioritized_actors": [entry]}]))


# ---------------------------------------------------------------------------
# Rejection — wrong types
# ---------------------------------------------------------------------------


class TestWrongTypes:
    def test_actor_id_non_string_rejected(self):
        entry = copy.deepcopy(_VALID_ACTOR_ENTRY)
        entry["actor_id"] = 12345
        with pytest.raises(ValidationError):
            PIRDocument.from_payload(_wrap([{**_PIR_WITH_ACTORS, "prioritized_actors": [entry]}]))

    def test_name_non_string_rejected(self):
        entry = copy.deepcopy(_VALID_ACTOR_ENTRY)
        entry["name"] = ["list-not-string"]
        with pytest.raises(ValidationError):
            PIRDocument.from_payload(_wrap([{**_PIR_WITH_ACTORS, "prioritized_actors": [entry]}]))

    def test_score_breakdown_non_object_rejected(self):
        entry = copy.deepcopy(_VALID_ACTOR_ENTRY)
        entry["score_breakdown"] = "not-an-object"
        with pytest.raises(ValidationError):
            PIRDocument.from_payload(_wrap([{**_PIR_WITH_ACTORS, "prioritized_actors": [entry]}]))

    def test_aliases_non_list_rejected(self):
        entry = copy.deepcopy(_VALID_ACTOR_ENTRY)
        entry["aliases"] = "not-a-list"
        with pytest.raises(ValidationError):
            PIRDocument.from_payload(_wrap([{**_PIR_WITH_ACTORS, "prioritized_actors": [entry]}]))


# ---------------------------------------------------------------------------
# Integration smoke test — full BEACON-shaped PIR
# ---------------------------------------------------------------------------


def test_beacon_shaped_pir_passes_trace_validator():
    """Full BEACON 0.15.0-shaped PIR round-trips through TRACE validator."""
    beacon_pir = {
        "pir_id": "PIR-2026-001",
        "intelligence_level": "strategic",
        "organizational_scope": "Information Security (department)",
        "decision_point": "How will state-sponsored threats impact core banking?",
        "description": "State-sponsored actor risk to finance sector assets.",
        "rationale": "High composite score due to geography and sector match.",
        "recommended_action": "Review segmentation and access controls.",
        "threat_actor_tags": ["apt-china", "apt-russia"],
        "notable_groups": [],
        "asset_weight_rules": [{"tag": "external-facing", "criticality_multiplier": 2.0}],
        "collection_focus": ["Monitor new TTPs for matched actor groups"],
        "valid_from": "2026-05-22",
        "valid_until": "2027-05-22",
        "risk_score": {"likelihood": 5, "impact": 5, "composite": 25},
        "source_elements": [],
        "prioritized_actors": [
            _VALID_ACTOR_ENTRY,
            {
                "actor_id": "threat-actor--00000000-0000-4000-8000-000000000002",
                "name": "TestActorBeta",
                "aliases": ["test-alias-3"],
                "likelihood": 0.000033,
                "score_breakdown": {
                    "intent": {
                        "score": 0.01,
                        "motivation_alignment": 0.5,
                        "industry_match": 0.02,
                    },
                    "capability": {
                        "score": 0.14,
                        "sophistication_score": 0.667,
                        "ttp_count_norm": 0.82,
                        "recency_active_campaigns": 0.25,
                    },
                    "opportunity": {
                        "score": 0.02,
                        "victimology_match": 1.0,
                        "geographic_match": 0.03,
                        "surface_ttp_coverage": 0.62,
                    },
                    "data_quality": {"degraded": True, "missing_sources": ["misp_galaxy"]},
                },
                "rationale": {
                    "text": "Likelihood = Intent(0.011) × Cap(0.137) × Opp(0.022)",
                    "intent_factors": {"motivation_alignment": 0.5, "industry_match": 0.02},
                    "capability_factors": {
                        "sophistication_score": 0.667,
                        "ttp_count_norm": 0.82,
                        "recency_active_campaigns": 0.25,
                    },
                    "opportunity_factors": {
                        "victimology_match": 1.0,
                        "geographic_match": 0.03,
                        "surface_ttp_coverage": 0.62,
                    },
                },
            },
        ],
    }

    doc = PIRDocument.from_payload(_wrap([beacon_pir]))
    pir = doc.root[0]

    assert pir.pir_id == "PIR-2026-001"
    assert len(pir.prioritized_actors) == 2
    assert pir.prioritized_actors[0].actor_id == (
        "threat-actor--00000000-0000-4000-8000-000000000001"
    )
    assert pir.prioritized_actors[0].likelihood == pytest.approx(0.07)
    assert pir.prioritized_actors[1].score_breakdown.data_quality.degraded is True
    # All likelihood values are in [0, 1]
    for actor in pir.prioritized_actors:
        assert 0.0 <= actor.likelihood <= 1.0


# ---------------------------------------------------------------------------
# Direct model tests
# ---------------------------------------------------------------------------


class TestActorTriageEntryDirectly:
    def test_model_validate_valid_entry(self):
        actor = ActorTriageEntry.model_validate(_VALID_ACTOR_ENTRY)
        assert actor.name == "TestActorAlpha"
        assert actor.likelihood == pytest.approx(0.07)

    def test_score_component_score_bounds_enforced(self):
        from trace_engine.validate.schema import ScoreComponent  # noqa: PLC0415

        with pytest.raises(ValidationError):
            ScoreComponent.model_validate({"score": 1.001})
        with pytest.raises(ValidationError):
            ScoreComponent.model_validate({"score": -0.001})

    def test_score_component_accepts_enumerated_sub_factors(self):
        """Canonical sub-factor names listed on ``ScoreComponent`` pass.

        ``recency_active_campaigns`` has been the canonical name since
        BEACON 0.17.0 / schema_version 0.17.0 (Initiative F field
        rename); Initiative H committed it as the 1.0.0 surface and
        removed the legacy ``_90d``-suffix normaliser.
        """
        from trace_engine.validate.schema import ScoreComponent  # noqa: PLC0415

        sc = ScoreComponent.model_validate(
            {"score": 0.5, "ttp_count_norm": 0.9, "recency_active_campaigns": 0.25}
        )
        assert sc.score == 0.5
        assert sc.ttp_count_norm == pytest.approx(0.9)
        assert sc.recency_active_campaigns == pytest.approx(0.25)

    def test_score_component_rejects_legacy_recency_field_directly(self):
        """The bare model has no alias for the renamed field — extra='forbid'."""
        from trace_engine.validate.schema import ScoreComponent  # noqa: PLC0415

        with pytest.raises(ValidationError) as exc:
            ScoreComponent.model_validate({"score": 0.5, "recency_active_campaigns_90d": 0.25})
        assert "recency_active_campaigns_90d" in str(exc.value)

    def test_score_component_rejects_unknown_sub_factor(self):
        """TRACE 1.9.0 strict mode — unknown sub-factor keys raise."""
        from trace_engine.validate.schema import ScoreComponent  # noqa: PLC0415

        with pytest.raises(ValidationError) as exc:
            ScoreComponent.model_validate({"score": 0.5, "made_up_field": 0.1})
        assert "made_up_field" in str(exc.value)
