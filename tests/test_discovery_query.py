"""Tests for PIR-to-term discovery query generation."""

from __future__ import annotations

from trace_engine.discovery.query import build_search_terms
from trace_engine.validate.schema import PIRDocument


def _pir_payload() -> dict:
    component = {"score": 0.5}
    return {
        "schema_version": "2.0.0",
        "pirs": [
            {
                "pir_id": "PIR-2026-001",
                "description": (
                    "Monitor telecom edge appliance targeting by Salt Typhoon operators."
                ),
                "threat_actor_tags": ["apt-china", "APT-China"],
                "asset_weight_rules": [{"tag": "external-facing", "criticality_multiplier": 2.0}],
                "valid_from": "2026-01-01",
                "valid_until": "2027-01-01",
                "collection_focus": ["telecom edge devices"],
                "notable_groups": ["Salt Typhoon"],
                "prioritized_actors": [
                    {
                        "actor_id": "intrusion-set--11111111-1111-4111-8111-111111111111",
                        "name": "Salt Typhoon",
                        "aliases": ["GhostEmperor", "salt typhoon"],
                        "likelihood": 0.8,
                        "score_breakdown": {
                            "intent": component,
                            "capability": component,
                            "opportunity": component,
                        },
                        "rationale": {"text": "Fixture actor"},
                    }
                ],
            }
        ],
    }


def test_build_search_terms_prioritises_actor_aliases_and_tags() -> None:
    pir_doc = PIRDocument.from_payload(_pir_payload())

    terms = build_search_terms(pir_doc)
    by_value = {term.term: term for term in terms}

    assert by_value["salt typhoon"].category == "actor"
    assert by_value["ghostemperor"].category == "actor_alias"
    assert by_value["apt-china"].category == "threat_actor_tag"
    assert by_value["external-facing"].category == "asset_tag"
    assert by_value["telecom edge devices"].category == "collection_focus"


def test_build_search_terms_deduplicates_normalised_values() -> None:
    pir_doc = PIRDocument.from_payload(_pir_payload())

    values = [term.term for term in build_search_terms(pir_doc)]

    assert values.count("salt typhoon") == 1
    assert values.count("apt-china") == 1
