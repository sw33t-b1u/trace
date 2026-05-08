"""Tests for stix/extractor.py."""

from __future__ import annotations

import json
import re
from unittest.mock import patch

from trace_engine.stix.extractor import (
    _VALID_ENTITY_TYPES,
    _VALID_RELATIONSHIP_TYPES,
    ExtractedEntity,
    ExtractedRelationship,
    Extraction,
    build_stix_bundle_from_extraction,
    extract_entities,
)

_UUIDV4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def _as_json(value) -> str:
    return json.dumps(value)


def _patch_llm(value):
    return patch("trace_engine.stix.extractor.call_llm", return_value=_as_json(value))


# ---------------------------------------------------------------------------
# extract_entities
# ---------------------------------------------------------------------------


class TestExtractEntities:
    def test_returns_extraction_with_entities(self):
        payload = {
            "entities": [
                {
                    "local_id": "actor_1",
                    "type": "intrusion-set",
                    "name": "FIN7",
                    "labels": ["financially-motivated"],
                }
            ],
            "relationships": [],
        }
        with _patch_llm(payload):
            extraction = extract_entities("article body")
        assert len(extraction.entities) == 1
        assert extraction.entities[0].local_id == "actor_1"
        assert extraction.entities[0].type == "intrusion-set"
        assert extraction.entities[0].properties["name"] == "FIN7"

    def test_drops_entities_with_unknown_type(self):
        payload = {
            "entities": [
                {"local_id": "ok", "type": "malware", "name": "X"},
                {"local_id": "bad", "type": "x-custom", "name": "Y"},
            ],
            "relationships": [],
        }
        with _patch_llm(payload):
            extraction = extract_entities("text")
        assert len(extraction.entities) == 1
        assert extraction.entities[0].local_id == "ok"

    def test_drops_relationships_with_unknown_type(self):
        payload = {
            "entities": [
                {"local_id": "a", "type": "intrusion-set", "name": "FIN7"},
                {"local_id": "b", "type": "tool", "name": "Cobalt Strike"},
            ],
            "relationships": [
                {"source": "a", "target": "b", "relationship_type": "uses"},
                {"source": "a", "target": "b", "relationship_type": "x-bogus"},
            ],
        }
        with _patch_llm(payload):
            extraction = extract_entities("text")
        assert len(extraction.relationships) == 1
        assert extraction.relationships[0].relationship_type == "uses"

    def test_response_not_an_object_returns_empty(self):
        with patch("trace_engine.stix.extractor.call_llm", return_value="not json"):
            extraction = extract_entities("text")
        assert extraction.entities == []
        assert extraction.relationships == []

    def test_uses_medium_task_by_default(self):
        with patch("trace_engine.stix.extractor.call_llm", return_value="{}") as mock_call:
            extract_entities("text")
        assert mock_call.call_args[0][0] == "medium"

    def test_accepts_complex_task_override(self):
        with patch("trace_engine.stix.extractor.call_llm", return_value="{}") as mock_call:
            extract_entities("text", task="complex")
        assert mock_call.call_args[0][0] == "complex"

    def test_prompt_contains_report_text(self):
        with patch("trace_engine.stix.extractor.call_llm", return_value="{}") as mock_call:
            extract_entities("CVE-2023-3519 exploitation report")
        prompt_arg = mock_call.call_args[0][1]
        assert "CVE-2023-3519" in prompt_arg
        # Refactor: PIR_CONTEXT_BLOCK placeholder must always be substituted out.
        assert "{{PIR_CONTEXT_BLOCK}}" not in prompt_arg
        assert "{{REPORT_TEXT}}" not in prompt_arg


def test_valid_entity_and_relationship_vocabularies_are_disjoint():
    # 'relationship' is no longer a valid entity type — only entities are.
    assert "relationship" not in _VALID_ENTITY_TYPES
    assert _VALID_RELATIONSHIP_TYPES == frozenset({"uses", "exploits", "indicates"})


# ---------------------------------------------------------------------------
# build_stix_bundle_from_extraction
# ---------------------------------------------------------------------------


def _ent(local_id: str, type_: str, name: str | None = None, **extra) -> ExtractedEntity:
    props = {"name": name} if name else {}
    props.update(extra)
    return ExtractedEntity(local_id=local_id, type=type_, properties=props)


class TestBuildBundle:
    def test_empty_extraction_yields_minimal_bundle(self):
        bundle = build_stix_bundle_from_extraction(Extraction())
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert bundle["id"].startswith("bundle--")
        assert bundle["objects"] == []

    def test_entities_become_stix_objects_with_v4_ids(self):
        extraction = Extraction(
            entities=[_ent("a", "intrusion-set", "FIN7"), _ent("b", "tool", "Cobalt")]
        )
        bundle = build_stix_bundle_from_extraction(extraction)
        assert len(bundle["objects"]) == 2
        for obj in bundle["objects"]:
            assert obj["spec_version"] == "2.1"
            assert obj["created"] == obj["modified"]
            assert obj["created"].endswith(".000Z")
            tail = obj["id"].split("--")[1]
            assert _UUIDV4.match(tail), f"{obj['id']} is not UUIDv4"

    def test_all_objects_share_one_timestamp(self):
        ext = Extraction(entities=[_ent("a", "malware", "X"), _ent("b", "tool", "Y")])
        bundle = build_stix_bundle_from_extraction(ext)
        ts = {obj["created"] for obj in bundle["objects"]}
        assert len(ts) == 1
        assert bundle["created"] in ts

    def test_relationships_resolved_via_local_id_map(self):
        ext = Extraction(
            entities=[_ent("a", "intrusion-set", "FIN7"), _ent("b", "tool", "Cobalt")],
            relationships=[ExtractedRelationship("a", "b", "uses")],
        )
        bundle = build_stix_bundle_from_extraction(ext)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert len(rels) == 1
        ent_ids = {o["id"] for o in bundle["objects"] if o["type"] != "relationship"}
        assert rels[0]["source_ref"] in ent_ids
        assert rels[0]["target_ref"] in ent_ids
        assert rels[0]["source_ref"] != rels[0]["target_ref"]

    def test_unresolved_relationship_dropped(self):
        ext = Extraction(
            entities=[_ent("a", "intrusion-set", "FIN7")],
            relationships=[
                ExtractedRelationship("a", "ghost", "uses"),
                ExtractedRelationship("ghost", "a", "uses"),
            ],
        )
        bundle = build_stix_bundle_from_extraction(ext)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert rels == []

    def test_llm_supplied_fields_do_not_override_wire_format(self):
        # If the LLM tries to sneak in `id` / `spec_version`, code wins.
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="a",
                    type="malware",
                    properties={
                        "id": "malware--12345678-90ab-cdef-1234-227092301234",
                        "spec_version": "2.0",
                        "created": "2020-01-01T00:00:00:000Z",
                        "name": "X",
                    },
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        obj = bundle["objects"][0]
        tail = obj["id"].split("--")[1]
        assert _UUIDV4.match(tail)
        assert obj["spec_version"] == "2.1"
        assert obj["created"].endswith(".000Z")
        assert obj["created"] != "2020-01-01T00:00:00:000Z"

    def test_x_trace_metadata_included_when_supplied(self):
        ext = Extraction()
        bundle = build_stix_bundle_from_extraction(
            ext,
            source_url="https://example.com/post",
            matched_pir_ids=["PIR-X"],
            relevance_score=0.7,
            relevance_rationale="actor named in report",
        )
        assert bundle["x_trace_source_url"] == "https://example.com/post"
        assert bundle["x_trace_collected_at"]
        assert bundle["x_trace_matched_pir_ids"] == ["PIR-X"]
        assert bundle["x_trace_relevance_score"] == 0.7
        assert bundle["x_trace_relevance_rationale"] == "actor named in report"

    def test_x_trace_metadata_omitted_when_not_supplied(self):
        bundle = build_stix_bundle_from_extraction(Extraction())
        for key in (
            "x_trace_source_url",
            "x_trace_matched_pir_ids",
            "x_trace_relevance_score",
            "x_trace_relevance_rationale",
        ):
            assert key not in bundle
