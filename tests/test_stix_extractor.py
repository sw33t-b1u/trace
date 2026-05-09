"""Tests for stix/extractor.py."""

from __future__ import annotations

import json
import re
from unittest.mock import patch

from trace_engine.config import Config
from trace_engine.stix.extractor import (
    _VALID_ENTITY_TYPES,
    _VALID_RELATIONSHIP_TYPES,
    ExtractedEntity,
    ExtractedRelationship,
    Extraction,
    _chunk_text,
    _extract_json_from_text,
    _merge_extractions,
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


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------


class TestChunkText:
    def test_short_text_returns_single_chunk(self):
        text = "Para A.\n\nPara B."
        assert _chunk_text(text, max_chars=1000) == [text]

    def test_paragraph_aligned_split(self):
        text = "A" * 100 + "\n\n" + "B" * 100 + "\n\n" + "C" * 100
        chunks = _chunk_text(text, max_chars=210)
        # Each chunk fits 2 paragraphs (100 + 2 + 100 = 202 <= 210); 3rd goes alone.
        assert len(chunks) == 2
        assert all(len(c) <= 210 for c in chunks)
        assert "A" * 100 in chunks[0]
        assert "C" * 100 in chunks[1]

    def test_paragraph_larger_than_limit_is_hard_split(self):
        big = "X" * 500
        chunks = _chunk_text(big, max_chars=200)
        assert len(chunks) == 3
        assert all(len(c) <= 200 for c in chunks)
        assert "".join(chunks) == big

    def test_max_chars_must_be_positive(self):
        import pytest

        with pytest.raises(ValueError):
            _chunk_text("x", max_chars=0)


# ---------------------------------------------------------------------------
# Merging across chunks
# ---------------------------------------------------------------------------


class TestMergeExtractions:
    def test_dedupes_entities_by_normalized_name(self):
        # Same actor named in two chunks with different casing → one merged entity.
        a = Extraction(entities=[_ent("c0_x", "intrusion-set", "FIN7")])
        b = Extraction(entities=[_ent("c1_y", "intrusion-set", "fin7")])
        merged = _merge_extractions([a, b])
        assert len(merged.entities) == 1
        assert merged.entities[0].properties["name"] == "FIN7"

    def test_keeps_distinct_entities_with_same_name_different_type(self):
        a = Extraction(entities=[_ent("c0_a", "tool", "Cobalt")])
        b = Extraction(entities=[_ent("c1_b", "intrusion-set", "Cobalt")])
        merged = _merge_extractions([a, b])
        assert len(merged.entities) == 2

    def test_unions_list_valued_properties(self):
        a = Extraction(entities=[_ent("c0_x", "malware", "Emotet", labels=["banker"])])
        b = Extraction(entities=[_ent("c1_y", "malware", "Emotet", labels=["banker", "loader"])])
        merged = _merge_extractions([a, b])
        assert len(merged.entities) == 1
        assert sorted(merged.entities[0].properties["labels"]) == ["banker", "loader"]

    def test_relationships_remapped_to_canonical_local_ids(self):
        # Chunk 0 introduces FIN7 + Cobalt + uses(FIN7, Cobalt).
        # Chunk 1 reintroduces FIN7 (different alias), adds new rel.
        a = Extraction(
            entities=[
                _ent("c0_a", "intrusion-set", "FIN7"),
                _ent("c0_t", "tool", "Cobalt"),
            ],
            relationships=[ExtractedRelationship("c0_a", "c0_t", "uses")],
        )
        b = Extraction(
            entities=[
                _ent("c1_a", "intrusion-set", "fin7"),
                _ent("c1_v", "vulnerability", "CVE-2024-1234"),
            ],
            relationships=[ExtractedRelationship("c1_a", "c1_v", "exploits")],
        )
        merged = _merge_extractions([a, b])
        # FIN7 merged → 3 unique entities total
        assert len(merged.entities) == 3
        # Both relationships preserved, both source-resolved to FIN7's canonical id
        assert len(merged.relationships) == 2
        actor_id = next(e.local_id for e in merged.entities if e.properties.get("name") == "FIN7")
        assert {r.source for r in merged.relationships} == {actor_id}

    def test_duplicate_relationships_deduped(self):
        a = Extraction(
            entities=[_ent("c0_a", "intrusion-set", "FIN7"), _ent("c0_t", "tool", "Cobalt")],
            relationships=[ExtractedRelationship("c0_a", "c0_t", "uses")],
        )
        b = Extraction(
            entities=[_ent("c1_a", "intrusion-set", "FIN7"), _ent("c1_t", "tool", "cobalt")],
            relationships=[ExtractedRelationship("c1_a", "c1_t", "uses")],
        )
        merged = _merge_extractions([a, b])
        assert len(merged.relationships) == 1


# ---------------------------------------------------------------------------
# extract_entities — chunked path
# ---------------------------------------------------------------------------


class TestExtractEntitiesChunked:
    def _patch_chunked_responses(self, responses: list[dict]):
        return patch(
            "trace_engine.stix.extractor.call_llm",
            side_effect=[json.dumps(r) for r in responses],
        )

    def test_long_article_chunked_and_merged(self):
        cfg = Config(extraction_chunk_chars=200)
        # 3 paragraphs, each 150 chars → 3 chunks at chunk_chars=200.
        text = "\n\n".join(["A" * 150, "B" * 150, "C" * 150])

        responses = [
            {
                "entities": [{"local_id": "actor_1", "type": "intrusion-set", "name": "FIN7"}],
                "relationships": [],
            },
            {
                "entities": [
                    {"local_id": "actor_1", "type": "intrusion-set", "name": "fin7"},
                    {"local_id": "tool_1", "type": "tool", "name": "Cobalt Strike"},
                ],
                "relationships": [
                    {"source": "actor_1", "target": "tool_1", "relationship_type": "uses"}
                ],
            },
            {
                "entities": [{"local_id": "vuln_1", "type": "vulnerability", "name": "CVE-2024-1"}],
                "relationships": [],
            },
        ]
        with self._patch_chunked_responses(responses):
            extraction = extract_entities(text, config=cfg)

        # FIN7 dedupe + Cobalt + CVE = 3 entities
        names = sorted(e.properties.get("name") for e in extraction.entities)
        assert names == ["CVE-2024-1", "Cobalt Strike", "FIN7"]
        assert len(extraction.relationships) == 1

    def test_chunk_failure_does_not_kill_other_chunks(self):
        cfg = Config(extraction_chunk_chars=200)
        text = "\n\n".join(["A" * 150, "B" * 150])
        responses_raw = [
            "not json at all",  # first chunk fails
            json.dumps(
                {
                    "entities": [{"local_id": "x", "type": "tool", "name": "Mimikatz"}],
                    "relationships": [],
                }
            ),
        ]
        with patch("trace_engine.stix.extractor.call_llm", side_effect=responses_raw):
            extraction = extract_entities(text, config=cfg)
        assert len(extraction.entities) == 1
        assert extraction.entities[0].properties["name"] == "Mimikatz"


# ---------------------------------------------------------------------------
# Bracket-balanced salvage of truncated LLM responses (max_output_tokens hit)
# ---------------------------------------------------------------------------


class TestSalvageTruncatedExtraction:
    def test_truncated_mid_object_recovers_complete_entries(self):
        # Outer JSON cut off after the second entity's closing brace, before
        # the array's `]` / outer `}` — exact pattern observed in production
        # when Gemini hits max_output_tokens.
        truncated = (
            '{\n  "entities": [\n'
            '    {"local_id": "a", "type": "intrusion-set", "name": "FIN7"},\n'
            '    {"local_id": "t", "type": "tool", "name": "Cobalt Strike"},\n'
            '    {"local_id": "v", "type": "vulnerability", "name": "CVE-2024-'
        )
        result = _extract_json_from_text(truncated)
        assert isinstance(result, dict)
        assert [e["local_id"] for e in result["entities"]] == ["a", "t"]
        assert result["relationships"] == []

    def test_truncated_after_relationships_section(self):
        truncated = (
            '{"entities": [{"local_id": "a", "type": "intrusion-set"}],\n'
            ' "relationships": [\n'
            '    {"source": "a", "target": "b", "relationship_type": "uses"},\n'
            '    {"source": "a", "target": "c", "relationship_t'
        )
        result = _extract_json_from_text(truncated)
        assert isinstance(result, dict)
        assert len(result["entities"]) == 1
        assert len(result["relationships"]) == 1
        assert result["relationships"][0]["source"] == "a"

    def test_well_formed_json_still_parses_normally(self):
        payload = {
            "entities": [{"local_id": "a", "type": "tool", "name": "Mimikatz"}],
            "relationships": [],
        }
        result = _extract_json_from_text(json.dumps(payload))
        assert result == payload

    def test_returns_none_when_no_recoverable_arrays(self):
        # Random prose with no entities/relationships keys at all.
        assert _extract_json_from_text("Not JSON, just narrative text.") is None

    def test_handles_strings_with_braces_inside(self):
        # Description containing a `}` should not confuse bracket counting.
        truncated = (
            '{"entities": [\n'
            '    {"local_id": "a", "type": "tool", "name": "X",'
            ' "description": "writes {key: value} pairs"},\n'
            '    {"local_id": "b", "type": "malware", "name": "Y'
        )
        result = _extract_json_from_text(truncated)
        assert isinstance(result, dict)
        assert len(result["entities"]) == 1
        assert result["entities"][0]["local_id"] == "a"


# ---------------------------------------------------------------------------
# STIX 2.1 type-specific required-property defaults (0.3.2)
# ---------------------------------------------------------------------------


class TestRequiredPropertyDefaults:
    def test_malware_gets_is_family_false_default(self):
        ext = Extraction(entities=[_ent("m", "malware", "Mimikatz")])
        bundle = build_stix_bundle_from_extraction(ext)
        malware = next(o for o in bundle["objects"] if o["type"] == "malware")
        assert malware["is_family"] is False

    def test_malware_keeps_llm_supplied_is_family_true(self):
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="m",
                    type="malware",
                    properties={"name": "Emotet", "is_family": True},
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        malware = next(o for o in bundle["objects"] if o["type"] == "malware")
        assert malware["is_family"] is True

    def test_indicator_gets_valid_from_default_to_bundle_ts(self):
        ext = Extraction(entities=[_ent("i", "indicator", "ip-1.2.3.4")])
        bundle = build_stix_bundle_from_extraction(ext)
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        assert indicator["valid_from"] == bundle["created"]

    def test_indicator_gets_pattern_type_stix_default(self):
        ext = Extraction(entities=[_ent("i", "indicator", "domain-example")])
        bundle = build_stix_bundle_from_extraction(ext)
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        assert indicator["pattern_type"] == "stix"

    def test_indicator_keeps_llm_supplied_pattern_type(self):
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="i",
                    type="indicator",
                    properties={
                        "name": "yara-rule",
                        "pattern": "rule X { strings: $a = \"abc\" condition: $a }",
                        "pattern_type": "yara",
                        "valid_from": "2026-01-01T00:00:00.000Z",
                    },
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        assert indicator["pattern_type"] == "yara"
        assert indicator["valid_from"] == "2026-01-01T00:00:00.000Z"

    def test_other_types_get_no_extra_defaults(self):
        # tool / threat-actor / intrusion-set / attack-pattern / vulnerability
        # have no extra required properties beyond name (which the LLM emits).
        ext = Extraction(
            entities=[
                _ent("t", "tool", "Cobalt Strike"),
                _ent("a", "intrusion-set", "FIN7"),
                _ent("p", "attack-pattern", "Spearphishing"),
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        for obj in bundle["objects"]:
            assert "is_family" not in obj
            assert "valid_from" not in obj
            assert "pattern_type" not in obj
