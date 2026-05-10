"""Tests for stix/extractor.py."""

from __future__ import annotations

import json
import re
from datetime import UTC
from unittest.mock import patch

from trace_engine.config import Config
from trace_engine.stix.extractor import (
    _VALID_ENTITY_TYPES,
    _VALID_RELATIONSHIP_TYPES,
    ExtractedEntity,
    ExtractedRelationship,
    Extraction,
    IdentityAssetEdge,
    _chunk_text,
    _extract_json_from_text,
    _merge_extractions,
    build_stix_bundle_from_extraction,
    extract_entities,
)

_UUIDV4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
# UUIDv5 has the same shape as v4 except the version nibble is `5`.
_UUID5_HEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


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
    # 1.0.0 added `targets` for actor → identity edges.
    # 1.1.0 added `x-trace-has-access` for identity → internal asset
    # (Initiative A); the bundle assembler does not yet emit it
    # (TRACE 1.2.0), but the vocabulary is declared so SAGE 0.6.0 can
    # accept the type when receiving bundles produced by 1.2.0+.
    assert _VALID_RELATIONSHIP_TYPES == frozenset(
        {"uses", "exploits", "indicates", "targets", "x-trace-has-access"}
    )
    assert "identity" in _VALID_ENTITY_TYPES


# ---------------------------------------------------------------------------
# build_stix_bundle_from_extraction
# ---------------------------------------------------------------------------


def _ent(local_id: str, type_: str, name: str | None = None, **extra) -> ExtractedEntity:
    props = {"name": name} if name else {}
    props.update(extra)
    return ExtractedEntity(local_id=local_id, type=type_, properties=props)


class TestBuildBundle:
    def test_empty_extraction_yields_minimal_bundle(self):
        # 0.4.0: bundle envelope no longer carries `spec_version` or `created`
        # (STIX 2.1 deprecated those at envelope level).
        bundle = build_stix_bundle_from_extraction(Extraction())
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        assert bundle["objects"] == []
        assert "spec_version" not in bundle
        assert "created" not in bundle

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

    def test_indicator_gets_valid_from_default_to_object_ts(self):
        ext = Extraction(
            entities=[_ent("i", "indicator", "ip-1.2.3.4", pattern="[ipv4-addr:value = '1.2.3.4']")]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        # All non-extension objects share one timestamp; valid_from equals it.
        assert indicator["valid_from"] == indicator["created"]

    def test_indicator_gets_pattern_type_stix_default(self):
        ext = Extraction(
            entities=[
                _ent(
                    "i",
                    "indicator",
                    "domain-example",
                    pattern="[domain-name:value = 'example.com']",
                )
            ]
        )
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
                        "pattern": 'rule X { strings: $a = "abc" condition: $a }',
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


# ---------------------------------------------------------------------------
# 0.4.0 extension migration
# ---------------------------------------------------------------------------


class TestBundleExtensionMigration:
    def test_envelope_omits_deprecated_fields(self):
        ext = Extraction(entities=[_ent("a", "tool", "X")])
        bundle = build_stix_bundle_from_extraction(ext)
        # STIX 2.1 deprecated these at the bundle envelope.
        assert "spec_version" not in bundle
        assert "created" not in bundle
        # `type`, `id`, `objects` remain.
        assert bundle["type"] == "bundle"
        assert "id" in bundle
        assert "objects" in bundle

    def test_no_extension_definition_when_no_x_trace_metadata(self):
        ext = Extraction(entities=[_ent("a", "tool", "X")])
        bundle = build_stix_bundle_from_extraction(ext)
        types = [o["type"] for o in bundle["objects"]]
        assert "extension-definition" not in types
        assert "extensions" not in bundle

    def test_extension_definition_included_when_x_trace_metadata_present(self):
        ext = Extraction(entities=[_ent("a", "tool", "X")])
        bundle = build_stix_bundle_from_extraction(
            ext,
            source_url="https://example.com/post",
            matched_pir_ids=["PIR-001"],
            relevance_score=0.9,
        )
        ext_objects = [o for o in bundle["objects"] if o["type"] == "extension-definition"]
        assert len(ext_objects) == 1
        ext_obj = ext_objects[0]
        assert ext_obj["spec_version"] == "2.1"
        assert "toplevel-property-extension" in ext_obj["extension_types"]
        # Bundle declares it uses the extension.
        assert "extensions" in bundle
        assert ext_obj["id"] in bundle["extensions"]
        assert (
            bundle["extensions"][ext_obj["id"]]["extension_type"] == "toplevel-property-extension"
        )

    def test_extension_id_is_stable_across_emissions(self):
        # Two bundles produced at different times must reference the same
        # extension definition id — that's what makes consumers able to
        # recognise the extension without per-bundle discovery.
        from datetime import datetime as _dt

        ext = Extraction(entities=[_ent("a", "tool", "X")])
        b1 = build_stix_bundle_from_extraction(
            ext, source_url="u1", now=_dt(2026, 1, 1, tzinfo=UTC)
        )
        b2 = build_stix_bundle_from_extraction(
            ext, source_url="u2", now=_dt(2026, 6, 1, tzinfo=UTC)
        )
        ext_id_1 = next(o["id"] for o in b1["objects"] if o["type"] == "extension-definition")
        ext_id_2 = next(o["id"] for o in b2["objects"] if o["type"] == "extension-definition")
        assert ext_id_1 == ext_id_2

    def test_extension_definition_carries_required_fields(self):
        ext = Extraction(entities=[_ent("a", "tool", "X")])
        bundle = build_stix_bundle_from_extraction(ext, source_url="u")
        ext_obj = next(o for o in bundle["objects"] if o["type"] == "extension-definition")
        # STIX 2.1 §7.3 required fields.
        for field_name in ("name", "schema", "version", "extension_types"):
            assert field_name in ext_obj, f"missing required field: {field_name}"

    def test_x_trace_fields_remain_at_bundle_root_when_extension_active(self):
        ext = Extraction(entities=[_ent("a", "tool", "X")])
        bundle = build_stix_bundle_from_extraction(
            ext,
            source_url="https://example.com/post",
            matched_pir_ids=["PIR-001"],
            relevance_score=0.9,
            relevance_rationale="actor named",
        )
        assert bundle["x_trace_source_url"] == "https://example.com/post"
        assert bundle["x_trace_matched_pir_ids"] == ["PIR-001"]
        assert bundle["x_trace_relevance_score"] == 0.9
        assert bundle["x_trace_relevance_rationale"] == "actor named"


# ---------------------------------------------------------------------------
# 0.5.1 — extension_properties + open-vocab demotion to labels
# ---------------------------------------------------------------------------


class TestExtensionPropertiesAndVocabDemotion:
    def test_extension_definition_lists_extension_properties(self):
        ext = Extraction(entities=[_ent("a", "tool", "X")])
        bundle = build_stix_bundle_from_extraction(ext, source_url="u")
        ext_obj = next(o for o in bundle["objects"] if o["type"] == "extension-definition")
        assert "extension_properties" in ext_obj
        assert "x_trace_source_url" in ext_obj["extension_properties"]
        assert "x_trace_relevance_score" in ext_obj["extension_properties"]
        # The five known x_trace_* fields are exactly listed.
        assert set(ext_obj["extension_properties"]) == {
            "x_trace_source_url",
            "x_trace_collected_at",
            "x_trace_matched_pir_ids",
            "x_trace_relevance_score",
            "x_trace_relevance_rationale",
        }

    def test_tool_types_vocab_violation_demoted_to_labels(self):
        # 'loader' / 'framework' are NOT in STIX 2.1 tool-type-ov.
        # 'remote-access' IS. Mixed input.
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="t",
                    type="tool",
                    properties={
                        "name": "Cobalt Strike",
                        "tool_types": ["loader", "remote-access", "framework"],
                    },
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        tool = next(o for o in bundle["objects"] if o["type"] == "tool")
        assert tool["tool_types"] == ["remote-access"]
        assert "loader" in tool["labels"]
        assert "framework" in tool["labels"]

    def test_malware_types_vocab_violation_demoted_to_labels(self):
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="m",
                    type="malware",
                    properties={
                        "name": "X",
                        "malware_types": ["loader", "backdoor"],
                    },
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        malware = next(o for o in bundle["objects"] if o["type"] == "malware")
        assert malware["malware_types"] == ["backdoor"]
        assert "loader" in malware["labels"]

    def test_all_values_non_conforming_removes_field(self):
        # Field should be dropped entirely when nothing conforms; the
        # values still survive in `labels`.
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="t",
                    type="tool",
                    properties={"name": "X", "tool_types": ["loader", "framework"]},
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        tool = next(o for o in bundle["objects"] if o["type"] == "tool")
        assert "tool_types" not in tool
        assert {"loader", "framework"}.issubset(set(tool["labels"]))

    def test_existing_labels_preserved_and_extended(self):
        # If the LLM already supplied `labels`, demoted values append
        # without duplicating.
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="t",
                    type="tool",
                    properties={
                        "name": "X",
                        "tool_types": ["loader", "remote-access"],
                        "labels": ["financially-motivated", "loader"],
                    },
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        tool = next(o for o in bundle["objects"] if o["type"] == "tool")
        assert tool["tool_types"] == ["remote-access"]
        # No duplicate "loader" introduced; original order preserved.
        assert tool["labels"] == ["financially-motivated", "loader"]

    def test_conforming_only_input_unchanged(self):
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="m",
                    type="malware",
                    properties={"name": "Emotet", "malware_types": ["downloader", "trojan"]},
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        malware = next(o for o in bundle["objects"] if o["type"] == "malware")
        assert malware["malware_types"] == ["downloader", "trojan"]
        assert "labels" not in malware


# ---------------------------------------------------------------------------
# 0.5.2 — sophistication on intrusion-set demoted to labels ({401} fix)
# ---------------------------------------------------------------------------


class TestSophisticationDemotion:
    def test_intrusion_set_sophistication_moves_to_labels(self):
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="a",
                    type="intrusion-set",
                    properties={"name": "FIN7", "sophistication": "advanced"},
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        actor = next(o for o in bundle["objects"] if o["type"] == "intrusion-set")
        assert "sophistication" not in actor
        assert "advanced" in actor["labels"]

    def test_intrusion_set_sophistication_dedup_in_existing_labels(self):
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="a",
                    type="intrusion-set",
                    properties={
                        "name": "FIN7",
                        "sophistication": "advanced",
                        "labels": ["financially-motivated", "advanced"],
                    },
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        actor = next(o for o in bundle["objects"] if o["type"] == "intrusion-set")
        assert "sophistication" not in actor
        # No duplicate "advanced".
        assert actor["labels"] == ["financially-motivated", "advanced"]

    def test_threat_actor_sophistication_preserved(self):
        # `sophistication` is valid on threat-actor — must NOT be demoted.
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="a",
                    type="threat-actor",
                    properties={"name": "FIN7", "sophistication": "advanced"},
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        actor = next(o for o in bundle["objects"] if o["type"] == "threat-actor")
        assert actor.get("sophistication") == "advanced"
        assert "advanced" not in actor.get("labels", [])


# ---------------------------------------------------------------------------
# 0.6.1 — empty-array scrub, pattern validation, relationship type table
# ---------------------------------------------------------------------------


class TestEmptyArrayScrub:
    def test_empty_aliases_removed(self):
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="a",
                    type="intrusion-set",
                    properties={"name": "FIN7", "aliases": [], "labels": []},
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        actor = next(o for o in bundle["objects"] if o["type"] == "intrusion-set")
        assert "aliases" not in actor
        assert "labels" not in actor

    def test_non_empty_lists_preserved(self):
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="a",
                    type="intrusion-set",
                    properties={
                        "name": "FIN7",
                        "aliases": ["GOLD NIAGARA"],
                        "labels": ["financially-motivated"],
                    },
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        actor = next(o for o in bundle["objects"] if o["type"] == "intrusion-set")
        assert actor["aliases"] == ["GOLD NIAGARA"]
        assert "financially-motivated" in actor["labels"]


class TestIndicatorPatternValidation:
    def test_valid_stix_pattern_kept(self):
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="i",
                    type="indicator",
                    properties={
                        "pattern": "[ipv4-addr:value = '198.51.100.1']",
                        "pattern_type": "stix",
                        "indicator_types": ["malicious-activity"],
                    },
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert len(indicators) == 1

    def test_malformed_stix_pattern_drops_indicator(self):
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="i",
                    type="indicator",
                    properties={
                        "pattern": "[file:hashes.SHA-256 = 'abc'",  # missing closing bracket
                        "pattern_type": "stix",
                    },
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert indicators == []

    def test_yara_pattern_passes_through_untouched(self):
        # We only validate stix patterns; YARA / Snort / PCRE are pass-through.
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="i",
                    type="indicator",
                    properties={
                        "pattern": 'rule X { strings: $a = "abc" condition: $a }',
                        "pattern_type": "yara",
                    },
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert len(indicators) == 1

    def test_relationships_to_dropped_indicator_fall_through(self):
        # When the indicator is dropped, any `indicator indicates X`
        # relationship pointing at it loses its source endpoint and is
        # dropped through the existing dangling-ref guard.
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="i",
                    type="indicator",
                    properties={
                        "pattern": "[broken",  # malformed
                        "pattern_type": "stix",
                    },
                ),
                _ent("m", "malware", "Emotet"),
            ],
            relationships=[ExtractedRelationship("i", "m", "indicates")],
        )
        bundle = build_stix_bundle_from_extraction(ext)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert rels == []


class TestRelationshipTypeTable:
    def test_intrusion_set_uses_malware_kept(self):
        ext = Extraction(
            entities=[_ent("a", "intrusion-set", "FIN7"), _ent("m", "malware", "X")],
            relationships=[ExtractedRelationship("a", "m", "uses")],
        )
        bundle = build_stix_bundle_from_extraction(ext)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert len(rels) == 1

    def test_tool_uses_malware_accepted_per_0_5_2(self):
        # 0.5.2 explicitly accepted `tool uses malware` and `tool uses tool`.
        ext = Extraction(
            entities=[_ent("t", "tool", "Cobalt"), _ent("m", "malware", "X")],
            relationships=[ExtractedRelationship("t", "m", "uses")],
        )
        bundle = build_stix_bundle_from_extraction(ext)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert len(rels) == 1

    def test_malware_indicates_dropped(self):
        # `indicates` source must be `indicator` only.
        ext = Extraction(
            entities=[_ent("m", "malware", "X"), _ent("a", "intrusion-set", "FIN7")],
            relationships=[ExtractedRelationship("m", "a", "indicates")],
        )
        bundle = build_stix_bundle_from_extraction(ext)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert rels == []

    def test_attack_pattern_exploits_dropped(self):
        # `exploits` source must be malware/intrusion-set/threat-actor/campaign.
        ext = Extraction(
            entities=[
                _ent("p", "attack-pattern", "Spearphishing"),
                _ent("v", "vulnerability", "CVE-2024-1234"),
            ],
            relationships=[ExtractedRelationship("p", "v", "exploits")],
        )
        bundle = build_stix_bundle_from_extraction(ext)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert rels == []

    def test_indicator_indicates_indicator_dropped(self):
        # `indicates` target must not be indicator itself.
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="i1",
                    type="indicator",
                    properties={
                        "pattern": "[ipv4-addr:value = '1.2.3.4']",
                        "pattern_type": "stix",
                    },
                ),
                ExtractedEntity(
                    local_id="i2",
                    type="indicator",
                    properties={
                        "pattern": "[ipv4-addr:value = '5.6.7.8']",
                        "pattern_type": "stix",
                    },
                ),
            ],
            relationships=[ExtractedRelationship("i1", "i2", "indicates")],
        )
        bundle = build_stix_bundle_from_extraction(ext)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert rels == []

    def test_indicator_indicates_malware_kept(self):
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="i",
                    type="indicator",
                    properties={
                        "pattern": "[ipv4-addr:value = '1.2.3.4']",
                        "pattern_type": "stix",
                    },
                ),
                _ent("m", "malware", "X"),
            ],
            relationships=[ExtractedRelationship("i", "m", "indicates")],
        )
        bundle = build_stix_bundle_from_extraction(ext)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert len(rels) == 1


# ---------------------------------------------------------------------------
# 1.0.0 — identity SDO + targets relationship
# ---------------------------------------------------------------------------


class TestIdentityEntity:
    def test_identity_minimal_passes_through(self):
        ext = Extraction(
            entities=[ExtractedEntity(local_id="i", type="identity", properties={"name": "CFO"})]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        ident = next(o for o in bundle["objects"] if o["type"] == "identity")
        assert ident["name"] == "CFO"
        assert ident["spec_version"] == "2.1"

    def test_identity_class_in_vocab_preserved(self):
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="i",
                    type="identity",
                    properties={"name": "Acme Corp", "identity_class": "organization"},
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        ident = next(o for o in bundle["objects"] if o["type"] == "identity")
        assert ident["identity_class"] == "organization"
        assert "labels" not in ident

    def test_identity_class_outside_vocab_demoted_to_labels(self):
        # 'executive' is not in STIX 2.1 §6.7 identity-class-ov.
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="i",
                    type="identity",
                    properties={"name": "Jane Doe", "identity_class": "executive"},
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        ident = next(o for o in bundle["objects"] if o["type"] == "identity")
        assert "identity_class" not in ident
        assert "executive" in ident["labels"]


class TestTargetsRelationship:
    def test_actor_targets_identity_kept(self):
        ext = Extraction(
            entities=[
                _ent("a", "intrusion-set", "FIN7"),
                ExtractedEntity(local_id="i", type="identity", properties={"name": "CFO"}),
            ],
            relationships=[ExtractedRelationship("a", "i", "targets")],
        )
        bundle = build_stix_bundle_from_extraction(ext)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert len(rels) == 1
        assert rels[0]["relationship_type"] == "targets"

    def test_threat_actor_targets_vulnerability_kept(self):
        ext = Extraction(
            entities=[
                _ent("a", "threat-actor", "Hacker"),
                _ent("v", "vulnerability", "CVE-2024-1234"),
            ],
            relationships=[ExtractedRelationship("a", "v", "targets")],
        )
        bundle = build_stix_bundle_from_extraction(ext)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert len(rels) == 1

    def test_identity_targets_actor_dropped(self):
        # `targets` source must be in the §4.13 source set (actor /
        # malware / tool / etc.). Identity → actor reverses the
        # relationship and must be dropped.
        ext = Extraction(
            entities=[
                ExtractedEntity(local_id="i", type="identity", properties={"name": "CFO"}),
                _ent("a", "intrusion-set", "FIN7"),
            ],
            relationships=[ExtractedRelationship("i", "a", "targets")],
        )
        bundle = build_stix_bundle_from_extraction(ext)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert rels == []

    def test_indicator_targets_identity_dropped(self):
        # `indicator` is not a valid `targets` source per §4.13.
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="ind",
                    type="indicator",
                    properties={
                        "pattern": "[ipv4-addr:value = '1.2.3.4']",
                        "pattern_type": "stix",
                    },
                ),
                ExtractedEntity(local_id="i", type="identity", properties={"name": "CFO"}),
            ],
            relationships=[ExtractedRelationship("ind", "i", "targets")],
        )
        bundle = build_stix_bundle_from_extraction(ext)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert rels == []


# ---------------------------------------------------------------------------
# 1.0.1 — sectors vocab demotion + indicator name/description defaults
# ---------------------------------------------------------------------------


class TestIdentitySectorsDemotion:
    def test_in_vocab_sectors_preserved(self):
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="i",
                    type="identity",
                    properties={"name": "Acme Bank", "sectors": ["financial-services"]},
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        ident = next(o for o in bundle["objects"] if o["type"] == "identity")
        assert ident["sectors"] == ["financial-services"]
        assert "labels" not in ident

    def test_out_of_vocab_sectors_demoted_to_labels(self):
        # 'fintech' / 'card-payments' are not in STIX 2.1 §6.6
        # industry-sector-ov.
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="i",
                    type="identity",
                    properties={
                        "name": "Edy Co.",
                        "sectors": ["financial-services", "fintech", "card-payments"],
                    },
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        ident = next(o for o in bundle["objects"] if o["type"] == "identity")
        assert ident["sectors"] == ["financial-services"]
        assert "fintech" in ident["labels"]
        assert "card-payments" in ident["labels"]


class TestIndicatorNameDescriptionDefaults:
    def test_indicator_without_name_gets_derived_from_ipv4_pattern(self):
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="i",
                    type="indicator",
                    properties={
                        "pattern": "[ipv4-addr:value = '198.51.100.1']",
                        "pattern_type": "stix",
                    },
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        ind = next(o for o in bundle["objects"] if o["type"] == "indicator")
        assert ind["name"] == "ipv4-addr: 198.51.100.1"
        assert ind["description"]  # non-empty

    def test_indicator_without_name_gets_derived_from_file_hash_pattern(self):
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="i",
                    type="indicator",
                    properties={
                        "pattern": (
                            "[file:hashes.'SHA-256' = "
                            "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']"
                        ),
                        "pattern_type": "stix",
                    },
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        ind = next(o for o in bundle["objects"] if o["type"] == "indicator")
        # The hash pattern uses a quoted property `hashes.'SHA-256'`,
        # so the regex falls back to type-only and produces e.g.
        # "Indicator: file".
        assert "file" in ind["name"]

    def test_indicator_existing_name_preserved(self):
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="i",
                    type="indicator",
                    properties={
                        "name": "FIN7 C2 IPv4",
                        "pattern": "[ipv4-addr:value = '198.51.100.1']",
                        "pattern_type": "stix",
                    },
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        ind = next(o for o in bundle["objects"] if o["type"] == "indicator")
        assert ind["name"] == "FIN7 C2 IPv4"

    def test_indicator_existing_description_preserved(self):
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="i",
                    type="indicator",
                    properties={
                        "pattern": "[ipv4-addr:value = '1.2.3.4']",
                        "pattern_type": "stix",
                        "description": "Custom description",
                    },
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        ind = next(o for o in bundle["objects"] if o["type"] == "indicator")
        assert ind["description"] == "Custom description"


# ---------------------------------------------------------------------------
# 1.0.2 — vulnerability.aliases demotion + tighter exploits source set
# ---------------------------------------------------------------------------


class TestVulnerabilityAliasesDemotion:
    def test_aliases_moves_to_labels(self):
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="v",
                    type="vulnerability",
                    properties={
                        "name": "CVE-2021-26855",
                        "aliases": ["ProxyLogon", "Microsoft Exchange RCE"],
                    },
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        vuln = next(o for o in bundle["objects"] if o["type"] == "vulnerability")
        assert "aliases" not in vuln
        assert "ProxyLogon" in vuln["labels"]
        assert "Microsoft Exchange RCE" in vuln["labels"]

    def test_existing_labels_preserved_with_aliases_merge(self):
        ext = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="v",
                    type="vulnerability",
                    properties={
                        "name": "CVE-2017-0144",
                        "aliases": ["EternalBlue"],
                        "labels": ["smb", "EternalBlue"],
                    },
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        vuln = next(o for o in bundle["objects"] if o["type"] == "vulnerability")
        assert "aliases" not in vuln
        # Existing labels preserved; "EternalBlue" not duplicated.
        assert vuln["labels"] == ["smb", "EternalBlue"]


class TestExploitsSourceTightening:
    def test_malware_exploits_vulnerability_kept(self):
        ext = Extraction(
            entities=[
                _ent("m", "malware", "WannaCry"),
                _ent("v", "vulnerability", "CVE-2017-0144"),
            ],
            relationships=[ExtractedRelationship("m", "v", "exploits")],
        )
        bundle = build_stix_bundle_from_extraction(ext)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert len(rels) == 1
        assert rels[0]["relationship_type"] == "exploits"

    def test_intrusion_set_exploits_vulnerability_dropped(self):
        # 1.0.2: actor sources are no longer in the exploits table.
        # The relationship_type_mismatch_dropped guard fires.
        ext = Extraction(
            entities=[
                _ent("a", "intrusion-set", "FIN7"),
                _ent("v", "vulnerability", "CVE-2024-1234"),
            ],
            relationships=[ExtractedRelationship("a", "v", "exploits")],
        )
        bundle = build_stix_bundle_from_extraction(ext)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert rels == []

    def test_intrusion_set_targets_vulnerability_kept(self):
        # The semantically equivalent path the LLM should pick now.
        ext = Extraction(
            entities=[
                _ent("a", "intrusion-set", "FIN7"),
                _ent("v", "vulnerability", "CVE-2024-1234"),
            ],
            relationships=[ExtractedRelationship("a", "v", "targets")],
        )
        bundle = build_stix_bundle_from_extraction(ext)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert len(rels) == 1
        assert rels[0]["relationship_type"] == "targets"

    def test_threat_actor_exploits_vulnerability_dropped(self):
        ext = Extraction(
            entities=[
                _ent("a", "threat-actor", "Apt29"),
                _ent("v", "vulnerability", "CVE-2024-1234"),
            ],
            relationships=[ExtractedRelationship("a", "v", "exploits")],
        )
        bundle = build_stix_bundle_from_extraction(ext)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert rels == []


class TestVulnerabilityCveValidation:
    """1.0.3: drop vulnerability entities the LLM hallucinated from prose."""

    def test_drops_vulnerability_with_non_cve_name(self):
        ext = Extraction(
            entities=[_ent("v", "vulnerability", "Common Vulnerabilities and Exposures (CVEs)")]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        vulns = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
        assert vulns == []

    def test_keeps_vulnerability_with_proper_cve_name(self):
        ext = Extraction(entities=[_ent("v", "vulnerability", "CVE-2024-12345")])
        bundle = build_stix_bundle_from_extraction(ext)
        vulns = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
        assert len(vulns) == 1
        assert vulns[0]["name"] == "CVE-2024-12345"

    def test_extracts_cve_from_external_references_external_id(self):
        ext = Extraction(
            entities=[
                _ent(
                    "v",
                    "vulnerability",
                    "Path traversal in Foo",
                    external_references=[{"source_name": "cve", "external_id": "CVE-2023-9999"}],
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        vulns = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
        assert len(vulns) == 1
        # Name normalized to the CVE id even though the LLM wrote prose.
        assert vulns[0]["name"] == "CVE-2023-9999"

    def test_extracts_cve_from_external_references_url(self):
        ext = Extraction(
            entities=[
                _ent(
                    "v",
                    "vulnerability",
                    "Some advisory",
                    external_references=[
                        {
                            "source_name": "cve",
                            "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-4242",
                        }
                    ],
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        vulns = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
        assert len(vulns) == 1
        assert vulns[0]["name"] == "CVE-2025-4242"

    def test_drops_vulnerability_with_only_unrelated_external_references(self):
        ext = Extraction(
            entities=[
                _ent(
                    "v",
                    "vulnerability",
                    "Generic mention",
                    external_references=[
                        {"source_name": "mitre-attack", "url": "https://example.com"}
                    ],
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        vulns = [o for o in bundle["objects"] if o["type"] == "vulnerability"]
        assert vulns == []

    def test_relationships_to_dropped_vulnerability_fall_through_dangling_guard(self):
        ext = Extraction(
            entities=[
                _ent("m", "malware", "FooBot"),
                _ent("v", "vulnerability", "Generic CVE mention"),
            ],
            relationships=[ExtractedRelationship("m", "v", "exploits")],
        )
        bundle = build_stix_bundle_from_extraction(ext)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        # Vulnerability dropped; relationship lost its target → dangling-ref drop.
        assert rels == []


class TestIndicatorMissingPattern:
    """1.0.3: drop indicators with no pattern (was: kept; surfaced as validator error)."""

    def test_drops_indicator_without_pattern(self):
        ext = Extraction(entities=[_ent("i", "indicator", "Newly Registered Domains")])
        bundle = build_stix_bundle_from_extraction(ext)
        inds = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert inds == []

    def test_keeps_indicator_with_pattern(self):
        ext = Extraction(
            entities=[
                _ent(
                    "i",
                    "indicator",
                    "ip",
                    pattern="[ipv4-addr:value = '1.2.3.4']",
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        inds = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert len(inds) == 1


class TestAttackMotivationDemotion:
    """1.0.3: primary_motivation / secondary_motivations outside attack-motivation-ov."""

    def test_intrusion_set_in_vocab_motivation_kept(self):
        ext = Extraction(
            entities=[_ent("a", "intrusion-set", "FIN7", primary_motivation="organizational-gain")]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        actor = next(o for o in bundle["objects"] if o["type"] == "intrusion-set")
        assert actor["primary_motivation"] == "organizational-gain"
        assert "labels" not in actor

    def test_intrusion_set_out_of_vocab_motivation_demoted_to_labels(self):
        # "financial" and "espionage" are common LLM emissions but not in
        # STIX 2.1 §6.2 (the canonical values are organizational-gain etc.).
        ext = Extraction(
            entities=[_ent("a", "intrusion-set", "Lazarus", primary_motivation="financial")]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        actor = next(o for o in bundle["objects"] if o["type"] == "intrusion-set")
        assert "primary_motivation" not in actor
        assert "financial" in actor.get("labels", [])

    def test_threat_actor_out_of_vocab_motivation_demoted(self):
        ext = Extraction(
            entities=[_ent("a", "threat-actor", "APT29", primary_motivation="espionage")]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        actor = next(o for o in bundle["objects"] if o["type"] == "threat-actor")
        assert "primary_motivation" not in actor
        assert "espionage" in actor.get("labels", [])

    def test_secondary_motivations_filtered(self):
        ext = Extraction(
            entities=[
                _ent(
                    "a",
                    "intrusion-set",
                    "Mixed",
                    secondary_motivations=["organizational-gain", "espionage"],
                )
            ]
        )
        bundle = build_stix_bundle_from_extraction(ext)
        actor = next(o for o in bundle["objects"] if o["type"] == "intrusion-set")
        assert actor.get("secondary_motivations") == ["organizational-gain"]
        assert "espionage" in actor.get("labels", [])


# ---------------------------------------------------------------------------
# 1.2.0 — Identity-asset edges (Initiative A)
# ---------------------------------------------------------------------------


_ASSETS_FOR_IAE = [
    {"id": "asset-CA-001", "name": "決済処理中央サーバ", "tags": ["financial"]},
    {"id": "asset-CA-002", "name": "ERP System", "tags": ["erp"]},
]


class TestIdentityAssetEdgeCoercion:
    """LLM JSON parsing for the new identity_asset_edges field."""

    def test_extract_entities_parses_identity_asset_edges_from_llm_json(self):
        payload = {
            "entities": [{"local_id": "id_1", "type": "identity", "name": "CFO"}],
            "relationships": [],
            "identity_asset_edges": [
                {
                    "source": "id_1",
                    "asset_reference": "ERP System",
                    "description": "ERP admin",
                }
            ],
        }
        with _patch_llm(payload):
            extraction = extract_entities("text")
        assert len(extraction.identity_asset_edges) == 1
        edge = extraction.identity_asset_edges[0]
        assert edge.source == "id_1"
        assert edge.asset_reference == "ERP System"
        assert edge.description == "ERP admin"

    def test_extract_entities_handles_missing_identity_asset_edges_field(self):
        # 1.0.x bundles never had this field — should default to empty list.
        payload = {"entities": [], "relationships": []}
        with _patch_llm(payload):
            extraction = extract_entities("text")
        assert extraction.identity_asset_edges == []

    def test_coercer_drops_edge_with_blank_source_or_reference(self):
        payload = {
            "entities": [],
            "relationships": [],
            "identity_asset_edges": [
                {"source": "", "asset_reference": "ERP"},
                {"source": "id_1", "asset_reference": ""},
                {"source": "id_1", "asset_reference": "ERP"},
            ],
        }
        with _patch_llm(payload):
            extraction = extract_entities("text")
        assert len(extraction.identity_asset_edges) == 1


class TestBundleAssemblerIdentityAssetEdges:
    """Bundle assembler integrates resolve_asset_reference with IdentityAssetEdge."""

    def test_resolved_edge_emits_x_asset_internal_and_relationship(self):
        ext = Extraction(
            entities=[_ent("id_cfo", "identity", "CFO", identity_class="individual")],
            identity_asset_edges=[IdentityAssetEdge(source="id_cfo", asset_reference="ERP System")],
        )
        bundle = build_stix_bundle_from_extraction(ext, assets=_ASSETS_FOR_IAE)
        # Assembler must synthesize one x-asset-internal object for the
        # resolved asset and emit one x-trace-has-access relationship.
        x_asset = [o for o in bundle["objects"] if o["type"] == "x-asset-internal"]
        assert len(x_asset) == 1
        # 1.2.1: id is x-asset-internal--<uuid5> (STIX 2.1 §2.7 compliant);
        # the actual asset_id lives in the property.
        assert x_asset[0]["id"].startswith("x-asset-internal--")
        assert _UUIDV4.match(x_asset[0]["id"].split("--")[1]) or _UUID5_HEX.match(
            x_asset[0]["id"].split("--")[1]
        )
        assert x_asset[0]["asset_id"] == "asset-CA-002"

        rels = [
            o
            for o in bundle["objects"]
            if o["type"] == "relationship" and o["relationship_type"] == "x-trace-has-access"
        ]
        assert len(rels) == 1
        assert rels[0]["source_ref"].startswith("identity--")
        # target_ref points at the synthesized x-asset-internal object's id.
        assert rels[0]["target_ref"] == x_asset[0]["id"]
        assert rels[0]["confidence"] == 80  # tier 1 exact match

    def test_unresolved_reference_is_dropped(self):
        ext = Extraction(
            entities=[_ent("id_x", "identity", "X")],
            identity_asset_edges=[
                IdentityAssetEdge(source="id_x", asset_reference="Nonexistent System")
            ],
        )
        bundle = build_stix_bundle_from_extraction(ext, assets=_ASSETS_FOR_IAE)
        rels = [
            o
            for o in bundle["objects"]
            if o["type"] == "relationship" and o["relationship_type"] == "x-trace-has-access"
        ]
        assert rels == []
        x_asset = [o for o in bundle["objects"] if o["type"] == "x-asset-internal"]
        assert x_asset == []

    def test_no_assets_supplied_drops_all_edges_silently(self):
        ext = Extraction(
            entities=[_ent("id_x", "identity", "X")],
            identity_asset_edges=[IdentityAssetEdge(source="id_x", asset_reference="ERP System")],
        )
        # No assets= argument — assembler can't resolve, drops all edges.
        bundle = build_stix_bundle_from_extraction(ext)
        rels = [
            o
            for o in bundle["objects"]
            if o["type"] == "relationship" and o["relationship_type"] == "x-trace-has-access"
        ]
        assert rels == []

    def test_non_identity_source_is_dropped(self):
        ext = Extraction(
            entities=[_ent("a", "intrusion-set", "FIN7")],
            identity_asset_edges=[IdentityAssetEdge(source="a", asset_reference="ERP System")],
        )
        bundle = build_stix_bundle_from_extraction(ext, assets=_ASSETS_FOR_IAE)
        rels = [
            o
            for o in bundle["objects"]
            if o["type"] == "relationship" and o["relationship_type"] == "x-trace-has-access"
        ]
        assert rels == []

    def test_two_identities_same_asset_dedupes_x_asset_internal(self):
        ext = Extraction(
            entities=[
                _ent("id_alice", "identity", "Alice", identity_class="individual"),
                _ent("id_bob", "identity", "Bob", identity_class="individual"),
            ],
            identity_asset_edges=[
                IdentityAssetEdge(source="id_alice", asset_reference="ERP System"),
                IdentityAssetEdge(source="id_bob", asset_reference="ERP System"),
            ],
        )
        bundle = build_stix_bundle_from_extraction(ext, assets=_ASSETS_FOR_IAE)
        # One synthesized x-asset-internal object reused, two relationships.
        x_asset = [o for o in bundle["objects"] if o["type"] == "x-asset-internal"]
        assert len(x_asset) == 1
        rels = [
            o
            for o in bundle["objects"]
            if o["type"] == "relationship" and o["relationship_type"] == "x-trace-has-access"
        ]
        assert len(rels) == 2

    def test_unresolved_source_local_id_drops(self):
        ext = Extraction(
            entities=[],
            identity_asset_edges=[IdentityAssetEdge(source="ghost", asset_reference="ERP System")],
        )
        bundle = build_stix_bundle_from_extraction(ext, assets=_ASSETS_FOR_IAE)
        rels = [
            o
            for o in bundle["objects"]
            if o["type"] == "relationship" and o["relationship_type"] == "x-trace-has-access"
        ]
        assert rels == []
