"""Tests for stix/extractor.py."""

from __future__ import annotations

import json
from unittest.mock import patch

from trace_engine.stix.extractor import _VALID_STIX_TYPES, build_stix_bundle, extract_stix_objects


def _make_stix_obj(type_: str, name: str = "Test") -> dict:
    return {
        "type": type_,
        "id": f"{type_}--aaaaaaaa-0000-0000-0000-000000000001",
        "spec_version": "2.1",
        "created": "2026-04-11T00:00:00.000Z",
        "modified": "2026-04-11T00:00:00.000Z",
        "name": name,
    }


def _as_json(value) -> str:
    """Serialize a Python value as JSON string (simulates LLM plain-text output)."""
    return json.dumps(value)


class TestExtractStixObjects:
    def _patch_llm(self, return_value):
        # call_llm now returns a plain-text string; serialize the value as JSON
        return patch("trace_engine.stix.extractor.call_llm", return_value=_as_json(return_value))

    def test_returns_list_from_bare_array(self):
        objects = [_make_stix_obj("intrusion-set", "APT1")]
        with self._patch_llm(objects):
            result = extract_stix_objects("some CTI text")
        assert len(result) == 1
        assert result[0]["name"] == "APT1"

    def test_returns_list_from_wrapped_dict(self):
        objects = [_make_stix_obj("malware", "LODEINFO")]
        with self._patch_llm({"objects": objects}):
            result = extract_stix_objects("some CTI text")
        assert len(result) == 1

    def test_filters_unknown_types(self):
        objects = [
            _make_stix_obj("intrusion-set", "APT1"),
            {"type": "x-custom-thing", "id": "x-custom-thing--1234", "name": "noise"},
        ]
        with self._patch_llm(objects):
            result = extract_stix_objects("text")
        assert len(result) == 1
        assert result[0]["type"] == "intrusion-set"

    def test_handles_unexpected_response_format(self):
        # plain string that is not JSON → _extract_json_from_text returns None
        with patch("trace_engine.stix.extractor.call_llm", return_value="not json at all"):
            result = extract_stix_objects("text")
        assert result == []

    def test_accepts_all_valid_stix_types(self):
        objects = [_make_stix_obj(t) for t in _VALID_STIX_TYPES]
        with self._patch_llm(objects):
            result = extract_stix_objects("text")
        assert len(result) == len(_VALID_STIX_TYPES)

    def test_filters_non_dict_entries(self):
        objects = [
            _make_stix_obj("malware", "X"),
            "not a dict",
            42,
            None,
        ]
        with self._patch_llm(objects):
            result = extract_stix_objects("text")
        assert len(result) == 1

    def test_prompt_contains_report_text(self):
        with patch("trace_engine.stix.extractor.call_llm", return_value="[]") as mock_call:
            extract_stix_objects("CVE-2023-3519 exploitation report")
        prompt_arg = mock_call.call_args[0][1]  # positional arg: prompt
        assert "CVE-2023-3519" in prompt_arg

    def test_uses_medium_task_type_by_default(self):
        with patch("trace_engine.stix.extractor.call_llm", return_value="[]") as mock_call:
            extract_stix_objects("text")
        task_arg = mock_call.call_args[0][0]
        assert task_arg == "medium"

    def test_accepts_complex_task_override(self):
        with patch("trace_engine.stix.extractor.call_llm", return_value="[]") as mock_call:
            extract_stix_objects("text", task="complex")
        task_arg = mock_call.call_args[0][0]
        assert task_arg == "complex"


class TestBuildStixBundle:
    def test_bundle_has_required_fields(self):
        bundle = build_stix_bundle([])
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert bundle["id"].startswith("bundle--")
        assert isinstance(bundle["objects"], list)

    def test_bundle_id_is_unique(self):
        b1 = build_stix_bundle([])
        b2 = build_stix_bundle([])
        assert b1["id"] != b2["id"]

    def test_bundle_includes_objects(self):
        obj = _make_stix_obj("malware", "TestMalware")
        bundle = build_stix_bundle([obj])
        assert len(bundle["objects"]) == 1
        assert bundle["objects"][0]["name"] == "TestMalware"

    def test_bundle_created_timestamp_format(self):
        bundle = build_stix_bundle([])
        # Should match "YYYY-MM-DDTHH:MM:SS.000Z"
        assert bundle["created"].endswith(".000Z")
        assert "T" in bundle["created"]
