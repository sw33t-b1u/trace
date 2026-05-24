"""Tests for ``trace_engine.ingest.ioc_extractor`` (Initiative G Phase 4)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from trace_engine.ingest.ioc_extractor import (
    IoC,
    IoCType,
    extract_iocs,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


# ---------------------------------------------------------------------------
# IoC Pydantic model
# ---------------------------------------------------------------------------


class TestIoCModel:
    def test_valid_entry_round_trips(self):
        ioc = IoC.model_validate(
            {
                "type": "fqdn",
                "value": "evil.example.com",
                "confidence": 0.9,
                "context_snippet": "C2 endpoint at evil.example.com",
            }
        )
        assert ioc.type is IoCType.FQDN
        assert ioc.value == "evil.example.com"
        assert ioc.confidence == 0.9
        assert ioc.context_snippet == "C2 endpoint at evil.example.com"

    def test_value_stripped(self):
        ioc = IoC.model_validate(
            {
                "type": "ipv4",
                "value": "  192.0.2.10  ",
                "confidence": 0.8,
            }
        )
        assert ioc.value == "192.0.2.10"

    def test_value_must_not_be_blank(self):
        with pytest.raises(ValidationError):
            IoC.model_validate({"type": "ipv4", "value": "   ", "confidence": 0.5})

    def test_confidence_out_of_range_rejected(self):
        with pytest.raises(ValidationError):
            IoC.model_validate({"type": "ipv4", "value": "1.2.3.4", "confidence": 1.5})

    def test_unknown_type_rejected(self):
        with pytest.raises(ValidationError):
            IoC.model_validate({"type": "registry_key", "value": "HKLM\\Run", "confidence": 0.5})

    def test_extra_field_rejected_strict_mode(self):
        with pytest.raises(ValidationError):
            IoC.model_validate(
                {
                    "type": "ipv4",
                    "value": "1.2.3.4",
                    "confidence": 0.5,
                    "unexpected": "field",
                }
            )

    def test_context_snippet_default_empty(self):
        ioc = IoC.model_validate({"type": "ipv4", "value": "1.2.3.4", "confidence": 0.5})
        assert ioc.context_snippet == ""

    def test_context_snippet_truncated_at_50(self):
        long_snippet = "a" * 100
        ioc = IoC.model_validate(
            {
                "type": "ipv4",
                "value": "1.2.3.4",
                "confidence": 0.5,
                "context_snippet": long_snippet,
            }
        )
        assert len(ioc.context_snippet) == 50

    def test_context_snippet_collapses_whitespace(self):
        ioc = IoC.model_validate(
            {
                "type": "ipv4",
                "value": "1.2.3.4",
                "confidence": 0.5,
                "context_snippet": "C2 endpoint\nat\t192.0.2.10",
            }
        )
        assert "\n" not in ioc.context_snippet
        assert "\t" not in ioc.context_snippet
        assert ioc.context_snippet == "C2 endpoint at 192.0.2.10"


# ---------------------------------------------------------------------------
# extract_iocs helper
# ---------------------------------------------------------------------------


class TestExtractIocs:
    def test_none_returns_empty(self):
        assert extract_iocs(None) == []

    def test_empty_list_returns_empty(self):
        assert extract_iocs([]) == []

    def test_non_list_input_returns_empty(self):
        # Dict / str / int payloads are unparseable — should not crash.
        assert extract_iocs({"value": "x"}) == []
        assert extract_iocs("not a list") == []
        assert extract_iocs(42) == []

    def test_valid_fixture_round_trips(self):
        fixture = _load_fixture("llm_response_with_iocs.json")
        validated = extract_iocs(fixture["iocs"], article_url="https://example.com/x")
        assert len(validated) == 4
        types = [v["type"] for v in validated]
        assert types == ["fqdn", "ipv4", "sha256", "cve_id"]

    def test_each_entry_serialisable_to_json(self):
        """Output dicts must round-trip through json.dumps without a model dump."""
        fixture = _load_fixture("llm_response_with_iocs.json")
        validated = extract_iocs(fixture["iocs"])
        serialised = json.dumps(validated)
        round_tripped = json.loads(serialised)
        assert round_tripped == validated

    def test_malformed_entry_dropped_individually(self):
        """A single bad entry must NOT drop valid neighbours."""
        raw = [
            {"type": "fqdn", "value": "evil.example.com", "confidence": 0.9},
            {"type": "registry_key", "value": "x", "confidence": 0.5},  # bad type
            {"type": "ipv4", "value": "1.2.3.4", "confidence": 0.8},
        ]
        validated = extract_iocs(raw)
        assert len(validated) == 2
        assert [v["type"] for v in validated] == ["fqdn", "ipv4"]

    def test_non_dict_entry_dropped(self):
        raw = [
            "evil.example.com",  # string entry — should drop
            {"type": "fqdn", "value": "evil.example.com", "confidence": 0.9},
        ]
        validated = extract_iocs(raw)
        assert len(validated) == 1
        assert validated[0]["value"] == "evil.example.com"

    def test_mixed_types_all_accepted(self):
        raw = [
            {"type": t, "value": f"value-{t}", "confidence": 0.5}
            for t in ["ipv4", "ipv6", "fqdn", "sha256", "sha1", "md5", "cve_id"]
        ]
        validated = extract_iocs(raw)
        assert len(validated) == 7

    def test_missing_required_field_drops_entry(self):
        raw = [
            {"type": "fqdn", "confidence": 0.9},  # missing value
            {"type": "fqdn", "value": "ok.example.com", "confidence": 0.9},
        ]
        validated = extract_iocs(raw)
        assert len(validated) == 1
        assert validated[0]["value"] == "ok.example.com"

    def test_extra_field_drops_entry(self):
        """extra='forbid' on IoC model — entries with unexpected keys drop."""
        raw = [
            {
                "type": "fqdn",
                "value": "evil.example.com",
                "confidence": 0.9,
                "extra_key": "rejected",
            }
        ]
        validated = extract_iocs(raw)
        assert validated == []

    def test_confidence_out_of_range_drops_entry(self):
        raw = [
            {"type": "ipv4", "value": "1.2.3.4", "confidence": 2.0},
        ]
        validated = extract_iocs(raw)
        assert validated == []
