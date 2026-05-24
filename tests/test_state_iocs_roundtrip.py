"""Round-trip tests for ``StateEntry.iocs`` (Initiative G Phase 4)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trace_engine.crawler.state import (
    STATE_VERSION,
    CrawlState,
    RelevanceRecord,
    StateEntry,
)

URL = "https://example.com/article"


def _relevance() -> RelevanceRecord:
    return RelevanceRecord(
        decision="kept",
        score=0.85,
        matched_pir_ids=["PIR-G-001"],
        rationale="active campaign",
        pir_set_hash="cafef00d",
    )


def _iocs() -> list[dict]:
    return [
        {
            "type": "fqdn",
            "value": "evil.example.com",
            "confidence": 0.95,
            "context_snippet": "C2 endpoint at evil.example.com",
        },
        {
            "type": "ipv4",
            "value": "192.0.2.10",
            "confidence": 0.9,
            "context_snippet": "hosted on 192.0.2.10",
        },
        {
            "type": "cve_id",
            "value": "CVE-2026-12345",
            "confidence": 0.97,
            "context_snippet": "exploited CVE-2026-12345 to elevate",
        },
    ]


class TestStateEntryRoundTrip:
    def test_iocs_serialised_in_as_dict(self):
        entry = StateEntry(
            first_seen="2026-05-24T10:00:00.000Z",
            last_seen="2026-05-24T11:00:00.000Z",
            content_sha256="abc",
            bundle_path="output/bundle.json",
            relevance=_relevance(),
            iocs=_iocs(),
        )
        d = entry.as_dict()
        assert d["iocs"] == _iocs()

    def test_iocs_round_trip_via_from_dict(self):
        entry = StateEntry(
            first_seen="2026-05-24T10:00:00.000Z",
            last_seen="2026-05-24T11:00:00.000Z",
            content_sha256="abc",
            bundle_path=None,
            relevance=_relevance(),
            iocs=_iocs(),
        )
        restored = StateEntry.from_dict(entry.as_dict())
        assert restored.iocs == _iocs()

    def test_iocs_missing_field_loads_as_empty_list(self):
        """Backward-compat: pre-Phase-4 state files have no iocs field."""
        legacy_payload = {
            "first_seen": "2026-05-23T10:00:00.000Z",
            "last_seen": "2026-05-23T11:00:00.000Z",
            "content_sha256": "abc",
            "bundle_path": None,
            "relevance": _relevance().as_dict(),
            # NOTE: no "iocs" key
        }
        restored = StateEntry.from_dict(legacy_payload)
        assert restored.iocs == []

    def test_iocs_null_field_loads_as_empty_list(self):
        """Defensive: an explicit null also normalises to []."""
        payload = {
            "first_seen": "2026-05-23T10:00:00.000Z",
            "last_seen": "2026-05-23T11:00:00.000Z",
            "content_sha256": "abc",
            "bundle_path": None,
            "relevance": _relevance().as_dict(),
            "iocs": None,
        }
        restored = StateEntry.from_dict(payload)
        assert restored.iocs == []


class TestCrawlStateRoundTrip:
    def test_save_and_load_preserves_iocs(self, tmp_path):
        state_path = tmp_path / "crawl_state.json"
        state = CrawlState(state_path)
        state.upsert(
            URL,
            content_sha256="abc",
            bundle_path="output/bundle.json",
            relevance=_relevance(),
            iocs=_iocs(),
        )
        state.save()

        # File on disk carries iocs
        raw = json.loads(state_path.read_text())
        assert raw["version"] == STATE_VERSION
        assert raw["entries"][URL]["iocs"] == _iocs()

        # Reload via CrawlState.load reconstructs them
        reloaded = CrawlState.load(state_path)
        entry = reloaded.get(URL)
        assert entry is not None
        assert entry.iocs == _iocs()

    def test_upsert_without_iocs_persists_empty_list(self, tmp_path):
        """Crawls before Phase 4 wired iocs in pass iocs=None — should store []."""
        state_path = tmp_path / "crawl_state.json"
        state = CrawlState(state_path)
        state.upsert(
            URL,
            content_sha256="abc",
            bundle_path=None,
            relevance=_relevance(),
        )
        state.save()
        reloaded = CrawlState.load(state_path)
        entry = reloaded.get(URL)
        assert entry is not None
        assert entry.iocs == []

    def test_legacy_state_file_loads_with_empty_iocs(self, tmp_path):
        """Hand-written legacy state.json (no iocs key) is forward-compatible."""
        state_path = tmp_path / "crawl_state.json"
        legacy = {
            "version": STATE_VERSION,
            "entries": {
                URL: {
                    "first_seen": "2026-05-23T10:00:00.000Z",
                    "last_seen": "2026-05-23T11:00:00.000Z",
                    "content_sha256": "abc",
                    "bundle_path": None,
                    "relevance": _relevance().as_dict(),
                }
            },
        }
        state_path.write_text(json.dumps(legacy))
        reloaded = CrawlState.load(state_path)
        entry = reloaded.get(URL)
        assert entry is not None
        assert entry.iocs == []

    def test_upsert_replaces_iocs_on_re_visit(self, tmp_path):
        """Re-upsert on the same URL replaces the iocs list (no append)."""
        state_path = tmp_path / "crawl_state.json"
        state = CrawlState(state_path)
        state.upsert(
            URL,
            content_sha256="abc",
            bundle_path=None,
            relevance=_relevance(),
            iocs=[{"type": "ipv4", "value": "1.1.1.1", "confidence": 0.5}],
        )
        state.upsert(
            URL,
            content_sha256="abc2",
            bundle_path=None,
            relevance=_relevance(),
            iocs=_iocs(),
        )
        assert state.get(URL).iocs == _iocs()


class TestRelevanceVerdictIntegration:
    """End-to-end shape check: LLM dict → RelevanceVerdict.iocs → state."""

    def test_verdict_iocs_persist_via_upsert(self, tmp_path):
        # Avoid importing trace_engine.pir.relevance until we need it so
        # this test only exercises the data path, not the LLM call.
        from trace_engine.pir.relevance import _verdict_from_dict

        llm_response = json.loads(
            (Path(__file__).parent / "fixtures" / "llm_response_with_iocs.json").read_text()
        )
        verdict = _verdict_from_dict(llm_response, article_url=URL)
        assert len(verdict.iocs) == 4

        state_path = tmp_path / "crawl_state.json"
        state = CrawlState(state_path)
        state.upsert(
            URL,
            content_sha256="abc",
            bundle_path=None,
            relevance=_relevance(),
            iocs=verdict.iocs,
        )
        state.save()
        reloaded = CrawlState.load(state_path)
        entry = reloaded.get(URL)
        assert entry is not None
        assert len(entry.iocs) == 4
        assert entry.iocs[0]["type"] == "fqdn"


@pytest.mark.parametrize(
    "ioc_type,value",
    [
        ("ipv4", "192.0.2.10"),
        ("ipv6", "2001:db8::1"),
        ("fqdn", "evil.example.com"),
        ("sha256", "a" * 64),
        ("sha1", "b" * 40),
        ("md5", "c" * 32),
        ("cve_id", "CVE-2026-12345"),
    ],
)
def test_all_seven_ioc_types_round_trip(tmp_path, ioc_type, value):
    """End-to-end: extract_iocs → state.upsert → save → load preserves the type."""
    from trace_engine.ingest.ioc_extractor import extract_iocs

    state_path = tmp_path / "crawl_state.json"
    state = CrawlState(state_path)
    validated = extract_iocs([{"type": ioc_type, "value": value, "confidence": 0.9}])
    state.upsert(
        URL,
        content_sha256="abc",
        bundle_path=None,
        relevance=_relevance(),
        iocs=validated,
    )
    state.save()
    reloaded = CrawlState.load(state_path)
    entry = reloaded.get(URL)
    assert entry is not None
    assert len(entry.iocs) == 1
    assert entry.iocs[0]["type"] == ioc_type
    assert entry.iocs[0]["value"] == value
    assert entry.iocs[0]["confidence"] == 0.9
