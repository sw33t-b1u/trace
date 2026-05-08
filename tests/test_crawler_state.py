"""Tests for ``trace_engine.crawler.state.CrawlState``."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trace_engine.crawler.state import (
    STATE_VERSION,
    CrawlState,
    RelevanceRecord,
    content_sha256,
)


def test_load_missing_returns_empty(tmp_path: Path) -> None:
    state = CrawlState.load(tmp_path / "missing.json")
    assert state.entries == {}


def test_round_trip(tmp_path: Path) -> None:
    p = tmp_path / "crawl_state.json"
    s1 = CrawlState.load(p)
    s1.upsert(
        "https://example.com/a",
        content_sha256="aa",
        bundle_path="output/a.json",
        relevance=RelevanceRecord(decision="kept", score=0.8, matched_pir_ids=["PIR-1"]),
    )
    s1.save()

    raw = json.loads(p.read_text())
    assert raw["version"] == STATE_VERSION
    assert "https://example.com/a" in raw["entries"]

    s2 = CrawlState.load(p)
    e = s2.get("https://example.com/a")
    assert e is not None
    assert e.content_sha256 == "aa"
    assert e.relevance.decision == "kept"
    assert e.relevance.matched_pir_ids == ["PIR-1"]


def test_first_seen_preserved_across_upsert(tmp_path: Path) -> None:
    state = CrawlState.load(tmp_path / "s.json")
    state.upsert(
        "https://example.com/x",
        content_sha256="aa",
        bundle_path=None,
        relevance=RelevanceRecord(decision="no_pir"),
        now="2026-01-01T00:00:00.000Z",
    )
    state.upsert(
        "https://example.com/x",
        content_sha256="bb",
        bundle_path=None,
        relevance=RelevanceRecord(decision="no_pir"),
        now="2026-02-01T00:00:00.000Z",
    )
    e = state.get("https://example.com/x")
    assert e is not None
    assert e.first_seen == "2026-01-01T00:00:00.000Z"
    assert e.last_seen == "2026-02-01T00:00:00.000Z"


def test_unsupported_version_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"version": 999, "entries": {}}))
    with pytest.raises(ValueError, match="Unsupported"):
        CrawlState.load(p)


def test_content_sha256_stable() -> None:
    assert content_sha256("abc") == content_sha256(b"abc")
    assert content_sha256("abc") != content_sha256("abd")
