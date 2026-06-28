"""Tests for RSS/Atom candidate discovery."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from trace_engine.config import Config
from trace_engine.discovery.catalog import load_catalog
from trace_engine.discovery.feed_search import discover_candidates
from trace_engine.validate.schema import PIRDocument

FIXTURES = Path(__file__).parent / "fixtures"


def _pir_doc() -> PIRDocument:
    payload = json.loads((FIXTURES / "valid_pir.json").read_text(encoding="utf-8"))
    payload["pirs"][0]["description"] = "Track Salt Typhoon telecom edge VPN activity."
    payload["pirs"][0]["threat_actor_tags"] = ["apt-china"]
    payload["pirs"][0]["notable_groups"] = ["Salt Typhoon"]
    return PIRDocument.from_payload(payload)


def test_discover_candidates_filters_scores_and_dedupes_feed_entries() -> None:
    catalog = load_catalog(FIXTURES / "discovery_source_catalog.yaml")
    feed_bytes = (FIXTURES / "discovery_sample_rss.xml").read_bytes()

    candidates = discover_candidates(
        _pir_doc(),
        catalog,
        start_date=date(2026, 6, 1),
        end_date=date(2026, 6, 30),
        config=Config(gcp_project_id="test"),
        fetch_feed=lambda _url, _cfg: feed_bytes,
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.url == "https://example.com/research/salt-typhoon-edge-vpn"
    assert candidate.source_name == "Example CTI Feed"
    assert candidate.matched_pir_ids == ["PIR-TEST-001"]
    assert {"apt-china", "salt typhoon"}.issubset(set(candidate.matched_terms))
    assert candidate.score > 0.5


def test_discover_candidates_returns_empty_when_no_terms_match() -> None:
    catalog = load_catalog(FIXTURES / "discovery_source_catalog.yaml")
    feed = b"""
    <rss version='2.0'>
      <channel>
        <item>
          <title>Unrelated</title>
          <link>https://example.com/a</link>
          <pubDate>Mon, 15 Jun 2026 10:00:00 GMT</pubDate>
        </item>
      </channel>
    </rss>
    """

    candidates = discover_candidates(
        _pir_doc(),
        catalog,
        start_date=date(2026, 6, 1),
        end_date=date(2026, 6, 30),
        config=Config(gcp_project_id="test"),
        fetch_feed=lambda _url, _cfg: feed,
    )

    assert candidates == []
