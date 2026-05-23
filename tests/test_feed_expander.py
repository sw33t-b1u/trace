"""Tests for ``crawler/feed_expander.expand_feed``."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from trace_engine.crawler.feed_expander import FeedParseError, expand_feed

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


class TestRSS:
    def test_returns_all_entry_urls(self):
        entries = expand_feed(_load("sample_rss.xml"))
        urls = [e.url for e in entries]
        assert urls == [
            "https://example.com/blog/apt-x-finance",
            "https://example.com/blog/ransomware-rebrand",
            "https://example.com/blog/2018-archive-post",
        ]

    def test_first_entry_metadata(self):
        entries = expand_feed(_load("sample_rss.xml"))
        first = entries[0]
        assert first.title == "APT-X targets finance sector"
        assert first.published == datetime(2026, 5, 20, 10, 0, 0, tzinfo=UTC)

    def test_archive_entry_published_parsed(self):
        entries = expand_feed(_load("sample_rss.xml"))
        archive = entries[2]
        assert archive.published == datetime(2018, 7, 3, 8, 0, 0, tzinfo=UTC)


class TestAtom:
    def test_returns_all_entry_urls(self):
        entries = expand_feed(_load("sample_atom.xml"))
        urls = [e.url for e in entries]
        assert urls == [
            "https://csirt.example.org/advisory/2026-001",
            "https://csirt.example.org/advisory/2026-002",
        ]

    def test_atom_entry_metadata(self):
        entries = expand_feed(_load("sample_atom.xml"))
        first = entries[0]
        assert first.title == "Advisory 2026-001: zero-day in MailGateway"
        assert first.published == datetime(2026, 5, 22, 11, 30, 0, tzinfo=UTC)


class TestMalformed:
    def test_raises_on_garbage_payload(self):
        with pytest.raises(FeedParseError) as exc_info:
            expand_feed(b"\x00\x01\x02 not xml at all", feed_url="https://broken.example/")
        assert "https://broken.example/" in str(exc_info.value)

    def test_does_not_raise_when_feedparser_recovers_entries(self):
        # Truncated but recoverable: feedparser sets bozo=True yet still
        # parses the partial entry. Recoverable feeds should NOT raise —
        # we only fail when there are zero entries AND bozo=True.
        body = b"<rss><channel><item><title>partial</title><link>https://x.test/p</link>"
        entries = expand_feed(body)
        assert len(entries) == 1
        assert entries[0].url == "https://x.test/p"

    def test_empty_feed_no_entries_returns_empty_list(self):
        # A well-formed feed with zero items should return [] and NOT raise.
        body = b'<?xml version="1.0"?><rss version="2.0"><channel><title>x</title></channel></rss>'
        assert expand_feed(body) == []
