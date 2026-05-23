"""Tests for the RSS/Atom feed expansion path in ``crawler/batch``.

Covers:

- HTTP Content-Type auto-detect routes a feed source through expansion.
- ``sources.yaml.feed_type`` override forces expansion when the server
  returns a misleading Content-Type.
- ``TRACE_FEED_MAX_ENTRIES`` caps the per-feed entry count.
- Transient feed-fetch failures retry 3× and recover.
- Persistent feed-fetch failures emit a structured giveup log and skip
  the feed (other sources keep processing).
- HTML sources pass through unchanged (no extra fetch, no expansion).
- Each feed entry's URL is independently keyed in ``CrawlState``.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from trace_engine.config import Config
from trace_engine.crawler import batch as batch_mod
from trace_engine.crawler.fetcher import FetchError, FetchResult
from trace_engine.crawler.state import CrawlState
from trace_engine.pir.relevance import RelevanceVerdict
from trace_engine.stix.extractor import ExtractedEntity, Extraction
from trace_engine.validate.schema import PIRDocument, SourceEntry, SourcesDocument

FIXTURES = Path(__file__).parent / "fixtures"
RSS_BYTES = (FIXTURES / "sample_rss.xml").read_bytes()
ATOM_BYTES = (FIXTURES / "sample_atom.xml").read_bytes()


def _verdict(kept: bool = True) -> RelevanceVerdict:
    return RelevanceVerdict(
        score=0.9 if kept else 0.1,
        matched_pir_ids=["PIR-TEST-001"] if kept else [],
        rationale="ok",
    )


def _extr(local_id: str = "a") -> Extraction:
    return Extraction(
        entities=[
            ExtractedEntity(
                local_id=local_id,
                type="threat-actor",
                properties={"name": local_id},
            )
        ]
    )


@pytest.fixture
def pir_doc() -> PIRDocument:
    with (FIXTURES / "valid_pir.json").open() as f:
        return PIRDocument.from_payload(json.load(f))


@pytest.fixture
def cfg() -> Config:
    # Wide since-window so the RSS fixture's 2026-05 entries qualify even
    # when the actual clock moves; the 2018 archive entry is still filtered.
    return Config(
        gcp_project_id="test",
        relevance_threshold=0.5,
        feed_max_entries=50,
        feed_since_days=180,
    )


def _html_fetch(url: str, body: bytes = b"<html>article</html>") -> FetchResult:
    return FetchResult(url=url, status_code=200, content=body, content_type="text/html")


class TestExpandSources:
    """Direct tests of ``_expand_sources`` using its injection points."""

    def test_html_source_passes_through_unchanged(self, cfg: Config):
        src = SourceEntry(url="https://example.com/page", label="page", task="medium")

        def head(url: str, c: Config) -> str | None:
            return "text/html; charset=utf-8"

        out = list(
            batch_mod._expand_sources(
                [src],
                cfg=cfg,
                sleep=lambda _: None,
                head_request=head,
            )
        )
        assert out == [src]

    def test_rss_auto_detected_via_content_type(self, cfg: Config):
        src = SourceEntry(url="https://example.com/feed.rss", label="rss-feed", task="medium")
        out = list(
            batch_mod._expand_sources(
                [src],
                cfg=cfg,
                sleep=lambda _: None,
                head_request=lambda u, c: "application/rss+xml",
                feed_fetch=lambda u, c: RSS_BYTES,
            )
        )
        urls = [s.url for s in out]
        # 2018 archive entry filtered by the 180-day since window; 2026
        # entries kept.
        assert urls == [
            "https://example.com/blog/apt-x-finance",
            "https://example.com/blog/ransomware-rebrand",
        ]
        for s in out:
            assert s.feed_type == "html"  # children never re-expand
            assert s.task == "medium"
            assert s.label.startswith("rss-feed: ")

    def test_atom_override_beats_html_header(self, cfg: Config):
        src = SourceEntry(
            url="https://csirt.example.org/atom",
            label="csirt",
            task="medium",
            feed_type="atom",
        )

        def head(*_):
            raise AssertionError("HEAD must not run when override is set")

        out = list(
            batch_mod._expand_sources(
                [src],
                cfg=cfg,
                sleep=lambda _: None,
                head_request=head,
                feed_fetch=lambda u, c: ATOM_BYTES,
            )
        )
        urls = [s.url for s in out]
        assert urls == [
            "https://csirt.example.org/advisory/2026-001",
            "https://csirt.example.org/advisory/2026-002",
        ]

    def test_max_entries_caps_result(self):
        src = SourceEntry(
            url="https://example.com/feed.rss",
            label="rss",
            task="medium",
            feed_type="rss",
        )
        cfg = Config(
            gcp_project_id="test",
            feed_max_entries=1,
            feed_since_days=3650,  # disable since-filter so cap is the only limit
        )
        out = list(
            batch_mod._expand_sources(
                [src],
                cfg=cfg,
                sleep=lambda _: None,
                head_request=lambda u, c: None,
                feed_fetch=lambda u, c: RSS_BYTES,
            )
        )
        assert len(out) == 1
        assert out[0].url == "https://example.com/blog/apt-x-finance"

    def test_since_filter_drops_old_entries(self):
        src = SourceEntry(
            url="https://example.com/feed.rss",
            label="rss",
            task="medium",
            feed_type="rss",
        )
        cfg = Config(
            gcp_project_id="test",
            feed_max_entries=100,
            feed_since_days=180,
        )
        out = list(
            batch_mod._expand_sources(
                [src],
                cfg=cfg,
                sleep=lambda _: None,
                head_request=lambda u, c: None,
                feed_fetch=lambda u, c: RSS_BYTES,
            )
        )
        urls = [s.url for s in out]
        assert "https://example.com/blog/2018-archive-post" not in urls
        assert urls == [
            "https://example.com/blog/apt-x-finance",
            "https://example.com/blog/ransomware-rebrand",
        ]

    def test_transient_feed_fetch_retries_then_succeeds(self, cfg: Config):
        src = SourceEntry(
            url="https://example.com/feed.rss",
            label="rss",
            task="medium",
            feed_type="rss",
        )
        attempts = {"n": 0}
        waits: list[float] = []

        def flaky_fetch(url: str, c: Config) -> bytes:
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise FetchError(f"transient {attempts['n']}")
            return RSS_BYTES

        out = list(
            batch_mod._expand_sources(
                [src],
                cfg=cfg,
                sleep=waits.append,
                head_request=lambda u, c: None,
                feed_fetch=flaky_fetch,
            )
        )
        assert attempts["n"] == 3
        # 2 retries before success → backoff 1s then 2s.
        assert waits == [1.0, 2.0]
        assert len(out) == 2

    def test_persistent_feed_fetch_failure_skips_source(self, cfg: Config, caplog):
        good = SourceEntry(
            url="https://example.com/article",
            label="article",
            task="medium",
        )
        bad = SourceEntry(
            url="https://example.com/feed.rss",
            label="rss",
            task="medium",
            feed_type="rss",
        )
        waits: list[float] = []

        def always_fail(url: str, c: Config) -> bytes:
            raise FetchError("upstream 503")

        out = list(
            batch_mod._expand_sources(
                [bad, good],
                cfg=cfg,
                sleep=waits.append,
                head_request=lambda u, c: "text/html",
                feed_fetch=always_fail,
            )
        )
        # bad feed contributes 0 entries; good html source passes through.
        assert out == [good]
        # 3 retries between 4 attempts → backoff sequence 1s/2s/4s.
        assert waits == [1.0, 2.0, 4.0]

    def test_persistent_parse_failure_skips_source(self, cfg: Config):
        src = SourceEntry(
            url="https://example.com/feed.rss",
            label="rss",
            task="medium",
            feed_type="rss",
        )
        waits: list[float] = []
        out = list(
            batch_mod._expand_sources(
                [src],
                cfg=cfg,
                sleep=waits.append,
                head_request=lambda u, c: None,
                feed_fetch=lambda u, c: b"\x00\x01\x02 garbage",
            )
        )
        assert out == []
        assert waits == [1.0, 2.0, 4.0]


class TestCrawlBatchEndToEnd:
    """Drive ``crawl_batch`` with a feed source mocked at the module level."""

    def test_feed_entries_processed_with_relevance_gate(
        self, tmp_path: Path, cfg: Config, pir_doc: PIRDocument
    ):
        sources = SourcesDocument(
            sources=[
                SourceEntry(
                    url="https://example.com/feed.rss",
                    label="rss",
                    task="medium",
                    feed_type="rss",
                )
            ]
        )
        state = CrawlState.load(tmp_path / "state.json")
        written: dict[Path, dict] = {}

        def write_bundle(p: Path, b: dict) -> None:
            written[p] = b

        # Each per-entry article fetch returns html bytes; relevance kept.
        with (
            patch.object(batch_mod, "_fetch_feed_bytes", return_value=RSS_BYTES),
            patch.object(batch_mod, "_head_content_type", return_value="application/rss+xml"),
            patch.object(
                batch_mod,
                "fetch",
                side_effect=lambda url, config=None: _html_fetch(
                    url, b"<html>" + url.encode() + b"</html>"
                ),
            ),
            patch.object(batch_mod, "read_report", return_value="article body"),
            patch.object(batch_mod.pir_relevance, "evaluate", return_value=_verdict(kept=True)),
            patch.object(batch_mod, "extract_entities", return_value=_extr("e1")),
        ):
            outcomes = list(
                batch_mod.crawl_batch(
                    sources,
                    state=state,
                    output_dir=tmp_path,
                    pir_doc=pir_doc,
                    config=cfg,
                    write_bundle=write_bundle,
                )
            )

        # Two 2026 entries survive the since-180 filter; both extracted.
        assert [o.kind for o in outcomes] == ["extracted", "extracted"]
        urls = sorted(o.url for o in outcomes)
        assert urls == [
            "https://example.com/blog/apt-x-finance",
            "https://example.com/blog/ransomware-rebrand",
        ]
        # State is keyed by entry URL, not the feed URL.
        assert state.get("https://example.com/feed.rss") is None
        assert state.get("https://example.com/blog/apt-x-finance") is not None
        assert state.get("https://example.com/blog/ransomware-rebrand") is not None

    def test_html_source_unchanged_no_head_request(
        self, tmp_path: Path, cfg: Config, pir_doc: PIRDocument
    ):
        # When feed_type is explicitly html, the auto-detect HEAD must not run.
        sources = SourcesDocument(
            sources=[
                SourceEntry(
                    url="https://example.com/article",
                    label="article",
                    task="medium",
                    feed_type="html",
                )
            ]
        )
        state = CrawlState.load(tmp_path / "state.json")

        def head_explodes(*_, **__):
            raise AssertionError("HEAD must not run for explicit html source")

        with (
            patch.object(batch_mod, "_head_content_type", side_effect=head_explodes),
            patch.object(batch_mod, "fetch", return_value=_html_fetch("u")),
            patch.object(batch_mod, "read_report", return_value="article body"),
            patch.object(batch_mod.pir_relevance, "evaluate", return_value=_verdict(kept=True)),
            patch.object(batch_mod, "extract_entities", return_value=_extr("e1")),
        ):
            outcomes = list(
                batch_mod.crawl_batch(
                    sources,
                    state=state,
                    output_dir=tmp_path,
                    pir_doc=pir_doc,
                    config=cfg,
                    write_bundle=lambda p, b: None,
                )
            )

        assert [o.kind for o in outcomes] == ["extracted"]
