"""Tests for the batch crawl driver — fetch/state/relevance/extract dataflow."""

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


def _extr(local_id: str = "a", type_: str = "indicator") -> Extraction:
    return Extraction(
        entities=[ExtractedEntity(local_id=local_id, type=type_, properties={"name": local_id})]
    )


FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def pir_doc() -> PIRDocument:
    with (FIXTURES / "valid_pir.json").open() as f:
        return PIRDocument.from_payload(json.load(f))


@pytest.fixture
def cfg() -> Config:
    return Config(gcp_project_id="test", relevance_threshold=0.5)


def _sources(*urls: str) -> SourcesDocument:
    return SourcesDocument(sources=[SourceEntry(url=u, label=u, task="medium") for u in urls])


def _fetch_result(url: str, body: bytes = b"hello world") -> FetchResult:
    return FetchResult(url=url, status_code=200, content=body, content_type="text/html")


def _patch_pipeline(
    *, content: bytes, text: str, verdict: RelevanceVerdict, extraction: Extraction
):
    """Convenience wrapper patching the four downstream dependencies of crawl_batch."""
    return [
        patch.object(batch_mod, "fetch", return_value=_fetch_result("u", content)),
        patch.object(batch_mod, "read_report", return_value=text),
        patch.object(batch_mod.pir_relevance, "evaluate", return_value=verdict),
        patch.object(batch_mod, "extract_entities", return_value=extraction),
    ]


def test_unchanged_url_skipped_on_second_run(tmp_path: Path, cfg: Config) -> None:
    state = CrawlState.load(tmp_path / "state.json")
    sources = _sources("https://example.com/a")
    written: dict[Path, dict] = {}

    def write_bundle(p: Path, b: dict) -> None:
        written[p] = b

    # First run: fetch, extract.
    with (
        patch.object(batch_mod, "fetch", return_value=_fetch_result("https://example.com/a")),
        patch.object(batch_mod, "read_report", return_value="article body"),
        patch.object(batch_mod, "extract_entities", return_value=_extr("a", "threat-actor")),
    ):
        outcomes = list(
            batch_mod.crawl_batch(
                sources,
                state=state,
                output_dir=tmp_path,
                config=cfg,
                write_bundle=write_bundle,
            )
        )
    assert [o.kind for o in outcomes] == ["extracted"]
    assert len(written) == 1

    # Second run: same content sha → skipped without re-extracting.
    with (
        patch.object(batch_mod, "fetch", return_value=_fetch_result("https://example.com/a")),
        patch.object(batch_mod, "read_report", side_effect=AssertionError("must not run")),
        patch.object(batch_mod, "extract_entities", side_effect=AssertionError("must not run")),
    ):
        outcomes2 = list(
            batch_mod.crawl_batch(
                sources,
                state=state,
                output_dir=tmp_path,
                config=cfg,
                write_bundle=write_bundle,
            )
        )
    assert [o.kind for o in outcomes2] == ["skipped_unchanged"]


def test_changed_content_triggers_reextraction(tmp_path: Path, cfg: Config) -> None:
    state = CrawlState.load(tmp_path / "state.json")
    sources = _sources("https://example.com/a")
    write = lambda p, b: None  # noqa: E731

    with (
        patch.object(
            batch_mod, "fetch", return_value=_fetch_result("https://example.com/a", b"v1")
        ),
        patch.object(batch_mod, "read_report", return_value="v1 body"),
        patch.object(batch_mod, "extract_entities", return_value=_extr()),
    ):
        first = list(
            batch_mod.crawl_batch(
                sources, state=state, output_dir=tmp_path, config=cfg, write_bundle=write
            )
        )
    assert first[0].kind == "extracted"

    with (
        patch.object(
            batch_mod, "fetch", return_value=_fetch_result("https://example.com/a", b"v2")
        ),
        patch.object(batch_mod, "read_report", return_value="v2 body"),
        patch.object(batch_mod, "extract_entities", return_value=_extr()),
    ):
        second = list(
            batch_mod.crawl_batch(
                sources, state=state, output_dir=tmp_path, config=cfg, write_bundle=write
            )
        )
    assert [o.kind for o in second] == ["extracted"]


def test_below_threshold_skips_extraction(
    tmp_path: Path, cfg: Config, pir_doc: PIRDocument
) -> None:
    state = CrawlState.load(tmp_path / "state.json")
    sources = _sources("https://example.com/a")
    extract = patch.object(
        batch_mod, "extract_entities", side_effect=AssertionError("should not run")
    )

    with (
        patch.object(batch_mod, "fetch", return_value=_fetch_result("https://example.com/a")),
        patch.object(batch_mod, "read_report", return_value="off-topic body"),
        patch.object(
            batch_mod.pir_relevance,
            "evaluate",
            return_value=RelevanceVerdict(score=0.1, matched_pir_ids=[]),
        ),
        extract,
    ):
        outcomes = list(
            batch_mod.crawl_batch(
                sources,
                state=state,
                output_dir=tmp_path,
                pir_doc=pir_doc,
                pir_set_hash="hash-1",
                threshold=0.5,
                config=cfg,
                write_bundle=lambda p, b: None,
            )
        )
    assert [o.kind for o in outcomes] == ["skipped_below_threshold"]
    e = state.get("https://example.com/a")
    assert e is not None
    assert e.relevance.decision == "skipped_below_threshold"
    assert e.relevance.pir_set_hash == "hash-1"


def test_relevance_failure_falls_open(tmp_path: Path, cfg: Config, pir_doc: PIRDocument) -> None:
    state = CrawlState.load(tmp_path / "state.json")
    sources = _sources("https://example.com/a")

    with (
        patch.object(batch_mod, "fetch", return_value=_fetch_result("https://example.com/a")),
        patch.object(batch_mod, "read_report", return_value="article"),
        patch.object(
            batch_mod.pir_relevance,
            "evaluate",
            return_value=RelevanceVerdict(score=0.0, failed=True),
        ),
        patch.object(batch_mod, "extract_entities", return_value=_extr()),
    ):
        outcomes = list(
            batch_mod.crawl_batch(
                sources,
                state=state,
                output_dir=tmp_path,
                pir_doc=pir_doc,
                threshold=0.5,
                config=cfg,
                write_bundle=lambda p, b: None,
            )
        )
    # extraction_failed verdict is fail-open → kept as 'extracted'
    assert outcomes[0].kind == "extracted"


def test_fetch_failure_recorded_no_state_change(tmp_path: Path, cfg: Config) -> None:
    state = CrawlState.load(tmp_path / "state.json")
    sources = _sources("https://example.com/a")

    with patch.object(batch_mod, "fetch", side_effect=FetchError("boom")):
        outcomes = list(
            batch_mod.crawl_batch(
                sources,
                state=state,
                output_dir=tmp_path,
                config=cfg,
                write_bundle=lambda p, b: None,
            )
        )
    assert [o.kind for o in outcomes] == ["fetch_failed"]
    assert state.get("https://example.com/a") is None


def test_dry_run_does_not_fetch(tmp_path: Path, cfg: Config) -> None:
    state = CrawlState.load(tmp_path / "state.json")
    sources = _sources("https://example.com/a", "https://example.com/b")

    with patch.object(batch_mod, "fetch", side_effect=AssertionError("must not fetch")):
        outcomes = list(
            batch_mod.crawl_batch(
                sources,
                state=state,
                output_dir=tmp_path,
                dry_run=True,
                config=cfg,
                write_bundle=lambda p, b: None,
            )
        )
    assert [o.kind for o in outcomes] == ["extracted", "extracted"]
    assert state.entries == {}


def test_recheck_on_pir_change_reextracts_when_hash_differs(
    tmp_path: Path, cfg: Config, pir_doc: PIRDocument
) -> None:
    state = CrawlState.load(tmp_path / "state.json")
    sources = _sources("https://example.com/a")
    write = lambda p, b: None  # noqa: E731

    with (
        patch.object(batch_mod, "fetch", return_value=_fetch_result("https://example.com/a")),
        patch.object(batch_mod, "read_report", return_value="article"),
        patch.object(
            batch_mod.pir_relevance,
            "evaluate",
            return_value=RelevanceVerdict(score=0.9, matched_pir_ids=["PIR-TEST-001"]),
        ),
        patch.object(batch_mod, "extract_entities", return_value=_extr()),
    ):
        list(
            batch_mod.crawl_batch(
                sources,
                state=state,
                output_dir=tmp_path,
                pir_doc=pir_doc,
                pir_set_hash="hash-1",
                threshold=0.5,
                config=cfg,
                write_bundle=write,
            )
        )

    # Same content, NEW PIR set hash, recheck flag on → re-extract.
    extract_call_count = {"n": 0}

    def stub_extract(*a, **k):
        extract_call_count["n"] += 1
        return _extr()

    with (
        patch.object(batch_mod, "fetch", return_value=_fetch_result("https://example.com/a")),
        patch.object(batch_mod, "read_report", return_value="article"),
        patch.object(
            batch_mod.pir_relevance,
            "evaluate",
            return_value=RelevanceVerdict(score=0.9, matched_pir_ids=["PIR-TEST-001"]),
        ),
        patch.object(batch_mod, "extract_entities", side_effect=stub_extract),
    ):
        out = list(
            batch_mod.crawl_batch(
                sources,
                state=state,
                output_dir=tmp_path,
                pir_doc=pir_doc,
                pir_set_hash="hash-2",
                threshold=0.5,
                recheck_on_pir_change=True,
                config=cfg,
                write_bundle=write,
            )
        )
    assert out[0].kind == "extracted"
    assert extract_call_count["n"] == 1
