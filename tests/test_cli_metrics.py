"""Tests for cli/_metrics.py."""

from __future__ import annotations

import json
from pathlib import Path

from trace_engine.cli._metrics import (
    MetricsCollector,
    render_summary,
    to_dict,
    write_batch_json,
    write_run_json,
)


def _emit(collector: MetricsCollector, **event_dict) -> None:
    """Helper: drive the collector as a structlog processor would."""
    collector(None, "info", dict(event_dict))


class TestMetricsCollector:
    def test_observes_full_crawl_single_lifecycle(self):
        c = MetricsCollector()
        c.start_run(input_url_or_path="https://example.com/post")
        _emit(c, event="url_converted", chars=31628, body_chars=24750)
        _emit(c, event="relevance_call_start", tier="simple")
        _emit(c, event="llm_call_start", task="simple", model="gemini-2.5-flash-lite")
        _emit(c, event="llm_call_done", task="simple", chars=120)
        _emit(c, event="relevance_call_done", score=0.6, matched_pir_ids=["PIR-001"])
        _emit(
            c,
            event="extracting_entities_chunked",
            total_chars=24750,
            chunks=3,
            chunk_chars=12000,
            task="medium",
        )
        for i in range(3):
            _emit(c, event="llm_call_start", task="medium", model="gemini-2.5-flash")
            _emit(c, event="llm_call_done", task="medium", chars=10000)
            _emit(
                c,
                event="chunk_extracted",
                chunk_index=i,
                chars=11000,
                entities=20,
                relationships=15,
            )
        _emit(
            c,
            event="extractions_merged",
            chunks=3,
            raw_entities=60,
            merged_entities=46,
            raw_relationships=45,
            merged_relationships=45,
            dropped_relationships=0,
        )
        _emit(c, event="external_ref_hashed", url="https://attack.mitre.org/T1234")
        _emit(c, event="external_ref_hashed", url="https://attack.mitre.org/T5678")
        _emit(c, event="indicator_dropped_invalid_pattern", local_id="i_bad")
        _emit(c, event="stix_relationships_type_mismatch_dropped", count=2)
        _emit(
            c,
            event="stix_bundle_written",
            path="output/bundle.json",
            entities=46,
            relationships=45,
            object_count=92,
        )
        run = c.finish_run()

        assert run is not None
        assert run.input_chars == 31628
        assert run.body_chars == 24750
        assert run.l2_score == 0.6
        assert run.l2_matched_pir_ids == ["PIR-001"]
        assert run.l2_model_tier == "simple"
        assert run.l3_chunks == 3
        assert run.l3_llm_calls == 3
        assert run.l3_llm_output_chars_total == 30000
        assert run.l3_merged_entities == 46
        assert run.external_ref_fetched == 2
        assert run.indicators_dropped_invalid_pattern == 1
        assert run.relationships_dropped_type_mismatch == 2
        assert run.bundle_object_count == 92

    def test_no_active_run_means_no_observation(self):
        c = MetricsCollector()
        # No start_run — events are silently ignored.
        _emit(c, event="llm_call_done", task="medium", chars=1000)
        # finish_run with no active run returns None.
        assert c.finish_run() is None

    def test_l2_failed_flag_set_on_call_failure(self):
        c = MetricsCollector()
        c.start_run(input_url_or_path="x")
        _emit(c, event="relevance_call_failed", error="timeout")
        run = c.finish_run()
        assert run is not None
        assert run.l2_failed is True

    def test_l2_salvaged_path(self):
        c = MetricsCollector()
        c.start_run(input_url_or_path="x")
        _emit(
            c,
            event="relevance_salvaged_partial_json",
            score=0.42,
            matched_pir_ids=["PIR-X"],
        )
        run = c.finish_run()
        assert run is not None
        assert run.l2_salvaged is True
        assert run.l2_score == 0.42
        assert run.l2_matched_pir_ids == ["PIR-X"]

    def test_parse_failure_count_increments(self):
        c = MetricsCollector()
        c.start_run(input_url_or_path="x")
        _emit(c, event="extraction_response_not_object", chunk_index=0, raw_chars=1000)
        _emit(c, event="extraction_response_not_object", chunk_index=1, raw_chars=2000)
        run = c.finish_run()
        assert run is not None
        assert run.l3_parse_failures == 2

    def test_processor_returns_event_dict_unchanged(self):
        # structlog requires processors to return the event_dict.
        c = MetricsCollector()
        c.start_run(input_url_or_path="x")
        ev = {"event": "llm_call_done", "task": "medium", "chars": 100}
        result = c(None, "info", ev)
        assert result is ev


class TestSerialisation:
    def _make_run(self) -> tuple[MetricsCollector, object]:
        c = MetricsCollector()
        c.start_run(input_url_or_path="https://x")
        _emit(c, event="url_converted", chars=10000, body_chars=8000)
        _emit(
            c,
            event="extractions_merged",
            chunks=1,
            raw_entities=5,
            merged_entities=5,
            raw_relationships=3,
            merged_relationships=3,
            dropped_relationships=0,
        )
        _emit(
            c,
            event="stix_bundle_written",
            path="out.json",
            entities=5,
            relationships=3,
            object_count=8,
        )
        run = c.finish_run()
        return c, run

    def test_to_dict_shape(self):
        _, run = self._make_run()
        d = to_dict(run)
        for key in ("run_id", "started_at", "ended_at", "duration_seconds"):
            assert key in d
        for nested_key in ("input", "l2", "l3", "defenses", "bundle"):
            assert nested_key in d
        assert d["bundle"]["object_count"] == 8
        assert d["input"]["body_chars"] == 8000

    def test_write_run_json_writes_atomically(self, tmp_path: Path):
        _, run = self._make_run()
        path = write_run_json(run, tmp_path)
        assert path.exists()
        loaded = json.loads(path.read_text(encoding="utf-8"))
        assert loaded["bundle"]["object_count"] == 8
        # No leftover .tmp files.
        leftovers = [p for p in tmp_path.iterdir() if p.suffix == ".tmp"]
        assert leftovers == []

    def test_write_batch_json_includes_summary(self, tmp_path: Path):
        c1 = MetricsCollector()
        c1.start_run(input_url_or_path="u1")
        _emit(
            c1,
            event="extractions_merged",
            chunks=1,
            raw_entities=5,
            merged_entities=5,
            raw_relationships=3,
            merged_relationships=3,
        )
        run1 = c1.finish_run()

        c2 = MetricsCollector()
        c2.start_run(input_url_or_path="u2")
        _emit(
            c2,
            event="extractions_merged",
            chunks=1,
            raw_entities=10,
            merged_entities=8,
            raw_relationships=4,
            merged_relationships=4,
        )
        run2 = c2.finish_run()

        path = write_batch_json([run1, run2], tmp_path)
        loaded = json.loads(path.read_text(encoding="utf-8"))
        assert loaded["summary"]["run_count"] == 2
        assert loaded["summary"]["merged_entities_total"] == 13
        assert loaded["summary"]["merged_relationships_total"] == 7
        assert len(loaded["runs"]) == 2


class TestRenderSummary:
    def test_renders_basic_run(self):
        c = MetricsCollector()
        c.start_run(input_url_or_path="https://example.com/post")
        _emit(c, event="url_converted", chars=10000, body_chars=8000)
        _emit(c, event="relevance_call_done", score=0.6, matched_pir_ids=["PIR-X"])
        _emit(c, event="extracting_entities_chunked", chunks=2, task="medium")
        _emit(c, event="llm_call_done", task="medium", chars=5000)
        _emit(c, event="llm_call_done", task="medium", chars=4000)
        _emit(
            c,
            event="extractions_merged",
            raw_entities=10,
            merged_entities=10,
            raw_relationships=5,
            merged_relationships=5,
        )
        _emit(
            c,
            event="stix_bundle_written",
            path="out.json",
            entities=10,
            relationships=5,
            object_count=15,
        )
        run = c.finish_run()
        text = render_summary(run)
        assert "Run summary" in text
        assert "https://example.com/post" in text
        assert "score=0.60" in text
        assert "merged 10/5" in text
        assert "out.json" in text


class TestEdgeCases:
    def test_to_dict_handles_unfinished_run(self):
        c = MetricsCollector()
        c.start_run(input_url_or_path="u")
        run = c._run  # not finish_run'd
        # No ended_at yet, but to_dict should still produce a payload.
        run.ended_at = None
        d = to_dict(run)
        assert d["ended_at"] is None
        assert d["duration_seconds"] is None

    def test_unknown_event_ignored(self):
        c = MetricsCollector()
        c.start_run(input_url_or_path="u")
        _emit(c, event="unknown_event_xyz", arbitrary_field="value")
        run = c.finish_run()
        # Nothing crashed; counters remain zero.
        assert run is not None
        assert run.l3_chunks == 0
        assert run.bundle_object_count is None

    def test_event_without_event_field_ignored(self):
        c = MetricsCollector()
        c.start_run(input_url_or_path="u")
        c(None, "info", {"no_event_key": True})
        run = c.finish_run()
        assert run is not None  # still finishes cleanly
