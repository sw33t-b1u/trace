"""Tests for the Markdown report renderer."""

from __future__ import annotations

from datetime import UTC, datetime

from trace_engine.review.markdown_report import render_report
from trace_engine.validate.semantic.findings import ValidationFinding


def test_empty_sections_render_pass() -> None:
    text = render_report(
        [("Assets: a.json", []), ("PIR: p.json", [])],
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
    )
    assert "Overall: **PASS**" in text
    assert "_No findings._" in text
    assert "2025-01-01T00:00:00Z" in text


def test_error_finding_marks_overall_fail() -> None:
    finding = ValidationFinding(
        severity="error",
        code="X",
        location="loc",
        message="boom",
    )
    text = render_report([("STIX bundle: b.json", [finding])])
    assert "Overall: **FAIL**" in text
    assert "`X`" in text
    assert "boom" in text


def test_warning_only_keeps_overall_pass() -> None:
    finding = ValidationFinding(
        severity="warning",
        code="W",
        location="loc",
        message="hmm",
    )
    text = render_report([("PIR: p.json", [finding])])
    assert "Overall: **PASS**" in text


def test_pipe_in_message_is_escaped() -> None:
    finding = ValidationFinding(
        severity="error",
        code="X",
        location="loc",
        message="a | b",
    )
    text = render_report([("S", [finding])])
    assert r"a \| b" in text
