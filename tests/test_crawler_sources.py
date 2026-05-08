"""Tests for ``input/sources.yaml`` schema and loader."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from trace_engine.crawler.sources import load_sources
from trace_engine.validate.schema import SourceEntry, SourcesDocument

FIXTURES = Path(__file__).parent / "fixtures"


def test_loads_valid_sources_yaml() -> None:
    doc = load_sources(FIXTURES / "sources.yaml")
    assert isinstance(doc, SourcesDocument)
    assert doc.version == 1
    assert len(doc.sources) == 2
    assert doc.sources[0].task == "medium"
    assert doc.sources[1].pir_ids == ["PIR-TEST-001"]


def test_default_task_is_medium() -> None:
    e = SourceEntry(url="https://example.com/x")
    assert e.task == "medium"
    assert e.max_chars is None
    assert e.pir_ids == []


def test_invalid_task_rejected() -> None:
    with pytest.raises(ValidationError):
        SourceEntry(url="https://example.com/x", task="urgent")


def test_max_chars_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        SourceEntry(url="https://example.com/x", max_chars=0)


def test_extra_fields_rejected() -> None:
    with pytest.raises(ValidationError):
        SourceEntry(url="https://example.com/x", interval="1h")
