"""Tests for TRACE storage-aware CLI input resolution."""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from trace_engine.io.inputs import normalize_storage_filename, resolve_input


def _cfg(tmp_path: Path, *, prefix: str = "") -> SimpleNamespace:
    return SimpleNamespace(
        trace_storage="local",
        trace_storage_base_dir=str(tmp_path),
        trace_storage_bucket="bucket",
        trace_storage_prefix=prefix,
    )


def test_resolve_existing_local_path_wins(tmp_path: Path) -> None:
    local = tmp_path / "pir_output.json"
    local.write_text('{"ok": true}', encoding="utf-8")

    resolved = resolve_input(_cfg(tmp_path), "pir", local)

    assert resolved.text == '{"ok": true}'
    assert resolved.source == "local"
    assert resolved.filename == "pir_output.json"


def test_resolve_bare_storage_filename(tmp_path: Path) -> None:
    (tmp_path / "pir").mkdir()
    (tmp_path / "pir" / "pir_output.json").write_text('{"pir": true}', encoding="utf-8")

    resolved = resolve_input(_cfg(tmp_path), "pir", "pir_output.json")

    assert resolved.text == '{"pir": true}'
    assert resolved.source == "storage"
    assert resolved.filename == "pir_output.json"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("pir_output.json", "pir_output.json"),
        ("pir/pir_output.json", "pir_output.json"),
        ("prod/pir/pir_output.json", "pir_output.json"),
        ("/prod/pir/pir_output.json", "pir_output.json"),
    ],
)
def test_normalize_storage_filename_accepts_filename_category_and_prefix(
    tmp_path: Path, value: str, expected: str
) -> None:
    assert normalize_storage_filename(_cfg(tmp_path, prefix="prod/"), "pir", value) == expected


def test_resolve_prefixed_storage_key(tmp_path: Path) -> None:
    (tmp_path / "pir").mkdir()
    (tmp_path / "pir" / "pir_output.json").write_text('{"pir": true}', encoding="utf-8")

    resolved = resolve_input(_cfg(tmp_path, prefix="prod/"), "pir", "prod/pir/pir_output.json")

    assert resolved.text == '{"pir": true}'
    assert resolved.source == "storage"


def test_resolve_missing_storage_key_raises_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        resolve_input(_cfg(tmp_path), "pir", "missing.json")


def test_resolve_gcs_uri_reads_exact_object(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    storage_mod = ModuleType("google.cloud.storage")

    class FakeBlob:
        def __init__(self, name: str) -> None:
            self.name = name

        def exists(self) -> bool:
            return self.name == "prod/pir/pir_output.json"

        def download_as_text(self, encoding: str = "utf-8") -> str:
            assert encoding == "utf-8"
            return '{"from": "gcs"}'

    class FakeBucket:
        def blob(self, name: str) -> FakeBlob:
            return FakeBlob(name)

    class FakeClient:
        def bucket(self, name: str) -> FakeBucket:
            assert name == "bucket"
            return FakeBucket()

    storage_mod.Client = FakeClient  # type: ignore[attr-defined]
    google_mod = ModuleType("google")
    google_mod.__path__ = []  # type: ignore[attr-defined]
    cloud_mod = ModuleType("google.cloud")
    cloud_mod.__path__ = []  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "google", google_mod)
    monkeypatch.setitem(sys.modules, "google.cloud", cloud_mod)
    monkeypatch.setitem(sys.modules, "google.cloud.storage", storage_mod)

    resolved = resolve_input(_cfg(tmp_path), "pir", "gs://bucket/prod/pir/pir_output.json")

    assert resolved.text == '{"from": "gcs"}'
    assert resolved.source == "gcs-uri"
    assert resolved.filename == "pir_output.json"
