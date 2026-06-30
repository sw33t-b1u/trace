"""Tests for ``cmd/discover_pir.py``."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from trace_engine.discovery.candidates import ArticleCandidate

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures"


def _load_cmd_module():
    path = PROJECT_ROOT / "cmd" / "discover_pir.py"
    spec = importlib.util.spec_from_file_location("_test_cmd_discover_pir", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_pir(tmp_path: Path) -> Path:
    src = FIXTURES / "valid_pir.json"
    dst = tmp_path / "pir_output.json"
    dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return dst


def test_discover_pir_json_output(monkeypatch, capsys, tmp_path: Path) -> None:
    mod = _load_cmd_module()
    pir_path = _write_pir(tmp_path)
    catalog_path = FIXTURES / "discovery_source_catalog.yaml"
    candidate = ArticleCandidate(
        url="https://example.com/report",
        title="Salt Typhoon report",
        source_name="Example CTI Feed",
        published_at=datetime(2026, 6, 15, tzinfo=UTC),
        matched_pir_ids=["PIR-TEST-001"],
        matched_terms=["salt typhoon"],
        score=0.9,
    )
    monkeypatch.setattr(mod, "discover_candidates", lambda *args, **kwargs: [candidate])
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "discover_pir.py",
            "--pir",
            str(pir_path),
            "--catalog",
            str(catalog_path),
            "--from",
            "2026-06-01",
            "--to",
            "2026-06-30",
            "--json",
        ],
    )

    assert mod.main() == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["schema_version"] == "1.0.0"
    assert payload["window"] == {"from": "2026-06-01", "to": "2026-06-30"}
    assert payload["candidates"][0]["url"] == "https://example.com/report"


def test_discover_pir_zero_candidates_json(monkeypatch, capsys, tmp_path: Path) -> None:
    mod = _load_cmd_module()
    pir_path = _write_pir(tmp_path)
    monkeypatch.setattr(mod, "discover_candidates", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "discover_pir.py",
            "--pir",
            str(pir_path),
            "--catalog",
            str(FIXTURES / "discovery_source_catalog.yaml"),
            "--since-days",
            "30",
            "--json",
        ],
    )

    assert mod.main() == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["candidates"] == []


def test_discover_pir_invalid_window_exits_2(monkeypatch, capsys, tmp_path: Path) -> None:
    mod = _load_cmd_module()
    pir_path = _write_pir(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "discover_pir.py",
            "--pir",
            str(pir_path),
            "--catalog",
            str(FIXTURES / "discovery_source_catalog.yaml"),
            "--from",
            "2026-07-01",
            "--to",
            "2026-06-01",
            "--json",
        ],
    )

    assert mod.main() == 2
    assert "invalid_window" in capsys.readouterr().err


def test_discover_pir_include_recent_forwarded(monkeypatch, tmp_path: Path) -> None:
    mod = _load_cmd_module()
    pir_path = _write_pir(tmp_path)
    seen: dict = {}

    def fake_discover(*args, **kwargs):
        seen.update(kwargs)
        return []

    monkeypatch.setattr(mod, "discover_candidates", fake_discover)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "discover_pir.py",
            "--pir",
            str(pir_path),
            "--catalog",
            str(FIXTURES / "discovery_source_catalog.yaml"),
            "--since-days",
            "30",
            "--include-recent",
            "--json",
        ],
    )

    assert mod.main() == 0
    assert seen["include_recent"] is True


def test_discover_pir_accepts_prefixed_storage_keys(monkeypatch, capsys, tmp_path: Path) -> None:
    mod = _load_cmd_module()
    (tmp_path / "pir").mkdir()
    (tmp_path / "input").mkdir()
    (tmp_path / "pir" / "pir_output.json").write_text(
        (FIXTURES / "valid_pir.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (tmp_path / "input" / "source_catalog.yaml").write_text(
        (FIXTURES / "discovery_source_catalog.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    monkeypatch.setenv("TRACE_STORAGE", "local")
    monkeypatch.setenv("TRACE_STORAGE_BASE_DIR", str(tmp_path))
    monkeypatch.setenv("TRACE_STORAGE_PREFIX", "prod/")
    monkeypatch.setattr(mod, "discover_candidates", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "discover_pir.py",
            "--pir",
            "prod/pir/pir_output.json",
            "--catalog",
            "prod/input/source_catalog.yaml",
            "--since-days",
            "30",
            "--json",
        ],
    )

    assert mod.main() == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["pir_path"] == "prod/pir/pir_output.json"
    assert payload["candidates"] == []
