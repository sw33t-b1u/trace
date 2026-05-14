"""Tests for cmd/enrich_bundle.py."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_CMD_PATH = Path(__file__).parent.parent / "cmd" / "enrich_bundle.py"
_spec = importlib.util.spec_from_file_location("enrich_bundle", _CMD_PATH)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

_REAL_TAXONOMY = Path(__file__).parents[1] / "schema" / "threat_taxonomy.cached.json"


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _minimal_bundle(actors: list[dict] | None = None) -> dict:
    return {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000001",
        "spec_version": "2.1",
        "objects": actors or [],
    }


def _run_main(argv: list[str]) -> None:
    orig = sys.argv
    sys.argv = ["enrich_bundle.py"] + argv
    try:
        _mod.main()
    finally:
        sys.argv = orig


class TestEnrichBundleCli:
    def test_mirrorface_gets_apt_china(self, tmp_path: Path):
        if not _REAL_TAXONOMY.exists():
            pytest.skip("threat_taxonomy.cached.json not present")
        bundle = _minimal_bundle(
            [
                {
                    "type": "threat-actor",
                    "id": "threat-actor--00000000-0000-4000-8000-000000000002",
                    "spec_version": "2.1",
                    "created": "2026-01-01T00:00:00.000Z",
                    "modified": "2026-01-01T00:00:00.000Z",
                    "name": "MirrorFace",
                }
            ]
        )
        inp = tmp_path / "input.json"
        out = tmp_path / "output.json"
        _write_json(inp, bundle)

        _run_main(
            [
                "--input",
                str(inp),
                "--output",
                str(out),
                "--taxonomy",
                str(_REAL_TAXONOMY),
            ]
        )

        result = json.loads(out.read_text(encoding="utf-8"))
        actor = next(o for o in result["objects"] if o["type"] == "threat-actor")
        assert "apt-china" in actor.get("labels", [])

    def test_idempotent(self, tmp_path: Path):
        if not _REAL_TAXONOMY.exists():
            pytest.skip("threat_taxonomy.cached.json not present")
        bundle = _minimal_bundle(
            [
                {
                    "type": "threat-actor",
                    "id": "threat-actor--00000000-0000-4000-8000-000000000003",
                    "spec_version": "2.1",
                    "created": "2026-01-01T00:00:00.000Z",
                    "modified": "2026-01-01T00:00:00.000Z",
                    "name": "MirrorFace",
                    "labels": ["apt-china"],
                }
            ]
        )
        inp = tmp_path / "input.json"
        out = tmp_path / "output.json"
        _write_json(inp, bundle)

        _run_main(
            [
                "--input",
                str(inp),
                "--output",
                str(out),
                "--taxonomy",
                str(_REAL_TAXONOMY),
            ]
        )

        result = json.loads(out.read_text(encoding="utf-8"))
        actor = next(o for o in result["objects"] if o["type"] == "threat-actor")
        assert actor["labels"].count("apt-china") == 1

    def test_exit_1_on_missing_input(self, tmp_path: Path):
        out = tmp_path / "out.json"
        with pytest.raises(SystemExit) as exc_info:
            _run_main(
                [
                    "--input",
                    str(tmp_path / "nonexistent.json"),
                    "--output",
                    str(out),
                    "--taxonomy",
                    str(_REAL_TAXONOMY),
                ]
            )
        assert exc_info.value.code == 1

    def test_exit_1_on_invalid_json(self, tmp_path: Path):
        inp = tmp_path / "bad.json"
        inp.write_text("not json", encoding="utf-8")
        out = tmp_path / "out.json"
        with pytest.raises(SystemExit) as exc_info:
            _run_main(
                [
                    "--input",
                    str(inp),
                    "--output",
                    str(out),
                    "--taxonomy",
                    str(_REAL_TAXONOMY),
                ]
            )
        assert exc_info.value.code == 1

    def test_exit_1_on_missing_taxonomy(self, tmp_path: Path):
        bundle = _minimal_bundle()
        inp = tmp_path / "input.json"
        _write_json(inp, bundle)
        with pytest.raises(SystemExit) as exc_info:
            _run_main(
                [
                    "--input",
                    str(inp),
                    "--output",
                    str(tmp_path / "out.json"),
                    "--taxonomy",
                    str(tmp_path / "no-taxonomy.json"),
                ]
            )
        assert exc_info.value.code == 1

    def test_atomic_write_no_temp_leftovers(self, tmp_path: Path):
        if not _REAL_TAXONOMY.exists():
            pytest.skip("threat_taxonomy.cached.json not present")
        bundle = _minimal_bundle()
        inp = tmp_path / "input.json"
        out = tmp_path / "output.json"
        _write_json(inp, bundle)

        _run_main(
            [
                "--input",
                str(inp),
                "--output",
                str(out),
                "--taxonomy",
                str(_REAL_TAXONOMY),
            ]
        )

        tmp_files = [p for p in tmp_path.iterdir() if p.suffix == ".tmp"]
        assert tmp_files == []
        assert out.exists()
