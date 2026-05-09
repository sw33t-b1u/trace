"""Tests for cmd/update_taxonomy_cache.py."""

from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

_CMD_PATH = Path(__file__).parent.parent / "cmd" / "update_taxonomy_cache.py"
_spec = importlib.util.spec_from_file_location("update_taxonomy_cache", _CMD_PATH)
update_taxonomy_cache = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(update_taxonomy_cache)  # type: ignore[union-attr]


_VALIDATE_SHAPE = update_taxonomy_cache._validate_shape
_ATOMIC_WRITE = update_taxonomy_cache._atomic_write_json


def _minimal_valid_taxonomy() -> dict:
    return {
        "_metadata": {
            "sources": {
                "mitre_attack": "https://example/",
                "misp_galaxy_threat_actor": "https://x",
            },
            "last_auto_sync": datetime.now(tz=UTC).isoformat(),
            "generator": "cmd/update_taxonomy.py",
        },
        "actor_categories": {
            "espionage": {"tags": ["espionage"], "mitre_groups": []},
        },
        "geography_threat_map": {"日本": {"apt_tags": [], "notable_groups": []}},
    }


class TestValidateShape:
    def test_accepts_minimal_valid_taxonomy(self):
        data = _minimal_valid_taxonomy()
        assert _VALIDATE_SHAPE(data) is data

    def test_rejects_non_object_root(self):
        with pytest.raises(ValueError, match="must be a JSON object"):
            _VALIDATE_SHAPE([1, 2, 3])

    def test_rejects_missing_required_keys(self):
        bad = _minimal_valid_taxonomy()
        del bad["actor_categories"]
        with pytest.raises(ValueError, match="missing required top-level keys"):
            _VALIDATE_SHAPE(bad)

    def test_rejects_empty_actor_categories(self):
        bad = _minimal_valid_taxonomy()
        bad["actor_categories"] = {}
        with pytest.raises(ValueError, match="non-empty"):
            _VALIDATE_SHAPE(bad)


class TestAtomicWrite:
    def test_writes_json_to_destination(self, tmp_path: Path):
        target = tmp_path / "nested" / "out.json"
        payload = {"a": 1, "b": [2, 3]}
        _ATOMIC_WRITE(target, payload)
        assert json.loads(target.read_text(encoding="utf-8")) == payload

    def test_overwrites_existing_file(self, tmp_path: Path):
        target = tmp_path / "out.json"
        target.write_text("{}", encoding="utf-8")
        _ATOMIC_WRITE(target, {"replaced": True})
        assert json.loads(target.read_text(encoding="utf-8")) == {"replaced": True}

    def test_does_not_leave_temp_files(self, tmp_path: Path):
        target = tmp_path / "out.json"
        _ATOMIC_WRITE(target, {"k": "v"})
        leftovers = [p for p in tmp_path.iterdir() if p.name != "out.json"]
        assert leftovers == []
