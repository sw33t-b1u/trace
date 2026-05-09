"""Tests for stix/external_ref_hash.py."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx

from trace_engine.stix.external_ref_hash import augment_external_references


def _make_objects(refs: list[dict]) -> list[dict]:
    return [
        {
            "type": "attack-pattern",
            "id": "attack-pattern--00000000-0000-4000-8000-000000000000",
            "external_references": refs,
        }
    ]


def _mock_response(content: bytes = b"<html>ok</html>", status: int = 200) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.content = content
    if status >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "fail", request=None, response=resp
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


class TestAugmentExternalReferences:
    def test_skips_when_disabled(self, tmp_path: Path):
        objects = _make_objects([{"source_name": "x", "url": "https://example.com/"}])
        augment_external_references(
            objects,
            cache_path=tmp_path / "cache.json",
            ttl_days=30,
            user_agent="test",
            enabled=False,
        )
        assert "hashes" not in objects[0]["external_references"][0]

    def test_skips_when_no_url(self, tmp_path: Path):
        objects = _make_objects([{"source_name": "x", "external_id": "T1234"}])
        augment_external_references(
            objects,
            cache_path=tmp_path / "cache.json",
            ttl_days=30,
            user_agent="test",
        )
        assert "hashes" not in objects[0]["external_references"][0]

    def test_skips_when_hashes_already_present(self, tmp_path: Path):
        ref = {
            "source_name": "x",
            "url": "https://example.com/",
            "hashes": {"SHA-256": "deadbeef" * 8},
        }
        objects = _make_objects([ref])
        with patch("httpx.Client") as cls:
            augment_external_references(
                objects,
                cache_path=tmp_path / "cache.json",
                ttl_days=30,
                user_agent="test",
            )
            cls.assert_not_called()
        assert ref["hashes"] == {"SHA-256": "deadbeef" * 8}

    def test_fetches_and_writes_hash_on_cache_miss(self, tmp_path: Path):
        cache_path = tmp_path / "cache.json"
        objects = _make_objects(
            [{"source_name": "mitre-attack", "url": "https://attack.mitre.org/T1234"}]
        )
        body = b"sample-html-body"
        with patch("httpx.Client") as cls:
            cls.return_value.__enter__ = lambda self: cls.return_value
            cls.return_value.__exit__ = lambda *a: None
            cls.return_value.get.return_value = _mock_response(content=body)
            augment_external_references(
                objects,
                cache_path=cache_path,
                ttl_days=30,
                user_agent="test/1.0",
            )

        ref = objects[0]["external_references"][0]
        assert "hashes" in ref
        sha = ref["hashes"]["SHA-256"]
        assert len(sha) == 64
        # cache persisted
        assert cache_path.exists()
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
        assert cache["https://attack.mitre.org/T1234"]["sha256"] == sha

    def test_uses_cache_hit_without_network(self, tmp_path: Path):
        cache_path = tmp_path / "cache.json"
        cache_path.write_text(
            json.dumps(
                {
                    "https://example.com/x": {
                        "sha256": "abcdef" * 10 + "abcd",  # 64 hex
                        "fetched_at": datetime.now(tz=UTC).isoformat(timespec="seconds"),
                        "status": "ok",
                    }
                }
            ),
            encoding="utf-8",
        )
        objects = _make_objects([{"source_name": "x", "url": "https://example.com/x"}])
        with patch("httpx.Client") as cls:
            augment_external_references(
                objects,
                cache_path=cache_path,
                ttl_days=30,
                user_agent="test",
            )
            cls.assert_not_called()
        assert objects[0]["external_references"][0]["hashes"]["SHA-256"] == "abcdef" * 10 + "abcd"

    def test_re_fetches_on_stale_cache(self, tmp_path: Path):
        cache_path = tmp_path / "cache.json"
        old = (datetime.now(tz=UTC) - timedelta(days=60)).isoformat(timespec="seconds")
        cache_path.write_text(
            json.dumps(
                {
                    "https://example.com/x": {
                        "sha256": "stale" + "0" * 59,
                        "fetched_at": old,
                        "status": "ok",
                    }
                }
            ),
            encoding="utf-8",
        )
        objects = _make_objects([{"source_name": "x", "url": "https://example.com/x"}])
        with patch("httpx.Client") as cls:
            cls.return_value.get.return_value = _mock_response(content=b"fresh")
            augment_external_references(
                objects,
                cache_path=cache_path,
                ttl_days=30,
                user_agent="test",
            )
        ref = objects[0]["external_references"][0]
        assert ref["hashes"]["SHA-256"] != "stale" + "0" * 59

    def test_offline_fallback_leaves_ref_unchanged_on_fetch_failure(self, tmp_path: Path):
        objects = _make_objects([{"source_name": "x", "url": "https://example.com/x"}])
        with patch("httpx.Client") as cls:
            cls.return_value.get.side_effect = httpx.ConnectError("network down")
            augment_external_references(
                objects,
                cache_path=tmp_path / "cache.json",
                ttl_days=30,
                user_agent="test",
            )
        # No `hashes` field added — bundle still usable, {302} reappears.
        assert "hashes" not in objects[0]["external_references"][0]

    def test_objects_without_external_references_unchanged(self, tmp_path: Path):
        objects = [
            {
                "type": "intrusion-set",
                "id": "intrusion-set--11111111-1111-4111-8111-111111111111",
                "name": "FIN7",
            }
        ]
        with patch("httpx.Client") as cls:
            augment_external_references(
                objects,
                cache_path=tmp_path / "cache.json",
                ttl_days=30,
                user_agent="test",
            )
            cls.assert_not_called()
        assert objects[0] == {
            "type": "intrusion-set",
            "id": "intrusion-set--11111111-1111-4111-8111-111111111111",
            "name": "FIN7",
        }
