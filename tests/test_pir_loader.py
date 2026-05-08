"""Tests for ``trace_engine.pir.loader.load_pir``."""

from __future__ import annotations

import json
from pathlib import Path

from trace_engine.pir.loader import load_pir

FIXTURES = Path(__file__).parent / "fixtures"


def test_loads_pir_and_returns_hash() -> None:
    doc, h = load_pir(FIXTURES / "valid_pir.json")
    assert doc.root[0].pir_id == "PIR-TEST-001"
    assert len(h) == 64  # sha256 hex


def test_hash_is_deterministic_per_payload(tmp_path: Path) -> None:
    p1 = tmp_path / "a.json"
    p2 = tmp_path / "b.json"
    payload = json.loads((FIXTURES / "valid_pir.json").read_text())
    p1.write_bytes(json.dumps(payload).encode())
    p2.write_bytes(json.dumps(payload).encode())
    _, h1 = load_pir(p1)
    _, h2 = load_pir(p2)
    assert h1 == h2
