"""Load BEACON-generated ``pir_output.json`` into a TRACE ``PIRDocument``.

Returns ``(PIRDocument, pir_set_hash)`` so callers can record the hash in
``crawl_state.json`` and detect when the PIR set has been re-generated.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from trace_engine.io.inputs import resolve_input
from trace_engine.validate.schema import PIRDocument


def load_pir(path: str | Path) -> tuple[PIRDocument, str]:
    raw = Path(path).read_bytes()
    return load_pir_text(raw.decode("utf-8"))


def load_pir_text(text: str) -> tuple[PIRDocument, str]:
    raw = text.encode("utf-8")
    payload = json.loads(text)
    doc = PIRDocument.from_payload(payload)
    pir_set_hash = hashlib.sha256(raw).hexdigest()
    return doc, pir_set_hash


def load_pir_resolved(config: object, value: str | Path) -> tuple[PIRDocument, str]:
    resolved = resolve_input(config, "pir", value)
    return load_pir_text(resolved.text)
