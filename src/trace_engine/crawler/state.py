"""Persistent state for batch crawl dedupe.

State file: ``output/crawl_state.json``. Written atomically via tmp + os.replace.
Schema (version 1):

    {
      "version": 1,
      "entries": {
        "<url>": {
          "first_seen": "<iso8601>",
          "last_seen":  "<iso8601>",
          "content_sha256": "<hex>",
          "bundle_path": "<path-or-null>",
          "relevance": {
            "decision": "kept" | "skipped_below_threshold" | "extraction_failed" | "no_pir",
            "score": <float-or-null>,
            "matched_pir_ids": [...],
            "rationale": "<str-or-null>",
            "pir_set_hash": "<sha256-or-null>"
          }
        }
      }
    }
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

STATE_VERSION = 1

RelevanceDecision = Literal[
    "kept",
    "skipped_below_threshold",
    "extraction_failed",
    "no_pir",
]


@dataclass
class RelevanceRecord:
    decision: RelevanceDecision
    score: float | None = None
    matched_pir_ids: list[str] = field(default_factory=list)
    rationale: str | None = None
    pir_set_hash: str | None = None

    def as_dict(self) -> dict:
        return {
            "decision": self.decision,
            "score": self.score,
            "matched_pir_ids": list(self.matched_pir_ids),
            "rationale": self.rationale,
            "pir_set_hash": self.pir_set_hash,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> RelevanceRecord:
        return cls(
            decision=raw["decision"],
            score=raw.get("score"),
            matched_pir_ids=list(raw.get("matched_pir_ids", [])),
            rationale=raw.get("rationale"),
            pir_set_hash=raw.get("pir_set_hash"),
        )


@dataclass
class StateEntry:
    first_seen: str
    last_seen: str
    content_sha256: str
    bundle_path: str | None
    relevance: RelevanceRecord

    def as_dict(self) -> dict:
        return {
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "content_sha256": self.content_sha256,
            "bundle_path": self.bundle_path,
            "relevance": self.relevance.as_dict(),
        }

    @classmethod
    def from_dict(cls, raw: dict) -> StateEntry:
        return cls(
            first_seen=raw["first_seen"],
            last_seen=raw["last_seen"],
            content_sha256=raw["content_sha256"],
            bundle_path=raw.get("bundle_path"),
            relevance=RelevanceRecord.from_dict(raw.get("relevance") or {"decision": "no_pir"}),
        )


class CrawlState:
    def __init__(self, path: Path, entries: dict[str, StateEntry] | None = None) -> None:
        self.path = path
        self.entries: dict[str, StateEntry] = entries or {}
        # Concurrent batch crawls (TRACE 0.8.0) call get / upsert from
        # multiple worker threads. Mutations and reads are serialised via
        # this lock so the in-memory dict stays consistent. The atomic
        # tempfile + os.replace dance in save() is unaffected.
        self._lock = threading.Lock()

    @classmethod
    def load(cls, path: str | Path) -> CrawlState:
        p = Path(path)
        if not p.exists():
            return cls(p, {})
        raw = json.loads(p.read_text(encoding="utf-8"))
        if raw.get("version") != STATE_VERSION:
            raise ValueError(
                f"Unsupported crawl_state.json version: {raw.get('version')!r} "
                f"(expected {STATE_VERSION})"
            )
        entries = {url: StateEntry.from_dict(v) for url, v in raw.get("entries", {}).items()}
        return cls(p, entries)

    def save(self) -> None:
        with self._lock:
            entries_snapshot = {url: e.as_dict() for url, e in self.entries.items()}
        payload = {
            "version": STATE_VERSION,
            "entries": entries_snapshot,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # atomic: write to tmp in same dir, then os.replace
        with tempfile.NamedTemporaryFile(
            "w",
            dir=self.path.parent,
            prefix=self.path.name + ".",
            suffix=".tmp",
            delete=False,
            encoding="utf-8",
        ) as tmp:
            json.dump(payload, tmp, indent=2, ensure_ascii=False)
            tmp_path = tmp.name
        os.replace(tmp_path, self.path)

    def get(self, url: str) -> StateEntry | None:
        with self._lock:
            return self.entries.get(url)

    def upsert(
        self,
        url: str,
        *,
        content_sha256: str,
        bundle_path: str | None,
        relevance: RelevanceRecord,
        now: str | None = None,
    ) -> StateEntry:
        ts = now or _now_iso()
        with self._lock:
            prev = self.entries.get(url)
            first_seen = prev.first_seen if prev else ts
            entry = StateEntry(
                first_seen=first_seen,
                last_seen=ts,
                content_sha256=content_sha256,
                bundle_path=bundle_path,
                relevance=relevance,
            )
            self.entries[url] = entry
        return entry


def content_sha256(payload: bytes | str) -> str:
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _now_iso() -> str:
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
