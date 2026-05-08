"""Loader for the cached threat taxonomy.

The authoritative file lives in BEACON (``BEACON/schema/threat_taxonomy.json``);
TRACE keeps a snapshot at ``schema/threat_taxonomy.cached.json`` refreshed by
``cmd/update_taxonomy_cache.py``. Validators read only the snapshot so the
gate is reproducible offline.
"""

from __future__ import annotations

import json
from pathlib import Path

DEFAULT_TAXONOMY_PATH = (
    Path(__file__).resolve().parents[3].parent / "schema" / "threat_taxonomy.cached.json"
)


def load_taxonomy_tags(path: Path | None = None) -> set[str]:
    """Return the set of all ``threat_actor_tags`` values defined by the taxonomy.

    The file structure has two layouts under ``actor_categories``:
      - ``state_sponsored.<Country>.tags`` (per-country)
      - ``<category>.tags`` (espionage / financial_crime / sabotage)

    Both are walked uniformly: any ``"tags": [...]`` list anywhere in the
    ``actor_categories`` subtree contributes to the result.
    """
    target = path or DEFAULT_TAXONOMY_PATH
    with target.open() as f:
        doc = json.load(f)

    tags: set[str] = set()
    _collect_tags(doc.get("actor_categories", {}), tags)
    return tags


def _collect_tags(node: object, sink: set[str]) -> None:
    if isinstance(node, dict):
        raw = node.get("tags")
        if isinstance(raw, list):
            for tag in raw:
                if isinstance(tag, str):
                    sink.add(tag)
        for v in node.values():
            _collect_tags(v, sink)
    elif isinstance(node, list):
        for v in node:
            _collect_tags(v, sink)
