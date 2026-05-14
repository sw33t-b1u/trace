"""Taxonomy enrichment for STIX threat-actor / intrusion-set objects.

Reads the TRACE-side snapshot of BEACON's threat taxonomy
(``schema/threat_taxonomy.cached.json``) and annotates STIX objects with
the PIR vocabulary tags (``apt-china``, ``apt-russia``, ``ransomware``, …)
so SAGE's ``pir_filter.is_relevant_actor`` can match them.

Usage (library):
    from pathlib import Path
    from trace_engine.stix.taxonomy_enrich import load_taxonomy_index, enrich_bundle_objects

    index = load_taxonomy_index(Path("schema/threat_taxonomy.cached.json"))
    enriched = enrich_bundle_objects(bundle["objects"], index)
"""

from __future__ import annotations

import json
import re
from pathlib import Path


def _normalize(name: str) -> str:
    return re.sub(r"\s+", " ", name.strip()).lower()


def _collect_group_index(node: object, sink: dict[str, list[str]]) -> None:
    """Recursively walk a taxonomy subtree.

    Any dict that has both a ``tags`` list and a ``mitre_groups`` list is
    treated as a leaf category: each group name is mapped to the category's
    tags.  The recursion naturally covers both the flat categories
    (``espionage``, ``financial_crime``, ``sabotage``) and the nested
    ``state_sponsored.<Country>`` nodes without special-casing.
    """
    if not isinstance(node, dict):
        return
    raw_tags = node.get("tags")
    groups = node.get("mitre_groups")
    if isinstance(raw_tags, list) and isinstance(groups, list):
        valid_tags = [t for t in raw_tags if isinstance(t, str)]
        for name in groups:
            if not isinstance(name, str):
                continue
            key = _normalize(name)
            if key not in sink:
                sink[key] = []
            for tag in valid_tags:
                if tag not in sink[key]:
                    sink[key].append(tag)
    for v in node.values():
        _collect_group_index(v, sink)


def load_taxonomy_index(path: Path) -> dict[str, list[str]]:
    """Build a ``{normalized_group_name: [tag, ...]}`` index from the cache.

    Only ``actor_categories`` is walked so that geography or other top-level
    sections never contribute spurious entries.
    """
    with path.open(encoding="utf-8") as f:
        doc = json.load(f)
    index: dict[str, list[str]] = {}
    _collect_group_index(doc.get("actor_categories", {}), index)
    return index


def enrich_threat_actor_object(obj: dict, index: dict[str, list[str]]) -> bool:
    """Merge taxonomy tags into a single STIX object's ``labels``.

    Looks up ``obj["name"]`` and each alias in ``obj.get("aliases", [])``
    (case-insensitive, whitespace-normalised) against *index*.  All matching
    tags are appended to ``obj["labels"]`` without duplicates, preserving
    insertion order.

    Returns True if at least one tag was added.
    """
    names: list[str] = []
    raw_name = obj.get("name")
    if isinstance(raw_name, str):
        names.append(raw_name)
    for alias in obj.get("aliases") or []:
        if isinstance(alias, str):
            names.append(alias)

    tags_to_add: list[str] = []
    for name in names:
        for tag in index.get(_normalize(name), []):
            if tag not in tags_to_add:
                tags_to_add.append(tag)

    if not tags_to_add:
        return False

    existing = obj.get("labels")
    if isinstance(existing, list):
        for tag in tags_to_add:
            if tag not in existing:
                existing.append(tag)
    else:
        obj["labels"] = list(tags_to_add)
    return True


def enrich_bundle_objects(objects: list[dict], index: dict[str, list[str]]) -> int:
    """Apply taxonomy enrichment to all threat-actor and intrusion-set objects.

    Returns the number of objects that received at least one new tag.
    """
    _enrichable = {"threat-actor", "intrusion-set"}
    enriched = 0
    for obj in objects:
        if obj.get("type") in _enrichable:
            if enrich_threat_actor_object(obj, index):
                enriched += 1
    return enriched
