"""Tests for stix/taxonomy_enrich.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trace_engine.stix.taxonomy_enrich import (
    enrich_bundle_objects,
    enrich_threat_actor_object,
    load_taxonomy_index,
)

# ---------------------------------------------------------------------------
# Minimal taxonomy fixture for unit tests (no file I/O needed for most cases)
# ---------------------------------------------------------------------------

_SAMPLE_TAXONOMY: dict = {
    "_metadata": {"generator": "test"},
    "actor_categories": {
        "state_sponsored": {
            "China": {
                "tags": ["apt-china"],
                "mitre_groups": ["APT41", "MirrorFace", "Volt Typhoon"],
            },
            "Russia": {
                "tags": ["apt-russia"],
                "mitre_groups": ["Sandworm Team", "APT28"],
            },
        },
        "espionage": {
            "tags": ["espionage"],
            "mitre_groups": ["OilRig", "APT29"],
        },
        "financial_crime": {
            "tags": ["financial-crime"],
            "mitre_groups": [],
        },
        "sabotage": {
            "tags": ["sabotage"],
            "mitre_groups": [],
        },
    },
    "geography_threat_map": {},
}


def _write_taxonomy(tmp_path: Path, data: dict) -> Path:
    p = tmp_path / "taxonomy.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# load_taxonomy_index
# ---------------------------------------------------------------------------


class TestLoadTaxonomyIndex:
    def test_maps_mirrorface_to_apt_china(self, tmp_path: Path):
        path = _write_taxonomy(tmp_path, _SAMPLE_TAXONOMY)
        index = load_taxonomy_index(path)
        assert "apt-china" in index["mirrorface"]

    def test_maps_apt41_to_apt_china(self, tmp_path: Path):
        path = _write_taxonomy(tmp_path, _SAMPLE_TAXONOMY)
        index = load_taxonomy_index(path)
        assert "apt-china" in index["apt41"]

    def test_maps_sandworm_to_apt_russia(self, tmp_path: Path):
        path = _write_taxonomy(tmp_path, _SAMPLE_TAXONOMY)
        index = load_taxonomy_index(path)
        assert "apt-russia" in index["sandworm team"]

    def test_maps_espionage_group(self, tmp_path: Path):
        path = _write_taxonomy(tmp_path, _SAMPLE_TAXONOMY)
        index = load_taxonomy_index(path)
        assert "espionage" in index["oilrig"]

    def test_case_insensitive_key(self, tmp_path: Path):
        path = _write_taxonomy(tmp_path, _SAMPLE_TAXONOMY)
        index = load_taxonomy_index(path)
        # keys are all lowercase
        assert "apt28" in index
        assert "APT28" not in index

    def test_empty_mitre_groups_does_not_add_entry(self, tmp_path: Path):
        path = _write_taxonomy(tmp_path, _SAMPLE_TAXONOMY)
        index = load_taxonomy_index(path)
        # financial_crime and sabotage have empty mitre_groups lists
        # so no spurious empty entries should appear
        for key in index:
            assert index[key], f"Entry {key!r} has empty tag list"

    def test_loads_real_cached_taxonomy(self):
        real_path = Path(__file__).parents[1] / "schema" / "threat_taxonomy.cached.json"
        if not real_path.exists():
            pytest.skip("threat_taxonomy.cached.json not present")
        index = load_taxonomy_index(real_path)
        assert "mirrorface" in index
        assert "apt-china" in index["mirrorface"]
        assert "sandworm team" in index
        assert "apt-russia" in index["sandworm team"]


# ---------------------------------------------------------------------------
# enrich_threat_actor_object
# ---------------------------------------------------------------------------


def _make_index() -> dict[str, list[str]]:
    return {
        "mirrorface": ["apt-china"],
        "apt41": ["apt-china"],
        "sandworm team": ["apt-russia"],
        "oilrig": ["espionage"],
    }


class TestEnrichThreatActorObject:
    def test_adds_tag_by_name(self):
        index = _make_index()
        obj = {"type": "threat-actor", "name": "MirrorFace"}
        assert enrich_threat_actor_object(obj, index) is True
        assert obj["labels"] == ["apt-china"]

    def test_adds_tag_case_insensitive(self):
        index = _make_index()
        obj = {"type": "threat-actor", "name": "MIRRORFACE"}
        assert enrich_threat_actor_object(obj, index) is True
        assert "apt-china" in obj["labels"]

    def test_adds_tag_via_alias(self):
        index = _make_index()
        obj = {
            "type": "intrusion-set",
            "name": "Unknown Group",
            "aliases": ["MirrorFace", "GroupX"],
        }
        assert enrich_threat_actor_object(obj, index) is True
        assert "apt-china" in obj["labels"]

    def test_preserves_existing_labels(self):
        index = _make_index()
        obj = {"type": "threat-actor", "name": "MirrorFace", "labels": ["malware-dev"]}
        enrich_threat_actor_object(obj, index)
        assert "malware-dev" in obj["labels"]
        assert "apt-china" in obj["labels"]

    def test_no_duplicate_labels(self):
        index = _make_index()
        obj = {"type": "threat-actor", "name": "MirrorFace", "labels": ["apt-china"]}
        enrich_threat_actor_object(obj, index)
        assert obj["labels"].count("apt-china") == 1

    def test_returns_false_when_no_match(self):
        index = _make_index()
        obj = {"type": "threat-actor", "name": "Unknown Actor"}
        assert enrich_threat_actor_object(obj, index) is False
        assert "labels" not in obj

    def test_returns_false_when_no_name(self):
        index = _make_index()
        obj = {"type": "threat-actor"}
        assert enrich_threat_actor_object(obj, index) is False

    def test_alias_only_match(self):
        index = _make_index()
        obj = {
            "type": "threat-actor",
            "name": "NoMatch",
            "aliases": ["Sandworm Team"],
        }
        assert enrich_threat_actor_object(obj, index) is True
        assert "apt-russia" in obj["labels"]

    def test_order_preserved_no_duplicates(self):
        index = {"apt41": ["apt-china", "espionage"], "apt29": ["espionage"]}
        obj = {
            "type": "intrusion-set",
            "name": "APT41",
            "aliases": ["APT29"],
            "labels": ["existing"],
        }
        enrich_threat_actor_object(obj, index)
        # apt-china and espionage from APT41; espionage already added → not duplicated
        assert obj["labels"] == ["existing", "apt-china", "espionage"]


# ---------------------------------------------------------------------------
# enrich_bundle_objects
# ---------------------------------------------------------------------------


class TestEnrichBundleObjects:
    def test_only_enriches_actor_types(self):
        index = _make_index()
        objects = [
            {"type": "threat-actor", "name": "MirrorFace"},
            {"type": "intrusion-set", "name": "Sandworm Team"},
            {"type": "malware", "name": "Some Malware"},
            {"type": "relationship", "source_ref": "x", "target_ref": "y"},
        ]
        count = enrich_bundle_objects(objects, index)
        assert count == 2
        assert "apt-china" in objects[0].get("labels", [])
        assert "apt-russia" in objects[1].get("labels", [])
        assert "labels" not in objects[2]
        assert "labels" not in objects[3]

    def test_returns_zero_when_no_actors(self):
        index = _make_index()
        objects = [{"type": "malware", "name": "MirrorFace"}]
        assert enrich_bundle_objects(objects, index) == 0

    def test_returns_zero_when_no_match(self):
        index = _make_index()
        objects = [{"type": "threat-actor", "name": "Unknown"}]
        assert enrich_bundle_objects(objects, index) == 0

    def test_idempotent_double_enrich(self):
        index = _make_index()
        objects = [{"type": "threat-actor", "name": "MirrorFace"}]
        enrich_bundle_objects(objects, index)
        first_labels = list(objects[0]["labels"])
        enrich_bundle_objects(objects, index)
        assert objects[0]["labels"] == first_labels

    def test_empty_objects_list(self):
        index = _make_index()
        assert enrich_bundle_objects([], index) == 0
