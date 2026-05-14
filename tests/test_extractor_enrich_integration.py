"""Integration tests: taxonomy enrichment wired into build_stix_bundle_from_extraction."""

from __future__ import annotations

from pathlib import Path

import pytest

from trace_engine.config import Config
from trace_engine.stix.extractor import (
    ExtractedEntity,
    Extraction,
    build_stix_bundle_from_extraction,
)

# Path to the real cached taxonomy (present in the repo fixture).
_REAL_TAXONOMY = Path(__file__).parents[1] / "schema" / "threat_taxonomy.cached.json"


def _mirrorface_extraction() -> Extraction:
    return Extraction(
        entities=[
            ExtractedEntity(
                local_id="actor_1",
                type="threat-actor",
                properties={"name": "MirrorFace"},
            )
        ],
        relationships=[],
    )


def _config_with_taxonomy(taxonomy_path: Path) -> Config:
    cfg = Config()
    cfg.threat_taxonomy_cache_path = taxonomy_path
    cfg.external_ref_hash_enabled = False
    return cfg


class TestEnrichmentInBundleAssembly:
    def test_mirrorface_gets_apt_china_label(self):
        if not _REAL_TAXONOMY.exists():
            pytest.skip("threat_taxonomy.cached.json not present")
        cfg = _config_with_taxonomy(_REAL_TAXONOMY)
        bundle = build_stix_bundle_from_extraction(_mirrorface_extraction(), config=cfg)
        actors = [o for o in bundle["objects"] if o.get("type") == "threat-actor"]
        assert len(actors) == 1
        assert "apt-china" in actors[0].get("labels", [])

    def test_intrusion_set_enriched(self):
        if not _REAL_TAXONOMY.exists():
            pytest.skip("threat_taxonomy.cached.json not present")
        cfg = _config_with_taxonomy(_REAL_TAXONOMY)
        extraction = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="is_1",
                    type="intrusion-set",
                    properties={"name": "Sandworm Team"},
                )
            ],
            relationships=[],
        )
        bundle = build_stix_bundle_from_extraction(extraction, config=cfg)
        actors = [o for o in bundle["objects"] if o.get("type") == "intrusion-set"]
        assert len(actors) == 1
        assert "apt-russia" in actors[0].get("labels", [])

    def test_cache_missing_graceful(self, tmp_path: Path):
        """When taxonomy cache is absent, bundle assembly completes without error."""
        cfg = _config_with_taxonomy(tmp_path / "nonexistent.json")
        bundle = build_stix_bundle_from_extraction(_mirrorface_extraction(), config=cfg)
        # Bundle must have the actor object (enrichment skipped, not crashed)
        actors = [o for o in bundle["objects"] if o.get("type") == "threat-actor"]
        assert len(actors) == 1
        # No apt-china tag added (enrichment disabled)
        assert "apt-china" not in actors[0].get("labels", [])

    def test_non_actor_types_not_enriched(self):
        if not _REAL_TAXONOMY.exists():
            pytest.skip("threat_taxonomy.cached.json not present")
        cfg = _config_with_taxonomy(_REAL_TAXONOMY)
        extraction = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="m_1",
                    type="malware",
                    properties={"name": "MirrorFace", "is_family": False},
                )
            ],
            relationships=[],
        )
        bundle = build_stix_bundle_from_extraction(extraction, config=cfg)
        malware_objs = [o for o in bundle["objects"] if o.get("type") == "malware"]
        assert len(malware_objs) == 1
        # Malware named "MirrorFace" should NOT get apt-china label
        assert "apt-china" not in malware_objs[0].get("labels", [])

    def test_enrichment_idempotent_in_bundle(self):
        """Labels are not duplicated when building a bundle with an already-labelled actor."""
        if not _REAL_TAXONOMY.exists():
            pytest.skip("threat_taxonomy.cached.json not present")
        cfg = _config_with_taxonomy(_REAL_TAXONOMY)
        extraction = Extraction(
            entities=[
                ExtractedEntity(
                    local_id="actor_1",
                    type="threat-actor",
                    properties={"name": "MirrorFace", "labels": ["apt-china"]},
                )
            ],
            relationships=[],
        )
        bundle = build_stix_bundle_from_extraction(extraction, config=cfg)
        actors = [o for o in bundle["objects"] if o.get("type") == "threat-actor"]
        assert actors[0]["labels"].count("apt-china") == 1
