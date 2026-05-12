"""Tests for stix/asset_resolver.py (Initiative A §6.2)."""

from __future__ import annotations

from trace_engine.stix.asset_resolver import resolve_asset_reference

_ASSETS = [
    {"id": "asset-CA-001", "name": "業務処理中央サーバ", "tags": ["financial", "core"]},
    {"id": "asset-CA-002", "name": "業務データベース", "tags": ["database", "financial"]},
    {
        "id": "asset-CA-003",
        "name": "Customer Self-Service Portal",
        "tags": ["web", "external-facing"],
    },
    {"id": "asset-CA-004", "name": "Identity System", "tags": ["identity", "auth"]},
]


class TestTier1Exact:
    def test_exact_japanese_name(self):
        r = resolve_asset_reference("業務処理中央サーバ", _ASSETS)
        assert r is not None
        assert r.asset_id == "asset-CA-001"
        assert r.confidence == 80
        assert r.tier == 1

    def test_exact_english_case_insensitive(self):
        r = resolve_asset_reference("customer self-service portal", _ASSETS)
        assert r is not None
        assert r.asset_id == "asset-CA-003"
        assert r.confidence == 80


class TestTier2Substring:
    def test_substring_match(self):
        r = resolve_asset_reference("Self-Service", _ASSETS)
        assert r is not None
        assert r.asset_id == "asset-CA-003"
        assert r.confidence == 50
        assert r.tier == 2

    def test_short_substring_below_threshold_does_not_match(self):
        # "Cus" (3 chars) is below the 4-char minimum and is a
        # substring of "Customer Self-Service Portal".
        r = resolve_asset_reference("Cus", _ASSETS)
        # Drops or matches via tags — neither tag has "cus" so falls through.
        assert r is None

    def test_ambiguous_substring_drops(self):
        # "Financial" appears as a tag in 2 assets — but tier 2 is name-
        # based so falls through. Add an asset to force tier-2 ambiguity.
        assets = _ASSETS + [
            {"id": "asset-CA-099", "name": "Customer Self-Service Reports", "tags": []},
        ]
        # "Self-Service" now matches both CA-003 and CA-099 → ambiguous.
        r = resolve_asset_reference("Self-Service", assets)
        assert r is None


class TestTier3Tag:
    def test_tag_match_unique(self):
        # `external-facing` is a tag on CA-003 only and is not a substring
        # of any asset name — exercises tier 3 cleanly.
        r = resolve_asset_reference("external-facing", _ASSETS)
        assert r is not None
        assert r.asset_id == "asset-CA-003"
        assert r.confidence == 30
        assert r.tier == 3

    def test_tag_match_ambiguous_drops(self):
        # `financial` tag is on CA-001 and CA-002 — drop.
        r = resolve_asset_reference("financial", _ASSETS)
        assert r is None

    def test_name_substring_wins_over_tag(self):
        # "identity" appears as a substring of CA-004's name "Identity
        # System" — tier 2 fires before tier 3, so this resolves to
        # confidence=50 not 30.
        r = resolve_asset_reference("identity", _ASSETS)
        assert r is not None
        assert r.tier == 2
        assert r.asset_id == "asset-CA-004"


class TestNoMatch:
    def test_unknown_reference_drops(self):
        r = resolve_asset_reference("Nonexistent Quantum System", _ASSETS)
        assert r is None

    def test_empty_reference_drops(self):
        r = resolve_asset_reference("", _ASSETS)
        assert r is None

    def test_whitespace_only_drops(self):
        r = resolve_asset_reference("   ", _ASSETS)
        assert r is None


class TestEmptyAssets:
    def test_no_assets_drops_anything(self):
        r = resolve_asset_reference("Some asset", [])
        assert r is None
