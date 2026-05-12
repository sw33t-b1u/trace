"""Tests for stix/identity_resolver.py (Initiative C §3.2)."""

from __future__ import annotations

from trace_engine.stix.identity_resolver import resolve_identity_reference

_IDENTITIES = [
    {
        "id": "id-supplier-dhl",
        "name": "DHL",
        "roles": ["logistics-provider"],
        "sectors": ["transportation"],
    },
    {
        "id": "id-brand-microsoft",
        "name": "Microsoft",
        "roles": [],
        "sectors": ["technology"],
    },
    {
        "id": "id-exec-cfo",
        "name": "Chief Financial Officer",
        "roles": ["cfo", "executive"],
        "sectors": [],
    },
]


class TestTier1ExactMatch:
    def test_exact_name_match_returns_tier1(self):
        res = resolve_identity_reference("DHL", _IDENTITIES)
        assert res is not None
        assert res.identity_id == "id-supplier-dhl"
        assert res.tier == 1
        assert res.confidence == 80

    def test_case_insensitive_match(self):
        res = resolve_identity_reference("dhl", _IDENTITIES)
        assert res is not None
        assert res.identity_id == "id-supplier-dhl"
        assert res.tier == 1


class TestTier2SubstringMatch:
    def test_substring_match_in_name_returns_tier2(self):
        res = resolve_identity_reference("Micro", _IDENTITIES)
        assert res is not None
        assert res.identity_id == "id-brand-microsoft"
        assert res.tier == 2
        assert res.confidence == 50

    def test_reference_contains_name(self):
        # "Microsoft Corporation" contains "Microsoft" (≥4 chars)
        res = resolve_identity_reference("Microsoft Corporation", _IDENTITIES)
        assert res is not None
        assert res.tier == 2


class TestTier3RolesAndSectors:
    def test_roles_match_returns_tier3(self):
        res = resolve_identity_reference("cfo", _IDENTITIES)
        assert res is not None
        assert res.identity_id == "id-exec-cfo"
        assert res.tier == 3
        assert res.confidence == 30

    def test_sectors_match_returns_tier3(self):
        res = resolve_identity_reference("transportation", _IDENTITIES)
        assert res is not None
        assert res.identity_id == "id-supplier-dhl"
        assert res.tier == 3


class TestTier4NoMatch:
    def test_unresolvable_returns_none(self):
        from structlog.testing import capture_logs

        with capture_logs() as cap:
            res = resolve_identity_reference("UnknownCorp", _IDENTITIES)
        assert res is None
        assert any(e.get("event") == "identity_reference_unresolved" for e in cap)


class TestAmbiguityDrop:
    def test_ambiguous_tier1_returns_none(self):
        from structlog.testing import capture_logs

        ambiguous = [
            {"id": "id-a", "name": "DHL", "roles": [], "sectors": []},
            {"id": "id-b", "name": "DHL", "roles": [], "sectors": []},
        ]
        with capture_logs() as cap:
            res = resolve_identity_reference("DHL", ambiguous)
        assert res is None
        assert any(e.get("event") == "identity_resolution_ambiguous" for e in cap)

    def test_empty_reference_returns_none(self):
        res = resolve_identity_reference("", _IDENTITIES)
        assert res is None
