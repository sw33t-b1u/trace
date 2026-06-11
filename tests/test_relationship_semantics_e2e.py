"""E2E tests for relationship-semantics validation using synthetic bundles.

Exercises ``validate.semantic.relationships`` end-to-end against three
hand-built STIX bundles: a fully emit-ready bundle (all allowed
source × relationship_type × target combinations), a bundle made only of
out-of-spec combinations that must be flagged, and an extension-definition
roundtrip bundle for the custom internal SDO types.
"""

from __future__ import annotations

import json
from pathlib import Path

from trace_engine.validate.semantic.relationships import (
    check_identity_ref_resolution,
    check_relationship_type_match,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "relationship_semantics"

_KNOWN_IDENTITY_IDS = {"id-supplier-dhl", "id-brand-microsoft", "id-exec-cfo"}


def _load(name: str) -> dict:
    return json.loads((_FIXTURES / name).read_text())


class TestSpecCompliantBundle:
    """spec_compliant_bundle.json — covers all 5 emit-ready combinations.

    Emit-ready = the source × relationship_type × target rows allowed by
    ``_RELATIONSHIP_TYPE_TABLE`` (attributed-to / impersonates / targets).
    The impersonates combination (threat-actor → identity /
    x-identity-internal) has two instances: one targeting an
    x-identity-internal with no roles (multiplier=1.0, eff=30) and one
    targeting an executive-role identity (roles=[cfo], multiplier=1.5,
    eff=90) to exercise the role-based priority boost end-to-end.
    """

    def test_six_relationships_present(self):
        bundle = _load("spec_compliant_bundle.json")
        rels = [o for o in bundle["objects"] if o.get("type") == "relationship"]
        assert len(rels) == 6

    def test_no_relationship_type_match_errors(self):
        bundle = _load("spec_compliant_bundle.json")
        findings = check_relationship_type_match(bundle)
        errors = [f for f in findings if f.severity == "error"]
        assert errors == []

    def test_x_identity_internal_identity_id_resolves(self):
        bundle = _load("spec_compliant_bundle.json")
        findings = check_identity_ref_resolution(bundle, _KNOWN_IDENTITY_IDS)
        assert findings == []


class TestPendingDropBundle:
    """pending_drop_bundle.json — out-of-spec rows flagged + unresolved identity.

    Contains the 5 source × relationship_type × target rows NOT allowed by
    ``_RELATIONSHIP_TYPE_TABLE`` (each must raise a RELATIONSHIP_TYPE_MATCH
    error) plus one reference to an identity id absent from the known set
    (must raise an IDENTITY_REF_RESOLUTION warning).
    """

    def test_five_relationship_type_match_errors(self):
        bundle = _load("pending_drop_bundle.json")
        findings = check_relationship_type_match(bundle)
        errors = [
            f for f in findings if f.severity == "error" and f.code == "RELATIONSHIP_TYPE_MATCH"
        ]
        assert len(errors) == 5

    def test_tier4_unresolved_identity_warning(self):
        bundle = _load("pending_drop_bundle.json")
        findings = check_identity_ref_resolution(bundle, _KNOWN_IDENTITY_IDS)
        warnings = [
            f for f in findings if f.severity == "warning" and f.code == "IDENTITY_REF_RESOLUTION"
        ]
        assert len(warnings) == 1
        assert "id-unknown-corp" in warnings[0].message

    def test_error_codes_name_relationship_type_match(self):
        bundle = _load("pending_drop_bundle.json")
        findings = check_relationship_type_match(bundle)
        for finding in findings:
            if finding.severity == "error":
                assert finding.code == "RELATIONSHIP_TYPE_MATCH"


class TestExtensionRoundtripBundle:
    """extension_roundtrip_bundle.json — v1.1 extension-definition roundtrip."""

    def test_extension_definition_version_is_1_1(self):
        bundle = _load("extension_roundtrip_bundle.json")
        ext_def = next(
            (o for o in bundle["objects"] if o.get("type") == "extension-definition"), None
        )
        assert ext_def is not None
        assert ext_def["version"] == "1.1"

    def test_extension_types_include_new_sdo_and_toplevel(self):
        bundle = _load("extension_roundtrip_bundle.json")
        ext_def = next(o for o in bundle["objects"] if o.get("type") == "extension-definition")
        assert "new-sdo" in ext_def["extension_types"]
        assert "toplevel-property-extension" in ext_def["extension_types"]

    def test_x_asset_internal_carries_extensions_map(self):
        bundle = _load("extension_roundtrip_bundle.json")
        x_asset = next(o for o in bundle["objects"] if o.get("type") == "x-asset-internal")
        ext_id = "extension-definition--c1e4d6a7-2f3b-4e8c-9a5f-1b8d7e6c4a3f"
        assert ext_id in x_asset.get("extensions", {})
        assert x_asset["extensions"][ext_id]["extension_type"] == "new-sdo"

    def test_x_identity_internal_carries_extensions_map(self):
        bundle = _load("extension_roundtrip_bundle.json")
        x_ident = next(o for o in bundle["objects"] if o.get("type") == "x-identity-internal")
        ext_id = "extension-definition--c1e4d6a7-2f3b-4e8c-9a5f-1b8d7e6c4a3f"
        assert ext_id in x_ident.get("extensions", {})
        assert x_ident["extensions"][ext_id]["extension_type"] == "new-sdo"
