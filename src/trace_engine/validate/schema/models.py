"""Pydantic v2 models for SAGE input artifacts.

These models define the schema contract that TRACE enforces before SAGE
ingests any artifact. The shapes are derived from:

- ``SAGE/cmd/load_assets.py`` and ``SAGE/tests/fixtures/sample_assets.json``
  for ``AssetsDocument``.
- ``SAGE/src/sage/pir/filter.py`` (lines 25-39) and
  ``SAGE/tests/fixtures/sample_pir.json`` for ``PIRItem``.

Schema validation only — referential / semantic checks live in
``trace_engine.validate.semantic``.
"""

from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, model_validator


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


class NetworkSegment(_StrictModel):
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    cidr: str = Field(min_length=1)
    zone: str = Field(min_length=1)


class SecurityControl(_StrictModel):
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    control_type: str | None = None
    coverage: list[str] = Field(default_factory=list)


class Asset(_StrictModel):
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    asset_type: str | None = None
    environment: str | None = None
    criticality: float = Field(default=5.0, ge=0.0, le=10.0)
    owner: str | None = None
    network_segment_id: str | None = None
    exposed_to_internet: bool = False
    tags: list[str] = Field(default_factory=list)
    security_control_ids: list[str] = Field(default_factory=list)


class AssetVulnerability(_StrictModel):
    asset_id: str = Field(min_length=1)
    vuln_stix_id_ref: str = Field(min_length=1)
    remediation_status: str = "open"


class AssetConnection(_StrictModel):
    src: str = Field(min_length=1)
    dst: str = Field(min_length=1)
    protocol: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)


class ActorTarget(_StrictModel):
    actor_stix_id_ref: str = Field(min_length=1)
    asset_id: str = Field(min_length=1)
    confidence: int | None = Field(default=None, ge=0, le=100)


class AssetsDocument(BaseModel):
    """Top-level shape of ``assets.json`` consumed by SAGE."""

    model_config = ConfigDict(extra="allow")  # tolerate "_comment" etc.

    network_segments: list[NetworkSegment] = Field(default_factory=list)
    security_controls: list[SecurityControl] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    asset_vulnerabilities: list[AssetVulnerability] = Field(default_factory=list)
    asset_connections: list[AssetConnection] = Field(default_factory=list)
    actor_targets: list[ActorTarget] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# PIR
# ---------------------------------------------------------------------------


class AssetWeightRule(_StrictModel):
    tag: str = Field(min_length=1)
    criticality_multiplier: float = Field(gt=0.0)


class PIRItem(BaseModel):
    """Single PIR entry.

    Mirrors SAGE's ``PIRFilter.from_file`` consumer in shape, while
    accepting the richer field set BEACON's generator emits
    (``intelligence_level``, ``rationale``, ``risk_score`` etc.) so
    BEACON-authored PIRs round-trip without loss.
    """

    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)

    pir_id: str = Field(min_length=1)
    threat_actor_tags: list[str] = Field(default_factory=list)
    asset_weight_rules: list[AssetWeightRule] = Field(default_factory=list)
    valid_from: date
    valid_until: date

    organizational_scope: str | None = None
    description: str | None = None
    intelligence_level: str | None = None  # strategic / operational / tactical

    @model_validator(mode="after")
    def _check_validity_window(self) -> PIRItem:
        if self.valid_from >= self.valid_until:
            raise ValueError(
                f"valid_from ({self.valid_from}) must be earlier than "
                f"valid_until ({self.valid_until})"
            )
        return self


class PIRDocument(RootModel[list[PIRItem]]):
    """A PIR file is a JSON list of PIRItem (single-object form is normalized
    to a one-element list before validation)."""

    @classmethod
    def from_payload(cls, payload: object) -> PIRDocument:
        items = payload if isinstance(payload, list) else [payload]
        return cls.model_validate(items)


# ---------------------------------------------------------------------------
# Sources (input/sources.yaml — batch crawl source list)
# ---------------------------------------------------------------------------


class SourceEntry(_StrictModel):
    """One entry in ``input/sources.yaml``.

    Fields beyond ``url`` are optional and supply per-source policy used by
    ``cmd/crawl_batch.py``.
    """

    url: str = Field(min_length=1)
    label: str | None = None
    task: Literal["simple", "medium", "complex"] = "medium"
    max_chars: int | None = Field(default=None, gt=0)
    pir_ids: list[str] = Field(
        default_factory=list,
        description=(
            "Optional restriction: only run the L2 relevance gate against "
            "these PIR ids. Empty list (default) means evaluate against all PIRs."
        ),
    )


class SourcesDocument(_StrictModel):
    version: int = Field(default=1, ge=1)
    sources: list[SourceEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Identity assets (Initiative A — TRACE 1.1.0 / SAGE 0.6.0)
# ---------------------------------------------------------------------------
# Pydantic mirror of BEACON 0.11.0's `identity_assets.json` artifact.
# The schema is shape-validation only — cross-reference (asset_id ∈
# assets.json, identity_id ∈ identities[].id) is performed by
# ``validate_identity_assets`` semantic.


_IDENTITY_CLASS_OV: tuple[str, ...] = (
    "individual",
    "group",
    "system",
    "organization",
    "class",
    "unknown",
)


class IdentityEntry(_StrictModel):
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    identity_class: Literal[
        "individual",
        "group",
        "system",
        "organization",
        "class",
        "unknown",
    ] = "group"
    sectors: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    description: str = ""


class HasAccessEntry(_StrictModel):
    identity_id: str = Field(min_length=1)
    asset_id: str = Field(min_length=1)
    access_level: Literal["read", "write", "admin", "deny"] = "read"
    role: str = ""
    granted_at: str = ""  # ISO date or empty
    revoked_at: str = ""

    @model_validator(mode="after")
    def _granted_before_revoked(self) -> HasAccessEntry:
        if self.granted_at and self.revoked_at and self.granted_at >= self.revoked_at:
            raise ValueError(
                f"granted_at ({self.granted_at}) must precede revoked_at ({self.revoked_at})"
            )
        return self


class IdentityAssetsDocument(_StrictModel):
    version: int = Field(default=1, ge=1)
    identities: list[IdentityEntry] = Field(default_factory=list)
    has_access: list[HasAccessEntry] = Field(default_factory=list)
    # Allow the optional _comment field BEACON emits as a hint to the
    # operator. Strict mode would reject it otherwise.
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)


# ---------------------------------------------------------------------------
# User accounts (Initiative B — TRACE 1.3.0 / SAGE 0.7.0)
# ---------------------------------------------------------------------------
# Pydantic mirror of BEACON 0.12.0's `user_accounts.json` artifact. Same
# shape-only validation pattern as IdentityAssetsDocument; cross-reference
# (user_account_id ∈ user_accounts[*].id, asset_id ∈ assets[*].id,
# identity_id ∈ identity_assets identities[*].id when supplied) is enforced
# in ``validate_user_accounts`` semantic.


# 1.4.2: STIX 2.1 §6.4 ``account-type-ov`` canonical vocabulary plus
# empty string for "no suitable spec value". Operational distinctions
# (Azure AD / Kerberos / SaaS / generic services) move to
# ``is_service_account`` + ``description`` instead. {244} validator
# warning therefore disappears.
_ACCOUNT_TYPE_OV: tuple[str, ...] = (
    "",
    "unix",
    "windows-local",
    "windows-domain",
    "ldap",
    "tacacs",
    "radius",
    "nis",
    "openid",
    "facebook",
    "skype",
    "twitter",
    "kavi",
)


class UserAccountEntry(_StrictModel):
    id: str = Field(min_length=1)
    account_login: str = Field(min_length=1)
    display_name: str = ""
    account_type: Literal[
        "",
        "unix",
        "windows-local",
        "windows-domain",
        "ldap",
        "tacacs",
        "radius",
        "nis",
        "openid",
        "facebook",
        "skype",
        "twitter",
        "kavi",
    ] = ""
    is_privileged: bool = False
    is_service_account: bool = False
    identity_id: str = ""  # optional
    description: str = ""


class AccountOnAssetEntry(_StrictModel):
    user_account_id: str = Field(min_length=1)
    asset_id: str = Field(min_length=1)
    first_seen: str = ""
    last_seen: str = ""

    @model_validator(mode="after")
    def _first_before_last(self) -> AccountOnAssetEntry:
        if self.first_seen and self.last_seen and self.first_seen >= self.last_seen:
            raise ValueError(
                f"first_seen ({self.first_seen}) must precede last_seen ({self.last_seen})"
            )
        return self


class UserAccountsDocument(_StrictModel):
    version: int = Field(default=1, ge=1)
    user_accounts: list[UserAccountEntry] = Field(default_factory=list)
    account_on_asset: list[AccountOnAssetEntry] = Field(default_factory=list)
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)
