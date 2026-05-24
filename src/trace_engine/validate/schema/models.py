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

from pydantic import BaseModel, ConfigDict, Field, RootModel, field_validator, model_validator


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


# ---------------------------------------------------------------------------
# Actor triage (BEACON 0.15.0 / TRACE 1.8.0 — Phase 5)
# ---------------------------------------------------------------------------


class ScoreComponent(BaseModel):
    """Generic I×C×O score component — strict mode.

    Used for intent / capability / opportunity sub-breakdowns in
    ActorTriageEntry. ``extra='forbid'`` rejects unknown fields,
    catching typos and silent producer drift. Adding a new sub-factor
    requires bumping ``SUPPORTED_PIR_SCHEMA_VERSIONS`` and extending
    this model.

    Canonical sub-factor names (committed surface as of schema_version
    1.0.0; see ``docs/api-stability.md``):
      Intent:       motivation_alignment, industry_match
      Capability:   ttp_count_norm, sophistication_score,
                    recency_active_campaigns, tool_sophistication,
                    targeting_persistence, evasion_capability, depth,
                    breadth, ir_observed_capability
      Opportunity:  victimology_match, geographic_match,
                    surface_ttp_coverage, ir_observed_opportunity
    """

    model_config = ConfigDict(extra="forbid")
    score: float = Field(ge=0.0, le=1.0)

    # Intent sub-factors (BEACON IntentComponent).
    motivation_alignment: float | None = Field(default=None, ge=0.0, le=1.0)
    industry_match: float | None = Field(default=None, ge=0.0, le=1.0)

    # Capability sub-factors (BEACON CapabilityComponent).
    ttp_count_norm: float | None = Field(default=None, ge=0.0, le=1.0)
    sophistication_score: float | None = Field(default=None, ge=0.0, le=1.0)
    recency_active_campaigns: float | None = Field(default=None, ge=0.0, le=1.0)
    tool_sophistication: float | None = Field(default=None, ge=0.0, le=1.0)
    targeting_persistence: float | None = Field(default=None, ge=0.0, le=1.0)
    evasion_capability: float | None = Field(default=None, ge=0.0, le=1.0)
    depth: float | None = Field(default=None, ge=0.0, le=1.0)
    breadth: float | None = Field(default=None, ge=0.0, le=1.0)
    ir_observed_capability: float | None = Field(default=None, ge=0.0, le=1.0)

    # Opportunity sub-factors (BEACON OpportunityComponent).
    victimology_match: float | None = Field(default=None, ge=0.0, le=1.0)
    geographic_match: float | None = Field(default=None, ge=0.0, le=1.0)
    surface_ttp_coverage: float | None = Field(default=None, ge=0.0, le=1.0)
    ir_observed_opportunity: float | None = Field(default=None, ge=0.0, le=1.0)


class DataQuality(BaseModel):
    """Data quality metadata for actor triage entries.

    ``extra='allow'`` is preserved so new additive quality flags can be
    added without a TRACE major bump (additive changes stay on
    schema_version 1.0.0 per H-2 / api-stability.md).
    """

    model_config = ConfigDict(extra="allow")
    degraded: bool = False
    missing_sources: list[str] = Field(default_factory=list)
    ir_boost_skipped: bool = False


class ActorScoreBreakdown(BaseModel):
    """Structured score breakdown for ActorTriageEntry."""

    model_config = ConfigDict(extra="allow")
    intent: ScoreComponent
    capability: ScoreComponent
    opportunity: ScoreComponent
    data_quality: DataQuality = Field(default_factory=DataQuality)


class ActorRationale(BaseModel):
    """Human-readable and structured rationale for ActorTriageEntry."""

    model_config = ConfigDict(extra="allow")
    text: str
    intent_factors: dict[str, float] = Field(default_factory=dict)
    capability_factors: dict[str, float] = Field(default_factory=dict)
    opportunity_factors: dict[str, float] = Field(default_factory=dict)


class ActorTriageEntry(BaseModel):
    """Single actor triage entry from BEACON's ``prioritized_actors[]``.

    ``extra='allow'`` keeps the entry forward-compatible with additive
    BEACON sub-field additions (allowed in minors per the 90-day BC
    policy).
    """

    model_config = ConfigDict(extra="allow")
    actor_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    aliases: list[str] = Field(default_factory=list)
    likelihood: float = Field(ge=0.0, le=1.0)
    score_breakdown: ActorScoreBreakdown
    rationale: ActorRationale


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
    prioritized_actors: list[ActorTriageEntry]

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
    to a one-element list before validation).

    BEACON 1.0.0+ emits a wrapped object {"schema_version": ..., "pirs": [...]};
    ``from_payload`` routes the wrapped form through ``PIROutputDocument`` so
    the schema_version gate (see ``SUPPORTED_PIR_SCHEMA_VERSIONS``) fires
    before per-item validation. Bare list / single-object payloads remain
    accepted for the SAGE-side PIR loader and direct ``PIRItem`` tests.
    """

    @classmethod
    def from_payload(cls, payload: object) -> PIRDocument:
        if isinstance(payload, dict) and "pirs" in payload:
            wrapper = PIROutputDocument.model_validate(payload)
            return cls(root=wrapper.pirs)
        if isinstance(payload, list):
            items = payload
        else:
            items = [payload]
        return cls.model_validate(items)


# Initiative H (TRACE 1.12.0): tightened to ``{"1.0.0"}``. Pre-1.0 versions
# (0.16.0 / 0.17.0 / 0.18.0) are now rejected with a per-version message
# (see ``_REJECTED_VERSION_HISTORY`` below) directing the operator to
# re-emit with BEACON 1.0.0+.
SUPPORTED_PIR_SCHEMA_VERSIONS: set[str] = {"1.0.0"}

# Plan H-12b: per-version reject message maps each historically supported
# pre-1.0 schema_version to the TRACE minor that last accepted it. Other
# unrecognised values (e.g. ``"0.15.0"`` or a future ``"1.1.0"``) fall
# through to the generic message that names the current TRACE version.
_REJECTED_VERSION_HISTORY: dict[str, str] = {
    "0.16.0": "1.9.0",
    "0.17.0": "1.10.0",
    "0.18.0": "1.11.0",
}

# Hard-coded current TRACE version name used in reject messages. Kept in
# sync with ``pyproject.toml`` at each release tag (Initiative H §6
# Phase 7). A constant rather than ``importlib.metadata.version`` lookup
# so the validator works during ``uv sync`` first-run before the package
# is fully installed.
_TRACE_VERSION = "1.12.0"


class PIROutputDocument(BaseModel):
    """Document-level schema for pir_output.json (BEACON 1.0.0+).

    Mirrors BEACON's ``PIROutputDocument`` shape for drift-check alignment.
    ``schema_version`` is required; bundles without it or with a value
    outside ``SUPPORTED_PIR_SCHEMA_VERSIONS`` are rejected so unannounced
    producer schema changes cannot slip through to SAGE ingestion.
    """

    model_config = ConfigDict(extra="allow")
    schema_version: str = Field(
        description="Semantic version of the pir_output schema.",
    )
    pirs: list[PIRItem]

    @field_validator("schema_version")
    @classmethod
    def _check_supported_schema_version(cls, v: str) -> str:
        if v in SUPPORTED_PIR_SCHEMA_VERSIONS:
            return v
        legacy_trace = _REJECTED_VERSION_HISTORY.get(v)
        if legacy_trace is not None:
            raise ValueError(
                f'schema_version "{v}" was supported in TRACE {legacy_trace}; '
                f"please re-emit with BEACON 1.0.0+ output."
            )
        supported = "{" + ", ".join(sorted(SUPPORTED_PIR_SCHEMA_VERSIONS)) + "}"
        raise ValueError(
            f'schema_version "{v}" is not supported by TRACE {_TRACE_VERSION}; '
            f"supported: {supported}."
        )


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
    feed_type: Literal["html", "rss", "atom"] | None = Field(
        default=None,
        description=(
            "Optional override for the URL's feed type. When unset, "
            "``crawler/feed_detector.py`` infers the type from the HTTP "
            "Content-Type header. Set this only when an upstream server "
            "returns an incorrect Content-Type (e.g. ``application/octet-stream`` "
            "for an RSS feed) and feed expansion is required."
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
    # Initiative C Phase 2 (BEACON 0.13.0 / TRACE 1.6.0 / SAGE 0.9.0):
    # producer-side flag set when an identity is a high-value impersonation
    # target. SAGE reads this to set `effective_priority` multiplier=1.5
    # via the flag-first path; TRACE's PIR L2 gate consumes it for
    # pre-extraction prioritisation. Optional defaults preserve backward
    # compat with BEACON 0.12.x output.
    is_high_value_impersonation_target: bool = False
    impersonation_risk_factors: list[str] = Field(default_factory=list)


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
