# TRACE Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Changed — RULES.md compliance pass

- `.env.example` now documents every `TRACE_*` env var read by `Config.from_env()`,
  including the 1.7.0 taxonomy-sync settings and the previously undocumented
  `TRACE_CRAWL_CONCURRENCY` / `TRACE_EXTERNAL_REF_HASH_*` /
  `TRACE_EXTRACTION_CHUNK_CHARS` (Rule 24).
- `docs/beacon_handoff.ja.md` added as the Japanese counterpart of
  `docs/beacon_handoff.md` (Rule 11).
- `docs/structure.md` + `docs/structure.ja.md` added to document TRACE's
  top-level layout and the `src/` deviation from Rule 26's suggested
  `internal/` / `pkg/` shape.
- `high-level-design.md` moved from project root to `docs/` so the location
  matches Rule 27. `.gitignore` updated to keep the new path out of VCS
  per maintainer policy. README links updated.

## [1.7.0] — 2026-05-15

### Added — Taxonomy enrichment for PIR binding

Fixes the silent zero-ingest issue where `run_etl --manual-bundle` dropped
all actors/edges because TRACE bundles lacked the PIR vocabulary tags
(`apt-china`, `apt-russia`, …) that SAGE's `pir_filter.is_relevant_actor`
requires.

- `src/trace_engine/stix/taxonomy_enrich.py` — new module:
  - `load_taxonomy_index(path)` builds a `{normalized_group_name: [tag, ...]}` lookup from the cached taxonomy.
  - `enrich_threat_actor_object(obj, index)` merges matching tags into `labels` (dedup, order-preserving).
  - `enrich_bundle_objects(objects, index)` applies enrichment to all `threat-actor` / `intrusion-set` objects.
- `src/trace_engine/crawler/taxonomy_sync.py` — new module:
  - `ensure_taxonomy_fresh(config)` — best-effort sync from BEACON source to TRACE cache; logs `taxonomy_sync_skipped` when BEACON is unavailable and falls back to the existing snapshot.
  - `_sync_taxonomy(source, output)` — low-level write path used by the explicit CLI.
- `src/trace_engine/stix/extractor.py` — `build_stix_bundle_from_extraction` now loads the taxonomy index once at function entry and enriches each `threat-actor` / `intrusion-set` object before bundle assembly. Logs `taxonomy_enrich_disabled` and continues if the cache is absent.
- `src/trace_engine/config.py` — two new config fields:
  - `threat_taxonomy_cache_path` (env `TRACE_TAXONOMY_CACHE_PATH`) — path to the TRACE-side cache; defaults to `schema/threat_taxonomy.cached.json`.
  - `beacon_taxonomy_source_path` (env `TRACE_BEACON_TAXONOMY_SOURCE`) — path to the BEACON master file for auto-sync; defaults to `../BEACON/schema/threat_taxonomy.json`.
- `cmd/crawl_single.py`, `cmd/crawl_batch.py` — call `ensure_taxonomy_fresh(config)` at startup (best-effort). New `--no-sync-taxonomy` flag to opt out (CI / air-gapped environments).
- `cmd/enrich_bundle.py` — rescue CLI for external bundles (OpenCTI feeds, hand-authored STIX, old TRACE output). Reads a bundle, enriches actors, writes atomically. Use before `run_etl --manual-bundle`.
- `cmd/update_taxonomy_cache.py` — refactored to delegate the write path to `taxonomy_sync._sync_taxonomy`; CLI behavior unchanged.

### Tests

- `tests/test_taxonomy_enrich.py` — 21 cases covering index build, per-object enrichment, bundle enrichment, idempotency, and alias-only match.
- `tests/test_extractor_enrich_integration.py` — 5 cases: MirrorFace → `apt-china`, Sandworm Team → `apt-russia`, cache-missing graceful path, non-actor types untouched, idempotency.
- `tests/test_enrich_bundle_cli.py` — 6 cases: round-trip, idempotency, exit codes, atomic write.
- `tests/test_stix_extractor.py` — three existing tests updated to pass `config` with a nonexistent taxonomy path, isolating label-demotion behavior from enrichment.

## [1.6.0] — 2026-05-13

### Added — Initiative C Phase 2 (consumer side)

Paired release with BEACON 0.13.0 + SAGE 0.9.0. TRACE 1.6.0 consumes the
new `is_high_value_impersonation_target` flag (and adjacent
`impersonation_risk_factors` list) that BEACON 0.13.0 emits into
`identity_assets.json` for high-value impersonation targets.

- `IdentityEntry` Pydantic model
  (`src/trace_engine/validate/schema/models.py`) gains two optional
  fields matching BEACON's Identity schema:
  - `is_high_value_impersonation_target: bool = False`
  - `impersonation_risk_factors: list[str] = []`
  Defaults preserve backward compat with BEACON 0.12.x identity_assets
  (which omit the fields).
- PIR L2 relevance gate (`src/trace_engine/pir/relevance.py`):
  - `evaluate()` accepts a new optional
    `high_value_identity_names: list[str] | None` parameter.
  - Helper `_apply_high_value_boost` adds a `+0.2` boost (capped at 1.0)
    to the LLM verdict when the crawled document mentions any flagged
    identity name (case-insensitive substring match).
  - Boost is skipped on failed verdicts (preserves fail-open semantics).
  - Structured-log event `high_value_identity_boost_applied` records the
    matched names, score before / after, and boost magnitude.
- `cmd/crawl_single.py`: new `--identity-assets` CLI option that loads
  BEACON's `identity_assets.json`, extracts the names of flagged
  identities, and threads them into the PIR L2 gate.

### Tests

- `tests/test_pir_relevance.py`: new `TestHighValueIdentityBoost` class
  with seven cases covering the boost (match / no match / case-insensitive
  / cap at 1.0 / failed-verdict no-op / empty list no-op / None no-op).
- `tests/test_validate_identity_assets.py`: two new cases verifying that
  the flag defaults to False and round-trips with risk factors.

## [1.5.1] — 2026-05-13

### Added

- `cmd/generate_schemas.py` exporting consumer-canonical JSON Schemas
  (`schema/pir.schema.json` from `PIRItem`,
  `schema/assets.schema.json` from `AssetsDocument`). Both schemas are
  committed to git as the wire-format contract that TRACE enforces on
  SAGE input artifacts.
- `scripts/check_pir_schema_drift.py` — standard-library drift detector
  comparing BEACON's producer canonical against TRACE's consumer
  canonical per plan §2.2 rules. ERROR rules (1 / 2 / 3) cause non-zero
  exit; WARNING rules (4 / 5 / 6) surface known acceptable drift on
  stderr. Rule 6 covers JSON Schema `format` constraint drift on shared
  string properties (e.g. BEACON `valid_from: string` vs TRACE
  `valid_from: string format=date`) so plan §2.3 known drift becomes
  visible without blocking release.
- `make check-pir-schema-drift` target chained into `check`. Skips
  gracefully when the BEACON sibling repo is not present so TRACE-only
  contributors can still run the full quality gate.

### Tests

- `tests/fixtures/initiative_c/spec_compliant_bundle.json` (canonical):
  added an executive-role `identity` SDO (`roles=["cfo"]`) and a second
  `impersonates` relationship (`confidence=60`) targeting it. Closes the
  Phase 1 post-impl gap where the §6.6 `effective_priority` multiplier=1.5
  path was unit-covered but not exercised end-to-end via the synthetic
  bundle (HLD §8.5 required "executive-role vs non-privileged identities"
  coverage). `tests/test_initiative_c_e2e.py` relationship-count
  assertion bumped from 5 to 6. The bundle still covers all 5 §3.4
  emit-ready type combinations — combination 5 simply has two instances.
  No source-code or wire-format change.

## [1.5.0] — 2026-05-12

### Added — Initiative C Phase 1: `attributed-to` / `impersonates` SRO support

Paired release with SAGE 0.8.0. Implements STIX 2.1 §7.2 spec-standard
attribution and impersonation edges end-to-end from L3 LLM extraction
through STIX bundle assembly.

#### New capabilities

- **`attributed-to` SRO** (5 emit-ready source/target combos per §3.4):
  `campaign → threat-actor/intrusion-set`, `intrusion-set → threat-actor`,
  `threat-actor → identity`.
- **`impersonates` SRO**: `threat-actor → identity`.
- **`campaign` entity type** added to `_VALID_ENTITY_TYPES` for SolarWinds-class
  named adversarial operations (STIX 2.1 §4.4 canonical source for
  `attributed-to`).
- **Identity resolver** (`stix/identity_resolver.py`): 4-tier matching ladder
  (exact name → substring → roles/sectors → drop) modeled on `asset_resolver`.
  Returns `Resolution(identity_id, tier, confidence)` for cross-artifact
  identity resolution against `identity_assets.json`.
- **`x-identity-internal` SDO** synthesis: UUIDv5-deterministic STIX id
  (namespace `c4f8d2e6-9b1a-5c7d-8e3f-2a4b6d8e1c5f`, input = BEACON
  `identity_id` slug). Carries `extensions` map entry per STIX 2.1 §7.3.
- **ICD 203 confidence parser** (`_confidence_from_hedge_phrase`): 7-band
  Words of Estimative Probability → integer mapping; omits field when no
  hedge phrase matched (no fabrication).
- **Extension-definition v1.0 → v1.1**: `extension_types` gains `"new-sdo"`;
  description documents `x-asset-internal` (Initiative A) and
  `x-identity-internal` (Initiative C). All `x-asset-internal` instances
  retrofit the `extensions` map entry.
- **Semantic validator** (`validate/semantic/relationships.py`):
  `check_relationship_type_match` flags `RELATIONSHIP_TYPE_MATCH` errors;
  `check_identity_ref_resolution` flags `IDENTITY_REF_RESOLUTION` warnings.
- **`validate_stix.py --identity-assets`** flag: cross-checks
  `x-identity-internal[*].identity_id ∈ identity_assets.json[*].identities[*].id`.
- **L3 prompt** (`stix_extraction.md`): campaign entity guidance, attribution /
  impersonation relationship vocabulary, ICD 203 confidence table,
  prose-normalization examples, `identity_relationship_edges` output shape.
- **Synthetic test fixtures** (`tests/fixtures/initiative_c/`): 3 bundles
  covering the §8.5 deterministic CI gate.

#### Out-of-spec combinations dropped (§3.1.1 pending)

`incident → attributed-to → *`, `threat-actor → attributed-to → intrusion-set`,
`intrusion-set → attributed-to → identity`, `intrusion-set → impersonates → identity`
are dropped at `_RELATIONSHIP_TYPE_TABLE` guard with `relationship_type_mismatch_dropped`
structured log. Deferred per strict-compliance posture of TRACE 1.4.2/1.4.3.

#### Tests

317 tests pass (51 new Initiative C cases).

---

## [1.4.3] — 2026-05-10

### Fixed — `identity_class` aligned to STIX 2.1 §6.7 ``identity-class-ov``

Pairs with BEACON 0.12.2. Initiative A (TRACE 1.1.0) inherited
the same ``"unspecified"`` typo for the `identity_class` open
vocabulary that BEACON 0.11.0 carried. The canonical STIX 2.1
§6.7 value is ``"unknown"`` — verified against
``stix2-validator``'s ``IDENTITY_CLASS_OV``.

Symptom: TRACE 1.4.2 real-LLM crawl on the Trend Micro article
emitted exactly one ``{213}`` validator warning per identity SDO
that landed on ``unspecified``. Same architectural class as the
``{244}`` warnings 1.4.2 fixed — just a different vocabulary.

#### Changes

- `_STIX21_IDENTITY_CLASS_OV` frozenset (`stix/extractor.py`):
  `unspecified` → `unknown`. The demote-to-labels function was
  doing the right thing — it was the OV constant itself that was
  wrong, so spec-compliant LLM output was passing through *and
  then* tripping the validator on the wire.
- L3 prompt (`stix_extraction.md`): same correction in the
  identity entity's optional fields block.
- `validate/schema/models.IdentityEntry.identity_class` Literal
  (and the parallel `_IDENTITY_CLASS_OV` tuple): same correction.
  Cross-project parity with BEACON 0.12.2.

No test changes — no test asserted on the typo'd value.

#### Verification

After the fix, the identity SDO emitted by the L3 LLM extractor
on ambiguous victim references (e.g. "owner of compromised email
server") carries `identity_class: "unknown"`, which both Pydantic
and ``stix2-validator`` accept without warnings.

---

## [1.4.2] — 2026-05-10

### Changed — `account_type` aligned to STIX 2.1 §6.4 ``account-type-ov`` strictly

Pairs with BEACON 0.12.1. Initiative B's first slice (TRACE
1.4.0 / BEACON 0.12.0) emitted operationally-named values
(`service`, `unix-account`, `azure-ad`, `google-workspace`,
`saas`, `kerberos`, `other`) on the synthesized STIX
`user-account` SCO. None of those appear in STIX 2.1 §6.4
``account-type-ov``, so the OASIS ``stix2-validator`` issued one
`{244}` warning per emitted SCO — Initiative B real-LLM crawl on
the Trend Micro article in 1.4.1 produced 4 such warnings.

We do not extend the STIX vocabulary; doing so erodes the
rationale for using STIX. 1.4.2 restricts emitted values to the
spec OV and treats every other distinction as either
`is_service_account: true` or free-form `description`.

#### Extractor changes

- `UserAccountObservation.account_type` default changed from
  ``"other"`` → ``""``.
- `_coerce_user_account_observations` rewrote the validation
  set: only the 12 STIX OV values are kept; anything else is
  coerced to empty string so the bundle assembler can omit
  `account_type` entirely (it is OPTIONAL in STIX 2.1 §6.4).
- L3 prompt (`stix_extraction.md`) updated to instruct the LLM
  to use STIX OV only and to leave `account_type` empty when no
  spec value applies. Examples reworked accordingly (Azure AD /
  service accounts → empty + `is_service_account: true`).

#### Pydantic schema

`validate/schema/models.UserAccountEntry.account_type` Literal
now restricts values to:

```
"" | unix | windows-local | windows-domain | ldap | tacacs |
radius | nis | openid | facebook | skype | twitter | kavi
```

This matches the BEACON 0.12.1 schema; the cross-project
validator (`validate_user_accounts`) accepts both BEACON-source
and trace-source artifacts under the same vocabulary.

#### Bundle assembler

- `account_type` is emitted on the `user-account` SCO **only when
  set** (non-empty STIX OV value). When empty, the property is
  omitted from the SCO — STIX 2.1 §6.4 makes `account_type`
  OPTIONAL, so this is fully spec-compliant.
- `{244}` validator warning therefore disappears on Initiative B
  real-LLM crawl output.

#### Test updates

- `test_unknown_account_type_demoted_to_other` →
  `test_unknown_account_type_coerced_to_empty`.
- Fixtures updated: `unix-account` → `unix`, `service` → ``""``
  + `is_service_account=True`.

#### Migration (consumers)

- `BEACON/input/context.md` user-account entries: see BEACON
  0.12.1 migration table.
- `SAGE/tests/fixtures/synthetic_trace_user_account_bundle.json`:
  `service` SCO drops `account_type`; STIX OV values pass through
  unchanged.

SAGE 0.7.0 schema needs no change (STRING(64) `account_type`
already accepts both OV values and NULL/empty).

---

## [1.4.1] — 2026-05-10

### Fixed — `crawl_user_agent` ignored by URL fetch (markitdown path)

Initiative B E2E verification stalled at the LLM-crawl step with
``HTTPError: 429 Client Error: Too Many Requests`` against
Trend Micro's research blog. Re-trying after a long wait did not
help — root cause was structural, not rate-limit timing.

`ingest/report_reader._markitdown_convert` instantiated
``MarkItDown()`` without arguments. The library's default behaviour
creates an internal ``requests.Session`` that sets only the
``Accept`` header — no ``User-Agent``. The underlying ``requests``
library therefore sent ``python-requests/<version>`` as the UA,
which Cloudflare-fronted CTI sites reliably block as bot traffic.
The TRACE ``crawl_user_agent`` config / ``TRACE_CRAWL_USER_AGENT``
env var was wired into ``crawler/fetcher.py`` (used only by the
batch path's httpx fetch) but **not** into the markitdown URL fetch
that ``crawl_single`` uses.

#### Fix

- `_markitdown_convert(source, *, config=None)` now builds a
  ``requests.Session`` with both the configured UA and markitdown's
  preferred ``Accept`` header, then passes it as
  ``MarkItDown(requests_session=session)``.
- `read_report(source, max_chars=..., *, config=None)` accepts and
  forwards the same parameter.
- `cmd/crawl_single.py` and `crawler/batch._process_source_body`
  pass their already-loaded ``Config`` instance through.

#### Default UA changed

The pre-1.4.1 default carried a tool-identifying string. Cloudflare-
class WAFs treated it as a known bot pattern. The new default is a
widely-deployed Firefox-on-macOS string, which passes typical
commercial bot-detection heuristics. Operators who deliberately
want to identify CTI collectors override via
``TRACE_CRAWL_USER_AGENT``.

```
# Before (1.4.0):
TRACE_CRAWL_USER_AGENT default = "TRACE/0.1 (+https://github.com/...)"

# After (1.4.1):
TRACE_CRAWL_USER_AGENT default = "Mozilla/5.0 (Macintosh; Intel Mac
  OS X 11.1; rv:136.0) Gecko/20100101 Firefox/136.0"
```

### Tests

5 new cases in `tests/test_report_reader_ua.py`:

- `MarkItDown(requests_session=...)` receives a session whose
  ``User-Agent`` header equals ``Config.crawl_user_agent``
- the session retains markitdown's preferred ``Accept`` header
- the in-code default is a browser-shaped string with no
  ``TRACE/`` / ``trace/`` / ``github.com/sw33t-b1u`` substring
- ``TRACE_CRAWL_USER_AGENT`` env var override still wins
- ``read_report`` forwards the caller-supplied ``Config`` to
  ``_markitdown_convert`` (regression guard for the CLI path)

Plus `tests/test_crawl_batch.py::test_concurrent_crawl_processes_all_sources`'s
mock signature updated to accept the new ``config=`` kwarg.

All 266 tests pass; 0 vulnerabilities.

---

## [1.4.0] — 2026-05-10

### Added — Initiative B Phase 2: L3 prompt + bundle assembler for user-account

Completes the User-Account SCO trace-source pipeline that 1.3.0
declared. The L3 prompt now asks the LLM to emit
``user_account_observations`` from CTI report text; the bundle
assembler synthesizes STIX 2.1 §6.4 user-account SCOs (UUIDv5-id'd
for cross-run determinism), wraps them in §4.10 observed-data SDOs,
and emits ``x-trace-valids-on`` relationships for each
asset-resolved host. Mirror of 1.2.0's identity_asset_edges flow
with the same asset_resolver ladder.

#### Extraction pipeline

- New `UserAccountObservation` dataclass on `Extraction`.
- `_coerce_user_account_observations` parses the LLM's
  `user_account_observations[]` array (account_login required,
  account_type validated against the §6.4 vocab and demoted to
  `other` when unknown).
- `_extract_chunk` populates the new field; chunked extractions
  re-prefix `identity_local_id` so the merge stage can resolve it
  through the canonical alias map.
- `_merge_extractions` deduplicates on
  `(account_login.lower(), account_type)` and clears unresolved
  identity owner links.

#### Bundle assembler

`build_stix_bundle_from_extraction` now processes
`user_account_observations` after the IAE block:

1. Each observation produces one user-account SCO with
   ``id = user-account--<uuid5(NAMESPACE, account_login + "\\0" +
   account_type)>``. Same login + type across crawls produces the
   same STIX id, so SAGE 0.7.0's
   ``upsert_user_account`` updates rather than duplicates.
2. One observed-data SDO per observation wraps the SCO in
   `object_refs` (STIX-spec carrier).
3. When `identity_local_id` resolves to an extracted identity
   entity, emit a `related-to` relationship binding the account to
   its owner. SAGE 0.7.0 maps `(identity → user-account,
   related-to)` to `UserAccountBelongsTo`.
4. For each `asset_references[*]`, run the same
   `resolve_asset_reference` 4-tier ladder used for IAE, reuse the
   `x-asset-internal` cache built by the IAE block (so the same
   host shared by an IAE and a UAO produces a single
   `x-asset-internal` object), and emit one `x-trace-valids-on`
   relationship.

The same `assets=` argument from 1.2.0 powers both flows; no CLI
changes required (`crawl_single` / `crawl_batch` already accept
`--assets`).

#### L3 prompt update

`stix_extraction.md` gained a `user_account_observations` block in
the schema and a new "User-account observations" section with three
worked examples (mailbox compromise, service-account credential
harvest, Domain Admin lateral movement) and an explicit attacker-
account exclusion rule.

#### `_USER_ACCOUNT_NAMESPACE` constant

UUIDv5 namespace mirroring `_X_ASSET_INTERNAL_NAMESPACE` so the
synthesized user-account ids are deterministic per
`(login, account_type)`.

### Tests

12 new cases:

- `tests/test_stix_extractor.py::TestUserAccountObservationCoercion`
  (4) — LLM JSON parsing, missing-field tolerance, blank-login
  guard, account_type vocabulary demotion.
- `tests/test_stix_extractor.py::TestBundleAssemblerUserAccountObservations`
  (8) — SCO + observed-data emission, deterministic STIX id across
  re-emissions, resolved asset reference emits valids-on, unresolved
  drops relationship but keeps SCO, no-assets drops relationships,
  identity owner emits related-to, unknown owner drops link, IAE +
  UAO sharing one asset reuses one x-asset-internal object.

All 261 tests pass; 0 vulnerabilities.

### SAGE pairing

Initiative B Phase 1 SAGE 0.7.0 already accepts
`x-trace-valids-on` and the supporting types. No SAGE release is
required for this slice; existing forward-compatibility (parser
SUPPORTED_TYPES, mapper dispatch, `upsert_account_on_asset`) covers
everything 1.4.0 emits.

### Future scope

- E2E verification with the in-house e-money pilot context.md
  once a User Accounts section is added there (mirrors Initiative
  A's verification flow).
- Phase 2 evaluation gate (per Initiative B design doc):
  privileged-account PIR weighting, account lifecycle automation,
  query API endpoints.

---

## [1.3.0] — 2026-05-10

### Added — Initiative B: user_accounts validator + STIX vocabulary

Validation gate for BEACON 0.12.0's `user_accounts.json`. Mirrors
the Initiative A validator pattern; `--assets` is required for the
asset_id cross-reference, and `--identity-assets` is optional for
the additional `identity_id` cross-reference.

The full Initiative B initiative spans two TRACE releases:

- **1.3.0 (this release)** — schema, semantic validator, CLI,
  STIX type vocabulary additions (`user-account`, `observed-data`,
  `x-trace-valids-on`). The L3 prompt and bundle assembler still
  treat user-account content as out-of-band (BEACON-supplied via
  `cmd/load_user_accounts.py` in SAGE 0.7.0); CTI-extracted
  user-account observations arrive in 1.4.0.
- **1.4.0 (next)** — L3 prompt extension to extract user-account
  observations and `x-trace-valids-on` relationships from CTI
  reports; bundle assembler integration; `crawl_single` /
  `crawl_batch` use the existing `--assets` flag.

#### Pydantic schema additions

`src/trace_engine/validate/schema/models.py`:

- `UserAccountEntry` — `id`, `account_login`, `display_name`,
  `account_type` (Literal of STIX 2.1 §6.4 `account-type-ov`),
  `is_privileged`, `is_service_account`, `identity_id` (optional),
  `description`.
- `AccountOnAssetEntry` — `user_account_id`, `asset_id`,
  `first_seen`, `last_seen`. A `model_validator` rejects
  `first_seen >= last_seen`.
- `UserAccountsDocument` — top-level container with `version`,
  `user_accounts[]`, `account_on_asset[]`. `extra="ignore"` to
  accept BEACON's `_comment` field.

#### Cross-reference checks

`src/trace_engine/validate/semantic/user_accounts.py`:

- `user_accounts[*].id` uniqueness — error.
- `account_on_asset[*].user_account_id` resolves to
  `user_accounts[*].id` — error.
- `account_on_asset[*].asset_id` resolves to a supplied
  `assets.json`'s `assets[*].id` — error.
- (Optional) `user_accounts[*].identity_id` resolves to a supplied
  `identity_assets.json`'s `identities[*].id` — error.
- Duplicate `(user_account_id, asset_id)` pairs — warning.

#### `cmd/validate_user_accounts.py` CLI

`--assets` required, `--identity-assets` optional. Same exit-code
contract as `validate_identity_assets.py`.

#### Extractor vocabulary expansion

- `_VALID_ENTITY_TYPES += {"user-account", "observed-data"}` —
  STIX 2.1 §6.4 SCO + §4.10 SDO. Declared so SAGE 0.7.0 can accept
  bundles emitted by TRACE 1.4.0+ without a vocabulary mismatch.
- `_VALID_RELATIONSHIP_TYPES += "x-trace-valids-on"` — same
  pattern as 1.1.0's `x-trace-has-access` declaration.
- `_RELATIONSHIP_TYPE_TABLE[("user-account", "x-trace-valids-on")] =
  {"x-asset-internal"}` — declares the intended target type for
  forward compatibility.

The bundle assembler does not yet emit any of these (the LLM
prompt is unchanged in 1.3.0); existing tests remain green.

### Tests

13 new cases:

- `tests/test_validate_user_accounts.py` (12) —
  - `TestSchema` (4): minimal account, account_type rejection,
    first_seen/last_seen inversion, optional `_comment` accepted.
  - `TestCrossReference` (5): clean doc, dangling user_account_id,
    dangling asset_id, duplicate user_account_id, duplicate
    account-asset pair.
  - `TestIdentityCrossReference` (2): unknown identity_id with
    identity-assets supplied (error), without identity-assets
    (silent).
  - `TestCli` (2): subprocess clean / dangling.
- `test_stix_extractor.py::test_valid_entity_and_relationship_vocabularies_are_disjoint`
  updated to assert the new entity / relationship types.

All 249 tests pass; 0 vulnerabilities.

### Future scope (TRACE share of remaining Initiative B)

- 1.4.0: L3 prompt extension to emit user-account observed-data +
  `x-trace-valids-on`; bundle assembler integration with
  `asset_resolver`. crawl_single/crawl_batch already accept
  `--assets` from 1.2.0.

---

## [1.2.1] — 2026-05-10

### Fixed — `x-asset-internal` STIX identifier format violation

E2E verification of the trace-source HasAccess path surfaced a
spec-level bug: 1.2.0 emitted ``x-asset-internal--asset-CA-001`` as
the synthetic STIX object's id, but STIX 2.1 §2.7 requires every
identifier referenced by a relationship to match
``<object-type>--<UUIDv4|v5>``. The ``stix2`` library used by SAGE's
parser raised
``Invalid value for Relationship 'target_ref': not a valid STIX
identifier``, dropping every ``x-trace-has-access`` relationship at
parse time. The bug was latent in 1.2.0 because the only real-URL
crawl produced ``emitted=0`` (asset resolver dropped all candidates).

#### Format change

The ``x-asset-internal`` id now uses ``uuid5(_NAMESPACE, asset_id)``,
keeping the id deterministic per asset_id (same SAGE asset always
produces the same STIX id across runs) while satisfying the §2.7
identifier regex. The actual SAGE-side ``asset_id`` lives in the
``asset_id`` property on the object, where SAGE 0.6.2's
parser/worker reads it from.

```python
# Before (1.2.0):
"id": "x-asset-internal--asset-CA-001"  # rejected by stix2 lib

# After (1.2.1):
"id": "x-asset-internal--<uuid5(NAMESPACE, 'asset-CA-001')>",
"asset_id": "asset-CA-001"
```

The relationship's ``target_ref`` points at the new UUID5 form.

### Tests

Updated `TestBundleAssemblerIdentityAssetEdges::test_resolved_edge_emits_x_asset_internal_and_relationship` to assert on the UUID5 shape rather than the raw asset_id; verified that the relationship `target_ref` points at the synthesized object's id (not the raw asset_id).

All 236 tests pass; 0 vulnerabilities.

### SAGE pairing

Requires SAGE 0.6.2 to read the `asset_id` property and route
``x-trace-has-access`` relationships to the ``HasAccess`` table.
Lockstep release per memory `project_release_pairing.md`.

---

## [1.2.0] — 2026-05-10

### Added — Initiative A Phase 2: L3 prompt + bundle assembler integration

Completes the Initiative A trace-source extraction pipeline that 1.1.0
laid the ground for. The L3 prompt now asks the LLM to emit
`identity_asset_edges` from CTI report text; the bundle assembler
resolves each free-form asset reference against `assets.json` via the
4-tier matching ladder (1.1.0's `asset_resolver`); resolved edges
become `x-asset-internal--<asset_id>` synthetic STIX objects plus
`x-trace-has-access` relationships that SAGE 0.6.0 ingests as
`HasAccess` rows with `source = "trace"`.

#### Extraction pipeline

`Extraction.identity_asset_edges: list[IdentityAssetEdge]` is now
populated by `extract_entities`. The new `_coerce_identity_asset_edges`
parser reads the LLM's top-level `identity_asset_edges[]` array (each
entry: `source` local_id of an identity, `asset_reference` free-form
hint, `description` short role label). Chunked extractions namespace
edges per chunk; `_merge_extractions` deduplicates on
`(canonical_source, asset_reference.lower())`.

#### Bundle assembler

`build_stix_bundle_from_extraction(..., assets=...)` accepts the
asset inventory. For each identity-asset edge:

1. The source local_id is resolved to a STIX `identity--*` id
   (else dropped with `identity_asset_edge_unresolved_source`).
2. `asset_reference` runs through `resolve_asset_reference` against
   `assets`. Unresolved or ambiguous references are dropped.
3. The first emission for a given asset_id synthesizes a
   `x-asset-internal--<asset_id>` STIX object (carries
   `asset_id` for SAGE's mapper); subsequent emissions reuse it.
4. An `x-trace-has-access` STIX relationship is appended with the
   resolution's `confidence` (80 / 50 / 30 per tier).

Without `assets`, no edges are emitted (the LLM may extract them but
they cannot be resolved). The L3 prompt declares this contract so
operators understand the dependency.

#### CLI: `crawl_single` / `crawl_batch` accept `--assets`

```bash
# Single URL with identity-asset extraction
uv run python cmd/crawl_single.py \
  --input '<url>' \
  --pir ../BEACON/output/pir_output.json \
  --assets ../BEACON/output/assets.json \
  --output output/bundle.json

# Batch crawl with identity-asset extraction
uv run python cmd/crawl_batch.py \
  --pir ../BEACON/output/pir_output.json \
  --assets ../BEACON/output/assets.json
```

`--assets` is optional. When omitted, the bundle is identical to
1.1.0 output (no `identity_asset_edges` processing).

#### L3 prompt update

`stix_extraction.md` gained a new "Identity-asset access
(`identity_asset_edges`)" section that:

- Defines what qualifies (legitimate operator / owner / administrator
  with named role-asset link in the report).
- Explicitly excludes attacker-side relationships (those use
  `targets`, not `identity_asset_edges`).
- Provides three concrete examples (CFO mailbox, SRE Kubernetes,
  DBA database).
- Returns empty array when no identity-asset context is present.

The output JSON shape adds `identity_asset_edges[]` at the top level.

### Tests

- `tests/test_stix_extractor.py::TestIdentityAssetEdgeCoercion` (3) —
  LLM JSON parsing, missing-field tolerance, blank-source guard.
- `tests/test_stix_extractor.py::TestBundleAssemblerIdentityAssetEdges`
  (6) — resolved emission, unresolved drop, no-assets drop,
  non-identity source drop, x-asset-internal dedup across multiple
  identities sharing one asset, dangling source local_id drop.

All 236 tests pass; 0 vulnerabilities.

### Migration notes

- BEACON 0.11.0 + SAGE 0.6.0 are the matching peers. SAGE 0.6.0 was
  forward-compatible with TRACE 1.2.0 emissions (the
  `x-trace-has-access` dispatch was wired in advance), so no SAGE
  release is needed for this slice.
- TRACE consumers using `crawl_single` / `crawl_batch` without
  `--assets` see no behavior change.
- Bundle output for runs that include identity-asset edges is larger
  by the count of unique resolved assets (1 `x-asset-internal` object
  per asset) plus the number of accepted edges (1 relationship per
  edge). Unresolved edges add nothing.

### Future scope

- 1.3.0+: confidence-tier tuning based on Phase 2 evaluation
  (operational decision after BEACON/SAGE/TRACE Phase 1 production
  data accumulates).
- The `_TRACE_EXTENSION_PROPERTIES` block does not yet declare
  `x-trace-has-access` and `x-asset-internal` as registered
  extension types — STIX validators may emit informational
  notices about the unknown types. Adding them is cosmetic and
  deferred.

---

## [1.1.0] — 2026-05-10

### Added — Initiative A: identity_assets validator + asset resolver

Second slice of the Identity-Asset HasAccess initiative. BEACON 0.11.0
emits the new `identity_assets.json` artifact; this release is the
validation gate that artifact must clear before SAGE 0.6.0 ingests it.

The full initiative spans two TRACE releases:

- **1.1.0 (this release)** — schema, semantic validator, CLI, asset
  resolver helper. The L3 prompt and bundle assembler still treat
  `identity_assets` content as out-of-band (analyst-supplied via
  BEACON); CTI-extracted identity-asset edges arrive in 1.2.0.
- **1.2.0 (next)** — L3 prompt extension to extract
  `x-trace-has-access` relationships from CTI reports, bundle
  assembler integration, `crawl_single --assets` flag.

Splitting the work keeps 1.1.0 immediately useful (BEACON's
authoritative `source=beacon` artifact validates and ingests into
SAGE 0.6.0) while the more complex bundle-rewrite work matures
separately.

#### Pydantic schema additions

`src/trace_engine/validate/schema/models.py`:

- `IdentityEntry` — `id`, `name`, `identity_class` (Literal of STIX
  2.1 §6.7 `identity-class-ov`: individual / group / system /
  organization / class / unspecified), `sectors[]`, `roles[]`,
  `description`.
- `HasAccessEntry` — `identity_id`, `asset_id`, `access_level`
  (Literal: read / write / admin / deny), `role`, `granted_at`,
  `revoked_at`. A `model_validator` rejects `granted_at >= revoked_at`.
- `IdentityAssetsDocument` — top-level container with `version`,
  `identities[]`, `has_access[]`. `extra="ignore"` to accept the
  optional `_comment` field BEACON emits.

#### Cross-reference checks

`src/trace_engine/validate/semantic/identity_assets.py`:

- `identities[*].id` uniqueness — error.
- `has_access[*].identity_id` resolves to `identities[*].id` — error.
- `has_access[*].asset_id` resolves to a supplied `assets.json`'s
  `assets[*].id` — error.
- Duplicate `(identity_id, asset_id)` pairs — warning (SAGE upsert
  collapses duplicates to the last entry; the analyst should know).

#### `cmd/validate_identity_assets.py` CLI

`--assets` is **required** (Initiative A 2026-05-10 design decision —
independent validation provides too little safety to be worth the
API surface):

```bash
uv run python cmd/validate_identity_assets.py \
  --identity-assets ../BEACON/output/identity_assets.json \
  --assets ../BEACON/output/assets.json
```

Same exit-code contract as `validate_assets.py` /
`validate_pir.py` (0 clean, 1 errors, 2 input).

#### `src/trace_engine/stix/asset_resolver.py` — 4-tier matching ladder

Resolves an LLM-supplied free-form asset reference against a known
`assets[]` list. Used by 1.2.0+'s extractor; exposed in 1.1.0 for
testing and analyst tooling. The ladder (decided 2026-05-10):

| Tier | Match | Confidence |
|------|-------|------------|
| 1 | `Asset.name` exact (case-insensitive) | 80 |
| 2 | `Asset.name` substring overlap ≥ 4 chars (bidirectional) | 50 |
| 3 | Single `Asset.tags` exact match | 30 |
| 4 | No match → drop with `asset_resolution_no_match` | — |

Ambiguous matches (multiple assets at the same tier) drop with
`asset_resolution_ambiguous` rather than picking arbitrarily.

#### Extractor vocabulary expansion

`_VALID_RELATIONSHIP_TYPES += "x-trace-has-access"` — declared so SAGE
0.6.0 can accept bundles emitted by TRACE 1.2.0+ without a vocabulary
mismatch. The bundle assembler does not yet emit this type (the LLM
prompt is unchanged in 1.1.0); existing tests remain green.

`_RELATIONSHIP_TYPE_TABLE[("identity", "x-trace-has-access")] =
{"x-asset-internal"}` — declares the intended target type for
forward compatibility.

`IdentityAssetEdge` dataclass added to the extractor module. Unused
in 1.1.0 (always empty list); 1.2.0 will populate it from the L3
prompt.

### Tests

24 new cases across two new test files:

- `tests/test_validate_identity_assets.py` (12) —
  - `TestSchema` (5): minimal, identity_class validation,
    access_level default, granted/revoked inversion rejected,
    optional `_comment` accepted.
  - `TestCrossReference` (5): clean doc, dangling identity_id /
    asset_id, duplicate identity_id, duplicate access pair.
  - `TestCli` (2): CLI exit code 0 / 1 against real subprocess spawn.
- `tests/test_asset_resolver.py` (12) —
  - `TestTier1Exact` (2): exact ja/en name match.
  - `TestTier2Substring` (3): substring match, threshold guard,
    ambiguous drops.
  - `TestTier3Tag` (3): unique tag match, ambiguous tag drops, name
    substring wins over tag.
  - `TestNoMatch` (3) + `TestEmptyAssets` (1).
- `test_stix_extractor.py::test_valid_entity_and_relationship_vocabularies_are_disjoint`
  updated for the expanded relationship vocabulary.

All 227 tests pass; 0 vulnerabilities.

### Future scope (TRACE share of remaining Initiative A)

- 1.2.0: L3 prompt extension to emit `x-trace-has-access`; bundle
  assembler integration with `asset_resolver`; `--assets` flag on
  `crawl_single` / `crawl_batch`; `extension-definition` block
  declares `x-asset-internal` and `x-trace-has-access`.
- 1.3.0+: per-identity asset-resolution confidence tuning based on
  Phase 1 production data.

---

## [1.0.3] — 2026-05-10

### Fixed — Three defects surfaced by CISA AA22-108a Lazarus E2E crawl

End-to-end verification (BEACON 0.10.2 → TRACE 1.0.2 → SAGE 0.5.0)
on the CISA AA22-108a Lazarus advisory produced a 192-object bundle
that landed at `errors=1 warnings=2` in `validate_stix`, and SAGE
ETL aborted on the first vulnerability row. Three structural
defects were identified, all in the same family (LLM emitting
syntactically incomplete or out-of-vocab STIX) and all addressed
together since they share the existing drop / demote scaffolding.

#### Vulnerability without parseable CVE id (drop)

The L3 LLM extracted a vulnerability entity named
`"Common Vulnerabilities and Exposures (CVEs)"` (43 chars) from a
generic prose mention. SAGE's `Vulnerability.cve_id STRING(32)`
column rejected the row, halting the ETL pipeline.

New helper `_extract_cve_id(obj)` resolves a CVE id by:

1. Scanning `external_references[*]` for entries with
   `source_name == "cve"`, checking `external_id` first then
   extracting `CVE-YYYY-NNNN` from `url` via regex.
2. Falling back to `name` when it parses as a CVE id.

Vulnerabilities that yield no CVE id are dropped at the entity
loop with `vulnerability_dropped_no_cve` warning. Surviving entries
have their `name` normalized to the canonical CVE id even when the
LLM emitted a longer descriptive name. Relationships pointing at a
dropped vulnerability fall through the existing dangling-ref guard.

CVE format: `^CVE-\d{4}-\d{4,}$` (CVE program rules — high-volume
years exceed 6 digits, so no upper bound on the trailing block).

#### Indicator without `pattern` (drop)

STIX 2.1 §4.7 marks `pattern` as REQUIRED on indicator. The L3 LLM
sometimes emits "indicator" entities for prose descriptions of
patterns ("Newly Registered Domains") without an actual pattern.
`_validate_indicator_pattern` now drops indicators where `pattern`
is missing or empty (previously: returned True deferring to the
validator → SAGE ETL parse failure).

#### `attack-motivation-ov` open-vocab demotion ({211})

STIX 2.1 §6.2 `attack-motivation-ov` defines 10 canonical values
(`organizational-gain`, `personal-gain`, etc.). The L3 LLM commonly
emits `financial`, `espionage`, `sabotage`, etc. — semantically
similar but not in the spec list, tripping {211}. Same demote-to-
labels pattern as `identity_class` (1.0.0), `sectors` (1.0.1), and
`sophistication` (0.5.1):

- `intrusion-set.primary_motivation` outside ov → moved to `labels`,
  field cleared.
- `intrusion-set.secondary_motivations[*]` → in-vocab values stay,
  out-of-vocab move to `labels`.
- `threat-actor` gets the same handling (STIX 2.1 §4.17 uses the
  same vocab on the same fields).

`_STIX21_ATTACK_MOTIVATION_OV` constant added.

### Tests

- 16 new cases:
  - `TestVulnerabilityCveValidation` (6) — drop on non-CVE name,
    keep on proper CVE name, extract from `external_id`, extract
    from `url`, drop with unrelated external_references, dangling-
    ref drop on dropped vulnerability.
  - `TestIndicatorMissingPattern` (2) — drop without pattern, keep
    with valid pattern.
  - `TestAttackMotivationDemotion` (4) — in-vocab kept, out-of-
    vocab demoted on `intrusion-set` and `threat-actor`,
    `secondary_motivations` filtered.
  - 4 existing indicator-default tests updated to supply a valid
    `pattern` (regression: defaulting `valid_from` / `pattern_type`
    no longer hides a missing-pattern emission).

All 203 tests pass; 0 vulnerabilities.

### Compliance

Combined with prior 0.x.x and 1.0.x defenses, FIN7-class and
Lazarus-class bundles now produce `errors=0` and only the
documented SHOULD-level `{202}` accepted warnings remain
(`tool uses {malware,tool}` and `attack-pattern uses attack-pattern`).

---

## [1.0.2] — 2026-05-09

### Fixed — `{401}` vulnerability.aliases + `{202}` actor-source exploits

Real-URL FIN7 verification on TRACE 1.0.1 produced `errors=0
warnings=2`. Both warnings traced to LLM choices that the bundle
assembler now corrects.

#### `{401}` vulnerability.aliases → labels

STIX 2.1 §4.18 vulnerability does not define `aliases`. The L3 LLM
occasionally puts CVE alternate names ("ProxyLogon", "EternalBlue")
under that key. Added a vulnerability branch in
`_apply_required_property_defaults` that demotes the list into
`labels` (open vocab on common SDO properties) so the alternate names
survive without the {401} flag. Existing `labels` entries are
preserved with order; merged values dedupe.

New helper `_demote_list_to_labels` covers the list-shaped
counterpart of 0.5.2's `_demote_property_to_labels`.

#### `{202}` `intrusion-set / threat-actor / campaign exploits` → drop

STIX 2.1 §4.13 lists `malware` as the only suggested source for
`exploits`. Actor-side "exploits vulnerability" semantics are
expressed via `targets` (`intrusion-set targets vulnerability`,
already in the table). Tightened
`_RELATIONSHIP_TYPE_TABLE`:

```python
# Before
("malware", "exploits"): frozenset({"vulnerability"}),
("intrusion-set", "exploits"): frozenset({"vulnerability"}),
("threat-actor", "exploits"): frozenset({"vulnerability"}),
("campaign", "exploits"): frozenset({"vulnerability"}),

# After
("malware", "exploits"): frozenset({"vulnerability"}),
```

LLM-emitted `intrusion-set exploits vuln` falls through the existing
`relationship_type_mismatch_dropped` guard. The L3 prompt already
points actors at `targets`, so a follow-up prompt edit is unnecessary.

### Tests

- 6 new cases:
  - `TestVulnerabilityAliasesDemotion` (2): aliases moves to labels,
    existing labels preserved with merge dedupe.
  - `TestExploitsSourceTightening` (4): malware-exploits-vuln kept,
    intrusion-set-exploits-vuln dropped, intrusion-set-targets-vuln
    kept (the canonical replacement), threat-actor-exploits-vuln
    dropped.

### Compliance

Combined with all prior 0.x.x and 1.0.x defenses, FIN7-class bundles
now produce `errors=0` and only the documented SHOULD-level `{202}`
accepted warnings remain (`tool uses {malware,tool}` and
`attack-pattern uses attack-pattern`).

---

## [1.0.1] — 2026-05-09

### Fixed — Residual {215} / {303} warnings on FIN7-class bundles

Real-URL FIN7 verification on TRACE 1.0.0 produced a 177-object bundle
that validated `errors=0 warnings=19`. Three warning categories
remained, two of them mechanically fixable.

#### {215} `identity.sectors` outside `industry-sector-ov`

Same demote-to-labels pattern as 0.5.1 / 0.5.2:
`_STIX21_INDUSTRY_SECTOR_OV` constant added (33 STIX 2.1 §6.6 values),
`_filter_open_vocab` invoked in the identity branch of
`_apply_required_property_defaults`. Out-of-vocab values like
`fintech`, `card-payments`, `electronic-money` move to `labels`;
in-vocab values stay in `sectors`.

#### {303} indicator missing `name` / `description`

STIX 2.1 §4.7 SHOULD: indicators carry both. The L3 LLM frequently
emits `pattern` only. Added defaults in
`_apply_required_property_defaults`:

- `name` → `_derive_indicator_name(pattern)` synthesises a short
  label from the SCO type and first quoted value
  (`[ipv4-addr:value = '198.51.100.1']` → `ipv4-addr: 198.51.100.1`).
  Falls back to `Indicator: <type>` when the pattern uses quoted
  property names like `hashes.'SHA-256'` that don't match the simple
  pattern parser.
- `description` → `"Indicator extracted from CTI report"` (generic
  fallback). Existing values from the LLM win via `setdefault`.

### Documented — `attack-pattern uses attack-pattern` accepted

`{202}` warnings for this combination are now in the
"Accepted OASIS validator warnings" section of
`docs/data-model.{md,ja.md}`. The relationship is the canonical way
to express MITRE ATT&CK sub-technique chaining; dropping it would
erase the technique hierarchy from the attack graph. Same SHOULD-level
acceptance as the 0.5.2 `tool uses {malware,tool}` cases.

### Tests

- 7 new cases in `tests/test_stix_extractor.py`:
  - `TestIdentitySectorsDemotion` (2): in-vocab preserved,
    out-of-vocab demoted to labels.
  - `TestIndicatorNameDescriptionDefaults` (4): IPv4 pattern → name
    derived, file-hash pattern → type fallback name, existing name
    preserved, existing description preserved.
- Existing `TestRequiredPropertyDefaults::test_indicator_gets_pattern_type_default`
  still passes — the new name/description defaults don't override
  prior LLM output.

### Compliance

Combined with 0.3.2 / 0.4.0 / 0.5.x / 0.6.x / 0.7.0 / 0.8.0 / 1.0.0,
FIN7-class bundles now produce `errors=0` and only the documented
SHOULD-level `{202}` accepted warnings remain.

---

## [1.0.0] — 2026-05-09

### Added — `identity` SDO + `targets` relationship (paired with SAGE 0.5.0)

Verizon DBIR 2025 (stolen credentials = #1 initial access at 22%) and
CrowdStrike GTR 2025 (valid account abuse = #1 cloud vector at 35%)
made the credential / org-targeting blind spot unavoidable. 1.0.0
extends the L3 extraction vocabulary so reports about FIN7 spear-
phishing the CFO, or APT29 targeting a specific finance department,
land in SAGE's attack graph as a real edge instead of being lost in
prose.

#### Entity vocabulary

- `_VALID_ENTITY_TYPES += "identity"` — STIX 2.1 §4.4 SDO. The
  L3 prompt now describes when to extract identity records and how to
  pick `identity_class` from the §6.7 vocabulary.

#### Relationship vocabulary

- `_VALID_RELATIONSHIP_TYPES += "targets"` — STIX 2.1 §4.13. Source
  vocabulary: `attack-pattern, campaign, intrusion-set, malware,
  threat-actor, tool`. Target vocabulary: `identity, location,
  vulnerability, infrastructure`.

`_RELATIONSHIP_TYPE_TABLE` extended with six `("<source>", "targets")`
entries enumerating the suggested target types. Source/target pairs
outside the table are dropped at bundle assembly time with the
existing structured-log warning (`relationship_type_mismatch_dropped`).

#### Open-vocab demotion for `identity_class`

Same pattern as 0.5.1 (`tool_types`, `malware_types`) and 0.5.2
(`sophistication`): when the LLM picks an identity class outside
STIX 2.1 §6.7 (e.g., "executive"), demote it to `labels` (open vocab)
and clear the field. Information survives, validator stays clean.

`_demote_scalar_to_labels_if_outside` is the new helper for scalar
properties with an open-vocab guard.

### SAGE coordination

- SAGE 0.5.0 ships in lockstep, adding the `Identity` Spanner table
  and the `ActorTargetsIdentity` edge.
- SAGE only stores `targets` edges sourced from `threat-actor` /
  `intrusion-set`. Other valid sources (`malware`, `tool`,
  `attack-pattern`, `campaign`) survive TRACE's bundle but are
  dropped at SAGE's `map_relationship` with a structured-log warning.
  This is documented as a 0.6.0+ extension point on the SAGE side.

### L3 prompt update

`stix_extraction.md` gained an `identity` section explaining when to
extract (named victims, targeted roles, affected organisations) and
how to pick `identity_class`. The relationship-type list now includes
the `targets` row covering source / target combinations TRACE
accepts.

### Tests

- Updated existing
  `test_valid_entity_and_relationship_vocabularies_are_disjoint` —
  asserts `targets` is now in the relationship vocabulary and
  `identity` is in the entity vocabulary.
- 7 new cases:
  - `TestIdentityEntity` (3) — minimal identity, in-vocab class
    preserved, out-of-vocab class demoted to labels.
  - `TestTargetsRelationship` (4) — actor → identity kept, threat-
    actor → vulnerability kept, identity → actor (reversed) dropped,
    indicator → identity (invalid source) dropped.

### BREAKING (vocabulary expansion)

Any downstream consumer that filtered on the previous tight
relationship-type set (`uses`, `exploits`, `indicates`) will now
encounter `targets` records and `identity` objects. SAGE 0.5.0 is the
canonical consumer; other consumers must add identity/targets handling
or filter explicitly.

### Future scope (deferred to 1.1.0+)

- `user-account` SCO support via `observed-data` SDO — credential-
  level granularity finer than the per-person Identity node.
- `attributed-to` relationship for actor → identity attribution.
- `impersonates` relationship for actor → identity (BEC use case).
- BEACON-side identity-asset metadata to populate
  `Identity → Asset HasAccess` edges in SAGE.

---

## [0.8.0] — 2026-05-09

### Added — Concurrent batch crawl

Sequential `crawl_batch` execution dominated wall-clock time on
list-driven runs — every URL waited on Gemini round-trips before the
next URL even started. Per-URL work is mostly I/O-bound (httpx fetches,
Gemini calls, ATT&CK URL hashing), so a small thread pool yields
near-linear speedup until the Vertex AI quota is the bottleneck.

`crawl_batch(...)` now accepts `max_workers` (defaults to
`Config.crawl_concurrency`, env `TRACE_CRAWL_CONCURRENCY`, default 4):

- `max_workers <= 1` keeps the legacy sequential generator behaviour —
  bit-for-bit identical for existing callers and tests.
- `> 1` dispatches sources to a `ThreadPoolExecutor` and yields outcomes
  in **completion order** (not source order). Each worker thread runs
  a self-contained `_process_source` invocation.

#### Per-URL work refactored to `_process_source`

The big inline for-loop body that previously lived inside
`crawl_batch` is now a top-level helper. The function returns one
`BatchOutcome` per source. The main `crawl_batch` either calls it in a
plain loop (sequential) or submits it to the executor.

The new `BatchOutcome.metrics` field carries the per-URL
`_RunMetrics` when a metrics collector is registered. The CLI driver
no longer manages metrics lifecycle inline — it just collects
`outcome.metrics` from each yielded record.

### Changed — `MetricsCollector` is thread-local

The 0.7.0 collector held a single active run on the instance, which
would have collapsed concurrent worker runs into one shared bag. The
0.8.0 collector keeps an active run **per thread id** (`dict[int,
_RunMetrics]`, lock-protected). `start_run` / `finish_run` /
`__call__` all consult the current thread's entry. Single-threaded
callers see no behaviour change.

### Changed — `CrawlState` is concurrency-safe

`get` / `upsert` mutations are now serialised through a
`threading.Lock`. The atomic `tempfile + os.replace` write in `save()`
already protected disk consistency; the new lock protects the
in-memory `entries` dict during concurrent worker access.

### Tests

- 2 new cases in `tests/test_crawl_batch.py`:
  - `test_concurrent_crawl_processes_all_sources` — 8 URLs through 4
    workers; every URL emits exactly one outcome.
  - `test_concurrent_state_upserts_dont_corrupt` — 20 URLs through 8
    workers; every URL has a state entry afterwards (no race losses).
- 1 new case in `tests/test_cli_metrics.py::TestThreadLocalRuns` —
  two threads run independent runs simultaneously without interfering.

### Operational notes

- Vertex AI per-tier QPM caps are not actively rate-limited by TRACE.
  Bumping `crawl_concurrency` past Vertex AI's `gemini-2.5-flash`
  quota will surface as `google.api_core.exceptions.ResourceExhausted`
  errors logged at `extract_entities` call sites; the worker's outcome
  will be `extraction_failed`. Recommended range 1..8.
- Outcome order is no longer deterministic for `max_workers > 1`. The
  state file and bundle outputs are unchanged; only the order of CLI
  log lines and per-URL summaries differ run-to-run.

---

## [0.7.0] — 2026-05-09

### Added — Per-run metrics collection

Chunked extraction (0.3.0) multiplied the number of LLM calls per
crawl, but operators had no way to see token consumption, parse
failures, or defense activations except by reading raw structured
logs. 0.7.0 adds a non-intrusive metrics layer.

#### `MetricsCollector` (`src/trace_engine/cli/_metrics.py`)

- Registered as a structlog **processor** in
  ``cli/_logging.py`` so existing log call sites are unaffected.
- Inspects each log record's ``event`` field and updates an in-memory
  ``_RunMetrics`` for the active run (lifecycle: ``start_run`` /
  ``finish_run``).
- Records that arrive while no run is active are passed through
  untouched — non-CLI callers (tests, library use) see no behaviour
  change.

#### Tracked counters

- **L2**: model_tier, score, matched_pir_ids, salvaged / failed flags.
- **L3**: model, task, chunks, chunk_chars_max, llm_calls,
  llm_output_chars_total, parse_failures, raw_entities,
  merged_entities, raw_relationships, merged_relationships.
- **Defenses**: indicators_dropped_invalid_pattern,
  relationships_dropped_unresolved,
  relationships_dropped_type_mismatch, external_ref_fetched,
  external_ref_fetch_failed.
- **Per-tier LLM totals**: `simple` / `medium` / `complex` calls and
  output character counts (rolling totals).
- **Bundle**: path, entities, relationships, object_count.

#### `crawl_single` integration

- Starts a run on entry, finishes on bundle write.
- Prints a human-readable summary to stdout after the bundle line:

  ```
  === Run summary ===
  Input:        https://example.com/post (8,000 body / 10,000 raw chars)
  L2:           score=0.60 → kept matched=PIR-001
  L3:           3 chunks, 3 LLM calls, 30,000 output chars, 0 parse failures
                raw 60/45 → merged 46/45 (entities/relationships)
  Bundle:       92 objects (46 entities, 45 relationships) → output/bundle.json
  Defenses:     2 ATT&CK URLs hashed, 1 indicators dropped (bad pattern)
  Duration:     12.3s
  Metrics:      output/run_metrics_<ts>_<id8>.json
  ```

- Persists the full structured payload as JSON in
  ``output/run_metrics_<ts>_<id8>.json``.

#### `crawl_batch` integration

- Starts a run **per source URL** (option (a) of the design poll). The
  generator-driven loop calls ``finish_run`` on each yielded outcome
  and ``start_run`` for the next URL before resuming.
- All per-URL summaries print to stdout in order, followed by a
  combined ``output/run_metrics_batch_<ts>.json`` containing every
  run plus a ``summary`` section with batch-level totals.

### Tests

- 13 new cases in `tests/test_cli_metrics.py` covering full
  lifecycle observation, L2 failure / salvage paths, parse-failure
  counting, processor pass-through semantics, atomic JSON write,
  batch-summary aggregation, and unknown-event resilience.

### Compatibility

- No public API changes. Library callers
  (`extract_entities`, `build_stix_bundle_from_extraction`,
  `validate_*` modules) behave identically. Metrics collection is
  opt-in via ``_metrics.install_collector()`` from CLI entry points
  only.

---

## [0.6.1] — 2026-05-09

### Fixed — Defensive guards for the more permissive 0.6.0 prompt

The 0.6.0 prompt strengthening lifted FIN7-class extraction from 40 to
61 entities (+52%) but exposed three classes of LLM mistake the bundle
assembler had not previously needed to defend against. Real-URL
verification regressed validation from `errors=0 warnings=0` to
`errors=5 warnings=4`. 0.6.1 adds three structural defenses; the
validator now returns to `errors=0` (and {202} warnings limited to the
two TRACE-accepted exceptions documented in 0.5.2).

#### 1. Empty-array scrub

`_scrub_empty_arrays` strips keys whose value is an empty list. STIX
2.1 disallows `aliases: []` / `labels: []` / `kill_chain_phases: []`
etc.; the LLM emitted these when nothing was known about the field.
Removing the key entirely satisfies the validator.

#### 2. STIX patterning syntax validation

`_validate_indicator_pattern` parses the indicator's `pattern` with
`stix2patterns.v21.pattern.Pattern` (transitive dep of
`stix2-validator`). Indicators with malformed STIX patterns are
dropped with a structured-log warning; relationships pointing at the
dropped indicator fall through the existing dangling-ref guard.

Only `pattern_type == "stix"` is parsed — YARA, Snort, PCRE patterns
pass through untouched (the OASIS validator handles those languages).

#### 3. Relationship type table (STIX 2.1 §4.13)

`_RELATIONSHIP_TYPE_TABLE` enumerates the suggested
`(source_type, relationship_type) → {target_types}` mapping for the
three relationships TRACE emits (`uses`, `exploits`, `indicates`).
`_is_relationship_suggested` filters out violators before bundle
assembly with a structured-log warning. The two 0.5.2-accepted
exceptions (`tool uses malware`, `tool uses tool`) are encoded as
table allow-list entries.

This drops common LLM mistakes:

- `malware indicates X` → only indicator may indicate (drop)
- `attack-pattern exploits X` → only malware/intrusion-set/threat-actor/campaign may exploit (drop)
- `indicator indicates indicator` → indicator is not in the suggested target set for `indicates` (drop)

### Tests

- 11 new cases in `tests/test_stix_extractor.py` covering all three
  defenses: empty-array scrub (preserved vs removed), pattern
  validation (valid/malformed/YARA/dangling-rel cascade), and the
  relationship type table (kept/dropped per source-target combo).

---

## [0.6.0] — 2026-05-09

### Changed — L3 prompt strengthened against PIR-induced under-extraction

Real-URL verification with a single-PIR `pir_output.json`
(`financial_crime` family only) showed the L3 LLM occasionally returning
empty `{entities: [], relationships: []}` even when the source report
clearly named threats. The behaviour traced back to the prior PIR
context wording — "*guidance only — do not invent*" — being read as a
filter signal, with the model dropping real entities that didn't
overlap with the (sparse) PIR set.

The prompt now states the policy explicitly in two places:

- **`stix_extraction.md` header** gains a *Critical extraction policy*
  block: be exhaustive, PIR is a priority hint not a filter, do not
  invent.
- **`_render_pir_context_block`** now emits a header
  `## PIR Context (priority hint, NOT a filter)` plus a *Required
  behaviour* list that:
  - mandates extraction of every named entity regardless of PIR overlap,
  - reframes PIRs as ranking input only (when long reports force a
    choice in detail),
  - retains the existing "do not invent" guardrail.

Behaviour for callers:

- No API change. `extract_entities(text, pir_doc=...)` signature
  unchanged.
- Empty-output regression risk on sparse-PIR runs is reduced; no
  hallucination surface added (the *don't invent* guardrail moved with
  the wording, not removed).

### Tests

- New
  `tests/test_stix_pir_context.py::test_pir_context_block_explicitly_describes_priority_not_filter`
  pins the strengthened wording so future prompt edits do not silently
  weaken it.

---

## [0.5.2] — 2026-05-09

### Fixed — `{401} sophistication` on intrusion-set

The L3 LLM occasionally emits `sophistication` on intrusion-set
objects. STIX 2.1 §4.5 defines `sophistication` for `threat-actor`
only; on intrusion-set it is a custom property that triggers `{401}`.
The bundle assembler now demotes it to `labels` (open vocab) — same
pattern as the 0.5.1 vocab demotion. The semantic survives without
the warning.

`threat-actor.sophistication` is preserved untouched.

### Documented — Accepted `{202}` suggested-target warnings

Two `{202}` warnings (`tool uses malware` and `tool uses tool`) are
now explicitly accepted in `docs/data-model.{md,ja.md}` under a new
"Accepted OASIS validator warnings" section. STIX 2.1 §4.13 lists
these as SHOULD rather than MUST, and dropping the relationships
would discard valid attack-graph edges that incident reports
regularly carry. Major consumers (MISP, OpenCTI) ingest these without
complaint. Users who want to gate on them can run
`validate_stix --strict` to promote to errors.

### Tests

- 3 new cases in
  `tests/test_stix_extractor.py::TestSophisticationDemotion`:
  intrusion-set demotion, dedup against existing labels, and
  threat-actor preservation.

### Compliance

Combined with 0.3.2 / 0.4.0 / 0.5.0 / 0.5.1, FIN7-class bundles now
pass the OASIS validator with **errors=0** and **warnings=2** (the
two intentionally-accepted `{202}` cases).

---

## [0.5.1] — 2026-05-09

### Fixed — Remaining warnings on FIN7-class bundles

Real-URL FIN7 verification on TRACE 0.5.0 produced a clean bundle —
errors=0 — but nine residual warnings remained:

- `{306} For extensions of the 'toplevel-property-extension' type, the
  'extension_properties' property SHOULD include one or more property
  names.` — TRACE's `extension-definition` object did not list the
  property names it introduces.
- `{216} malware_types contains a value not in the malware-type-ov
  vocabulary.` — Gemini emitted values like `loader` not present in
  the STIX 2.1 §6.4 open vocabulary.
- `{222} tool_types contains a value not in the tool-type-ov
  vocabulary.` — Same pattern for STIX 2.1 §6.5 tool vocabulary.

#### Fix 1: `extension_properties` enumeration

Added a stable ``_TRACE_EXTENSION_PROPERTIES`` constant listing the
five `x_trace_*` field names; the bundle assembler injects it into
the extension-definition object. SHOULD requirement satisfied.

#### Fix 2: Open-vocab demotion to `labels`

`_filter_open_vocab` (called from `_apply_required_property_defaults`)
splits `tool_types` / `malware_types` into vocab-conforming and non-
conforming sublists. Conforming values stay in place; non-conforming
values move to the `labels` field (also open vocab) where they
remain visible to downstream tools without violating the type-specific
vocabulary constraint.

- Empty conforming list removes the field entirely (no empty array
  in the bundle).
- Existing `labels` are preserved with order; demoted values append
  without duplicating.
- Conforming-only input passes through unchanged; no `labels` is
  spuriously created.

The STIX 2.1 vocabulary tables ship as in-module constants
(`_STIX21_TOOL_TYPE_OV`, `_STIX21_MALWARE_TYPE_OV`) — they're stable
across the spec's minor revisions and cheap to keep in sync.

### Tests

- 6 new cases in
  `tests/test_stix_extractor.py::TestExtensionPropertiesAndVocabDemotion`
  covering the extension-properties listing, mixed vocab demotion for
  both tools and malware, all-non-conforming field removal, existing
  labels preserved, and conforming-only passthrough.

### Compliance

Combined with 0.3.2 / 0.4.0 / 0.5.0, FIN7-class bundles now produce
**zero errors and zero warnings** against the OASIS validator (modulo
fetch-time {302} fallback when an ATT&CK URL is uncached and offline).

---

## [0.5.0] — 2026-05-09

### Added — SHA-256 augmentation for `external_references`

The OASIS validator emits `{302} External reference '<source>' has a
URL but no hash` for every entry that includes `url` without `hashes`.
On a typical FIN7 bundle that's a dozen+ warnings against ATT&CK
references. 0.5.0 fetches each external-reference URL once, hashes
the response body with SHA-256, and writes
`hashes: {"SHA-256": "<hex>"}` back into the entry.

- New module `src/trace_engine/stix/external_ref_hash.py` implements
  `augment_external_references(objects, cache_path, ttl_days,
  user_agent, enabled)`.
- On-disk JSON cache (default `output/external_ref_hash_cache.json`,
  configurable via `TRACE_EXTERNAL_REF_HASH_CACHE`) keyed by URL,
  storing `{sha256, fetched_at, status}`. Subsequent bundles reuse
  cached hashes without a network round-trip.
- TTL default 30 days
  (`Config.external_ref_hash_ttl_days`, env
  `TRACE_EXTERNAL_REF_HASH_TTL_DAYS`). MITRE ATT&CK pages are stable
  enough that monthly refresh is safe.
- Offline fallback: cache miss + fetch failure leaves the reference
  unchanged. The `{302}` warning re-appears for that one reference
  but the bundle remains usable. We deliberately prefer
  "warning + good bundle" over "failed bundle assembly".
- Lazy `httpx.Client` construction — bundles that hit the cache for
  every URL never open a network handle.
- Master switch
  `Config.external_ref_hash_enabled` (env
  `TRACE_EXTERNAL_REF_HASH_ENABLED=false`) for air-gapped use.

`build_stix_bundle_from_extraction` now accepts an optional
`config: Config | None` parameter so tests and air-gapped callers can
disable the augmentation step explicitly without environment fiddling.

### Tests

- 8 new cases in `tests/test_external_ref_hash.py` covering disabled
  switch, no-URL skip, hashes-already-present skip, cache-miss fetch,
  cache-hit no-network, stale-cache re-fetch, offline fallback, and
  no-external-references-shortcircuit.

### Compliance

Combined with 0.3.2 and 0.4.0, the FIN7-class bundle now validates
clean: zero {103} UUIDv4 errors, zero required-property errors, zero
{401} envelope warnings, and zero {302} hash warnings on cached or
freshly-fetched ATT&CK references.

---

## [0.4.0] — 2026-05-09

### Changed (BREAKING) — Bundle envelope drops deprecated fields

STIX 2.1 §3 deprecated `spec_version` and `created` on the bundle
envelope (they live on each object instead). TRACE 0.x kept them on
the envelope to satisfy a SAGE-side check, which produced two
non-compliant `{401}` warnings on every bundle. SAGE's parser
(`SAGE/src/sage/stix/parser.py`) actually iterates `bundle.objects[]`
and reads per-object `spec_version`, so the fields were never necessary.

- Removed `bundle.spec_version` and `bundle.created` from the envelope.
- Removed the local `BUNDLE_SPEC_VERSION` check from
  `validate/stix/validator.py`.
- Per-object `spec_version` and `created`/`modified` continue to be
  emitted on every entity, relationship, and the new
  `extension-definition` object.

Any downstream consumer that read the envelope `spec_version` /
`created` directly must read them from `bundle.objects[*]` instead.

### Changed (BREAKING) — `x_trace_*` metadata wrapped in STIX extension

The previous bare-`x_trace_*` properties triggered five `{401}`
custom-property warnings per bundle. Migrated to a STIX 2.1 §7.3
toplevel-property extension:

- A new `extension-definition` object with **stable id**
  `extension-definition--c1e4d6a7-2f3b-4e8c-9a5f-1b8d7e6c4a3f` is
  prepended to `objects[]` whenever any `x_trace_*` metadata is
  supplied. The id is hardcoded so consumers can recognise the
  extension across emissions without per-bundle discovery.
- `bundle.extensions[<ext-id>] = { extension_type:
  "toplevel-property-extension" }` is added at the bundle root.
- `x_trace_source_url`, `x_trace_collected_at`,
  `x_trace_matched_pir_ids`, `x_trace_relevance_score`, and
  `x_trace_relevance_rationale` continue to live at the bundle root —
  now permitted under the extension.
- Bundles emitted without any L4 metadata (raw extraction, no PIR or
  source URL) skip the extension definition entirely.

Combined with 0.3.2, FIN7-class bundles now validate clean against the
OASIS validator: no {103} UUIDv4 errors, no required-property errors,
no {401} custom-property warnings on the envelope.

### Documentation

- `docs/data-model.{md,ja.md}` rewritten "TRACE bundle metadata
  extension (L4)" section explaining the extension definition and
  the rationale for the fixed id.
- `docs/crawl_design.{md,ja.md}` §4a / §5 updated to describe the new
  bundle assembly steps (extension-definition prepend, `extensions`
  map, envelope deprecation).

### SAGE coordination

SAGE's parser already reads per-object `spec_version` and ignores the
envelope, so no SAGE-side change is required. SAGE consumes the
extension-definition object as a regular STIX object — it is not in
the supported-types list and will be skipped, which is the desired
behaviour.

### Tests

- 6 new cases in `tests/test_stix_extractor.py::TestBundleExtensionMigration`
  covering envelope field omission, conditional extension emission,
  stable id across emissions, required-fields presence, and `x_trace_*`
  retention at bundle root.
- `tests/test_validate_stix.py::test_wrong_spec_version_caught` removed
  (the local check it asserted no longer exists).
- `tests/test_stix_pir_context.py` updated: bundle-envelope
  `spec_version` assertion replaced with extension-object
  `spec_version` assertion.

---

## [0.3.2] — 2026-05-09

### Fixed — STIX 2.1 type-specific required-property defaults

Real-URL FIN7 verification on TRACE 0.3.1 produced a 93-object bundle
that the OASIS validator rejected with 10 hard errors:

- 7 × `malware` objects missing required `is_family` boolean.
- 3 × `indicator` objects missing required `valid_from` timestamp (and
  also `pattern_type`).

The L3 prompt asks the LLM for domain knowledge — it does not know
which STIX wire-format fields are mandatory per object type. The
bundle assembler now fills in conservative defaults via
`_apply_required_property_defaults`:

- `malware.is_family` defaults to `false` (instance, not family) —
  incident reports usually describe a single deployment.
- `indicator.valid_from` defaults to the bundle timestamp.
- `indicator.pattern_type` defaults to `"stix"` — STIX patterning is
  the only language reliably emitted by the L3 prompt.

`setdefault` semantics: anything the LLM did supply wins. A YARA
indicator with explicit `pattern_type: "yara"` is preserved.

### Tests

- 6 new cases in `tests/test_stix_extractor.py::TestRequiredPropertyDefaults`
  covering malware default, malware LLM override, indicator
  `valid_from` default, indicator `pattern_type` default, indicator
  LLM override, and confirmation that other types receive no extra
  defaults.

---

## [0.3.1] — 2026-05-09

### Fixed — Per-chunk output truncation on dense reports

0.3.0 split long reports into paragraph-aligned chunks so a single LLM
call would not blow past `max_output_tokens`, but the per-chunk output
ceiling was still 8,192 tokens and that turned out to be insufficient
for entity-dense chunks of CTI articles. Real-URL verification on a
24,750-char Picus FIN7 report saw chunks 0 and 1 truncate mid-property
and mid-relationship-array respectively, leaving the merged extraction
empty.

Two layered mitigations:

- **Per-chunk `max_output_tokens` raised from 8,192 to 32,768.** Gemini
  2.5 flash supports up to 65,535 output tokens; 32,768 leaves headroom
  while still bounding cost per call. This handles the common case.
- **Bracket-balanced salvage in `_extract_json_from_text`.** When a
  chunk's response is still truncated past 32,768 tokens, walk the
  raw text, find each `"entities":` / `"relationships":` array, and
  extract whatever complete `{...}` records are well-formed. The
  partial result feeds the merge stage rather than being discarded.

Together with the chunked input pipeline shipped in 0.3.0, this gives
TRACE a structural answer to long, dense reports: input is chunked,
output is bounded with headroom, and any residual truncation is
salvaged rather than dropped.

### Tests

- 5 new salvage cases in `tests/test_stix_extractor.py` covering
  mid-property cut, mid-relationship-array cut, well-formed JSON
  passthrough, no-recoverable-arrays guard, and embedded-brace string
  handling.

---

## [0.3.0] — 2026-05-09

### Added — Chunked L3 extraction for long reports

Long CTI reports (multi-page advisories, dense vendor PDFs) hit Gemini's
`max_output_tokens` ceiling and produced a JSON response that was truncated
mid-stream, causing `extract_entities` to return zero objects. The fix is
structural: split the article on paragraph boundaries (`\n\n`) into chunks
no larger than `Config.extraction_chunk_chars` (default `12000`, env
`TRACE_EXTRACTION_CHUNK_CHARS`) and run the L3 prompt once per chunk.

- Per-chunk `local_id`s are namespaced (`c0_actor_1`, `c1_actor_1`) to
  prevent cross-chunk alias collisions.
- `_merge_extractions` deduplicates entities by
  `(type, name.strip().lower())` (or `(type, pattern)` for indicators),
  unions list-valued properties (`labels`, `aliases`,
  `kill_chain_phases`, `external_references`, `malware_types`,
  `tool_types`), rewrites relationship `source` / `target` through the
  merge alias map, and collapses identical
  `(source, target, relationship_type)` triples.
- A single chunk failing to parse is logged with `chunk_index` and
  skipped — other chunks still contribute their entities. An extraction
  fails only when *every* chunk fails.
- Short articles (`len(text) <= chunk_chars`) bypass the chunk loop and
  preserve 0.2.0's single-call behavior.

### Added — Config field and env variable

- `Config.extraction_chunk_chars: int = 12000` (env
  `TRACE_EXTRACTION_CHUNK_CHARS`).

### Changed — `extract_entities` signature

`config: Config | None = None` is now an explicit parameter type
(previously untyped). Behavior unchanged when omitted (`load_config()`).

### Added — `cmd/update_taxonomy_cache.py`

The CLI was promised by `docs/data-model.md` and the
`validate/semantic/taxonomy.py` docstring since 0.1.0 but never landed.
Copies `BEACON/schema/threat_taxonomy.json` into
`TRACE/schema/threat_taxonomy.cached.json` atomically (`tempfile +
os.replace`), validates the expected top-level shape (`_metadata`,
`actor_categories` non-empty, `geography_threat_map`), and stamps a
TRACE-side `_trace_cache` block recording when and from where the
snapshot was taken (so future runs can show drift in `--dry-run`).

### Documentation

- `docs/crawl_design.md` and `docs/crawl_design.ja.md` document the
  chunking strategy under §4 ("Chunked extraction for long reports").

---

## [0.2.0] — 2026-05-09

### Changed — STIX extraction split into LLM-extract + code-build (BREAKING)

The L3 pipeline no longer asks the LLM to emit STIX 2.1 objects directly.
Instead the LLM returns a structured ``Extraction`` (entities and
relationships keyed by short ``local_id`` aliases) and TRACE's code
assembles the STIX 2.1 bundle. This eliminates the wire-format mistakes
that the LLM kept making — non-UUIDv4 ids, ``HH:mm:ss:sss`` timestamps,
duplicate ids, dangling cross-references — by removing the LLM's chance
to make them at all.

**Public API changes** (any caller importing from `trace_engine.stix.extractor`):

- Removed `extract_stix_objects(text, ...) -> list[dict]`.
  Replaced by `extract_entities(text, ..., pir_doc=None) -> Extraction`.
- Removed `build_stix_bundle(objects, ...) -> dict`.
  Replaced by `build_stix_bundle_from_extraction(extraction, source_url=None,
  collected_at=None, matched_pir_ids=None, relevance_score=None,
  relevance_rationale=None) -> dict`.
- New dataclasses exported: `Extraction`, `ExtractedEntity`,
  `ExtractedRelationship`.
- Module constant rename: `_VALID_STIX_TYPES` → `_VALID_ENTITY_TYPES`
  (now excludes `relationship`, which is no longer an entity type).
  Added `_VALID_RELATIONSHIP_TYPES = {"uses", "exploits", "indicates"}`.

**Prompt change**: `src/trace_engine/llm/prompts/stix_extraction.md` was
fully rewritten. The LLM is now asked for
`{entities: [{local_id, type, name, …}], relationships: [{source, target,
relationship_type}]}` only — no `id`, `spec_version`, `created`,
`modified`, or `source_ref`/`target_ref` fields.

### Added

- ``Extraction`` / ``ExtractedEntity`` / ``ExtractedRelationship`` dataclasses
  in `trace_engine.stix.extractor` to model the LLM's structured output.
- L2 partial-JSON salvage: when Gemini truncates the verdict JSON
  (typically inside `rationale`), `pir.relevance.evaluate` now extracts
  `score` and `matched_pir_ids` via regex and proceeds with a real
  decision instead of failing open. Verdicts where the rationale was
  cut off are recorded as `rationale="(truncated)"`.

### Removed

- `_normalize_stix_objects` post-processing in `stix.extractor` is gone.
  UUIDv4 ids and millisecond-precise timestamps are now produced by
  construction in `build_stix_bundle_from_extraction`, so there is
  nothing left to coerce.
- Tests `tests/test_stix_postprocess.py` (post-processor is gone).

### Fixed

- OASIS `{103}` UUIDv4 validity errors caused by LLM emitting sequential
  or non-v4 ids (`12345678-90ab-cdef-1234-…`).
- STIX timestamp format errors caused by LLM writing
  `2026-04-11T00:00:00:000Z` (colon) instead of the spec's
  `2026-04-11T00:00:00.000Z` (dot).
- Duplicate STIX ids in a single bundle when the LLM reused the same id
  across multiple objects.
- L2 relevance gate failing open on every article whose response Gemini
  truncated mid-`rationale` (the prior cause of bundles being generated
  for clearly off-topic articles when `--pir` was supplied).

### Documentation

- HLD §5.2 (STIX bundle output schema), §6.1 (single-URL pipeline), and
  §6.3 (L2 verdict shape) rewritten to describe the new flow.
- `docs/data-model.md` STIX section reorganised around "LLM extracts,
  code builds".
- `docs/crawl_design.md` §4 split into L3 (entity extraction) + §4a
  (L4 bundle assembly).

---

## [0.1.0] — 2026-05-08

### Added — Initial scope

**PIR-driven web collection (URL / PDF → STIX 2.1 bundle):**
- `cmd/crawl_single.py` — on-demand single URL or PDF ingestion
- `cmd/crawl_batch.py` — list-driven batch crawl from `input/sources.yaml`
  with URL × content-SHA256 deduplication via `output/crawl_state.json`
- L2 relevance gate (`src/trace_engine/pir/relevance.py`) — when `--pir` is
  supplied, articles below the configurable relevance threshold are
  skipped before STIX extraction (`gemini-2.5-flash-lite` by default).
  Skip decisions are recorded in `crawl_state.json` with the originating
  PIR set's hash so re-evaluation is possible after PIR updates
  (`crawl_batch --recheck-on-pir-change`).
- L3 PIR-conditioned extraction — when a PIR document is loaded, the
  STIX extraction prompt is augmented with the PIR's `threat_actor_tags`,
  `notable_groups`, and `collection_focus` to bias the LLM towards
  relevant entities.
- L4 bundle metadata — every emitted bundle carries
  `x_trace_source_url`, `x_trace_collected_at`, and (when the gate ran)
  `x_trace_matched_pir_ids`, `x_trace_relevance_score`, and
  `x_trace_relevance_rationale`. SAGE ignores unknown `x_*` properties.
- Migrated from BEACON: `report_reader` (markitdown-based PDF/URL extraction),
  `stix_extractor` (Vertex AI Gemini → STIX object array),
  `prompts/stix_extraction.md`. The previous BEACON CLI
  `cmd/stix_from_report.py` is replaced with a deprecation stub for one
  release before deletion.

**Validation gate (BEACON / TRACE outputs → SAGE):**
- `cmd/validate_assets.py` — Pydantic schema check against SAGE's
  `assets.json` contract (`SAGE/cmd/load_assets.py`,
  `SAGE/tests/fixtures/sample_assets.json`) plus reference-integrity checks
  (id uniqueness, `network_segment_id` / `security_control_ids` /
  `asset_connections.{src,dst}` / `asset_vulnerabilities.asset_id` resolve)
- `cmd/validate_pir.py` — Pydantic schema check against SAGE's PIR contract
  (`SAGE/src/sage/pir/filter.py:25-39`) plus taxonomy presence check for
  `threat_actor_tags`, asset-tag match for `asset_weight_rules.tag`, and
  `valid_from < valid_until`. **Supersedes BEACON's
  `cmd/validate_pir.py`** (which performed schema-only validation);
  BEACON keeps a deprecation stub for one release.
- `cmd/validate_stix.py` — OASIS `stix2-validator` plus local checks for
  bundle id uniqueness, `relationship.{source_ref,target_ref}` resolution,
  `kill_chain_name == "mitre-attack"`, and `bundle.spec_version == "2.1"`
- `cmd/validate_all.py` — aggregate runner producing a single Markdown
  report at `output/validation_report_<ts>.md`

**Human review support:**
- `cmd/submit_review.py` — emits the Markdown report; opt-in
  `--open-issue` posts the report as a GitHub Enterprise issue (mirrors
  BEACON's `cmd/submit_for_review.py` pattern, duplicated rather than
  imported)

**Auxiliary tooling:**
- `cmd/generate_schemas.py` — exports Pydantic models to
  `schema/*.schema.json`
- `cmd/update_taxonomy_cache.py` — refreshes
  `schema/threat_taxonomy.cached.json` from BEACON's authoritative file

### Documentation

- `high-level-design.md` (Japanese, mirrors BEACON convention)
- `README.md` / `README.ja.md`
- `docs/setup.{md,ja.md}`, `docs/data-model.{md,ja.md}`,
  `docs/crawl_design.{md,ja.md}`, `docs/dependencies.{md,ja.md}`,
  `docs/beacon_handoff.md`

### Project layout

- `pyproject.toml` (uv + ruff, name=`trace`, Python ≥ 3.12)
- `Makefile` with `check / vet / lint / test / audit / format / setup`
  targets matching BEACON
- `.githooks/` for pre-commit (`make vet lint`) and pre-push (`make check`)

### Notes

- The Python import package is named **`trace_engine`** even though the
  distribution name is `trace`. Python's stdlib ships a built-in `trace`
  module that would shadow our package; `trace_engine` borrows the
  "Engine" from "Threat Report Analyzer & Crawling Engine" to keep the
  project's brand while avoiding the conflict.
- BEACON `0.8.x → 0.9.0` (minor bump) accompanies this release: removes
  URL→STIX extraction (`cmd/stix_from_report.py`, `src/beacon/ingest/{report_reader,stix_extractor}.py`,
  the `markitdown[pdf]` dependency, and the corresponding tests). The
  schema-only `BEACON/cmd/validate_pir.py` remains in 0.9.0 and will be
  replaced by TRACE's richer `validate_pir.py` in a follow-up release
  (Phase C of TRACE).
- BEACON output artifact schemas (`assets.json`, `pir_output.json`) are
  unchanged.
- Web UI (FastAPI single-URL form) is deferred to a follow-up release.
- RSS/atom feed expansion in `sources.yaml` is deferred. MVP supports
  flat URL lists only.
- Relevance gate fails open: if the LLM relevance call errors out, the
  article proceeds to STIX extraction (rather than being silently
  dropped) so the failure is visible in the validation report.
