# TRACE API Stability Policy

**Status**: Effective from TRACE 2.0.0 (breaking release — PIR
schema_version "2.0.0" contract).

This document enumerates TRACE's committed public surface and the
backward-compatibility (BC) guarantee that applies to it. Anything not
listed as **Committed** is **Evolving** and may change in any minor
release without warning.

---

## 1. Versioning policy

TRACE reached 1.0.0 on 2026-05-09 (STIX 2.1 identity SDO milestone,
paired with SAGE 0.5.0) but historically allowed minor-version
breaking changes in the validator surface (Initiative E added strict
mode, F added schema_version gate, G added IR-factor acceptance).
Initiative H concluded this asymmetric period; TRACE 2.0.0 is the
first full breaking-change major bump.

| Version | Policy |
|---|---|
| 1.0.0 – 1.11.0 | Historical: minor releases could break validator surface |
| **1.12.0 (Initiative H)** | **Final asymmetric minor** — pre-1.0 normaliser removed, PIR validator restricted to `schema_version: "1.0.0"` only |
| 1.13.0 | Last release accepting `schema_version: "1.0.0"` |
| **2.0.0** | **Breaking**: `SUPPORTED_PIR_SCHEMA_VERSIONS` → `{"2.0.0"}`; `schema_version: "1.0.0"` now rejected. Paired with BEACON 2.0.0. |

From TRACE 2.0.0 onwards:

- **Major** (`X.0.0`) — breaking changes to any Committed surface item.
- **Minor** (`2.X.0`) — additive only.
- **Patch** (`2.0.X`) — bug fixes only.

---

## 2. Quick reference

| Surface | Committed? | First version | Notes |
|---|---|---|---|
| PIR validator: `SUPPORTED_PIR_SCHEMA_VERSIONS = {"2.0.0"}` | ✓ | 2.0.0 | Versions ≤ "1.0.0" rejected with per-version error message; paired with BEACON 2.0.0 |
| `PIRDocument.from_payload()` API | ✓ | 1.12.0 | Pydantic dispatcher for PIR validation |
| `STIX2.1 bundle` validation API | ✓ | 1.12.0 | Wraps `stix2-validator` |
| `Assets bundle` validation API | ✓ | 1.12.0 | `validate_assets` / `validate_identity_assets` / `validate_user_accounts` |
| `schema/pir.schema.json` | ✓ | 1.12.0 | Mirror of BEACON `pir_output.schema.json` for cross-repo drift check |
| `schema/sources.schema.json` | ✓ | 1.10.0 (F) | Includes `feed_type` enum (html/rss/atom) |
| `schema/assets.schema.json` | ✓ | 1.0.0 | Identity + asset bundle shape |
| `sources.yaml` schema (operator config) | ✓ | 1.10.0 | `url`, `label`, `task`, `max_chars`, `pir_ids`, `feed_type` |
| Crawl output: STIX 2.1 bundles | ✓ | 1.0.0 | x_trace_collected_at extension, conforming STIX 2.1 |
| Crawl output: `crawl_state.json` schema | ✓ | 1.11.0 (G) | Per-entry `iocs[]` since G Phase 4 |
| LLM IoC extraction (`iocs[]` shape) | ✓ | 1.11.0 (G) | 7 IoC types, confidence, context_snippet |
| `trace` CLI entry + subcommands (Phase 6 of H) | ✓ | 1.12.0 | Subcommand names + main flags frozen |
| Legacy `python -m cmd.<name>` | (removed) | n/a | Removed in 2.1.0; use `trace <subcommand>` |
| Env vars (§5) | ✓ | 1.12.0 | Name + meaning + default frozen |
| Internal Python modules (`src/trace_engine/*` non-public symbols) | ✗ | n/a | Underscore-prefixed and undocumented helpers may change |
| `validate/schema/models.py` Pydantic class names | ✗ | n/a | Consumers go through `PIRDocument.from_payload()`, not direct Pydantic import |
| LLM prompts under `src/trace_engine/llm/prompts/` | ✗ | n/a | Tuned per LLM model upgrade; output JSON shape stays Committed |

---

## 3. Committed surface — detail

### 3.1 PIR validator API

The single supported entry point is `PIRDocument.from_payload()` in
`src/trace_engine/validate/schema/models.py`. **From TRACE 1.12.0
(Initiative H Phase 3 carry-over)**: `from_payload` accepts ONLY
the wrapped envelope shape — bare-list and single-object payloads
are rejected.

**Committed**:
- `SUPPORTED_PIR_SCHEMA_VERSIONS: set[str] = {"2.0.0"}` — TRACE
  2.0.0 accepts only `"2.0.0"`. The previous `"1.0.0"` and pre-1.0
  versions (`0.16.0`, `0.17.0`, `0.18.0`) are rejected with per-version
  error messages:
  > `schema_version "1.0.0" was supported in TRACE 1.13.0; please
  > re-emit with BEACON 2.0.0+ output.`
  > (Full mapping: 0.16.0 → TRACE 1.9.0, 0.17.0 → 1.10.0, 0.18.0 →
  > 1.11.0, 1.0.0 → 1.13.0.)
- `PIRDocument.from_payload(payload: dict, *, ...)` — requires
  wrapped envelope `{"schema_version": "2.0.0", "pirs": [...]}`.
  Returns validated `PIROutputDocument` or raises `ValidationError`
  (Pydantic) / `ValueError` (envelope rejection — bare-list / single-
  object inputs).
- Bare-list rejection message:
  > `Bare-list PIR input is no longer supported as of TRACE 1.12.0;
  > wrap your input as {"schema_version": "2.0.0", "pirs": [...]}`
- `PIROutputDocument.PIRItem.prioritized_actors` — required field
  (must be present, MAY be empty list). BEACON 2.0.0 always emits
  this field.
- Cross-version contamination check — REMOVED in Initiative H Phase 2
  since only one schema_version is accepted (no contamination possible).

**Not committed**:
- Pydantic class definitions in `validate/schema/models.py` — consumers
  go through `PIRDocument.from_payload()`, not import the classes
  directly. Class names and internal nesting may change.
- CLI envelope-rejection translation: `cmd/validate_pir.py` and
  `cmd/validate_all.py` translate `ValueError` into a
  `SCHEMA_ENVELOPE` / `PIR_SCHEMA_ENVELOPE` structured finding so
  analysts see the migration message rather than a traceback. The
  finding code names are internal.

### 3.2 STIX bundle validation API

Wraps OASIS `stix2-validator`. `src/trace_engine/validate/stix/validator.py`
exposes `validate_bundle(bundle_dict) -> ValidationResult`.

**Committed**:
- `validate_bundle()` function signature + `ValidationResult` shape
  (`is_valid: bool`, `errors: list[str]`, `warnings: list[str]`).

### 3.3 Asset bundle validation API

For `assets.json`, `identity_assets.json`, `user_accounts.json`:

**Committed**: validator entry points for each (callable from CLI
subcommands `trace validate-assets`, `trace validate-identity`,
`trace validate-accounts`).

### 3.4 `schema/sources.schema.json` (operator config for crawl)

Sources YAML carries per-source policy used by the batch crawler.

**Committed fields**:
- `url` (required, HTTPS URL)
- `label` (optional, free text)
- `task` (optional, free text, batch tag)
- `max_chars` (optional, positive int)
- `pir_ids` (optional, list of PIR IDs this source addresses)
- `feed_type` (optional, enum `html|rss|atom`; defaults to auto-detect
  via HTTP Content-Type; explicit value overrides detection)

### 3.5 `schema/pir.schema.json` (mirror of BEACON output schema)

Regenerated from TRACE's `PIRDocument` Pydantic model. Drift check
`make check-pir-schema-drift` compares against
`../beacon/schema/pir_output.schema.json`.

**Committed**: schema content matches BEACON 2.0.0 output exactly
(no field difference).

### 3.6 Crawl output

#### 3.6.1 STIX 2.1 bundle

Each crawled article produces a STIX 2.1 bundle conforming to
`stix2-validator`. TRACE adds custom property
`x_trace_collected_at` (ISO timestamp) on the bundle envelope.

**Committed**: STIX 2.1 conformance + `x_trace_collected_at`
extension presence.

#### 3.6.2 `crawl_state.json`

Per-entry state for dedup + IoC index. Schema:
```
{
  "entries": {
    "<entry_url>": {
      "first_seen": "<iso>",
      "last_seen": "<iso>",
      "title": "<str>",
      "bundle_path": "<path>",
      "iocs": [
        {"type": "ipv4|ipv6|fqdn|sha256|sha1|md5|cve_id",
         "value": "<str>", "confidence": <float>,
         "context_snippet": "<str ≤ 50 chars>"}
      ]
    }
  }
}
```

**Committed**: top-level `entries` dict + per-entry required fields
(`first_seen`, `last_seen`, `bundle_path`). Missing `iocs` field on
read = empty list (backward-compat with pre-G state files).

### 3.7 LLM IoC extraction output (Initiative G Phase 4)

The Vertex AI relevance-check call returns:
```
{
  "relevant": bool,
  "reason": str,
  "iocs": [{"type": "...", "value": "...", "confidence": ...,
            "context_snippet": "..."}]
}
```

**Committed**:
- 7 IoC types: `ipv4 | ipv6 | fqdn | sha256 | sha1 | md5 | cve_id`
- `confidence ∈ [0, 1]`
- `context_snippet` (truncated to 50 chars by Pydantic validator)

**Not committed**:
- Prompt template content (`src/trace_engine/llm/prompts/relevance_check.md`)
  — tuned with each LLM model upgrade.
- LLM model selection.

### 3.8 `trace` CLI entry + subcommands (Phase 6 of H)

Initiative H Phase 6 introduces `trace` as a click `Group` entry
point. Subcommands wrap the existing `cmd/*.py` logic. Operator-
visible surface from 1.12.0:

| Subcommand | Replaces | Purpose |
|---|---|---|
| `trace crawl-batch` | `cmd/crawl_batch.py` | Batch crawl from `input/sources.yaml` (RSS/Atom + HTML, dedup via crawl_state.json) |
| `trace crawl-single` | `cmd/crawl_single.py` | One-shot crawl + STIX bundle emit |
| `trace search-iocs` | `cmd/search_iocs.py` | Query crawl_state IoC index (G Phase 5) |
| `trace validate-pir` | `cmd/validate_pir.py` | Validate BEACON pir_output.json |
| `trace validate-stix` | `cmd/validate_stix.py` | Validate STIX 2.1 bundles |
| `trace validate-assets` | `cmd/validate_assets.py` | Validate assets.json |
| `trace validate-identity` | `cmd/validate_identity_assets.py` | Validate identity_assets.json |
| `trace validate-accounts` | `cmd/validate_user_accounts.py` | Validate user_accounts.json |
| `trace validate-all` | `cmd/validate_all.py` | Run all validators sequentially |
| `trace enrich-bundle` | `cmd/enrich_bundle.py` | Post-process STIX bundle |
| `trace submit-review` | `cmd/submit_review.py` | Submit output to review system |
| `trace taxonomy-refresh` | `cmd/update_taxonomy_cache.py` | Refresh threat taxonomy cache |
| `trace schema-regenerate` | `cmd/generate_schemas.py` | Regenerate schema/*.schema.json from Pydantic models |

**Committed**: subcommand names + each subcommand's main flags
(e.g., `crawl-batch --sources`, `search-iocs --ioc`, `search-iocs
--tlp-max`, `search-iocs --json`).

**Evolving**: optional flag defaults, help text wording, output
formatting.

**Removed in 2.1.0**: `python -m cmd.<name>` invocation syntax. The
unified `trace` CLI is the only supported entry point. All `cmd/*.py`
modules remain callable via `main()` from the CLI wrappers.

### 3.9 Environment variables (Committed)

| Env | Default | Purpose |
|---|---|---|
| `ACTIVITY_WINDOW_DAYS` | `90` | Shared with BEACON/SAGE. TRACE_FEED_SINCE_DAYS falls back to this |
| `TRACE_FEED_MAX_ENTRIES` | `50` | Cap on RSS/Atom entries expanded per feed per crawl |
| `TRACE_FEED_SINCE_DAYS` | `90` (falls back to `ACTIVITY_WINDOW_DAYS`) | Filter feed entries by `published` date |
| `TRACE_STATE_PATH` | `output/crawl_state.json` | Crawl state file location |
| `TRACE_CRAWL_CONCURRENCY` | `4` | Parallel fetch workers |

**Other env vars** (deployment-specific, NOT committed):
- LLM: `TRACE_LLM_SIMPLE`, `TRACE_LLM_MEDIUM`, `TRACE_LLM_COMPLEX`,
  `TRACE_RELEVANCE_MODEL_TIER`, `TRACE_RELEVANCE_THRESHOLD`
- Extraction tuning: `TRACE_EXTRACTION_CHUNK_CHARS`,
  `TRACE_EXTERNAL_REF_HASH_ENABLED`, `TRACE_EXTERNAL_REF_HASH_TTL_DAYS`
- GCP: `GCP_PROJECT_ID`, `VERTEX_LOCATION`

These may change name or default in minor releases — operators set
them explicitly per deployment.

---

## 4. Evolving (NOT BC-protected)

- **Internal Python modules** under `src/trace_engine/` not exported
  via the documented API surface.
- **Pydantic class names** in `validate/schema/models.py` — consumers
  go through `PIRDocument.from_payload()`.
- **LLM prompt content** in `src/trace_engine/llm/prompts/` — tuned
  per LLM model upgrade. LLM **output JSON shape** is Committed
  (§3.7).
- **`trace schema-regenerate`** (`cmd/generate_schemas.py`) — dev tool
  for regenerating `schema/*.schema.json`; output format may change.
- **`schema/threat_taxonomy.cached.json`** — auto-generated taxonomy
  cache, refreshed via `trace taxonomy-refresh`.

---

## 5. Cross-repo dependencies

TRACE's Committed surface depends on:

- **BEACON `pir_output.json` schema** (BEACON 2.0.0+): TRACE
  validator accepts only `schema_version: "2.0.0"` payloads. BEACON
  output is the canonical input to `trace validate-pir`.
- **MITRE ATT&CK Enterprise STIX bundle** (read at validation time
  if loaded): for threat-actor / TTP resolution.
- **OASIS STIX 2.1 specification**: TRACE's STIX bundle output and
  the wrapped `stix2-validator` are bound to the STIX 2.1 release.

Full citation inventory: `../beacon/docs/citations.md`.

---

## 6. 2.0.0 trigger examples

Examples of changes that would force TRACE 2.0.0:

- Removing or renaming `PIRDocument.from_payload()`.
- Changing `crawl_state.json` top-level structure (e.g., renaming
  `entries`).
- Removing one of the 7 IoC types from §3.7.
- Removing `trace search-iocs` subcommand or its `--ioc` flag.
- Removing `TRACE_FEED_MAX_ENTRIES` env var.
- Adding a new required field to `sources.yaml` (existing
  operator configs would break).

Adding new IoC types, new validators, new subcommands, new optional
fields in any schema is allowed in minor releases.

---

## 7. Maintenance

Update this document whenever a Committed surface item is introduced
or deprecated. See BEACON `docs/api-stability.md` §7 for the same
maintenance convention.

---

*TRACE 2.0.0 — breaking release. schema_version "2.0.0" is the
accepted PIR contract; paired with BEACON 2.0.0.*
