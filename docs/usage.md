# TRACE — Usage Guide

Japanese translation: [`docs/usage.ja.md`](usage.ja.md)

This guide covers CLI commands, common workflows, key flags, day-to-day
operations, and troubleshooting. For detailed crawler architecture and L2–L4
pipeline internals, see [`docs/crawl_design.md`](crawl_design.md).

---

## CLI commands (`trace` entry point)

TRACE exposes a unified `trace` console script with 14 subcommands:

| Subcommand | Description |
|------------|-------------|
| `trace crawl-single` | Crawl a single URL or PDF and emit a STIX 2.1 bundle |
| `trace crawl-batch` | Batch crawl from `input/sources.yaml` with content-hash deduplication |
| `trace discover-pir` | Discover PIR-matching article candidates from an RSS/Atom source catalog |
| `trace validate-all` | Run all validators and produce a combined Markdown report |
| `trace validate-stix` | Validate a STIX 2.1 bundle (schema + local reference check) |
| `trace validate-pir` | Validate `pir_output.json` (Pydantic + taxonomy + asset-tag match) |
| `trace validate-assets` | Validate `assets.json` (Pydantic + semantic reference check) |
| `trace validate-identity` | Validate `identity_assets.json` (cross-ref vs `assets.json`) |
| `trace validate-accounts` | Validate `user_accounts.json` (cross-ref vs `assets.json`) |
| `trace enrich-bundle` | Add threat-actor taxonomy tags to an existing STIX bundle |
| `trace search-iocs` | Query the IoC index stored in `crawl_state.json` |
| `trace submit-review` | Post a validation report to GitHub (optional `--open-issue`) |
| `trace taxonomy-refresh` | Sync the local taxonomy cache from the BEACON source |
| `trace schema-regenerate` | Regenerate `schema/*.schema.json` from Pydantic contract models |

> Invoke TRACE via `uv run trace <subcommand>`.

---

## Key flags

| Flag | Commands | Description |
|------|----------|-------------|
| `--pir <path>` | `crawl-single`, `crawl-batch`, `discover-pir` | Path to `pir_output.json`; enables L2/L3/L4 for crawl commands and provides discovery context for `discover-pir` |
| `--output <path>` | `crawl-single` | Write bundle to explicit path (bypasses StorageBackend) |
| `--output-dir <path>` | `crawl-batch` | Write bundles to explicit directory (bypasses StorageBackend) |
| `--no-sync-taxonomy` | `crawl-single`, `crawl-batch` | Skip taxonomy auto-sync at startup (CI / air-gapped environments) |
| `--catalog <path>` | `discover-pir` | Source catalog YAML for RSS/Atom article discovery |
| `--from`, `--to`, `--since-days` | `discover-pir` | Discovery date window |
| `--max-candidates <N>` | `discover-pir` | Cap candidate JSON results |
| `--open-issue` | `submit-review` | Post the validation report as a GitHub issue |
| `--json` | `search-iocs`, `discover-pir` | Emit results as JSON instead of human-readable text |

---

## L2 / L3 / L4 pipeline (brief overview)

When `--pir` is supplied, each article passes through three stages:

- **L2 — Relevance gate**: A lightweight `gemini-2.5-flash-lite` call scores
  the article against the PIR. Articles below the threshold are skipped;
  skip decisions are recorded in `crawl_state.json`.
- **L3 — PIR-conditioned extraction**: The STIX extraction prompt is augmented
  with PIR `threat_actor_tags`, `notable_groups`, and `collection_focus` to
  bias the LLM towards relevant entities.
- **L4 — Bundle metadata**: Emitted bundles carry `x_trace_matched_pir_ids`
  and `x_trace_relevance_score` extension fields.

Without `--pir`, the gate is bypassed and all articles are fully extracted
(useful for experimentation). See [`docs/crawl_design.md`](crawl_design.md)
for the full architecture.

---

## Common workflows

### Single URL crawl

```bash
# Without PIR (all articles extracted)
uv run trace crawl-single --input https://example.com/report

# With PIR (L2 gate + L3 conditioning + L4 metadata)
uv run trace crawl-single --input https://example.com/report \
  --pir ../BEACON/output/pir_output.json

# Explicit output path (bypasses StorageBackend)
uv run trace crawl-single --input https://example.com/report \
  --pir ../BEACON/output/pir_output.json \
  --output output/my_bundle.json
```

### Batch crawl with sources.yaml

```bash
# Batch crawl with PIR filtering and content-hash deduplication
uv run trace crawl-batch --pir ../BEACON/output/pir_output.json

# Skip taxonomy sync for CI
uv run trace crawl-batch --pir ../BEACON/output/pir_output.json --no-sync-taxonomy

# Explicit output directory (bypasses StorageBackend)
uv run trace crawl-batch --pir ../BEACON/output/pir_output.json \
  --output-dir output/stix/
```

See [`docs/crawl_design.md`](crawl_design.md) for the `input/sources.yaml`
schema (including `feed_type` and per-source configuration).


### PIR-driven article discovery

`trace discover-pir` searches an RSS/Atom source catalog for article candidates
that match BEACON PIR terms. It does **not** extract STIX; the output is a
candidate JSON document intended for human approval in the BEACON Collection
UI or for an operator-managed review step. Approved URLs are then passed to
`trace crawl-batch --pir`, which runs the normal L2/L3/L4 pipeline.

```bash
# Discover candidates from input/source_catalog.yaml, falling back to the
# committed example catalog when the operator catalog does not exist.
uv run trace discover-pir \
  --pir ../BEACON/output/pir_output.json \
  --since-days 30 \
  --json \
  --output output/candidates.json

# Use an explicit catalog and absolute date window.
uv run trace discover-pir \
  --pir ../BEACON/output/pir_output.json \
  --catalog input/source_catalog.yaml \
  --from 2026-06-01 \
  --to 2026-06-30 \
  --max-candidates 25 \
  --json
```

The committed `input/source_catalog.example.yaml` is a template. Operators
should copy it to the gitignored `input/source_catalog.yaml` and customize the
feed list for their environment. See [`docs/crawl_design.md`](crawl_design.md)
for the catalog and candidate JSON contracts.

### Validation before SAGE ingestion

Run all validators together and produce a single Markdown report:

```bash
uv run trace validate-all
```

Or run individual validators:

```bash
uv run trace validate-stix output/stix/stix_bundle_*.json
uv run trace validate-pir  ../BEACON/output/pir_output.json
uv run trace validate-assets ../BEACON/output/assets.json
uv run trace validate-identity ../BEACON/output/identity_assets.json
uv run trace validate-accounts ../BEACON/output/user_accounts.json
```

Review the generated `output/validation_report_*.md` and optionally submit:

```bash
uv run trace submit-review --open-issue
```

SAGE only ingests artifacts that TRACE has validated.

### IoC search

```bash
# Search by value
uv run trace search-iocs --ioc 203.0.113.42

# Filter by type and TLP level
uv run trace search-iocs --type ipv4 --tlp-max green --json
```

---

## Crawl state management

TRACE tracks processed URLs in `output/crawl_state.json`
(path overridable via `TRACE_STATE_PATH`).

Each entry records:
- `content_hash` — SHA-256 of the fetched page content
- `bundle_path` — where the emitted STIX bundle was written
- `pir_hash` — hash of the PIR document used (enables recheck on PIR change)
- `skipped` — `true` if the L2 gate rejected the article
- `iocs[]` — IoC values extracted by the LLM (7 types: IPv4, IPv6, FQDN, SHA256, SHA1, MD5, CVE-ID)

**Content-hash deduplication:** `crawl-batch` skips any URL whose
`content_hash` matches a previous run. Pass `--recheck-on-pir-change` to
re-evaluate skipped articles when the PIR has been updated since the last run.

**Manual reset:** Delete the entry from `crawl_state.json` (or delete the
file entirely) to force re-crawl of all sources.

---

## External reference hash cache

TRACE computes SHA-256 hashes for STIX `external_references` URLs to detect
drift between runs. The cache file path is controlled by:

| Variable | Default | Description |
|----------|---------|-------------|
| `TRACE_EXTERNAL_REF_HASH_ENABLED` | `true` | Enable/disable external reference hashing |
| `TRACE_EXTERNAL_REF_HASH_CACHE` | `output/external_ref_hash_cache.json` | Cache file path |
| `TRACE_EXTERNAL_REF_HASH_TTL_DAYS` | `30` | Cache entry TTL in days |

Delete the cache file to force re-hashing of all external references.

---

## Taxonomy cache refresh

TRACE enriches `threat-actor` / `intrusion-set` STIX objects with tags
from the threat taxonomy. The local cache is at
`schema/threat_taxonomy.cached.json` (overridable via
`TRACE_TAXONOMY_CACHE_PATH`).

At startup, `crawl-single` and `crawl-batch` auto-sync the cache from the
BEACON source (`../BEACON/schema/threat_taxonomy.json` by default;
overridable via `TRACE_BEACON_TAXONOMY_SOURCE`). If BEACON is unavailable,
the existing snapshot is used and a `taxonomy_sync_skipped` log event is
emitted.

**Manual refresh:**

```bash
uv run trace taxonomy-refresh
```

**Skip auto-sync** (CI / air-gapped environments):

```bash
uv run trace crawl-batch --no-sync-taxonomy ...
```

---

## StorageBackend configuration

TRACE routes crawl output through a pluggable StorageBackend:

| Variable | Default | Description |
|----------|---------|-------------|
| `TRACE_STORAGE` | `local` | Backend selector: `local` or `gcs` |
| `TRACE_STORAGE_BASE_DIR` | `output/` | Root directory for `LocalStorage` |
| `TRACE_STORAGE_BUCKET` | — | GCS bucket name (required when `TRACE_STORAGE=gcs`) |
| `TRACE_STORAGE_PREFIX` | (empty) | Key prefix within the GCS bucket |

Output category `stix` produces filenames in the format
`stix_bundle_<YYYYMMDDHHmm>.json`.

Passing `--output` / `--output-dir` bypasses the StorageBackend and writes
to the explicit path.

---

## sources.yaml management

`input/sources.yaml` is the operator-managed list of sources for
`crawl-batch`. The file is gitignored (runtime artifact).

Each entry specifies a URL, optional `feed_type` (rss, html, pdf), per-source
crawl settings, and optional TLP override. See
[`docs/crawl_design.md`](crawl_design.md) for the full annotated schema.

Validate the sources file before committing changes:

```bash
trace validate-pir ../BEACON/output/pir_output.json  # ensure PIR is valid first
trace crawl-batch --dry-run                           # if supported by your build
```

---

## Troubleshooting

### LLM rate limits

**Symptom:** `ResourceExhausted` / 429 errors from Vertex AI.

**Resolution:**
- Reduce `TRACE_CRAWL_CONCURRENCY` (default: 4) to lower parallel LLM calls.
- Increase quota in the GCP console for the Vertex AI API.
- Use `--no-sync-taxonomy` to avoid the taxonomy sync call at startup.

### Relevance gate rejecting too many / too few articles

**Symptom:** Too many articles skipped (L2 threshold too strict) or STIX
bundles contain low-quality extractions (threshold too loose).

**Resolution:**
- The L2 threshold is a configurable constant in `src/trace_engine/pir/relevance.py`.
  Adjust and re-run `make check` to ensure tests still pass.
- Check the PIR document quality: vague `collection_focus` or missing
  `threat_actor_tags` reduce gate precision.
- Use `trace crawl-batch --recheck-on-pir-change` after updating the PIR to
  re-evaluate previously skipped articles.

### Validation failures before SAGE ingestion

**Symptom:** `trace validate-all` produces findings in the report.

**Resolution:**
1. Review `output/validation_report_*.md` for specific finding codes.
2. Fix the upstream artifact (BEACON output or STIX bundle) and re-validate.
3. Use `trace submit-review --open-issue` to track outstanding issues.

See [`docs/data-model.md`](data-model.md) for `ValidationFinding` codes and
remediation guidance.

### General setup issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| `GCP_PROJECT_ID not set` | env not loaded | `cp .env.example .env`, fill, re-run |
| `Input should be a valid dictionary` on `crawl_batch` | `sources.yaml` is a flat URL list | Wrap as `{version, sources: [...]}` — see [`crawl_design.md`](crawl_design.md) |
| `pip-audit` findings | Vulnerable dep | Bump in `pyproject.toml`, `uv lock`, document in `CHANGELOG.md` |
| L2 gate always fails-open (`parse_failed` / `call_failed`) | LLM returned non-JSON or call errored | Check `gcloud auth application-default print-access-token`; verify `TRACE_RELEVANCE_MODEL_TIER` is a real model id |
| Hook not running | `make setup` not executed | Run `make setup` in TRACE/ |
