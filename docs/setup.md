# TRACE — Setup Guide

> Verified Python: 3.12

Japanese translation: [`docs/setup.ja.md`](setup.ja.md)

For data flow / responsibility split with BEACON / SAGE, see `high-level-design.md`.
For dependency rationale, see [`docs/dependencies.md`](dependencies.md).
For GCP deployment, see [`docs/deploy.md`](deploy.md).

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.12+ | Required by `pyproject.toml` |
| [uv](https://docs.astral.sh/uv/) | latest | Virtual environment + package manager |
| GCP project | — | Required for L2 relevance gate and L3 STIX extraction (Vertex AI) |
| Git | 2.x+ | For hook installation |

---

## Step 1 — Clone and install dependencies

```bash
cd TRACE/
uv sync --extra dev
```

`make check` should print `92+ passed`, ruff clean, `pip-audit` clean.

---

## Step 2 — Install Git hooks

```bash
make setup
```

Sets `git config core.hooksPath .githooks` and enables:

- **pre-commit** — `make vet lint`
- **pre-push** — `make check` (full quality gate)

---

## Step 3 — Configure environment variables

```bash
cp .env.example .env   # if present
```

Fill in:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GCP_PROJECT_ID` | Yes | — | GCP project for Vertex AI Gemini |
| `VERTEX_LOCATION` | No | `us-central1` | Vertex AI region |
| `TRACE_LLM_SIMPLE` | No | `gemini-2.5-flash-lite` | L2 relevance gate model |
| `TRACE_LLM_MEDIUM` | No | `gemini-2.5-flash` | L3 STIX extraction default |
| `TRACE_LLM_COMPLEX` | No | `gemini-2.5-pro` | L3 STIX extraction for `--task complex` |
| `TRACE_RELEVANCE_MODEL_TIER` | No | `simple` | `simple` / `medium` / `complex` |
| `TRACE_RELEVANCE_THRESHOLD` | No | `0.5` | L2 score `>=` threshold keeps the article |
| `TRACE_EXTRACTION_CHUNK_CHARS` | No | `12000` | Max chars per LLM chunk in L3 extraction |
| `TRACE_EXTERNAL_REF_HASH_ENABLED` | No | `true` | SHA-256 hash augmentation for external references |
| `TRACE_EXTERNAL_REF_HASH_CACHE` | No | `output/external_ref_hash_cache.json` | Cache file for external-ref hashes |
| `TRACE_EXTERNAL_REF_HASH_TTL_DAYS` | No | `30` | TTL in days for cached hashes |
| `TRACE_CRAWL_USER_AGENT` | No | Firefox UA string | UA used by `crawler/fetcher.py` (see note below) |
| `TRACE_CRAWL_CONCURRENCY` | No | `4` | Thread pool size for `crawl-batch` (1 = sequential) |
| `TRACE_STATE_PATH` | No | `output/crawl_state.json` | Batch dedupe state file |
| `TRACE_FEED_MAX_ENTRIES` | No | `50` | Max entries per RSS/Atom feed after expansion |
| `TRACE_FEED_SINCE_DAYS` | No | `90` | Discard feed entries older than N days (falls back to `ACTIVITY_WINDOW_DAYS`) |
| `TRACE_GHE_TOKEN` | GHE only | — | PAT for `submit_review.py --open-issue` |
| `GHE_REPO` | GHE only | — | `owner/repo` |
| `GHE_API_BASE` | No | `https://api.github.com` | Override for self-hosted GHE |
| `TRACE_STORAGE` | No | `local` | Storage backend: `local` or `gcs` |
| `TRACE_STORAGE_BASE_DIR` | No | `output/` | Root directory for `LocalStorage` |
| `TRACE_GCS_BUCKET` | GCS only | — | GCS bucket name (required when `TRACE_STORAGE=gcs`) |
| `TRACE_GCS_PREFIX` | No | (empty) | Key prefix within the GCS bucket |

There is **no `--no-llm` mode** — both the L2 gate and L3 extraction are LLM-only.

#### GCS storage (optional)

To route crawl output to Google Cloud Storage instead of the local filesystem:

```bash
# Install the GCS extra
uv sync --extra gcs

export TRACE_STORAGE=gcs
export TRACE_GCS_BUCKET=my-cti-artifacts
export TRACE_GCS_PREFIX=trace/   # optional; defaults to empty string
```

The `google-cloud-storage` package is only required when `TRACE_STORAGE=gcs`.
Authentication uses Application Default Credentials (same as Vertex AI).

---

## Step 4 — Authenticate with GCP

```bash
gcloud auth application-default login
```

Vertex AI uses Application Default Credentials. No API key management.

---

## Step 5 — Verify

```bash
make test       # unit tests, no GCP needed
make check      # full gate: vet → lint → test → audit
```

---

## Testing

### Running tests

```bash
# Full quality gate (lint + test + audit)
make check

# Tests only
make test

# Tests only via uv
uv run pytest

# Run a specific test file
uv run pytest tests/test_stix_extractor.py -v

# Run tests matching a name pattern
uv run pytest -k "test_relevance" -v
```

No external services are required — all LLM calls are mocked in the test suite.

### Test fixtures

Fixtures live in `tests/fixtures/`. Each fixture is a static file used as
test input or expected output:

| Fixture type | Description |
|-------------|-------------|
| STIX bundle JSON | Sample bundles for extractor and validator tests |
| PIR JSON | Sample `pir_output.json` documents for validator tests |
| Assets JSON | Sample `assets.json` for asset validator tests |
| Taxonomy JSON | Cached taxonomy snapshot; used instead of BEACON live data |

The taxonomy fixture (`schema/threat_taxonomy.cached.json` or a copy in
`tests/fixtures/`) means tests do not depend on BEACON being present or
reachable.

### No external service dependency

- **LLM calls**: All Vertex AI / Gemini calls are patched with `unittest.mock`
  or `pytest-mock`. Tests do not require a GCP project, `GOOGLE_APPLICATION_CREDENTIALS`,
  or network access.
- **BEACON**: Taxonomy auto-sync is bypassed in tests. The test suite uses
  the committed taxonomy snapshot.
- **GCS**: `GCSStorage` is not exercised in unit tests. `LocalStorage` with a
  temporary directory is used instead.

### Common test patterns

#### Fixture-based STIX bundle tests

Most tests in `tests/test_stix_extractor.py` load a JSON fixture, call the
extractor or validator function, and assert on the result structure:

```python
def test_bundle_validates(tmp_path, stix_fixture):
    bundle = json.loads(stix_fixture.read_text())
    result = validate_stix_bundle(bundle)
    assert result.is_valid
```

#### Relevance gate tests

L2 gate tests patch the Vertex AI client and assert that articles below the
threshold are recorded as skipped in `crawl_state.json`:

```python
def test_low_relevance_skipped(mock_llm, crawl_state):
    mock_llm.return_value = RelevanceResponse(score=0.1)
    ...
    assert crawl_state[url]["skipped"] is True
```

### Taxonomy cache in tests

Tests that exercise taxonomy enrichment use the committed
`schema/threat_taxonomy.cached.json` snapshot (or a fixture copy). The
auto-sync path (`ensure_taxonomy_fresh`) is mocked to be a no-op, so no
BEACON dependency is needed.

To regenerate the test taxonomy snapshot from a live BEACON installation:

```bash
trace taxonomy-refresh
cp schema/threat_taxonomy.cached.json tests/fixtures/threat_taxonomy.json
```

---

## Security scanning

```bash
make audit
```

Runs `pip-audit`. Included in `make check`.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `GCP_PROJECT_ID not set` | env not loaded | `cp .env.example .env`, fill, re-run |
| `Input should be a valid dictionary` on `crawl_batch` | `sources.yaml` is a flat URL list | Wrap as `{version, sources: [...]}` — see [`crawl_design.md`](crawl_design.md) |
| `pip-audit` findings | Vulnerable dep | Bump in `pyproject.toml`, `uv lock`, document in `CHANGELOG.md` |
| L2 gate always fails-open (`parse_failed` / `call_failed`) | LLM returned non-JSON or call errored | Check `gcloud auth application-default print-access-token`; verify `TRACE_RELEVANCE_MODEL_TIER` is a real model id |
| Hook not running | `make setup` not executed | Run `make setup` in TRACE/ |
