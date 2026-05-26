# TRACE — Setup Guide

> 動作確認済 Python: 3.12

Japanese translation: [`docs/setup.ja.md`](setup.ja.md)

For data flow / responsibility split with BEACON / SAGE, see `high-level-design.md`.
For dependency rationale, see [`docs/dependencies.md`](dependencies.md).

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
| `TRACE_CRAWL_USER_AGENT` | No | `TRACE/0.1 (+...)` | UA used by `crawler/fetcher.py` |
| `TRACE_STATE_PATH` | No | `output/crawl_state.json` | Batch dedupe state file |
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

## Running TRACE

The full command set lives in [`docs/crawl_design.md`](crawl_design.md) (collection)
and [`docs/data-model.md`](data-model.md) (validation gate). Quick reference:

### Single URL → STIX bundle

```bash
# No PIR — extract everything the LLM finds.
uv run python cmd/crawl_single.py \
  --input 'https://example.com/cti-blog/post-42' \
  --output output/test_bundle.json

# With PIR — articles below the relevance threshold are skipped.
uv run python cmd/crawl_single.py \
  --input 'https://example.com/cti-blog/post-42' \
  --pir ../BEACON/output/pir_output.json
```

### Batch crawl

```bash
# input/sources.yaml schema is documented in docs/crawl_design.md.
uv run python cmd/crawl_batch.py --pir ../BEACON/output/pir_output.json
uv run python cmd/crawl_batch.py --pir ../BEACON/output/pir_output.json --recheck-on-pir-change
uv run python cmd/crawl_batch.py --dry-run
```

### Validation gate

```bash
uv run python cmd/validate_assets.py --assets ../BEACON/output/assets.json
uv run python cmd/validate_pir.py    --pir    ../BEACON/output/pir_output.json \
                                     --assets ../BEACON/output/assets.json
uv run python cmd/validate_stix.py   --bundle output/stix_bundle.json [--strict]

# Initiative A / Initiative C Phase 2 — Identity SDO + has_access edges.
# Cross-checks each has_access[].asset_id against assets.json and validates
# is_high_value_impersonation_target / impersonation_risk_factors (Phase 2).
uv run python cmd/validate_identity_assets.py \
  --identity-assets ../BEACON/output/identity_assets.json \
  --assets          ../BEACON/output/assets.json

# Initiative B — UserAccount SCO + account_on_asset edges.
uv run python cmd/validate_user_accounts.py \
  --user-accounts ../BEACON/output/user_accounts.json \
  --assets        ../BEACON/output/assets.json

uv run python cmd/validate_all.py \
  --assets ../BEACON/output/assets.json \
  --pir    ../BEACON/output/pir_output.json \
  --bundle output/stix_bundle.json \
  --report output/validation_report.md
```

### Taxonomy enrichment

TRACE bundles carry PIR vocabulary tags (`apt-china`, `apt-russia`, `ransomware`, …) on `threat-actor` and `intrusion-set` objects so that SAGE's `pir_filter.is_relevant_actor` retains actors for downstream graph ingestion.

**Auto-sync at crawl startup** (TRACE 1.7.0): `crawl_single` and `crawl_batch` call `ensure_taxonomy_fresh` at startup, which copies `../BEACON/schema/threat_taxonomy.json` to `schema/threat_taxonomy.cached.json` when BEACON is available. The sync is best-effort — if BEACON is absent, the existing cached snapshot is used and a `taxonomy_sync_skipped` warning is logged.

```bash
# Opt out of auto-sync (CI / air-gapped):
uv run python cmd/crawl_single.py --input report.pdf --no-sync-taxonomy

# Explicit cache refresh:
uv run python cmd/update_taxonomy_cache.py
```

**External-bundle rescue** — OpenCTI feeds, hand-authored STIX, or old TRACE bundles often lack these tags. Enrich them before feeding SAGE:

```bash
uv run python cmd/enrich_bundle.py \
    --input  external.json \
    --output enriched.json

# Then feed to SAGE:
cd ../SAGE
uv run python cmd/run_etl.py --manual-bundle ../TRACE/enriched.json
```

Override the taxonomy snapshot with `--taxonomy <path>` if needed (default: `schema/threat_taxonomy.cached.json`).

| Env var | Default | Description |
|---------|---------|-------------|
| `TRACE_TAXONOMY_CACHE_PATH` | `schema/threat_taxonomy.cached.json` | TRACE-side cache |
| `TRACE_BEACON_TAXONOMY_SOURCE` | `../BEACON/schema/threat_taxonomy.json` | BEACON master file for auto-sync |

### Reviewer handoff

```bash
# Echo Markdown to stdout.
uv run python cmd/submit_review.py --report output/validation_report.md

# Or post as a single GHE Issue.
uv run python cmd/submit_review.py \
  --report output/validation_report.md --open-issue \
  --title "TRACE validation 2026-05-08"
```

Exit codes everywhere: `0` success / `1` validation failures / `2` input or
auth-config error.

---

## Step 6 — Deploy TRACE to Cloud Run (Job)

Build the container image and deploy TRACE as a Cloud Run Job for batch execution.

```sh
# Load .env if not already sourced
source .env
export IMAGE=gcr.io/${GCP_PROJECT_ID}/trace-crawl

# Build and push container image via Cloud Build
gcloud builds submit --tag ${IMAGE} --project=${GCP_PROJECT_ID}

# Create the Cloud Run Job
gcloud run jobs create trace-crawl \
  --image=${IMAGE} \
  --region=${VERTEX_LOCATION:-us-central1} \
  --set-env-vars="GCP_PROJECT_ID=${GCP_PROJECT_ID},VERTEX_LOCATION=${VERTEX_LOCATION:-us-central1},TRACE_STORAGE=${TRACE_STORAGE:-gcs},TRACE_GCS_BUCKET=${TRACE_GCS_BUCKET}" \
  --set-secrets="TRACE_GCS_PREFIX=trace-gcs-prefix:latest" \
  --project=${GCP_PROJECT_ID}
```

> **Secret Manager:** Store sensitive values with
> `gcloud secrets create trace-gcs-prefix --data-file=- <<< "trace/"` and
> reference with `--set-secrets` instead of `--set-env-vars`.

> **Service account:** Create a dedicated service account and grant
> `roles/aiplatform.user` (Vertex AI Gemini), `roles/storage.objectAdmin`
> (GCS output), and `roles/run.invoker` before deploying.
>
> ```sh
> gcloud iam service-accounts create trace-crawl \
>   --display-name="TRACE Crawl Job" \
>   --project=${GCP_PROJECT_ID}
>
> for ROLE in roles/aiplatform.user roles/storage.objectAdmin roles/run.invoker; do
>   gcloud projects add-iam-policy-binding ${GCP_PROJECT_ID} \
>     --member="serviceAccount:trace-crawl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
>     --role="${ROLE}"
> done
>
> gcloud run jobs update trace-crawl \
>   --service-account="trace-crawl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
>   --region=${VERTEX_LOCATION:-us-central1} \
>   --project=${GCP_PROJECT_ID}
> ```

> **Overriding the subcommand:** The default `CMD ["crawl-batch"]` runs batch
> crawl. Pass `--args` to override, e.g.
> `gcloud run jobs update trace-crawl --args="validate-all,--assets,gs://..."`.

> **`sources.yaml`:** The container image does not include `input/sources.yaml`
> (it is gitignored and contains deployment-specific URLs). Mount it at runtime
> via GCS or a Secret Manager volume:
> ```sh
> gcloud run jobs update trace-crawl \
>   --add-volume=name=sources,type=cloud-storage,bucket=${TRACE_GCS_BUCKET} \
>   --add-volume-mount=volume=sources,mount-path=/app/input \
>   --region=${VERTEX_LOCATION:-us-central1} \
>   --project=${GCP_PROJECT_ID}
> ```

---

## Step 7 — Set up Cloud Scheduler (periodic crawl)

Trigger the TRACE crawl job automatically on a schedule.

```sh
gcloud services enable cloudscheduler.googleapis.com --project=${GCP_PROJECT_ID}

# Every 6 hours
gcloud scheduler jobs create http trace-periodic-crawl \
  --location=${VERTEX_LOCATION:-us-central1} \
  --schedule="0 */6 * * *" \
  --uri="https://${VERTEX_LOCATION:-us-central1}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${GCP_PROJECT_ID}/jobs/trace-crawl:run" \
  --message-body="{}" \
  --oauth-service-account-email="trace-crawl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --time-zone="UTC" \
  --project=${GCP_PROJECT_ID}
```

> **Manual trigger:** `gcloud run jobs execute trace-crawl --region=${VERTEX_LOCATION:-us-central1} --project=${GCP_PROJECT_ID}`

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
