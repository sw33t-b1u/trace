# TRACE — Cloud Run Deployment

Japanese translation: [`docs/deploy.ja.md`](deploy.ja.md)

Before deploying, complete [docs/setup.md](setup.md). Ensure `make check` passes before deploying.

---

## Day-0 Prerequisites

### Enable APIs

```sh
source .env
export REGION=${VERTEX_LOCATION:-us-central1}

gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  cloudscheduler.googleapis.com \
  aiplatform.googleapis.com \
  --project=${GCP_PROJECT_ID}
```

### Create Artifact Registry repository

```sh
gcloud artifacts repositories create cloud-run \
  --repository-format=docker \
  --location=${REGION} \
  --project=${GCP_PROJECT_ID}
```

### Create service account and grant IAM roles

Create the `trace-crawl` service account and bind the required roles before running any deploy commands that reference it.

```sh
gcloud iam service-accounts create trace-crawl \
  --display-name="TRACE Crawl Job" \
  --project=${GCP_PROJECT_ID}

for ROLE in roles/aiplatform.user roles/storage.objectAdmin roles/run.invoker; do
  gcloud projects add-iam-policy-binding ${GCP_PROJECT_ID} \
    --member="serviceAccount:trace-crawl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
    --role="${ROLE}"
done
```

> **Least-privilege alternative:** Grant `roles/storage.objectAdmin` at bucket level instead of project level:
> ```sh
> gcloud storage buckets add-iam-policy-binding gs://${TRACE_STORAGE_BUCKET} \
>   --member="serviceAccount:trace-crawl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
>   --role="roles/storage.objectAdmin"
> ```

### Create GCS bucket (if not already existing)

```sh
# TRACE writes STIX bundles here; SAGE reads from it (via SAGE_ETL_INPUT_BUCKET)
gcloud storage buckets create gs://${TRACE_STORAGE_BUCKET} \
  --location=${REGION} \
  --project=${GCP_PROJECT_ID}

# Upload sources.yaml under the input/ prefix (see Day-1 for volume mount)
gcloud storage cp sources.yaml gs://${TRACE_STORAGE_BUCKET}/input/sources.yaml
```

---

## Day-1 Initial Deploy

### trace-crawl (Cloud Run Job)

```sh
export IMAGE=${REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/cloud-run/trace-crawl

# Build and push container image via Cloud Build
gcloud builds submit --tag ${IMAGE} --project=${GCP_PROJECT_ID}

# Create the Cloud Run Job
gcloud run jobs create trace-crawl \
  --image=${IMAGE} \
  --region=${REGION} \
  --service-account="trace-crawl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --set-env-vars="GCP_PROJECT_ID=${GCP_PROJECT_ID},VERTEX_LOCATION=${VERTEX_LOCATION:-us-central1},TRACE_STORAGE=gcs,TRACE_STORAGE_BUCKET=${TRACE_STORAGE_BUCKET},TRACE_STORAGE_PREFIX=${TRACE_STORAGE_PREFIX:-trace/}" \
  --add-volume=name=sources,type=cloud-storage,bucket=${TRACE_STORAGE_BUCKET},mount-options="only-dir=input" \
  --add-volume-mount=volume=sources,mount-path=/app/input \
  --project=${GCP_PROJECT_ID}
```

> **`TRACE_STORAGE=gcs` + `TRACE_STORAGE_BUCKET` + `TRACE_STORAGE_PREFIX`:** required so
> `crawl-batch` writes STIX bundles to GCS for SAGE to consume. Set `TRACE_STORAGE_BUCKET`
> to the bucket created in Day-0. SAGE's `SAGE_ETL_INPUT_BUCKET` must point to the same
> bucket. `TRACE_STORAGE_PREFIX` controls the GCS prefix under which STIX bundles are
> written (default: `trace/`).

> **`sources.yaml` volume mount:** The container image does not include `input/sources.yaml`
> (it is gitignored and contains deployment-specific URLs). The `--add-volume` /
> `--add-volume-mount` flags above mount the `input/` subdir of the bucket at
> `/app/input`, so the file resolves to `/app/input/sources.yaml`. Upload the file
> to `gs://${TRACE_STORAGE_BUCKET}/input/sources.yaml` as shown in Day-0. Omit
> `mount-options="only-dir=input"` if you upload `sources.yaml` to the bucket root.

> **Overriding the subcommand:** The default `CMD ["crawl-batch"]` runs batch crawl.
> Pass `--args` to override:
> ```sh
> gcloud run jobs update trace-crawl \
>   --args="validate-all,--assets,gs://..." \
>   --region=${REGION} \
>   --project=${GCP_PROJECT_ID}
> ```

### (Optional) Cloud Scheduler for periodic crawl

```sh
gcloud services enable cloudscheduler.googleapis.com --project=${GCP_PROJECT_ID}

# Every 6 hours
gcloud scheduler jobs create http trace-periodic-crawl \
  --location=${REGION} \
  --schedule="0 */6 * * *" \
  --uri="https://${REGION}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${GCP_PROJECT_ID}/jobs/trace-crawl:run" \
  --message-body="{}" \
  --oauth-service-account-email="trace-crawl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --time-zone="UTC" \
  --project=${GCP_PROJECT_ID}
```

> **Manual trigger:** `gcloud run jobs execute trace-crawl --region=${REGION} --project=${GCP_PROJECT_ID}`

---

## Day-N Redeploy

### Code-only changes

Use this flow when only the container image changes (no env-var additions or removals).

```sh
export IMAGE=${REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/cloud-run/trace-crawl

# Rebuild and push the new image
gcloud builds submit --tag ${IMAGE} --project=${GCP_PROJECT_ID}

# Update the Cloud Run Job
gcloud run jobs update trace-crawl \
  --image=${IMAGE} \
  --region=${REGION} \
  --project=${GCP_PROJECT_ID}
```

### Env-var changes on an existing revision

Use `--update-env-vars` and `--remove-env-vars` — **not** `--set-env-vars`, which replaces the entire env-var set and silently drops any key not re-listed.

```sh
# Add or update a single variable without touching others
gcloud run jobs update trace-crawl \
  --update-env-vars=NEW_VAR=value \
  --region=${REGION} \
  --project=${GCP_PROJECT_ID}

# Remove an old variable at the same time
gcloud run jobs update trace-crawl \
  --update-env-vars=NEW_VAR=value \
  --remove-env-vars=OLD_VAR \
  --region=${REGION} \
  --project=${GCP_PROJECT_ID}
```

> **Verify:** `gcloud run jobs describe trace-crawl --region=${REGION} --format="value(spec.template.spec.containers[0].env[].name)" --project=${GCP_PROJECT_ID}`

---

## Access (Production = L2)

TRACE runs as a Cloud Run Job (batch, not a continuously exposed HTTP service). Access control applies to who can trigger the job and to the GCS bucket it writes.

### Grant job-execute permission

```sh
# Single user
gcloud run jobs add-iam-policy-binding trace-crawl \
  --region=${REGION} \
  --member="user:alice@example.com" \
  --role=roles/run.invoker \
  --project=${GCP_PROJECT_ID}

# Google Group (recommended for teams)
gcloud run jobs add-iam-policy-binding trace-crawl \
  --region=${REGION} \
  --member="group:trace-operators@example.com" \
  --role=roles/run.invoker \
  --project=${GCP_PROJECT_ID}
```

### Grant SAGE read access to the output bucket

SAGE's `sage-etl` service account needs read access to the TRACE output bucket.

```sh
gcloud storage buckets add-iam-policy-binding gs://${TRACE_STORAGE_BUCKET} \
  --member="serviceAccount:sage-etl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/storage.objectViewer"
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Container fails to start | Missing env vars | Verify `GCP_PROJECT_ID`, `TRACE_STORAGE_BUCKET`, and `VERTEX_LOCATION` are set in Cloud Run Job configuration |
| `Permission denied` on GCS writes | IAM not configured | Grant `roles/storage.objectAdmin` to the service account on the bucket |
| Vertex AI `PERMISSION_DENIED` | Missing AI Platform role | Grant `roles/aiplatform.user` to the service account |
| `sources.yaml` not found | File not mounted or upload missing | Upload `sources.yaml` to `gs://${TRACE_STORAGE_BUCKET}/input/sources.yaml` and confirm the volume mount is attached |
| Cloud Scheduler job not triggering | Scheduler not enabled or wrong region | Run `gcloud services enable cloudscheduler.googleapis.com` and confirm `--location` matches the job region |

---

## Out of scope

IAP / Internal Load Balancer / VPC Service Controls are not configured by this guide. For small Google Workspace user counts (a few users), the L2 IAM binding above is sufficient. If you need context-aware access or custom network topology, see https://cloud.google.com/iap/docs.

---

## CTI Platform console integration

TRACE can run as a standalone `trace-crawl` Cloud Run Job for scheduled batch
collection, or be bundled into the CTI Platform console image
(`beacon/Dockerfile.cti-console`) so the browser Collection tab can execute
`trace discover-pir` and `trace crawl-batch` as local subprocesses. The bundled
console uses `TRACE_ROOT_PATH=/app/trace`.
