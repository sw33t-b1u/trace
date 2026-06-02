# TRACE — Deployment Guide

Japanese translation: [`docs/deploy.ja.md`](deploy.ja.md)

This guide covers deploying TRACE to Google Cloud Run as a scheduled batch
job. Complete the local setup first — see [`docs/setup.md`](setup.md).

---

## Step 6 — Deploy TRACE to Cloud Run (Job)

Build the container image and deploy TRACE as a Cloud Run Job for batch execution.

```sh
# Load .env if not already sourced
source .env
export REGION=${VERTEX_LOCATION:-us-central1}

# Create Artifact Registry repository (first time only)
gcloud artifacts repositories create cloud-run \
  --repository-format=docker \
  --location=${REGION} \
  --project=${GCP_PROJECT_ID}

export IMAGE=${REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/cloud-run/trace-crawl

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
> via GCS or a Secret Manager volume. The default expects the file at
> `/app/input/sources.yaml`, so use `mount-options="only-dir=input"` if the
> file lives under an `input/` subdir of the bucket (recommended — keeps the
> bucket root free for crawl outputs):
> ```sh
> # Upload sources.yaml under the input/ prefix
> gcloud storage cp sources.yaml gs://${TRACE_GCS_BUCKET}/input/sources.yaml
>
> gcloud run jobs update trace-crawl \
>   --add-volume=name=sources,type=cloud-storage,bucket=${TRACE_GCS_BUCKET},mount-options="only-dir=input" \
>   --add-volume-mount=volume=sources,mount-path=/app/input \
>   --region=${VERTEX_LOCATION:-us-central1} \
>   --project=${GCP_PROJECT_ID}
> ```
> Omit `mount-options` if you upload `sources.yaml` to the bucket root.

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

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Container fails to start | Missing env vars | Verify `GCP_PROJECT_ID`, `TRACE_GCS_BUCKET`, and Vertex AI region are set in Cloud Run Job configuration |
| `Permission denied` on GCS writes | IAM not configured | Grant `roles/storage.objectAdmin` to the service account |
| Vertex AI `PERMISSION_DENIED` | Missing AI Platform role | Grant `roles/aiplatform.user` to the service account |
| `sources.yaml` not found | File not mounted | Mount the file via GCS volume or bake it into a custom image layer |
| Cloud Scheduler job not triggering | Scheduler not enabled or wrong region | Run `gcloud services enable cloudscheduler.googleapis.com` and confirm `--location` matches the job region |
