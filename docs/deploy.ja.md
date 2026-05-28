# TRACE — デプロイガイド

英語版（正本）: [`docs/deploy.md`](deploy.md)

本ガイドでは TRACE を Google Cloud Run のスケジュール済みバッチジョブとして
デプロイする手順を説明する。事前にローカルセットアップを完了すること —
[`docs/setup.ja.md`](setup.ja.md) 参照。

---

## Step 6 — TRACE を Cloud Run（Job）にデプロイ

コンテナイメージをビルドし、TRACE をバッチ実行用 Cloud Run Job としてデプロイする。

```sh
# .env がまだ読み込まれていない場合はロード
source .env
export REGION=${VERTEX_LOCATION:-us-central1}

# Artifact Registry リポジトリを作成（初回のみ）
gcloud artifacts repositories create cloud-run \
  --repository-format=docker \
  --location=${REGION} \
  --project=${GCP_PROJECT_ID}

export IMAGE=${REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/cloud-run/trace-crawl

# Cloud Build でコンテナイメージをビルド・プッシュ
gcloud builds submit --tag ${IMAGE} --project=${GCP_PROJECT_ID}

# Cloud Run Job を作成
gcloud run jobs create trace-crawl \
  --image=${IMAGE} \
  --region=${VERTEX_LOCATION:-us-central1} \
  --set-env-vars="GCP_PROJECT_ID=${GCP_PROJECT_ID},VERTEX_LOCATION=${VERTEX_LOCATION:-us-central1},TRACE_STORAGE=${TRACE_STORAGE:-gcs},TRACE_GCS_BUCKET=${TRACE_GCS_BUCKET}" \
  --set-secrets="TRACE_GCS_PREFIX=trace-gcs-prefix:latest" \
  --project=${GCP_PROJECT_ID}
```

> **Secret Manager:** 機密値は
> `gcloud secrets create trace-gcs-prefix --data-file=- <<< "trace/"` で保管し、
> `--set-env-vars` ではなく `--set-secrets` で参照すること。

> **サービスアカウント:** デプロイ前に専用のサービスアカウントを作成し、
> `roles/aiplatform.user`（Vertex AI Gemini）、`roles/storage.objectAdmin`
>（GCS 出力）、`roles/run.invoker` を付与すること。
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

> **サブコマンドの上書き:** デフォルトの `CMD ["crawl-batch"]` はバッチクロールを実行する。
> `--args` で上書き可能。例:
> `gcloud run jobs update trace-crawl --args="validate-all,--assets,gs://..."`。

> **`sources.yaml`:** コンテナイメージには `input/sources.yaml` が含まれない
>（gitignored であり、デプロイ固有の URL を含む）。実行時に GCS または
> Secret Manager ボリュームとしてマウントすること:
> ```sh
> gcloud run jobs update trace-crawl \
>   --add-volume=name=sources,type=cloud-storage,bucket=${TRACE_GCS_BUCKET} \
>   --add-volume-mount=volume=sources,mount-path=/app/input \
>   --region=${VERTEX_LOCATION:-us-central1} \
>   --project=${GCP_PROJECT_ID}
> ```

---

## Step 7 — Cloud Scheduler のセットアップ（定期クロール）

TRACE クロールジョブをスケジュールに従って自動実行する。

```sh
gcloud services enable cloudscheduler.googleapis.com --project=${GCP_PROJECT_ID}

# 6 時間ごと
gcloud scheduler jobs create http trace-periodic-crawl \
  --location=${VERTEX_LOCATION:-us-central1} \
  --schedule="0 */6 * * *" \
  --uri="https://${VERTEX_LOCATION:-us-central1}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${GCP_PROJECT_ID}/jobs/trace-crawl:run" \
  --message-body="{}" \
  --oauth-service-account-email="trace-crawl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --time-zone="UTC" \
  --project=${GCP_PROJECT_ID}
```

> **手動トリガー:** `gcloud run jobs execute trace-crawl --region=${VERTEX_LOCATION:-us-central1} --project=${GCP_PROJECT_ID}`

---

## トラブルシューティング

| 症状 | 原因 | 対処 |
|------|------|------|
| コンテナが起動しない | 環境変数が不足 | Cloud Run Job の設定で `GCP_PROJECT_ID`、`TRACE_GCS_BUCKET`、Vertex AI リージョンが設定されているか確認する |
| GCS 書き込み時に `Permission denied` | IAM 未設定 | サービスアカウントに `roles/storage.objectAdmin` を付与する |
| Vertex AI で `PERMISSION_DENIED` | AI Platform ロールが不足 | サービスアカウントに `roles/aiplatform.user` を付与する |
| `sources.yaml` が見つからない | ファイルがマウントされていない | GCS ボリューム経由でマウントするか、カスタムイメージレイヤーに含める |
| Cloud Scheduler ジョブが実行されない | Scheduler 未有効化またはリージョン不一致 | `gcloud services enable cloudscheduler.googleapis.com` を実行し、`--location` がジョブのリージョンと一致するか確認する |
