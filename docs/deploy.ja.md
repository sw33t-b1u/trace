# TRACE — Cloud Run デプロイガイド

英語版（正本）: [`docs/deploy.md`](deploy.md)

デプロイ前に [docs/setup.ja.md](setup.ja.md) の手順を完了すること。デプロイ前に `make check` がパスすることを確認すること。

---

## Day-0 前提条件

### API の有効化

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

### Artifact Registry リポジトリの作成

```sh
gcloud artifacts repositories create cloud-run \
  --repository-format=docker \
  --location=${REGION} \
  --project=${GCP_PROJECT_ID}
```

### サービスアカウントの作成と IAM ロールの付与

デプロイコマンドでサービスアカウントを参照する前に、`trace-crawl` サービスアカウントを作成して必要なロールを付与しておく。

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

> **最小権限の代替:** プロジェクトレベルではなくバケットレベルで `roles/storage.objectAdmin` を付与する:
> ```sh
> gcloud storage buckets add-iam-policy-binding gs://${TRACE_STORAGE_BUCKET} \
>   --member="serviceAccount:trace-crawl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
>   --role="roles/storage.objectAdmin"
> ```

### GCS バケットの作成（未作成の場合）

```sh
# TRACE が STIX バンドルを書き込み、SAGE がここから読み込む（SAGE_ETL_INPUT_BUCKET 経由）
gcloud storage buckets create gs://${TRACE_STORAGE_BUCKET} \
  --location=${REGION} \
  --project=${GCP_PROJECT_ID}

# sources.yaml を input/ プレフィックス配下にアップロード（Day-1 のボリュームマウント参照）
gcloud storage cp sources.yaml gs://${TRACE_STORAGE_BUCKET}/input/sources.yaml
```

---

## Day-1 初回デプロイ

### trace-crawl（Cloud Run Job）

```sh
export IMAGE=${REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/cloud-run/trace-crawl

# Cloud Build でコンテナイメージをビルドしてプッシュ
gcloud builds submit --tag ${IMAGE} --project=${GCP_PROJECT_ID}

# Cloud Run Job を作成
gcloud run jobs create trace-crawl \
  --image=${IMAGE} \
  --region=${REGION} \
  --service-account="trace-crawl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --set-env-vars="GCP_PROJECT_ID=${GCP_PROJECT_ID},VERTEX_LOCATION=${VERTEX_LOCATION:-us-central1},TRACE_STORAGE=gcs,TRACE_STORAGE_BUCKET=${TRACE_STORAGE_BUCKET},TRACE_STORAGE_PREFIX=${TRACE_STORAGE_PREFIX:-trace/}" \
  --add-volume=name=sources,type=cloud-storage,bucket=${TRACE_STORAGE_BUCKET},mount-options="only-dir=input" \
  --add-volume-mount=volume=sources,mount-path=/app/input \
  --project=${GCP_PROJECT_ID}
```

> **`TRACE_STORAGE=gcs` + `TRACE_STORAGE_BUCKET` + `TRACE_STORAGE_PREFIX`:** STIX バンドルを
> GCS に書き込んで SAGE に渡すために必須。`TRACE_STORAGE_BUCKET` は Day-0 で作成した
> バケットを指定する。SAGE の `SAGE_ETL_INPUT_BUCKET` は同じバケットを指す必要がある。
> `TRACE_STORAGE_PREFIX` は STIX バンドルを書き込む GCS プレフィックスを制御する（デフォルト: `trace/`）。

> **`sources.yaml` ボリュームマウント:** コンテナイメージには `input/sources.yaml` が含まれない
>（gitignored であり、デプロイ固有の URL を含む）。`--add-volume` / `--add-volume-mount` で
> バケットの `input/` サブディレクトリを `/app/input` にマウントし、
> `/app/input/sources.yaml` として解決する。Day-0 で示した通り
> `gs://${TRACE_STORAGE_BUCKET}/input/sources.yaml` にアップロードしておくこと。
> `sources.yaml` をバケットルートに置く場合は `mount-options="only-dir=input"` を省略する。

> **サブコマンドの上書き:** デフォルトの `CMD ["crawl-batch"]` はバッチクロールを実行する。
> `--args` で上書き可能:
> ```sh
> gcloud run jobs update trace-crawl \
>   --args="validate-all,--assets,gs://..." \
>   --region=${REGION} \
>   --project=${GCP_PROJECT_ID}
> ```

### （オプション）定期クロール用 Cloud Scheduler

```sh
gcloud services enable cloudscheduler.googleapis.com --project=${GCP_PROJECT_ID}

# 6 時間ごと
gcloud scheduler jobs create http trace-periodic-crawl \
  --location=${REGION} \
  --schedule="0 */6 * * *" \
  --uri="https://${REGION}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${GCP_PROJECT_ID}/jobs/trace-crawl:run" \
  --message-body="{}" \
  --oauth-service-account-email="trace-crawl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --time-zone="UTC" \
  --project=${GCP_PROJECT_ID}
```

> **手動トリガー:** `gcloud run jobs execute trace-crawl --region=${REGION} --project=${GCP_PROJECT_ID}`

---

## Day-N 再デプロイ

### コード変更のみの場合

env-var の追加・削除がなく、コンテナイメージのみ変更する場合はこのフローを使う。

```sh
export IMAGE=${REGION}-docker.pkg.dev/${GCP_PROJECT_ID}/cloud-run/trace-crawl

# 新しいイメージをビルドしてプッシュ
gcloud builds submit --tag ${IMAGE} --project=${GCP_PROJECT_ID}

# Cloud Run Job を更新
gcloud run jobs update trace-crawl \
  --image=${IMAGE} \
  --region=${REGION} \
  --project=${GCP_PROJECT_ID}
```

### 既存リビジョンの env-var 変更

`--update-env-vars` と `--remove-env-vars` を使うこと — **`--set-env-vars` は使わない**。`--set-env-vars` は env-var セット全体を置き換えるため、再指定しなかったキーが無音で削除される。

```sh
# 他の変数に影響せず 1 つの変数を追加・更新する
gcloud run jobs update trace-crawl \
  --update-env-vars=NEW_VAR=value \
  --region=${REGION} \
  --project=${GCP_PROJECT_ID}

# 古い変数を削除しながら新しい変数を追加する
gcloud run jobs update trace-crawl \
  --update-env-vars=NEW_VAR=value \
  --remove-env-vars=OLD_VAR \
  --region=${REGION} \
  --project=${GCP_PROJECT_ID}
```

> **確認:** `gcloud run jobs describe trace-crawl --region=${REGION} --format="value(spec.template.spec.containers[0].env[].name)" --project=${GCP_PROJECT_ID}`

---

## アクセス（本番推奨 = L2）

TRACE は Cloud Run Job（バッチ）として動作し、常駐の HTTP サービスとしては公開されない。アクセス制御はジョブのトリガー権限と、書き込み先の GCS バケットのアクセス制御に対して適用する。

### ジョブ実行権限の付与

```sh
# 個人ユーザー
gcloud run jobs add-iam-policy-binding trace-crawl \
  --region=${REGION} \
  --member="user:alice@example.com" \
  --role=roles/run.invoker \
  --project=${GCP_PROJECT_ID}

# Google グループ（チーム利用に推奨）
gcloud run jobs add-iam-policy-binding trace-crawl \
  --region=${REGION} \
  --member="group:trace-operators@example.com" \
  --role=roles/run.invoker \
  --project=${GCP_PROJECT_ID}
```

### SAGE への出力バケット読み取り権限の付与

SAGE の `sage-etl` サービスアカウントに TRACE 出力バケットの読み取り権限を付与する。

```sh
gcloud storage buckets add-iam-policy-binding gs://${TRACE_STORAGE_BUCKET} \
  --member="serviceAccount:sage-etl@${GCP_PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/storage.objectViewer"
```

---

## トラブルシューティング

| 症状 | 原因 | 対処 |
|------|------|------|
| コンテナが起動しない | 環境変数が不足 | Cloud Run Job の設定で `GCP_PROJECT_ID`、`TRACE_STORAGE_BUCKET`、`VERTEX_LOCATION` が設定されているか確認する |
| GCS 書き込み時に `Permission denied` | IAM 未設定 | バケットに対してサービスアカウントへ `roles/storage.objectAdmin` を付与する |
| Vertex AI で `PERMISSION_DENIED` | AI Platform ロールが不足 | サービスアカウントに `roles/aiplatform.user` を付与する |
| `sources.yaml` が見つからない | ファイルがアップロード未済またはマウント未設定 | `gs://${TRACE_STORAGE_BUCKET}/input/sources.yaml` にアップロードし、ボリュームマウントが設定されているか確認する |
| Cloud Scheduler ジョブが実行されない | Scheduler 未有効化またはリージョン不一致 | `gcloud services enable cloudscheduler.googleapis.com` を実行し、`--location` がジョブのリージョンと一致するか確認する |

---

## 対象外

IAP / 内部ロードバランサ / VPC Service Controls はこのガイドでは設定しない。少数の Google Workspace ユーザー運用（数名程度）では、上記の L2 IAM バインディングで十分である。コンテキストアウェアアクセスやカスタムネットワーク構成が必要な場合は https://cloud.google.com/iap/docs を参照すること。

---

## CTI Platform 統合デプロイ

ブラウザ完結運用では、BEACON repository の統合 CTI Platform runbook
`beacon/docs/deploy-cti-platform.ja.md` を使う。`cti-console` image は TRACE を
`/app/trace` に同梱し、`TRACE_ROOT_PATH=/app/trace` を設定するため、Collection タブは
TRACE をローカル実行できる。

ブラウザ console 外で schedule/background collection が必要な場合のみ、この standalone
TRACE deploy guide に従って任意の `trace-crawl` Cloud Run Job を運用する。
