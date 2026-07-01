# TRACE — セットアップガイド

英語版（正本）: [`docs/setup.md`](setup.md)

データフローと BEACON / SAGE との責務分担は `high-level-design.md` を参照。
依存関係の根拠は [`docs/dependencies.ja.md`](dependencies.ja.md) を参照。
GCP デプロイについては [`docs/deploy.ja.md`](deploy.ja.md) を参照。

## 前提条件

| 要件 | バージョン | 備考 |
|------|-----------|------|
| Python | 3.12+ | `pyproject.toml` で指定 |
| [uv](https://docs.astral.sh/uv/) | 最新版 | 仮想環境・パッケージ管理 |
| GCP プロジェクト | — | L2 リレバンスゲート / L3 STIX 抽出（Vertex AI）に必要 |
| Git | 2.x+ | フックインストール用 |

---

## Step 1 — クローンと依存インストール

```bash
cd TRACE/
uv sync --extra dev
```

`make check` で `92+ passed` / ruff クリーン / `pip-audit` クリーンを確認。

---

## Step 2 — Git フックをインストール

```bash
make setup
```

`git config core.hooksPath .githooks` を実行し、以下を有効化:

- **pre-commit** — `make vet lint`
- **pre-push** — `make check`（フル品質ゲート）

---

## Step 3 — 環境変数を設定

```bash
cp .env.example .env   # 存在する場合
```

以下を埋める:

| 変数名 | 必須 | デフォルト | 説明 |
|--------|------|-----------|------|
| `GCP_PROJECT_ID` | はい | — | Vertex AI Gemini で使う GCP プロジェクト ID |
| `VERTEX_LOCATION` | いいえ | `us-central1` | Vertex AI リージョン |
| `TRACE_LLM_SIMPLE` | いいえ | `gemini-3.1-flash-lite` | L2 リレバンスゲートのモデル |
| `TRACE_LLM_MEDIUM` | いいえ | `gemini-3.5-flash` | L3 STIX 抽出（既定） |
| `TRACE_LLM_COMPLEX` | いいえ | `gemini-2.5-pro` | L3 STIX 抽出（`--task complex` 指定時） |
| `TRACE_RELEVANCE_MODEL_TIER` | いいえ | `simple` | `simple` / `medium` / `complex` |
| `TRACE_RELEVANCE_THRESHOLD` | いいえ | `0.5` | L2 score `>=` 閾値で記事を残す |
| `TRACE_EXTRACTION_CHUNK_CHARS` | いいえ | `12000` | L3 抽出時の LLM チャンク最大文字数 |
| `TRACE_EXTERNAL_REF_HASH_ENABLED` | いいえ | `true` | 外部参照の SHA-256 ハッシュ付与 |
| `TRACE_EXTERNAL_REF_HASH_CACHE` | いいえ | `output/external_ref_hash_cache.json` | 外部参照ハッシュのキャッシュファイル |
| `TRACE_EXTERNAL_REF_HASH_TTL_DAYS` | いいえ | `30` | キャッシュの有効期限（日数） |
| `TRACE_CRAWL_USER_AGENT` | いいえ | Firefox UA 文字列 | `crawler/fetcher.py` が使う UA（下記注参照） |
| `TRACE_CRAWL_CONCURRENCY` | いいえ | `4` | `crawl-batch` のスレッドプールサイズ（1 = 逐次） |
| `TRACE_STATE_PATH` | いいえ | `output/crawl_state.json` | バッチ dedupe 状態ファイル |
| `TRACE_FEED_MAX_ENTRIES` | いいえ | `50` | RSS/Atom フィード展開時の最大エントリ数 |
| `TRACE_FEED_SINCE_DAYS` | いいえ | `90` | N 日より古いフィードエントリを破棄（`ACTIVITY_WINDOW_DAYS` にフォールバック） |
| `GHE_TOKEN` | GHE 利用時のみ | — | `submit_review.py --open-issue` 用 PAT |
| `GHE_REPO` | GHE 利用時のみ | — | `owner/repo` |
| `GHE_API_BASE` | いいえ | `https://api.github.com` | セルフホスト GHE 用に上書き |
| `TRACE_STORAGE` | いいえ | `local` | ストレージバックエンド: `local` または `gcs` |
| `TRACE_STORAGE_BASE_DIR` | いいえ | `output/` | `LocalStorage` のルートディレクトリ |
| `TRACE_STORAGE_BUCKET` | GCS 利用時のみ | — | GCS バケット名（`TRACE_STORAGE=gcs` 時に必須） |
| `TRACE_STORAGE_PREFIX` | いいえ | (空文字) | GCS バケット内のキープレフィックス |

**`--no-llm` モードは存在しません**。L2 ゲート・L3 抽出ともに LLM 必須。

#### GCS ストレージ（任意）

クロール出力をローカルファイルシステムではなく Google Cloud Storage に書き込む場合:

```bash
# GCS extra をインストール
uv sync --extra gcs

export TRACE_STORAGE=gcs
export TRACE_STORAGE_BUCKET=my-cti-artifacts
export TRACE_STORAGE_PREFIX=trace/   # 任意; デフォルトは空文字
```

`google-cloud-storage` パッケージは `TRACE_STORAGE=gcs` の場合のみ必要。
認証は Vertex AI と同様に Application Default Credentials を使用する。

---

## Step 4 — GCP 認証

```bash
gcloud auth application-default login
```

Vertex AI が使用する Application Default Credentials を設定。API キー管理は不要。

---

## Step 5 — 確認

```bash
make test       # ユニットテスト（GCP 不要）
make check      # フル品質ゲート: vet → lint → test → audit
```

---

## テスト

### テストの実行

```bash
# フル品質ゲート (lint + test + audit)
make check

# テストのみ
make test

# uv 経由でテストのみ実行
uv run pytest

# 特定のテストファイルを実行
uv run pytest tests/test_stix_extractor.py -v

# 名前パターンでテストを絞り込む
uv run pytest -k "test_relevance" -v
```

外部サービスは不要 — テストスイート内のすべての LLM 呼び出しはモックされている。

### テストフィクスチャ

フィクスチャは `tests/fixtures/` に置かれ、テスト入力または期待出力として使用される:

| フィクスチャの種類 | 説明 |
|-----------------|------|
| STIX バンドル JSON | 抽出器・バリデータテスト用のサンプルバンドル |
| PIR JSON | バリデータテスト用のサンプル `pir_output.json` |
| Assets JSON | アセットバリデータテスト用のサンプル `assets.json` |
| タクソノミ JSON | キャッシュ済みタクソノミスナップショット。BEACON ライブデータの代替 |

タクソノミフィクスチャ（`schema/threat_taxonomy.cached.json` またはその
`tests/fixtures/` へのコピー）により、テストは BEACON の存在や疎通を必要としない。

### 外部サービス不要

- **LLM 呼び出し**: Vertex AI / Gemini の呼び出しはすべて `unittest.mock` または
  `pytest-mock` でパッチされている。テストに GCP プロジェクト、
  `GOOGLE_APPLICATION_CREDENTIALS`、またはネットワークアクセスは不要。
- **BEACON**: タクソノミ自動同期はテストでバイパスされる。テストスイートは
  コミット済みタクソノミスナップショットを使用する。
- **GCS**: `GCSStorage` はユニットテストでは使用されない。一時ディレクトリを
  使った `LocalStorage` が代わりに使われる。

### 主要なテストパターン

#### フィクスチャベースの STIX バンドルテスト

`tests/test_stix_extractor.py` の多くのテストは JSON フィクスチャを読み込み、
抽出器またはバリデータ関数を呼び出して結果の構造をアサートする:

```python
def test_bundle_validates(tmp_path, stix_fixture):
    bundle = json.loads(stix_fixture.read_text())
    result = validate_stix_bundle(bundle)
    assert result.is_valid
```

#### リレバンスゲートテスト

L2 ゲートテストは Vertex AI クライアントをパッチし、閾値未満の記事が
`crawl_state.json` にスキップ済みとして記録されることをアサートする:

```python
def test_low_relevance_skipped(mock_llm, crawl_state):
    mock_llm.return_value = RelevanceResponse(score=0.1)
    ...
    assert crawl_state[url]["skipped"] is True
```

### テストにおけるタクソノミキャッシュ

タクソノミエンリッチメントをテストする際は、コミット済みの
`schema/threat_taxonomy.cached.json` スナップショット（またはフィクスチャのコピー）を使用する。
自動同期パス（`ensure_taxonomy_fresh`）はモックで no-op とし、BEACON 依存をなくしている。

ライブ BEACON からテスト用タクソノミスナップショットを再生成する場合:

```bash
uv run trace taxonomy-refresh
cp schema/threat_taxonomy.cached.json tests/fixtures/threat_taxonomy.json
```

---

## セキュリティスキャン

```bash
make audit
```

`pip-audit` を実行。`make check` に含まれる。

---

## トラブルシューティング

| 症状 | 原因 | 対処 |
|------|------|------|
| `GCP_PROJECT_ID not set` | env 未ロード | `.env` を作成してから再実行 |
| `crawl_batch` が `Input should be a valid dictionary` | `sources.yaml` がフラット URL リスト | `{version, sources: [...]}` で囲む — [`crawl_design.ja.md`](crawl_design.ja.md) 参照 |
| `pip-audit` 検出あり | 脆弱な依存 | `pyproject.toml` でバージョン更新 → `uv lock` → CHANGELOG に記録 |
| L2 ゲートが常に fail-open（`parse_failed` / `call_failed`） | LLM が非 JSON を返す or 呼び出し失敗 | `gcloud auth application-default print-access-token` で認証確認、`TRACE_RELEVANCE_MODEL_TIER` が実在モデル ID か確認 |
| フックが動作しない | `make setup` 未実行 | TRACE/ で `make setup` |
