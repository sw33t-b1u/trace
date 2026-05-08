# TRACE — セットアップガイド

英語版（正本）: [`docs/setup.md`](setup.md)

データフローと BEACON / SAGE との責務分担は `high-level-design.md` を参照。
依存関係の根拠は [`docs/dependencies.ja.md`](dependencies.ja.md) を参照。

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
| `TRACE_LLM_SIMPLE` | いいえ | `gemini-2.5-flash-lite` | L2 リレバンスゲートのモデル |
| `TRACE_LLM_MEDIUM` | いいえ | `gemini-2.5-flash` | L3 STIX 抽出（既定） |
| `TRACE_LLM_COMPLEX` | いいえ | `gemini-2.5-pro` | L3 STIX 抽出（`--task complex` 指定時） |
| `TRACE_RELEVANCE_MODEL_TIER` | いいえ | `simple` | `simple` / `medium` / `complex` |
| `TRACE_RELEVANCE_THRESHOLD` | いいえ | `0.5` | L2 score `>=` 閾値で記事を残す |
| `TRACE_CRAWL_USER_AGENT` | いいえ | `TRACE/0.1 (+...)` | `crawler/fetcher.py` が使う UA |
| `TRACE_STATE_PATH` | いいえ | `output/crawl_state.json` | バッチ dedupe 状態ファイル |
| `TRACE_GHE_TOKEN` | GHE 利用時のみ | — | `submit_review.py --open-issue` 用 PAT |
| `GHE_REPO` | GHE 利用時のみ | — | `owner/repo` |
| `GHE_API_BASE` | いいえ | `https://api.github.com` | セルフホスト GHE 用に上書き |

**`--no-llm` モードは存在しません**。L2 ゲート・L3 抽出ともに LLM 必須。

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

## TRACE の実行

詳細コマンドは [`docs/crawl_design.ja.md`](crawl_design.ja.md)（収集系）と
[`docs/data-model.ja.md`](data-model.ja.md)（検証ゲート）を参照。
クイックリファレンス:

### 単発 URL → STIX バンドル

```bash
# PIR 無し — LLM が見つけたものすべてを抽出。
uv run python cmd/crawl_single.py \
  --input 'https://example.com/cti-blog/post-42' \
  --output output/test_bundle.json

# PIR 有り — リレバンス閾値未満の記事はスキップ。
uv run python cmd/crawl_single.py \
  --input 'https://example.com/cti-blog/post-42' \
  --pir ../BEACON/output/pir_output.json
```

### バッチ収集

```bash
# input/sources.yaml のスキーマは docs/crawl_design.ja.md を参照。
uv run python cmd/crawl_batch.py --pir ../BEACON/output/pir_output.json
uv run python cmd/crawl_batch.py --pir ../BEACON/output/pir_output.json --recheck-on-pir-change
uv run python cmd/crawl_batch.py --dry-run
```

### 検証ゲート

```bash
uv run python cmd/validate_assets.py --input ../BEACON/output/assets.json
uv run python cmd/validate_pir.py    --input ../BEACON/output/pir_output.json \
                                     --assets ../BEACON/output/assets.json
uv run python cmd/validate_stix.py   --bundle output/stix_bundle.json [--strict]

uv run python cmd/validate_all.py \
  --assets ../BEACON/output/assets.json \
  --pir    ../BEACON/output/pir_output.json \
  --bundle output/stix_bundle.json \
  --report output/validation_report.md
```

### レビュー依頼

```bash
# Markdown を標準出力。
uv run python cmd/submit_review.py --report output/validation_report.md

# あるいは GHE Issue として 1 件投稿。
uv run python cmd/submit_review.py \
  --report output/validation_report.md --open-issue \
  --title "TRACE validation 2026-05-08"
```

終了コード規約: `0` 成功 / `1` 検証エラーあり / `2` 入力エラー or 認証設定エラー。

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
