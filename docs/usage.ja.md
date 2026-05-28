# TRACE — 使用ガイド

英語版（正本）: [`docs/usage.md`](usage.md)

本ガイドでは CLI コマンド、主要なワークフロー、主要フラグ、日常運用、および
トラブルシューティングを説明する。クローラーアーキテクチャと L2–L4 パイプライン
内部については [`docs/crawl_design.md`](crawl_design.md) を参照。

---

## CLI コマンド（`trace` エントリポイント）

TRACE は統合 `trace` コンソールスクリプトで 13 個のサブコマンドを提供する:

| サブコマンド | 説明 |
|------------|------|
| `trace crawl-single` | 単一 URL または PDF をクロールし STIX 2.1 バンドルを出力する |
| `trace crawl-batch` | `input/sources.yaml` からコンテンツハッシュ重複排除つきでバッチクロールする |
| `trace validate-all` | すべてのバリデータを実行し集約 Markdown レポートを生成する |
| `trace validate-stix` | STIX 2.1 バンドルを検証する（スキーマ + ローカル参照チェック）|
| `trace validate-pir` | `pir_output.json` を検証する（Pydantic + タクソノミ + asset タグ照合）|
| `trace validate-assets` | `assets.json` を検証する（Pydantic + セマンティック参照チェック）|
| `trace validate-identity` | `identity_assets.json` を検証する（`assets.json` とクロス参照）|
| `trace validate-accounts` | `user_accounts.json` を検証する（`assets.json` とクロス参照）|
| `trace enrich-bundle` | 既存の STIX バンドルに脅威アクタータクソノミタグを付与する |
| `trace search-iocs` | `crawl_state.json` に保存された IoC インデックスを検索する |
| `trace submit-review` | 検証レポートを GitHub に投稿する（任意で `--open-issue`）|
| `trace taxonomy-refresh` | BEACON ソースからローカルタクソノミキャッシュを同期する |
| `trace schema-regenerate` | Pydantic 契約モデルから `schema/*.schema.json` を再生成する |

> **2.1.0 で削除:** `python -m cmd.<name>` および `python cmd/<name>.py` は
> サポートされなくなった。代わりに `uv run trace <subcommand>` を使用すること。

---

## 主要フラグ

| フラグ | 対象コマンド | 説明 |
|-------|------------|------|
| `--pir <path>` | `crawl-single`, `crawl-batch` | `pir_output.json` のパス。L2 ゲート・L3 条件付け・L4 メタデータを有効にする |
| `--output <path>` | `crawl-single` | バンドルを明示パスに書き出す（StorageBackend をバイパス）|
| `--output-dir <path>` | `crawl-batch` | バンドルを明示ディレクトリに書き出す（StorageBackend をバイパス）|
| `--no-sync-taxonomy` | `crawl-single`, `crawl-batch` | 起動時のタクソノミ自動同期をスキップする（CI / エアギャップ環境向け）|
| `--open-issue` | `submit-review` | 検証レポートを GitHub Issue として投稿する |
| `--json` | `search-iocs` | 結果を人間可読テキストではなく JSON で出力する |

---

## L2 / L3 / L4 パイプライン（概要）

`--pir` を指定すると、各記事は 3 つのステージを経る:

- **L2 — リレバンスゲート**: 軽量な `gemini-2.5-flash-lite` 呼び出しが記事を PIR
  に対してスコアリングする。閾値未満の記事はスキップされ、スキップ決定は
  `crawl_state.json` に記録される。
- **L3 — PIR コンテキスト注入**: STIX 抽出プロンプトに PIR の `threat_actor_tags`・
  `notable_groups`・`collection_focus` が追加され、LLM を関連エンティティへ
  バイアスする。
- **L4 — バンドルメタデータ**: 出力バンドルに `x_trace_matched_pir_ids` および
  `x_trace_relevance_score` 拡張フィールドが付与される。

`--pir` 未指定時はゲートをバイパスし、全記事を STIX 化する（試行・実験用途）。
詳細なアーキテクチャは [`docs/crawl_design.md`](crawl_design.md) を参照。

---

## 主要ワークフロー

### 単発 URL クロール

```bash
# PIR なし（全記事を抽出）
trace crawl-single --input https://example.com/report

# PIR あり（L2 ゲート + L3 条件付け + L4 メタデータ）
trace crawl-single --input https://example.com/report \
  --pir ../BEACON/output/pir_output.json

# 明示出力パス指定（StorageBackend をバイパス）
trace crawl-single --input https://example.com/report \
  --pir ../BEACON/output/pir_output.json \
  --output output/my_bundle.json
```

### sources.yaml を使ったバッチクロール

```bash
# PIR フィルタリングとコンテンツハッシュ重複排除でバッチクロール
trace crawl-batch --pir ../BEACON/output/pir_output.json

# CI 向けにタクソノミ同期をスキップ
trace crawl-batch --pir ../BEACON/output/pir_output.json --no-sync-taxonomy

# 明示出力ディレクトリ（StorageBackend をバイパス）
trace crawl-batch --pir ../BEACON/output/pir_output.json \
  --output-dir output/stix/
```

`input/sources.yaml` スキーマ（`feed_type` やソースごとの設定を含む）については
[`docs/crawl_design.md`](crawl_design.md) を参照。

### SAGE 取り込み前の検証

すべてのバリデータをまとめて実行し、単一の Markdown レポートを生成:

```bash
trace validate-all
```

個別に実行する場合:

```bash
trace validate-stix output/stix/stix_bundle_*.json
trace validate-pir  ../BEACON/output/pir_output.json
trace validate-assets ../BEACON/output/assets.json
trace validate-identity ../BEACON/output/identity_assets.json
trace validate-accounts ../BEACON/output/user_accounts.json
```

生成された `output/validation_report_*.md` を確認し、必要に応じて提出:

```bash
trace submit-review --open-issue
```

SAGE は TRACE が検証通過させた artifact のみを取り込む。

### IoC 検索

```bash
# 値で検索
trace search-iocs --ioc 203.0.113.42

# タイプと TLP レベルでフィルタリング
trace search-iocs --type ipv4 --tlp-max green --json
```

---

## クロール状態管理

TRACE は処理済み URL を `output/crawl_state.json`
（`TRACE_STATE_PATH` で上書き可能）に記録する。

各エントリには以下が含まれる:
- `content_hash` — 取得したページコンテンツの SHA-256
- `bundle_path` — 出力した STIX バンドルの書き出し先
- `pir_hash` — 使用した PIR ドキュメントのハッシュ（PIR 変更時の再評価を可能にする）
- `skipped` — L2 ゲートが記事を棄却した場合 `true`
- `iocs[]` — LLM が抽出した IoC 値（7 種類: IPv4, IPv6, FQDN, SHA256, SHA1, MD5, CVE-ID）

**コンテンツハッシュ重複排除:** `crawl-batch` は前回実行の `content_hash`
と一致する URL をスキップする。PIR 更新後にスキップ済み記事を再評価するには
`--recheck-on-pir-change` を渡す。

**手動リセット:** `crawl_state.json` から該当エントリを削除する（または
ファイル全体を削除する）と、すべてのソースを強制的に再クロールする。

---

## 外部参照ハッシュキャッシュ

TRACE は STIX `external_references` URL の SHA-256 を計算し、実行間の差分を検出する。
キャッシュファイルのパスは以下の環境変数で制御する:

| 変数 | デフォルト | 説明 |
|------|-----------|------|
| `TRACE_EXTERNAL_REF_HASH_ENABLED` | `true` | 外部参照ハッシュの有効/無効 |
| `TRACE_EXTERNAL_REF_HASH_CACHE` | `output/external_ref_hash_cache.json` | キャッシュファイルパス |
| `TRACE_EXTERNAL_REF_HASH_TTL_DAYS` | `30` | キャッシュエントリの TTL（日数）|

キャッシュファイルを削除すると、すべての外部参照のハッシュを強制的に再計算する。

---

## タクソノミキャッシュの更新

TRACE は `threat-actor` / `intrusion-set` STIX オブジェクトに脅威タクソノミの
タグを付与する。ローカルキャッシュは `schema/threat_taxonomy.cached.json`
（`TRACE_TAXONOMY_CACHE_PATH` で上書き可能）。

起動時に `crawl-single` と `crawl-batch` は BEACON ソース
（デフォルト: `../BEACON/schema/threat_taxonomy.json`; `TRACE_BEACON_TAXONOMY_SOURCE`
で上書き可能）からキャッシュを自動同期する。BEACON が利用不可の場合は
既存スナップショットを使用し、`taxonomy_sync_skipped` ログイベントを出力する。

**手動更新:**

```bash
trace taxonomy-refresh
```

**自動同期のスキップ**（CI / エアギャップ環境向け）:

```bash
trace crawl-batch --no-sync-taxonomy ...
```

---

## StorageBackend 設定

TRACE はプラガブルな StorageBackend でクロール出力の書き先を切り替える:

| 変数 | デフォルト | 説明 |
|------|-----------|------|
| `TRACE_STORAGE` | `local` | バックエンド選択: `local` または `gcs` |
| `TRACE_STORAGE_BASE_DIR` | `output/` | `LocalStorage` のルートディレクトリ |
| `TRACE_GCS_BUCKET` | — | GCS バケット名（`TRACE_STORAGE=gcs` 時に必須）|
| `TRACE_GCS_PREFIX` | (空文字) | GCS バケット内のキープレフィックス |

出力カテゴリ `stix` のファイル名形式は `stix_bundle_<YYYYMMDDHHmm>.json`。

`--output` / `--output-dir` を指定すると StorageBackend をバイパスし、
従来通り明示パスに書き出す。

---

## sources.yaml 管理

`input/sources.yaml` は `crawl-batch` 用の運用者管理ソースリストで、
gitignored（ランタイム artifact）。

各エントリには URL、任意の `feed_type`（rss, html, pdf）、ソースごとの
クロール設定、任意の TLP オーバーライドを指定する。完全な注釈付きスキーマは
[`docs/crawl_design.md`](crawl_design.md) を参照。

---

## トラブルシューティング

### LLM レート制限

**症状:** Vertex AI から `ResourceExhausted` / 429 エラー。

**対処:**
- `TRACE_CRAWL_CONCURRENCY`（デフォルト: 4）を下げて並行 LLM 呼び出しを削減する。
- GCP コンソールで Vertex AI API のクォータを増やす。
- `--no-sync-taxonomy` を使い起動時のタクソノミ同期呼び出しを省く。

### リレバンスゲートが記事を棄却しすぎる / しなさすぎる

**症状:** 記事が多すぎてスキップされる（L2 閾値が厳しすぎる）または
STIX バンドルに品質の低い抽出結果が含まれる（閾値が緩すぎる）。

**対処:**
- L2 閾値は `src/trace_engine/pir/relevance.py` の設定定数で調整する。
  変更後に `make check` を実行してテストが通ることを確認する。
- PIR ドキュメントの品質を確認する: `collection_focus` が曖昧または
  `threat_actor_tags` が不足するとゲートの精度が低下する。
- PIR 更新後に `trace crawl-batch --recheck-on-pir-change` を実行して
  スキップ済み記事を再評価する。

### SAGE 取り込み前の検証エラー

**症状:** `trace validate-all` がレポートに finding を出力する。

**対処:**
1. `output/validation_report_*.md` で finding コードを確認する。
2. 上流の artifact（BEACON 出力または STIX バンドル）を修正して再検証する。
3. `trace submit-review --open-issue` で未解決の issue を追跡する。

`ValidationFinding` コードと修正指針については [`docs/data-model.md`](data-model.md) を参照。

### 一般的なセットアップ上の問題

| 症状 | 原因 | 対処 |
|------|------|------|
| `GCP_PROJECT_ID not set` | env 未ロード | `.env` を作成してから再実行 |
| `crawl_batch` が `Input should be a valid dictionary` | `sources.yaml` がフラット URL リスト | `{version, sources: [...]}` で囲む — [`crawl_design.ja.md`](crawl_design.ja.md) 参照 |
| `pip-audit` 検出あり | 脆弱な依存 | `pyproject.toml` でバージョン更新 → `uv lock` → CHANGELOG に記録 |
| L2 ゲートが常に fail-open（`parse_failed` / `call_failed`） | LLM が非 JSON を返す or 呼び出し失敗 | `gcloud auth application-default print-access-token` で認証確認、`TRACE_RELEVANCE_MODEL_TIER` が実在モデル ID か確認 |
| フックが動作しない | `make setup` 未実行 | TRACE/ で `make setup` |
