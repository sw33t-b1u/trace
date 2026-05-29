# TRACE

**Threat Report Analyzer & Crawling Engine**

CTI ベンダーブログ・ニュース記事・PDF レポート・任意の URL から脅威情報を収集し、組織の PIR（Priority Intelligence Requirements）と関連する記事のみを Google Gen AI（Gemini）で [SAGE](https://github.com/sw33t-b1u/sage) 互換の **STIX 2.1 バンドル** に変換する。さらに、BEACON が生成する `assets.json` / `pir_output.json` および TRACE 自身が生成する STIX バンドルが SAGE に取り込まれる前段の検証ゲートとしても機能する。

[English README is here](README.md)

> TRACE は 3 つの責務を持つ: PIR 駆動の Web 収集、STIX 2.1 バンドル生成、SAGE 入力検証ゲート。SAGE は TRACE が検証通過させた成果物のみを取り込む。

## 概要

```
  URL または PDF (単発)              input/sources.yaml (バッチ用 URL リスト)
         │                                       │
         └───────────────┬───────────────────────┘
                         │
                         ▼
              cmd/crawl_single.py / crawl_batch.py
                         │   --pir <BEACON pir_output.json>
                         │   ├── L2 リレバンスゲート (flash-lite)
                         │   ├── L3 PIR コンテキスト注入 (Gemini)
                         │   └── L4 バンドルメタデータ付与 (matched_pir_ids, score)
                         ▼
              StorageBackend stix/（デフォルト）または --output / --output-dir パス
              output/stix/stix_bundle_<YYYYMMDDHHmm>.json
                         │
                         ▼
              cmd/validate_stix.py  (cti-stix-validator + 局所 refcheck)
                         │
                         ▼
                   [SAGE ETL]


  BEACON 出力 (assets.json, pir_output.json,
               identity_assets.json, user_accounts.json)
         │
         └───► cmd/validate_assets.py            (Pydantic + 参照整合性)
         │
         └───► cmd/validate_pir.py               (Pydantic + タクソノミ + asset タグ照合)
         │
         └───► cmd/validate_identity_assets.py   (Identity + has_access の assets.json クロス参照、
         │                                        なりすましフラグ検証)
         │
         └───► cmd/validate_user_accounts.py     (UserAccount + account_on_asset クロス参照)
         │
         └───► cmd/validate_all.py               (集約 Markdown レポート)
                         │
                         ▼
              cmd/submit_review.py [--open-issue]
```

**モード:**

| モード | 入力 | LLM | 用途 |
|--------|------|-----|------|
| `crawl_single` | URL または PDF +（任意で）PIR | flash-lite（ゲート）+ Gemini（抽出） | アナリスト主導のオンデマンド取得 |
| `crawl_batch`  | `input/sources.yaml` +（任意で）PIR | flash-lite（ゲート）+ Gemini（抽出） | コンテンツハッシュ dedupe ＋ PIR 駆動の選別 |
| `validate_*`   | JSON / STIX バンドル | なし | SAGE 取り込み前の品質ゲート |

`--pir` を指定すると、STIX 抽出の前段で軽量リレバンスゲート（L2）が動作し、抽出プロンプトには PIR コンテキストが注入される（L3）。生成バンドルには `x_trace_matched_pir_ids` / `x_trace_relevance_score` メタデータが付与される（L4）。`--pir` 未指定時はゲートを無効化し、全記事を STIX 化する（試行・実験用途）。

## ドキュメント

| ドキュメント | 説明 |
|-------------|------|
| [docs/setup.md](docs/setup.md) / [ja](docs/setup.ja.md) | クローン・インストール・設定・テスト・初回実行 |
| [docs/deploy.md](docs/deploy.md) / [ja](docs/deploy.ja.md) | Cloud Run Job デプロイと Cloud Scheduler |
| [docs/usage.md](docs/usage.md) / [ja](docs/usage.ja.md) | CLI コマンド・クロールワークフロー・運用・トラブルシューティング |
| [docs/data-model.md](docs/data-model.md) / [ja](docs/data-model.ja.md) | 検証スキーマ・STIX バンドル形式 |
| [docs/crawl_design.md](docs/crawl_design.md) / [ja](docs/crawl_design.ja.md) | クローラーアーキテクチャ・L2-L4 パイプライン |
| [docs/structure.md](docs/structure.md) / [ja](docs/structure.ja.md) | プロジェクトディレクトリ構成 |
| [docs/dependencies.md](docs/dependencies.md) / [ja](docs/dependencies.ja.md) | 依存ライブラリの採用理由とライセンス |
| [docs/api-stability.md](docs/api-stability.md) / [ja](docs/api-stability.ja.md) | API 安定性ポリシーと後方互換保証 |

クロスプロジェクトドキュメント:
- [BEACON pipeline-guide.md](https://github.com/sw33t-b1u/beacon/blob/main/docs/pipeline-guide.md) — エンドツーエンド CTI パイプライン
- [BEACON citations.md](https://github.com/sw33t-b1u/beacon/blob/main/docs/citations.md) — 外部引用とライセンス一覧
- [SAGE ir-feedback-flow.md](https://github.com/sw33t-b1u/sage/blob/main/docs/ir-feedback-flow.md) — IR フィードバックループとスコアリング計算式

## クイックスタート

```bash
cd TRACE
uv sync --extra dev
make setup              # Git hook をインストール
cp .env.example .env    # GCP_PROJECT_ID 等の環境変数を入力
```

詳細な手順は [docs/setup.ja.md](docs/setup.ja.md) を参照。

## 開発コマンド

```bash
make setup     # Git hook をインストール (clone 後に 1 回)
make check     # lint + test + audit (品質ゲート)
make vet       # ruff check
make lint      # ruff format --check
make format    # ruff format + fix
make test      # pytest (ユニットテスト)
make audit     # pip-audit
```

## 参考資料

- [OASIS STIX 2.1 仕様](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [`oasis-open/cti-stix-validator`](https://github.com/oasis-open/cti-stix-validator)
- [SAGE](https://github.com/sw33t-b1u/sage) — 下流の取り込み先
- BEACON — `assets.json` / `pir_output.json` を生成する姉妹ツール

## ライセンス

Apache-2.0 — [LICENSE](LICENSE) を参照
