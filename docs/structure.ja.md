# TRACE ディレクトリ構成

English: [`docs/structure.md`](structure.md)

本ドキュメントは TRACE のトップレベルレイアウトと、`docs/RULES.md` Rule 26
の推奨構成から逸脱している箇所の根拠を記録する。Rule 26 は adaptation を
明示的に許容しており、本ファイルがその adaptation の権威ある記録となる。

## レイアウト

```
TRACE/
├── cmd/                # CLI エントリポイント (crawl_single, crawl_batch,
│                       #   validate_stix, enrich_bundle, …)。コマンドごと
│                       #   に 1 ファイル。src/trace_engine を呼び出す薄い
│                       #   層。
├── docs/               # 英語ドキュメント + .ja.md 翻訳 (Rule 11)。
│                       #   high-level-design.md を含む (maintainer 方針で
│                       #   gitignored; `.gitignore` エントリ
│                       #   `docs/high-level-design.md` 参照)。
├── input/              # 運用者が管理する入力 (sources.yaml, sample STIX
│                       #   バンドル)。ランタイム artifact — gitignored。
├── output/             # crawl 状態、生成バンドル、検証レポート。ランタイム
│                       #   artifact — gitignored。
├── schema/             # JSON schema (pir.schema.json,
│                       #   threat_taxonomy.cached.json 等)。
├── scripts/            # ヘルパースクリプト (`make check` で使う
│                       #   check_pir_schema_drift.py 等)。src パッケージ
│                       #   からは import されない。
├── src/                # Python ソースルート (下記「src レイアウト」参照)。
├── tests/              # pytest スイート (unit + integration マーカー)。
├── .githooks/          # `make setup` でインストールされる
│                       #   pre-commit / pre-push フック (Rule 20)。
├── CHANGELOG.md        # Keep a Changelog 形式 (Rule 22)。
├── LICENSE
├── Makefile            # 品質ゲート: vet → lint → test → audit (Rule 20)。
├── pyproject.toml      # uv 管理の Python プロジェクト (Rule 15)。
├── README.md / README.ja.md
└── uv.lock             # コミット対象のロックファイル (Rule 15)。
```

## src レイアウト (Rule 26 からの逸脱)

Rule 26 は Go 流の `internal/` と `pkg/` をソースコード用に推奨している
が、TRACE は `src/trace_engine/` を採用している。理由:

1. **Python の慣習**。`src/<package>/` は `pyproject.toml` ベースの Python
   プロジェクトにおける標準的なパッケージレイアウトで、`pyproject.toml`
   の `setuptools.packages.find` が `where = ["src"]` で参照する。
   `internal/` / `pkg/` 分割は import 名の変更を強制するうえ、Python の
   import はディレクトリ名で隔離されないため隔離メリットがない。
2. **単一ディストリビューションスコープ**。TRACE は単一の Python
   ディストリビューションであり、現状 public で再利用される subpackage
   はない。"internal vs public" 分割の消費側がまだ存在しない。
3. **BEACON / SAGE と一貫**。三兄弟プロジェクトすべてが
   `src/<package_name>/` 形式で揃っているため、コントリビュータの
   コンテキストスイッチ負担がない。

### `src/trace_engine/` 配下のサブパッケージ

| パス | 責務 |
|------|------|
| `cli/` | `cmd/*` エントリポイントが共有するヘルパー (argparse 関連、metrics)。 |
| `config.py` | `Config.from_env()` — 環境変数駆動の設定 (Rule 24)。 |
| `crawler/` | バッチ fetch、state 管理、taxonomy 自動同期。 |
| `ingest/` | レポート → Markdown 変換 (`report_reader.py`)。 |
| `llm/` | Vertex AI Gemini クライアント + プロンプトアセット。BEACON から複製; [`beacon_handoff.md`](beacon_handoff.md) 参照。 |
| `pir/` | L2 PIR 関連性ゲート。 |
| `review/` | 人手レビューハンドオフ (Markdown / GHE Issue)。 |
| `stix/` | L3 抽出、L4 バンドル組み立て、taxonomy エンリッチ、外部参照ハッシュ。 |
| `validate/` | Schema + semantic バリデータ (PIR, assets, STIX)。 |

## Rule 26 推奨ディレクトリとの対応

| Rule 26 dir | TRACE の対応 | 補足 |
|-------------|-------------|------|
| `api/` | `schema/` | TRACE は OpenAPI / protobuf ではなく JSON schema を露出している。 |
| `cmd/` | `cmd/` | 同じ。実行可能エントリポイントごとに 1 ファイル。 |
| `internal/` | `src/trace_engine/` | Python に強制的な `internal/` 機構は存在しない。 |
| `pkg/` | (なし) | 現時点で public な再利用ライブラリ面はない。 |
| `scripts/` | `scripts/` | 同じ。ヘルパースクリプトのみ; `src/` から import されない。 |

## ツリー外の前提

TRACE は存在する場合 BEACON 兄弟リポジトリが `../BEACON` に位置している
ことを前提とする (`make check-pir-schema-drift` および
`src/trace_engine/crawler/taxonomy_sync.py` の taxonomy 自動同期で使用)。
両パスは env (`TRACE_BEACON_TAXONOMY_SOURCE`) で上書き可能で、兄弟が不在
の場合は graceful に degrade するため TRACE 単独のコントリビュータでも
`make check` が動作する。
