# TRACE 依存関係

英語版（正本）: [`docs/dependencies.md`](dependencies.md)

RULES.md Rule 18 に従い、すべての runtime 依存に採用理由を記録する。本書が
正準であり、依存を追加した場合は本ファイルと `pyproject.toml` を **同一
コミット内で** 更新する。

## Runtime

| パッケージ | 最小バージョン | TRACE での用途 | ライセンス |
|-----------|--------------|--------------|-----------|
| `pydantic` | `>=2.0` | `assets.json`, `pir_output.json`, `sources.yaml` のスキーマ層 + `ValidationFinding` データモデル。`RootModel` と `model_validator(mode="after")` （`valid_from < valid_until` 検証用）が v2 必須。 | MIT |
| `google-genai` | `>=1.0` | Vertex AI Gemini クライアント。L2 PIR リレバンスゲート（`gemini-2.5-flash-lite`）と L3 STIX 抽出（`gemini-2.5-flash` / `pro`）で使用。BEACON と同じ SDK のため、複製した `llm/client.py` も SDK 境界で揃う。 | Apache-2.0 |
| `structlog` | `>=24.4.0` | 全エントリポイントの構造化 JSON ログ。Rule 19 が構造化ログを義務付け。 | MIT / Apache-2.0 |
| `httpx` | `>=0.27.0` | バッチクローラの `fetcher.py`、`review/github.py` の GHE Issue クライアントが使う同期 HTTP クライアント。 | BSD-3 |
| `cryptography` | `>=46.0.7` | CVE-2026-39892 修正バージョン pin。`google-genai` と `httpx` 経由で transitive。BEACON の pin と一致。 | Apache-2.0 / BSD |
| `markitdown[pdf]` | `>=0.1.0` | PDF / URL 入力を L3 プロンプト用にクリーンな Markdown へ変換。`[pdf]` extra で `pdfminer.six` を引き込む。BEACON 0.8.x から移管。 | MIT |
| `stix2-validator` | `>=3.2` | OASIS `cti-stix-validator`。STIX 2.1 バンドルが SAGE に渡る前にスキーマ + ベストプラクティスを確認。`validate/semantic/stix_refcheck.py` で局所 ID/参照/kill_chain チェックを上層に積む。 | BSD-3 |
| `pyyaml` | `>=6.0` | `input/sources.yaml` のパーサー（`crawler/sources.py` から）。 | MIT |
| `python-dotenv` | `>=1.0` | CLI 起動時に `.env` を `os.environ` にロード。`GCP_PROJECT_ID`, `TRACE_GHE_TOKEN` 等を手動 export 不要に。 | BSD-3 |

## 開発

| パッケージ | 最小バージョン | 用途 | ライセンス |
|-----------|--------------|------|-----------|
| `ruff` | `>=0.6.0` | Lint + format。`pyproject.toml` で設定済み。 | MIT |
| `pytest` | `>=9.0.3` | テストランナー。Integration テストは `-m integration` 経由。 | MIT |
| `pytest-cov` | `>=5.0.0` | カバレッジレポート（必要に応じて Makefile 経由）。 | MIT |
| `pip-audit` | `>=2.7.0` | `make check` で脆弱性スキャン（Rule 21）。 | Apache-2.0 |

## 意図的に追加していないもの

| パッケージ | 理由 |
|-----------|------|
| `feedparser` | RSS / Atom 展開は MVP 外。`sources.yaml` はフラット URL リスト。バッチオペレータから要求が出てから再評価。 |
| `sqlite3`（個別 dep として） | `tmp + os.replace` のアトミック JSON ファイルで MVP 規模は十分。並行バッチが要件になった時点で再評価。 |
| `fastapi` / `uvicorn` | Web UI は TRACE Phase 2 の予定。実装するまで依存表面積を絞る。 |
| `stix2` | TRACE は STIX 2.1 仕様キーで plain `dict` を組み立てる。フル `stix2` オブジェクトモデルは不要。仕様準拠は OASIS バリデータで担保。 |

## BEACON との重複

`src/trace_engine/llm/client.py` は `BEACON/src/beacon/llm/client.py` の
逐語コピー。同様に `src/trace_engine/review/github.py` は
`BEACON/src/beacon/review/github.py` をミラーし、TRACE 風に
`submit_validation_report`（検証レポート 1 件 = 1 Issue）を実装する。
BEACON は PIR ごとに Issue を立てる `submit_pirs_for_review` を持つ。

この重複は意図的（Rule 26: `internal/` パッケージはプロジェクト境界を跨いで
import 不可）。SAGE 側にも LLM 呼び出しコンポーネントが必要になった段階で、
共通パッケージとして抽出し、3 プロジェクトで lockstep に重複を解消する。

## CVE 履歴

| CVE | パッケージ | 修正 | 備考 |
|-----|-----------|------|------|
| CVE-2026-39892 | `cryptography` | `>=46.0.7` | TRACE 0.1.0 で BEACON の pin に合わせて固定。 |
