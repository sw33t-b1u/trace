# TRACE API 安定性ポリシー

**ステータス**: Initiative H — 1.0 安定化のドラフト（サインオフ保留中）。
TRACE 1.12.0（最終非対称マイナー）から有効。

本ドキュメントは TRACE のコミット済み公開サーフェスと、それに適用される
後方互換性（BC）保証を列挙する。**Committed（コミット済み）** として列挙されていないものは
**Evolving（発展中）** であり、事前通知なしに任意のマイナーリリースで変更される可能性がある。

---

## 1. バージョニングポリシー

TRACE は 2026-05-09 に 1.0.0 に到達した（STIX 2.1 identity SDO マイルストーン、
SAGE 0.5.0 とペアリング）が、歴史的にバリデーターサーフェスにおいてマイナーバージョンでの
破壊的変更を許容してきた（Initiative E で strict モード追加、F で schema_version ゲート追加、
G で IR 要因の受け入れ追加）。Initiative H でこの非対称期間を終了する。

| バージョン | ポリシー |
|---|---|
| 1.0.0 – 1.11.0 | 歴史的: マイナーリリースでバリデーターサーフェスの破壊的変更が可能だった |
| **1.12.0（Initiative H）** | **最終非対称マイナー** — pre-1.0 正規化処理を削除、PIR バリデーターは `schema_version: "1.0.0"` のみを受け付けるよう制限 |
| 1.13.0 以降 | **BEACON / SAGE の厳格ポリシーに準拠**: SemVer 2.0.0; 90 日間 BC 保証; 破壊的変更 = `2.0.0` |

TRACE 1.13.0 以降（H 後の最初のリリース）:

- **メジャー** (`X.0.0`) — Committed サーフェス項目に対する破壊的変更。
- **マイナー** (`1.X.0`) — 追加のみ。
- **パッチ** (`1.0.X`) — バグ修正のみ。

### 90 日間 BC 保証（1.13.0 から）

Committed サーフェス項目は、導入されたリリースから少なくとも 90 日間 BC が保証される。
廃止パスは BEACON / SAGE と同一（1.X.Y で警告 → 2.0.0 で削除）。
完全なポリシー文は BEACON `docs/api-stability.md` §1 を参照。

---

## 2. クイックリファレンス

| サーフェス | Committed? | 初版 | 備考 |
|---|---|---|---|
| PIR バリデーター: `SUPPORTED_PIR_SCHEMA_VERSIONS = {"1.0.0"}` | ✓ | 1.12.0 | Pre-1.0 バージョン（0.16.0 / 0.17.0 / 0.18.0）はバージョンごとのエラーメッセージとともに拒否 |
| `PIRDocument.from_payload()` API | ✓ | 1.12.0 | PIR 検証のための Pydantic ディスパッチャー |
| `STIX2.1 bundle` 検証 API | ✓ | 1.12.0 | `stix2-validator` をラップ |
| `Assets bundle` 検証 API | ✓ | 1.12.0 | `validate_assets` / `validate_identity_assets` / `validate_user_accounts` |
| `schema/pir.schema.json` | ✓ | 1.12.0 | クロスリポジトリのドリフト確認のための BEACON `pir_output.schema.json` のミラー |
| `schema/sources.schema.json` | ✓ | 1.10.0（F）| `feed_type` 列挙（html/rss/atom）を含む |
| `schema/assets.schema.json` | ✓ | 1.0.0 | ID + アセットバンドルの形式 |
| `sources.yaml` スキーマ（オペレーター設定）| ✓ | 1.10.0 | `url`、`label`、`task`、`max_chars`、`pir_ids`、`feed_type` |
| クロール出力: STIX 2.1 バンドル | ✓ | 1.0.0 | x_trace_collected_at 拡張、STIX 2.1 準拠 |
| クロール出力: `crawl_state.json` スキーマ | ✓ | 1.11.0（G）| G フェーズ 4 以降、エントリごとに `iocs[]` を持つ |
| LLM IoC 抽出（`iocs[]` の形式）| ✓ | 1.11.0（G）| 7 IoC タイプ、confidence、context_snippet |
| `trace` CLI エントリ + サブコマンド（H フェーズ 6）| ✓ | 1.12.0 | サブコマンド名 + 主要フラグは固定 |
| レガシー `python -m cmd.<name>` | （非推奨）| n/a | 1.12.0 で非推奨 → 2.0.0 で削除 |
| 環境変数（§5）| ✓ | 1.12.0 | 名前 + 意味 + デフォルト値を固定 |
| 内部 Python モジュール（`src/trace_engine/*` 非公開シンボル）| ✗ | n/a | アンダースコア付きおよびドキュメント未記載のヘルパーは変更される可能性あり |
| `validate/schema/models.py` の Pydantic クラス名 | ✗ | n/a | コンシューマーは直接 Pydantic インポートではなく `PIRDocument.from_payload()` 経由でアクセスする |
| `src/trace_engine/llm/prompts/` 配下の LLM プロンプト | ✗ | n/a | LLM モデルのアップグレードごとにチューニング; 出力 JSON の形式は Committed のまま |

---

## 3. Committed サーフェス — 詳細

### 3.1 PIR バリデーター API

`src/trace_engine/validate/schema/models.py` の `PIRDocument.from_payload()` が
唯一サポートされるエントリポイント。**TRACE 1.12.0 以降（Initiative H フェーズ 3 から引き継ぎ）**:
`from_payload` はラップされたエンベロープ形式のみを受け付け、
ベアリストおよび単一オブジェクトのペイロードは拒否される。

**Committed**:
- `SUPPORTED_PIR_SCHEMA_VERSIONS: set[str] = {"1.0.0"}` — TRACE 1.12.0 以降は `"1.0.0"` のみを受け付ける。Pre-1.0 バージョン（`0.16.0`、`0.17.0`、`0.18.0`）はバージョンごとのエラーメッセージとともに拒否される:
  > `schema_version "0.18.0" was supported in TRACE 1.11.0; please
  > re-emit with BEACON 1.0.0+ output.`
  > （マッピング: 0.16.0 → TRACE 1.9.0、0.17.0 → 1.10.0、0.18.0 → 1.11.0）
- `PIRDocument.from_payload(payload: dict, *, ...)` — ラップされたエンベロープ `{"schema_version": "1.0.0", "pirs": [...]}` を必要とする。検証済みの `PIROutputDocument` を返すか、`ValidationError`（Pydantic）/ `ValueError`（エンベロープ拒否 — ベアリスト / 単一オブジェクト入力）を発生させる。
- ベアリスト拒否メッセージ:
  > `Bare-list PIR input is no longer supported as of TRACE 1.12.0;
  > wrap your input as {"schema_version": "1.0.0", "pirs": [...]}`
- `PIROutputDocument.PIRItem.prioritized_actors` — 必須フィールド（存在必須、空リストも可）。Initiative H フェーズ 2 での厳格化 — BEACON 1.0.0 は常にこのフィールドを出力する。
- クロスバージョン汚染チェック — フェーズ 2 で削除（`"1.0.0"` のみが受け付けられるため、汚染の可能性はない）。

**Committed 対象外**:
- `validate/schema/models.py` の Pydantic クラス定義 — コンシューマーはクラスを直接インポートせず `PIRDocument.from_payload()` を経由する。クラス名と内部ネストは変更される可能性がある。
- CLI のエンベロープ拒否の変換: `cmd/validate_pir.py` と `cmd/validate_all.py` は `ValueError` を `SCHEMA_ENVELOPE` / `PIR_SCHEMA_ENVELOPE` の構造化された検出結果に変換し、アナリストがトレースバックではなくマイグレーションメッセージを見られるようにする。検出結果のコード名は内部的。

### 3.2 STIX バンドル検証 API

OASIS の `stix2-validator` をラップする。`src/trace_engine/validate/stix/validator.py` が
`validate_bundle(bundle_dict) -> ValidationResult` を公開する。

**Committed**:
- `validate_bundle()` 関数シグネチャ + `ValidationResult` の形式（`is_valid: bool`、`errors: list[str]`、`warnings: list[str]`）。

### 3.3 アセットバンドル検証 API

`assets.json`、`identity_assets.json`、`user_accounts.json` に対して:

**Committed**: 各ファイル用のバリデーターエントリポイント（CLI サブコマンド `trace validate-assets`、`trace validate-identity`、`trace validate-accounts` から呼び出し可能）。

### 3.4 `schema/sources.schema.json`（クロール用オペレーター設定）

Sources YAML はバッチクローラーが使用するソースごとのポリシーを搬送する。

**Committed フィールド**:
- `url`（必須、HTTPS URL）
- `label`（任意、自由テキスト）
- `task`（任意、自由テキスト、バッチタグ）
- `max_chars`（任意、正の整数）
- `pir_ids`（任意、このソースが対応する PIR ID のリスト）
- `feed_type`（任意、列挙 `html|rss|atom`; デフォルトは HTTP Content-Type による自動検出; 明示的な値は検出を上書き）

### 3.5 `schema/pir.schema.json`（BEACON 出力スキーマのミラー）

TRACE の `PIRDocument` Pydantic モデルから再生成される。ドリフトチェック
`make check-pir-schema-drift` は `../beacon/schema/pir_output.schema.json` と比較する。

**Committed**: スキーマの内容は BEACON 1.0.0 の出力と完全に一致する（フィールドの差異なし）。

### 3.6 クロール出力

#### 3.6.1 STIX 2.1 バンドル

クロールされた各記事は `stix2-validator` に準拠した STIX 2.1 バンドルを生成する。
TRACE はバンドルエンベロープにカスタムプロパティ `x_trace_collected_at`（ISO タイムスタンプ）を追加する。

**Committed**: STIX 2.1 準拠 + `x_trace_collected_at` 拡張の存在。

#### 3.6.2 `crawl_state.json`

重複排除 + IoC インデックス用のエントリごとの状態。スキーマ:
```
{
  "entries": {
    "<entry_url>": {
      "first_seen": "<iso>",
      "last_seen": "<iso>",
      "title": "<str>",
      "bundle_path": "<path>",
      "iocs": [
        {"type": "ipv4|ipv6|fqdn|sha256|sha1|md5|cve_id",
         "value": "<str>", "confidence": <float>,
         "context_snippet": "<str ≤ 50 chars>"}
      ]
    }
  }
}
```

**Committed**: トップレベルの `entries` dict + エントリごとの必須フィールド
（`first_seen`、`last_seen`、`bundle_path`）。読み取り時に `iocs` フィールドが
存在しない場合は空リストとして扱う（G 以前の状態ファイルとの後方互換）。

### 3.7 LLM IoC 抽出出力（Initiative G フェーズ 4）

Vertex AI 関連性チェック呼び出しが返す値:
```
{
  "relevant": bool,
  "reason": str,
  "iocs": [{"type": "...", "value": "...", "confidence": ...,
            "context_snippet": "..."}]
}
```

**Committed**:
- 7 IoC タイプ: `ipv4 | ipv6 | fqdn | sha256 | sha1 | md5 | cve_id`
- `confidence ∈ [0, 1]`
- `context_snippet`（Pydantic バリデーターにより 50 文字に切り捨て）

**Committed 対象外**:
- プロンプトテンプレートの内容（`src/trace_engine/llm/prompts/relevance_check.md`）— LLM モデルのアップグレードごとにチューニング。
- LLM モデルの選択。

### 3.8 `trace` CLI エントリ + サブコマンド（H フェーズ 6）

Initiative H フェーズ 6 は `trace` を click `Group` エントリポイントとして導入する。
サブコマンドは既存の `cmd/*.py` ロジックをラップする。1.12.0 からの
オペレーター向け公開サーフェス:

| サブコマンド | 置き換え対象 | 目的 |
|---|---|---|
| `trace crawl-batch` | `cmd/crawl_batch.py` | `input/sources.yaml` からバッチクロール（RSS/Atom + HTML、crawl_state.json による重複排除）|
| `trace crawl-single` | `cmd/crawl_single.py` | ワンショットクロール + STIX バンドル出力 |
| `trace search-iocs` | `cmd/search_iocs.py` | crawl_state IoC インデックスを照会（G フェーズ 5）|
| `trace validate-pir` | `cmd/validate_pir.py` | BEACON pir_output.json を検証 |
| `trace validate-stix` | `cmd/validate_stix.py` | STIX 2.1 バンドルを検証 |
| `trace validate-assets` | `cmd/validate_assets.py` | assets.json を検証 |
| `trace validate-identity` | `cmd/validate_identity_assets.py` | identity_assets.json を検証 |
| `trace validate-accounts` | `cmd/validate_user_accounts.py` | user_accounts.json を検証 |
| `trace validate-all` | `cmd/validate_all.py` | すべてのバリデーターを順次実行 |
| `trace enrich-bundle` | `cmd/enrich_bundle.py` | STIX バンドルの後処理 |
| `trace submit-review` | `cmd/submit_review.py` | 出力をレビューシステムに提出 |
| `trace taxonomy-refresh` | `cmd/update_taxonomy_cache.py` | 脅威タクソノミーキャッシュを更新 |

**Committed**: サブコマンド名 + 各サブコマンドの主要フラグ
（例: `crawl-batch --sources`、`search-iocs --ioc`、`search-iocs --tlp-max`、`search-iocs --json`）。

**Evolving**: オプションフラグのデフォルト値、ヘルプテキストの文言、出力フォーマット。

**非推奨（2.0.0 で削除）**: `python -m cmd.<name>` の呼び出し構文。cmd モジュールは後方互換のため 1.x には残るが、統一された `trace` エントリへの移行を促す `DeprecationWarning` を出力する。

### 3.9 環境変数（Committed）

| 環境変数 | デフォルト | 目的 |
|---|---|---|
| `ACTIVITY_WINDOW_DAYS` | `90` | BEACON/SAGE と共有。TRACE_FEED_SINCE_DAYS はこの値にフォールバック |
| `TRACE_FEED_MAX_ENTRIES` | `50` | クロールごとにフィードあたりで展開する RSS/Atom エントリの上限 |
| `TRACE_FEED_SINCE_DAYS` | `90`（`ACTIVITY_WINDOW_DAYS` にフォールバック）| `published` 日付によるフィードエントリのフィルタ |
| `TRACE_STATE_PATH` | `output/crawl_state.json` | クロール状態ファイルの場所 |
| `TRACE_CRAWL_CONCURRENCY` | `4` | 並列フェッチワーカー数 |

**その他の環境変数**（デプロイメント固有、Committed 対象外）:
- LLM: `TRACE_LLM_SIMPLE`、`TRACE_LLM_MEDIUM`、`TRACE_LLM_COMPLEX`、`TRACE_RELEVANCE_MODEL_TIER`、`TRACE_RELEVANCE_THRESHOLD`
- 抽出チューニング: `TRACE_EXTRACTION_CHUNK_CHARS`、`TRACE_EXTERNAL_REF_HASH_ENABLED`、`TRACE_EXTERNAL_REF_HASH_TTL_DAYS`
- GCP: `GCP_PROJECT_ID`、`VERTEX_LOCATION`

これらはマイナーリリースで名前やデフォルト値が変更される可能性がある — オペレーターはデプロイメントごとに明示的に設定すること。

---

## 4. Evolving（BC 保護対象外）

- **内部 Python モジュール** — `src/trace_engine/` 配下の、文書化された API サーフェス経由で公開されていないもの。
- **`validate/schema/models.py` の Pydantic クラス名** — コンシューマーは `PIRDocument.from_payload()` を経由する。
- **`src/trace_engine/llm/prompts/` 配下の LLM プロンプト内容** — LLM モデルのアップグレードごとにチューニング。LLM の**出力 JSON の形式**は Committed（§3.7）。
- **`generate_schemas.py`** 開発ツール — オペレーターは直接呼び出さない。
- **`schema/threat_taxonomy.cached.json`** — `trace taxonomy-refresh` 経由で更新される自動生成タクソノミーキャッシュ。

---

## 5. クロスリポジトリ依存関係

TRACE の Committed サーフェスは以下に依存する:

- **BEACON `pir_output.json` スキーマ**（BEACON 1.0.0+）: TRACE バリデーターは `schema_version: "1.0.0"` のペイロードのみを受け付ける。BEACON の出力が `trace validate-pir` への正規入力となる。
- **MITRE ATT&CK Enterprise STIX バンドル**（検証時に読み込まれた場合）: 脅威アクター / TTP の解決に使用。
- **OASIS STIX 2.1 仕様**: TRACE の STIX バンドル出力とラップされた `stix2-validator` は STIX 2.1 リリースに拘束される。

完全な引用インベントリ: `../beacon/docs/citations.md`。

---

## 6. 2.0.0 トリガー例

TRACE 2.0.0 を強制する変更の例:

- `PIRDocument.from_payload()` の削除または改名。
- `crawl_state.json` のトップレベル構造の変更（例: `entries` の改名）。
- §3.7 の 7 IoC タイプの 1 つを削除。
- `trace search-iocs` サブコマンドまたはその `--ioc` フラグを削除。
- `TRACE_FEED_MAX_ENTRIES` 環境変数を削除。
- `sources.yaml` に新しい必須フィールドを追加（既存のオペレーター設定が壊れる）。

新しい IoC タイプ、新しいバリデーター、新しいサブコマンド、任意スキーマへの新しい任意フィールドの追加はマイナーリリースで許可される。

---

## 7. メンテナンス

Committed サーフェス項目が導入または非推奨化されるたびに本ドキュメントを更新すること。
同様のメンテナンス規約については BEACON `docs/api-stability.md` §7 を参照。

---

*Initiative H — 1.0 安定化。TRACE 1.12.0 が最終非対称マイナー; 1.13.0 以降は厳格準拠。*
