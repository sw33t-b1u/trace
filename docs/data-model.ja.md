# TRACE — 検証データモデル

英語版（正本）: [`docs/data-model.md`](data-model.md)

TRACE が何を、どの契約に基づいて検証するかの正準リファレンス。本書のスキーマは
SAGE のランタイム期待値と一致する。SAGE 側と差分が出た場合は SAGE が正で、
TRACE 側を合わせる。

検証アルゴリズムの説明は `high-level-design.md` §5–§6 を参照。型定義の正準は
`src/trace_engine/validate/schema/models.py`。

---

## 1. TRACE が検証する入力

| アーティファクト | SAGE 側の真の信頼ソース | TRACE エントリポイント |
|----------------|------------------------|---------------------|
| `assets.json` | `SAGE/cmd/load_assets.py`, `SAGE/tests/fixtures/sample_assets.json` | `cmd/validate_assets.py` |
| `pir_output.json` | `SAGE/src/sage/pir/filter.py:25-39`, `SAGE/tests/fixtures/sample_pir.json` | `cmd/validate_pir.py` |
| STIX 2.1 バンドル | OASIS STIX 2.1 仕様 + `SAGE/src/sage/stix/parser.py` | `cmd/validate_stix.py` |

3 種を集約したレポートは `cmd/validate_all.py`。

---

## 2. `assets.json` スキーマ（`AssetsDocument`）

トップレベル辞書で以下のリストを保持。`extra="allow"` のため未知のトップレベル
キー（BEACON の `_comment` 等）は素通し。

| フィールド | 型 | 備考 |
|-----------|----|------|
| `network_segments[]` | `NetworkSegment` | id / name / cidr / zone — すべて必須 |
| `security_controls[]` | `SecurityControl` | id / name 必須、`control_type` と `coverage[]` 任意 |
| `assets[]` | `Asset` | 後述 |
| `asset_vulnerabilities[]` | `AssetVulnerability` | `asset_id`, `vuln_stix_id_ref`, `remediation_status`（既定 `open`） |
| `asset_connections[]` | `AssetConnection` | `src`, `dst`, 任意の `protocol`, `port` ∈ `[0, 65535]` |
| `actor_targets[]` | `ActorTarget` | `actor_stix_id_ref`, `asset_id`, 任意の `confidence` ∈ `[0, 100]` |

### `Asset`

| フィールド | 型 | 既定 | 備考 |
|-----------|----|-----|------|
| `id` | str | 必須 | `assets[]` 内で一意 |
| `name` | str | 必須 | |
| `asset_type` | str / null | null | |
| `environment` | str / null | null | |
| `criticality` | float | `5.0` | 範囲 `[0.0, 10.0]`（Pydantic + セマンティクス両方で確認） |
| `owner` | str / null | null | |
| `network_segment_id` | str / null | null | 設定時は `network_segments[*].id` に解決される必要 |
| `exposed_to_internet` | bool | `false` | |
| `tags` | list[str] | `[]` | |
| `security_control_ids` | list[str] | `[]` | 各値が `security_controls[*].id` に解決される必要 |

### セマンティクスチェック（`validate/semantic/assets.py`）

| コード | severity | トリガー |
|-------|---------|---------|
| `ID_NOT_UNIQUE` | error | `network_segments` / `security_controls` / `assets` の id 重複 |
| `ASSET_REF_SEGMENT` | error | `assets[].network_segment_id` が `network_segments[*].id` に解決不可 |
| `ASSET_REF_CONTROL` | error | `assets[].security_control_ids[*]` が `security_controls[*].id` に解決不可 |
| `CONNECTION_REF_ASSET` | error | `asset_connections[].{src,dst}` が `assets[*].id` に解決不可 |
| `VULN_REF_ASSET` | error | `asset_vulnerabilities[].asset_id` が `assets[*].id` に解決不可 |
| `ACTOR_TARGET_REF_ASSET` | error | `actor_targets[].asset_id` が `assets[*].id` に解決不可 |

---

## 3. `pir_output.json` スキーマ（`PIRDocument` / `PIRItem`)

JSON list 形式。単一 dict ペイロードは検証前に 1 要素 list へ正規化される
（`PIRDocument.from_payload`）。`PIRItem` は `extra="allow"` のため、BEACON が
出力する付加情報（`risk_score`, `rationale`, `notable_groups`,
`collection_focus` 等）はラウンドトリップ可能。

| フィールド | 型 | 必須 | 備考 |
|-----------|----|------|------|
| `pir_id` | str | はい | 文書内一意 |
| `threat_actor_tags` | list[str] | はい（空でも可） | 各値が脅威タクソノミースナップショットのキーであることを推奨 |
| `asset_weight_rules[]` | list[`AssetWeightRule`] | はい（空でも可） | `tag` (str) + `criticality_multiplier` (float, > 0) |
| `valid_from` | ISO date | はい | `valid_until` より厳密に過去 |
| `valid_until` | ISO date | はい | `valid_from` より厳密に未来 |
| `organizational_scope` | str / null | いいえ | |
| `description` | str / null | いいえ | |
| `intelligence_level` | str / null | いいえ | 通例 `strategic` / `operational` / `tactical` |

### セマンティクスチェック（`validate/semantic/pir.py`）

| コード | severity | トリガー |
|-------|---------|---------|
| `PIR_ID_NOT_UNIQUE` | error | `pir_id` 重複 |
| `PIR_TAG_NOT_IN_TAXONOMY` | warning | `threat_actor_tags[*]` が `schema/threat_taxonomy.cached.json` に無い（アナリスト独自タグは許容するがフラグ） |
| `PIR_RULE_TAG_UNUSED` | error（`--assets` 指定時） | `asset_weight_rules[*].tag` が `assets[*].tags` のいずれにも一致しない |
| validity-window 違反 | error | `valid_from >= valid_until`（Pydantic `model_validator` で raise） |

タクソノミーのスナップショットは `cmd/update_taxonomy_cache.py` で更新する。
L2 リレバンスゲートとの関係は [`crawl_design.ja.md`](crawl_design.ja.md) を参照。

---

## 4. STIX 2.1 バンドルスキーマ

OASIS `stix2-validator`（PyPI `stix2-validator>=3.2`）が仕様準拠の正準。
TRACE は `validate/stix/validator.py` 経由で OASIS バリデータを呼び出し、
それを補う局所チェックを上層に積む。

### `cti-stix-validator` でカバーされる範囲

- オブジェクト型 / 必須フィールド、語彙チェック、timestamp 形式、
  id 形式（`<type>--<uuid4>`）、ベストプラクティス警告（`{2xx}` /
  `{3xx}` / `{4xx}` コード）。

### 局所チェック（`validate/stix/validator.py:check_stix_bundle`）

| コード | severity | トリガー |
|-------|---------|---------|
| `BUNDLE_TYPE` | error | top-level `type != "bundle"` |
| ~~`BUNDLE_SPEC_VERSION`~~ | — | 0.4.0 で削除。bundle envelope は `spec_version` を持たない（STIX 2.1 §3 で envelope 廃止、object 単位のみ）。SAGE parser は `bundle.objects[]` を iterate して per-object `spec_version` を読む。 |
| `STIX_ID_NOT_UNIQUE` | error | `objects[]` 内 `id` 重複 |
| `REL_REF_MISSING` | error | `relationship` に `source_ref` / `target_ref` 欠落 |
| `REL_REF_UNRESOLVED` | error | `relationship.{source_ref,target_ref}` が `objects[*].id` に解決不可 |
| `KILL_CHAIN_NAME` | warning | `kill_chain_phases[*].kill_chain_name != "mitre-attack"`（SAGE が捨てる） |

### TRACE bundle metadata extension（L4）

`build_stix_bundle_from_extraction` は **STIX 2.1 §7.3 toplevel-property
extension** 経由で TRACE 固有メタデータを bundle に乗せる（裸の `x_*`
ではない）。これにより `x_*` カスタムプロパティに対する OASIS validator
の {401} warning を構造的に解消する。

メタデータが 1 つ以上設定される時、assembler は:

1. `objects[]` の先頭に **id 固定** の `extension-definition` オブジェクトを挿入（id は
   `extension-definition--c1e4d6a7-2f3b-4e8c-9a5f-1b8d7e6c4a3f` で全 emission 共通）。
2. bundle ルートに `extensions` map を追加し、定義 id に対し
   `extension_type: "toplevel-property-extension"` を宣言。
3. `x_trace_*` フィールドを bundle ルートに記述（extension 配下で許可された状態）。

メタデータ未指定の bundle（PIR / source URL なしの素抽出）は extension
定義を **emit しない**。

| プロパティ | 付与タイミング | 意味 |
|-----------|-------------|------|
| `x_trace_source_url` | CLI から呼ばれた時は常時 | 取得元 URL or 入力パス |
| `x_trace_collected_at` | 常時 | ISO-8601 タイムスタンプ |
| `x_trace_matched_pir_ids` | L2 ゲート稼働時 | 関連と判定された PIR ID |
| `x_trace_relevance_score` | L2 ゲート稼働時 | float `[0.0, 1.0]` |
| `x_trace_relevance_rationale` | L2 ゲート稼働時 | LLM が出した短い理由文。ゲートが fail-open した時は `parse_failed` / `call_failed` / `(truncated)` のいずれか |

#### extension id を固定にしている理由

STIX 2.1 §7.3 は `extension-definition` の id を emission 間で**安定**に
することを要求する（consumer が per-bundle discovery 不要で extension を
認識できる）。TRACE は uuid4() で 1 度生成した値を hardcode し、すべての
TRACE bundle が同じ定義 id を参照する。

### バンドル組立: LLM が抽出、コードが構築

TRACE は LLM に STIX 2.1 オブジェクトを書かせない。LLM はドメイン知識のみ
（エンティティ名、タイプ、description、labels、関係）を返し、`local_id` という
短いエイリアスでリンクする:

```json
{
  "entities": [
    {"local_id": "actor_1", "type": "intrusion-set", "name": "FIN7", ...},
    {"local_id": "tool_1", "type": "tool", "name": "Cobalt Strike", ...}
  ],
  "relationships": [
    {"source": "actor_1", "target": "tool_1", "relationship_type": "uses"}
  ]
}
```

`stix.extractor.build_stix_bundle_from_extraction` がコード側で STIX 2.1
バンドルを組み立てる:

- 各 entity / relationship に `id = "<type>--" + uuid.uuid4()` を採番
  （UUIDv4 厳密、構造的に正しい）
- すべてのオブジェクトと bundle envelope に統一 `created` / `modified`
  タイムスタンプ（millisecond 形式）を打刻
- 全オブジェクトに `spec_version = "2.1"`
- `relationships[*].{source,target}` を `local_id` から採番済み STIX id
  に変換
- 解決不能な参照（LLM の幻覚）は dangling ref を生成せず構造化ログ
  warning でドロップ

これにより、旧 LLM 直接生成方式で頻発していた 2 種のエラー（UUIDv4 違反 /
timestamp 形式違反）が **構造的に発生しなくなる**。残るのは語彙ミスマッチ
（`labels` / `malware_types` / `tool_types`）や `description` 欠落、
ATT&CK external_references の hash 欠落といったベストプラクティス警告のみで、
これらは OASIS バリデータが warning として報告する。

---

## 5. `ValidationFinding` とレポート形式

スキーマ・セマンティクス・STIX 各検査が `ValidationFinding` を返す。
`review/markdown_report.py` がセクションごとに決定論的に Markdown に整形する。

```python
@dataclass(frozen=True)
class ValidationFinding:
    severity: Literal["error", "warning", "info"]
    code: str           # 例: "PIR_TAG_NOT_IN_TAXONOMY"
    location: str       # JSON パス: "$.pirs[0].threat_actor_tags[2]"
    message: str
```

実行結果は **error severity が 0 の時のみ** `PASS`。warning は記録するが
全体評価には影響しない（`validate_stix --strict` で OASIS warning を error
に昇格可能）。
