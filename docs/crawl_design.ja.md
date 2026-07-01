# TRACE — Crawl 設計

英語版（正本）: [`docs/crawl_design.md`](crawl_design.md)

TRACE の 2 つの収集モード、ソース毎スキーマ、idempotent なバッチ収集を支える
永続状態を end-to-end で参照するドキュメント。

データフローの背景は `high-level-design.md` §2.3 / §6 と
[`docs/data-model.ja.md`](data-model.ja.md) を参照。

---

## 1. 2 つの収集モード

| モード | ドライバー | 用途 |
|--------|----------|------|
| 単発 | `cmd/crawl_single.py` | アナリストが URL or PDF を都度渡す |
| バッチ | `cmd/crawl_batch.py` | スケジューラ駆動で `input/sources.yaml` を巡回 |

両モードは内部パイプラインを共有:

```
 1. fetch        — httpx GET（Config の UA + timeout）
 2. read_report  — markitdown URL/PDF → クリーンな Markdown
                   （max_chars でクリップ）
 3. L2 gate      — pir.relevance.evaluate（--pir 指定時のみ）
 4. L3 extract   — stix.extractor.extract_entities が
                   Extraction（local_id エイリアス付きエンティティ + 関係）を返す
 5. L4 bundle    — build_stix_bundle_from_extraction が
                   STIX UUID + timestamp + spec_version を採番、
                   local_id 参照を解決し、x_trace_* メタデータを刻印
 6. write        — output/stix_bundle_<slug>.json（tmp + os.replace でアトミック）
```

---

## 2. `input/sources.yaml` スキーマ

`SourcesDocument`（`src/trace_engine/validate/schema/models.py`）で検証される。
`input/` ディレクトリは **gitignore 対象**のため、各オペレータがローカルで
保守する。

### トップレベル

| キー | 型 | 既定 | 備考 |
|-----|----|-----|------|
| `version` | int | `1` | 非互換変更時にバンプ |
| `sources` | list[`SourceEntry`] | 必須 | 1 URL = 1 エントリ |

### `SourceEntry`

| フィールド | 型 | 既定 | 備考 |
|-----------|----|-----|------|
| `url` | str (http(s)) | 必須 | httpx + markitdown にそのまま渡る |
| `label` | str / null | null | ログに表示される人間可読名 |
| `task` | `simple` / `medium` / `complex` | `medium` | L3 抽出の LLM tier |
| `max_chars` | int > 0 | `30000` | markitdown の既定クリップを上書き |
| `pir_ids` | list[str] | `[]` | 非空の場合、L2 ゲートはこのソースに対し列挙された PIR のみで評価 |

未知フィールドは拒否（`extra="forbid"`）。`task` や `max_chars` のタイポは
silently 無視されず、ロード時に明示的に失敗する。

### 注釈付き例

```yaml
# input/sources.yaml — 最小〜最大の例
version: 1

sources:
  # 最小: URL のみ。既定で task=medium、PIR pinning なし。
  - url: https://example.com/cti-blog/post-42

  # 標準: URL + 人間可読 label。
  - url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-001a
    label: CISA Advisory AA25-001A

  # 長文・高密度レポート — task tier と char budget をバンプ。
  - url: https://example-vendor.com/research/q4-threat-report.pdf
    label: ExampleVendor Q4 Threat Report
    task: complex
    max_chars: 60000

  # このソースに対して L2 が評価する PIR を限定。
  - url: https://example.com/regional-bulletin
    label: Regional Threat Bulletin
    pir_ids:
      - PIR-2026-001
      - PIR-2026-004
```

> **よくある誤り**: `version:` / `sources:` envelope を **付けずに** URL を
> 1 行ずつ書く。バリデータは
> `Input should be a valid dictionary or instance of SourcesDocument`
> で拒否する。必ず上記構造で囲む。

---

## 3. L2 PIR リレバンスゲート

`--pir <path>` 指定時:

1. PIR ファイルを `PIRDocument` にロードし、バイト列の SHA-256 を
   `pir_set_hash` として記録。
2. 各記事に対し `pir.relevance.evaluate(text, pir_doc)` が `simple` tier の
   LLM（既定 `gemini-2.5-flash`）を呼び出し、JSON のみを要求して
   `{score, matched_pir_ids[], rationale?}` を得る。
3. score は `[0.0, 1.0]` にクランプ。応答が full JSON としてパース失敗
   した場合、**regex で `score` と `matched_pir_ids` をサルベージ**する
   （rationale は応答末尾で truncation を喰いやすく、score / matched は先頭で
   出揃うため救出可能）。サルベージ失敗時は **fail-open**（記事は L3 へ進む。
   `decision="extraction_failed"` / rationale `parse_failed: …` を記録）。
4. それ以外: `score >= TRACE_RELEVANCE_THRESHOLD`（既定 `0.5`）なら L3 へ。
   閾値未満は `decision="skipped_below_threshold"` で記録してスキップ。

ソース毎の `pir_ids`（上記）は L2 を一部 PIR に絞るためのつまみ。

---

## 4. L3 エンティティ抽出（PIR コンテキスト注入）

`stix/extractor.extract_entities(text, task, pir_doc=...)`:

1. `prompts/stix_extraction.md` をロード。
2. `{{REPORT_TEXT}}` を記事本文で置換。
3. `pir_doc` が非空なら `{{PIR_CONTEXT_BLOCK}}` に
   `## PIR Context` セクションを差し込み、各 PIR の `intelligence_level`,
   `description`, `threat_actor_tags`, `notable_groups`,
   `collection_focus`, `prioritized_asset_tags` を要約。
4. Gemini を `json_mode=True` で呼び出し、
   `{entities: [...], relationships: [...]}` を要求。LLM は STIX
   ではなく **意味情報**（local_id, type, name, description, labels, …）
   のみを返す。`<type>--<uuid4>` フィールドや timestamp は LLM が
   触れない。
5. `_extract_json_from_text` で fence 剥がし含む復元。
6. 許可された型外の entity をドロップ
   （`threat-actor`, `intrusion-set`, `attack-pattern`, `malware`,
    `tool`, `vulnerability`, `indicator`）。
7. 許可された `relationship_type` 外
   （`{uses, exploits, indicates}` 以外）の relationship をドロップ。

PIR コンテキストは **ヒント**であり**フィルタではない**（フィルタは L2 で
完了）。プロンプトは "PIR を満たすためにエンティティを捏造するな" と明記する。

### 長文記事のチャンク抽出

Gemini の `max_output_tokens` 上限により、3 万字級の脅威レポートは JSON が
途中で切れて parse 失敗するリスクがある。これを構造的に回避するため、
`extract_entities` は記事を段落境界（`\n\n`）で
`Config.extraction_chunk_chars`（既定 `12000`、環境変数
`TRACE_EXTRACTION_CHUNK_CHARS`）以下のチャンクに分割し、L3 プロンプトを
チャンクごとに 1 回呼び出す。

- 単一段落が上限を超える場合は段落内で hard-cut。
- 各チャンクの `local_id` は `c0_actor_1`, `c1_actor_1` のように
  ネームスペース化され、別チャンクの同一エイリアスと衝突しない。
- 1 チャンクが parse 失敗しても `chunk_index` 付きで警告ログを残し、
  他チャンクの抽出結果は採用される。

`_merge_extractions` がチャンクごとの結果をマージ:

| ステップ | 挙動 |
|---------|------|
| エンティティ重複排除 | `indicator` 以外は `(type, name.strip().lower())`、`indicator` は `(type, pattern)`。後出しのプロパティは先出しに union。リストフィールド（`labels`, `aliases`, `kill_chain_phases`, `external_references`, `malware_types`, `tool_types`）は重複排除付き union。同名でも `type` が異なれば別エンティティ。 |
| リレーションシップの再配線 | `source` / `target` をマージ後の alias マップ経由でリマップし、跨チャンク関係も解決。 |
| リレーションシップ重複排除 | `(source, target, relationship_type)` 組み合わせの重複を圧縮。 |
| 幻覚 endpoint | エイリアスマップに存在しない参照はドロップ。`extractions_merged` ログ行にカウント。 |

短い記事（`len(text) <= chunk_chars`）はチャンクループをスキップし、
単発呼び出しと同一動作。

## 4a. L4 バンドル組立（コードが構築）

`stix/extractor.build_stix_bundle_from_extraction(extraction, ...)` は
決定論的な Python:

1. 各 entity に `<type>--<uuid4>` を採番し、`local_id → STIX id` マップを
   構築。
2. すべての object（entity / relationship / L4 メタデータの
   `extension-definition`）に統一の `created` を `YYYY-MM-DDTHH:mm:ss.000Z`
   形式で打刻し、`spec_version = "2.1"` を付与。STIX 2.1 仕様に従い
   bundle envelope 自体には `spec_version` / `created` を**付けない**。
3. 各 relationship について `relationship--<uuid4>` を採番し、
   `source_ref` / `target_ref` を `local_id` から新 STIX id に変換。
   マップに無い endpoint（LLM の幻覚由来）は構造化ログ警告とともにドロップ。
4. STIX 2.1 type 別必須プロパティのデフォルト
   （`malware.is_family = false`、`indicator.{valid_from, pattern_type}`）
   を LLM が出していない時のみ補完。
5. L4 メタデータが 1 つ以上指定された時、`objects[]` の先頭に id 固定の
   `extension-definition` を挿入し、bundle ルートに `extensions` map
   （toplevel-property-extension）を追加。`x_trace_*` フィールドはその
   extension 配下で bundle ルートに記述される。§5 参照。

この分離により、OASIS バリデータの `{103}` UUIDv4 / timestamp 形式 /
type 別必須プロパティ / {401} カスタムプロパティの各チェックが **構造的に
常に通る** — LLM はそれらフィールドに触れる機会がない。

---

## 5. L4 bundle envelope（extension 経由）

`build_stix_bundle_from_extraction` は L4 メタデータを STIX 2.1 §7.3
toplevel-property extension 経由で bundle に乗せる。1 つ以上のフィールド
が設定された時、assembler は:

- `objects[]` の先頭に **id 固定** の `extension-definition` を挿入
  （定義 id の詳細は `data-model.ja.md`）。
- bundle ルートに `extensions = { <ext-id>: { extension_type:
  "toplevel-property-extension" } }` を追加。
- `x_trace_*` フィールドを bundle ルートに記述。

| プロパティ | 設定元 |
|-----------|--------|
| `x_trace_source_url` | `source_url` 引数（CLI が `--input` を渡す） |
| `x_trace_collected_at` | `collected_at` 引数（既定は "now (UTC)"） |
| `x_trace_matched_pir_ids` | L2 verdict（ゲート稼働時） |
| `x_trace_relevance_score` | L2 verdict |
| `x_trace_relevance_rationale` | L2 verdict |

メタデータ未指定の bundle（PIR / source URL なしの素抽出）は extension
定義を **emit しない**。

---

## 6. `output/crawl_state.json` スキーマ

バッチ dedupe の永続状態。`tempfile + os.replace` でアトミック書き込み。
スキーマ（version `1`):

```json
{
  "version": 1,
  "entries": {
    "https://example.com/post-1": {
      "first_seen": "2026-05-01T08:00:00.000Z",
      "last_seen":  "2026-05-08T08:00:00.000Z",
      "content_sha256": "<hex>",
      "bundle_path": "output/stix_bundle_post-1.json",
      "relevance": {
        "decision": "kept",
        "score": 0.82,
        "matched_pir_ids": ["PIR-2026-001"],
        "rationale": "actor named in report",
        "pir_set_hash": "<sha256 of pir_output.json bytes>"
      }
    },
    "https://example.com/unrelated": {
      "first_seen": "2026-05-08T08:00:00.000Z",
      "last_seen":  "2026-05-08T08:00:00.000Z",
      "content_sha256": "<hex>",
      "bundle_path": null,
      "relevance": {
        "decision": "skipped_below_threshold",
        "score": 0.18,
        "matched_pir_ids": [],
        "rationale": "no PIR overlap",
        "pir_set_hash": "<sha256>"
      }
    }
  }
}
```

`relevance.decision` ∈ `{kept, skipped_below_threshold, extraction_failed,
no_pir}`。

---

## 7. dedupe 戦略

各 `crawl_batch` 実行で、ソースごとに:

1. `fetch(url)` → 生バイト。
2. `content_sha256 = sha256(bytes)`。
3. `state.entries[url]` を参照。以下の場合スキップ:
   - 記録された `content_sha256` と一致 **かつ**
   - `--recheck-on-pir-change` がオフ、または記録された `pir_set_hash`
     が現在の PIR ファイルと一致。
4. それ以外: read → L2 → L3 → bundle → state upsert。

`fetch` 失敗 / `extraction_failed` は outcome として報告するが、bundle は
書かず state も汚さない。次回実行で再試行される。

`first_seen` は upsert を跨いで保持される。`last_seen` は URL に触れる度に
更新される。これにより「いつ初めてこの記事を見たか」を後から問える。

---

## 8. 単発モードの追加事項

`trace crawl-single` はオンデマンド版。`crawl_state.json` には **永続化しない**。
主用途は「アナリストが URL を渡したのでバンドルが欲しい」という意図的な
ステートレス操作のため。L2 + L3 + L4 の挙動は同一。

```bash
uv run trace crawl-single --input '<url-or-pdf-path>' \
  --pir ../BEACON/output/pir_output.json \
  [--task complex] [--relevance-threshold 0.6]
```

L2 ゲートが記事をスキップした場合は
`Skipped (relevance score X.XX < threshold Y.YY)` を出力して exit `0`
（スキップは success path）。

---

## 9. ゲートのチューニング

| つまみ | 場所 | 既定 | 触る目安 |
|-------|------|-----|---------|
| 閾値 | `--relevance-threshold` または `TRACE_RELEVANCE_THRESHOLD` | `0.5` | ノイズ記事が多く通る → 上げる、関連記事まで弾かれる → 下げる |
| モデル tier | `TRACE_RELEVANCE_MODEL_TIER` | `simple` | `flash-lite` の判定品質が低いと感じたら `medium` |
| ソース毎の PIR pin | `sources.yaml: pir_ids` | `[]` | 特定フィードが特定 PIR にしか関係しない → 範囲を絞る |

`x_trace_relevance_rationale` が `parse_failed` / `call_failed` /
`(truncated)` を示している場合、ゲートは本来の判定を行えていない。
LLM 呼び出しパスを先に確認すること。

---

## 10. PIR 駆動の記事探索（`trace discover-pir`）

`trace discover-pir` は BEACON Collection UI が利用する pre-crawl の探索ステップ。
BEACON `pir_output.json` を読み、軽量な検索 term を生成し、指定期間内の
RSS/Atom ソースカタログ entry を検索し、人間の承認用 candidate JSON を出力する。
L2 リレバンス、L3 STIX 抽出、bundle 組立、`crawl_state.json` 更新は意図的に行わない。

Discovery は保守的なルーティング補助であり、インテリジェンス判定ではない:

1. Validator と crawl コマンドが使う同じ `PIRDocument.from_payload()` 契約で
   `pir_output.json` をロードする。
2. prioritized actor 名、actor alias、`threat_actor_tags`、任意の
   `notable_groups`、任意の `collection_focus`、`asset_weight_rules[].tag`
   から重み付き term を生成する。
3. `input/source_catalog.yaml` をロードする。存在しない場合はコミット済みの
   `input/source_catalog.example.yaml` テンプレートへフォールバックする。
4. 有効な RSS/Atom feed を取得・parse し、`published` / `updated` timestamp が
   要求期間内の entry を残す。timestamp がない entry は、多くの CTI feed が信頼できる
   公開日を省略するため、人間レビュー向けに残す。
5. entry title、summary、URL に PIR term を照合する。actor / alias term が最も高い
   weight を持ち、title match と recency が小さな bonus を加える。
6. 正規化 URL で重複排除し、上位 `--max-candidates` 件を出力する。
7. source ごとの `entries`、`in_window`、`matched` 件数と最終
   `discovery_summary` を log 出力し、candidate 0 件の理由を stderr から診断できるようにする。

`--include-recent` を指定すると、PIR term に合致しなかった期間内 entry も、matched candidate
の後ろに `score: 0.0`、空の `matched_pir_ids`、空の `matched_terms` として追加される。
件数は `--max-candidates` で制限される。この fallback は人間 triage 用であり、承認後は
通常どおり L2 gate が実行される。

承認済み candidate は BEACON UI が通常の `SourcesDocument` に変換し、
`trace crawl-batch --pir ...` に渡す。既存 crawl path が L2 PIR relevance、
STIX 抽出、state dedupe、bundle metadata の source of truth であり続ける。

### 10.1 `input/source_catalog.yaml` スキーマ

運用者カタログはローカル runtime 設定であり gitignored。TRACE はテンプレートとして
`input/source_catalog.example.yaml` をコミットする。

```yaml
version: 1
sources:
  - name: Microsoft Security Blog
    url: https://www.microsoft.com/en-us/security/blog/feed/
    type: rss        # rss | atom
    category: vendor # optional, informational
    enabled: true    # optional, default true
    max_entries: 50  # optional per-source cap for future provider tuning
```

| フィールド | 型 | 既定 | 備考 |
|-----------|----|------|------|
| `version` | int | `1` | カタログスキーマバージョン |
| `sources[].name` | str | 必須 | candidate に表示する人間可読ソース名 |
| `sources[].url` | http(s) URL | 必須 | RSS/Atom feed URL |
| `sources[].type` | `rss` / `atom` | `rss` | parser hint |
| `sources[].category` | str / null | null | 情報用 grouping（`vendor`, `news`, `government` など）|
| `sources[].enabled` | bool | `true` | false の source はスキップ |
| `sources[].max_entries` | int / null | null | source ごとの cap 予約枠。global `--max-candidates` は引き続き適用 |

### 10.2 Candidate JSON 契約

`trace discover-pir --json` は安定した envelope を出力する:

```json
{
  "schema_version": "1.0.0",
  "generated_at": "2026-06-28T00:00:00Z",
  "pir_path": "../BEACON/output/pir_output.json",
  "window": {"from": "2026-06-01", "to": "2026-06-30"},
  "candidates": [
    {
      "url": "https://example.com/report",
      "title": "Example report",
      "source_name": "Example Feed",
      "published_at": "2026-06-15T10:00:00Z",
      "matched_pir_ids": ["PIR-2026-001"],
      "matched_terms": ["salt typhoon"],
      "score": 0.9,
      "summary": "Short feed summary"
    }
  ]
}
```

`score` は `0.0..1.0` に clamp され、sorting と operator triage のみに使われる。
STIX bundle へコピーされない。crawl 時の `x_trace_relevance_score` は引き続き
L2 PIR relevance gate が出力する。
