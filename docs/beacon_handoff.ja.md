# BEACON → TRACE 移行ハンドオフ

English: [`docs/beacon_handoff.md`](beacon_handoff.md)

このノートは TRACE 新設時 (BEACON 0.9.0 / TRACE 0.1.0) に BEACON から
切り出された対象、その判断理由、および各要素の新しい配置先を記録する。

## 移動したもの

| BEACON のパス (削除) | TRACE のパス (新規) |
|---------------------|---------------------|
| `src/beacon/ingest/stix_extractor.py` | `src/trace_engine/stix/extractor.py` |
| `src/beacon/ingest/report_reader.py` | `src/trace_engine/ingest/report_reader.py` |
| `src/beacon/llm/prompts/stix_extraction.md` | `src/trace_engine/llm/prompts/stix_extraction.md` |
| `cmd/stix_from_report.py` | `cmd/crawl_single.py` |
| `tests/test_stix_extractor.py` | `tests/test_stix_extractor.py` |
| `tests/test_report_reader.py` | (TRACE Phase D の crawler テスト追加時に再導入) |
| `markitdown[pdf]` ランタイム依存 | `pyproject.toml` (TRACE) |

`BEACON/cmd/stix_from_report.py` は BEACON 0.9.x で deprecation stub
(リダイレクトメッセージ + exit 2) として出荷され、BEACON 0.10.0 で削除済。
`BEACON/cmd/validate_pir.py` も同じライフサイクルで BEACON 0.10.0 で削除済。

## コピーしたもの (移動ではない)

`src/beacon/llm/client.py` は `src/trace_engine/llm/client.py` として
複製されている。共有パッケージ化ではなく複製を選んだ理由:

- 二つのプロジェクトは独立してデプロイされ、それぞれ単独で動作する必要が
  ある (Rule 26: `internal/` はプロジェクト間でインポート不可)。
- SAGE が同じクライアントを必要とするまでは、共有ライブラリへの抽出は
  時期尚早。要件が顕在化した時点で第三のパッケージへ持ち上げる。

## なぜ "trace" ではなく "trace_engine"

Python ディストリビューション名 (PyPI / `pyproject.toml` `name`) は
`trace` だが、import パッケージ名は `trace_engine`。Python 標準ライブラリ
には組み込みの `trace` モジュール
(<https://docs.python.org/3/library/trace.html>) があり、`sys.path` 上で
こちらが優先されるため `from trace.X import …` は標準ライブラリへ解決
されてしまう。`trace_engine` はプロジェクトのブランド
(TRACE = Threat Report Analyzer & Crawling **Engine**) を保持しつつ、
この衝突を避ける。

## 移行した動機

URL/PDF → STIX を BEACON から押し出した三つの圧力:

1. **CTI レポート取り込みの所有権を一本化**。BEACON のミッションは
   内部コンテキスト (assets / PIR)。外部 CTI レポートのパースは境界を
   またぐため、crawling と validation と同居させて TRACE に置くことで
   責務が綺麗になる。
2. **本格的な crawl ストーリー**。BEACON は単一 URL / PDF しか扱え
   なかった。TRACE はリスト駆動のバッチ crawl と `output/crawl_state.json`
   による content-hash 重複排除を追加する。
3. **SAGE 前段の単一検証ゲート**。TRACE は `assets.json`,
   `pir_output.json`, STIX バンドルに対する schema + semantic + human-review
   検証を所有する。SAGE は TRACE が承認した artifact のみを取り込む。

## BEACON 0.8 からの動作変更

- `crawl_single.py` の `--max-chars` のデフォルトは **30 000** (BEACON 0.8
  の動作と一致)。
- 出力ファイル名パターン `output/stix_bundle_<bundle-id-last-12>.json`
  は変更なし。
- STIX 抽出プロンプトは `--no-pir` (デフォルト) ケースでは変更なし。
  `--pir` 指定時はプロンプトに PIR コンテキスト (L3) が追加され、バンドルは
  `x_trace_*` メタデータで装飾される (L4) — TRACE `high-level-design.md`
  §6 参照。

## 検証

移行後:

- `BEACON/make check` — green (移行したテストを除いた 255 テストが pass)。
- `TRACE/make check` — green (移行した `test_stix_extractor.py` スイートで
  13 テストが pass、バイト等価な振る舞い)。
- 両プロジェクトとも `pip-audit` clean。
