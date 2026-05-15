# BEACON → TRACE migration handoff

Japanese translation: [`docs/beacon_handoff.ja.md`](beacon_handoff.ja.md)

This note records what moved out of BEACON when TRACE was introduced
(BEACON 0.9.0 / TRACE 0.1.0), the rationale, and how to find the new home
of each piece.

## What moved

| BEACON path (removed) | TRACE path (new) |
|----------------------|------------------|
| `src/beacon/ingest/stix_extractor.py` | `src/trace_engine/stix/extractor.py` |
| `src/beacon/ingest/report_reader.py` | `src/trace_engine/ingest/report_reader.py` |
| `src/beacon/llm/prompts/stix_extraction.md` | `src/trace_engine/llm/prompts/stix_extraction.md` |
| `cmd/stix_from_report.py` | `cmd/crawl_single.py` |
| `tests/test_stix_extractor.py` | `tests/test_stix_extractor.py` |
| `tests/test_report_reader.py` | (re-introduced in TRACE Phase D when crawler tests are added) |
| `markitdown[pdf]` runtime dep | `pyproject.toml` (TRACE) |

`BEACON/cmd/stix_from_report.py` shipped as a deprecation stub in BEACON
0.9.x (redirect message + exit 2) and was deleted in BEACON 0.10.0.
`BEACON/cmd/validate_pir.py` followed the same lifecycle and was also
deleted in BEACON 0.10.0.

## What was copied (not moved)

`src/beacon/llm/client.py` is duplicated as
`src/trace_engine/llm/client.py`. We chose duplication over a shared
package because:

- The two projects are deployed independently and must each work in
  isolation (Rule 26: `internal/` is not importable across projects).
- Extracting a shared library is premature until SAGE also needs the
  same client; once that requirement appears we will hoist it into a
  third package.

## Why "trace_engine" instead of "trace"

The Python distribution name (PyPI / `pyproject.toml` `name`) is
`trace`, but the import package name is `trace_engine`. Python's
standard library ships a built-in `trace` module
(<https://docs.python.org/3/library/trace.html>) that takes precedence
over our package on `sys.path`, so `from trace.X import …` resolves to
the stdlib instead of our code. `trace_engine` keeps the project's
brand (TRACE = Threat Report Analyzer & Crawling **Engine**) while
avoiding the conflict.

## Why migrate at all

Three pressures pushed URL/PDF → STIX out of BEACON:

1. **Single ownership of CTI report ingestion.** BEACON's mandate is
   internal context (assets / PIR). External CTI report parsing
   straddles the boundary; co-locating it with crawling and validation
   in TRACE keeps the responsibility clean.
2. **A first-class crawl story.** BEACON only handled one URL or PDF at
   a time. TRACE adds list-driven batch crawling with content-hash
   deduplication via `output/crawl_state.json`.
3. **A single validation gate before SAGE.** TRACE owns schema +
   semantic + human-review validation for `assets.json`,
   `pir_output.json`, and STIX bundles. SAGE only ingests artifacts
   that TRACE has approved.

## Behavior changes vs. BEACON 0.8

- The default `--max-chars` for `crawl_single.py` is **30 000** (matches
  BEACON 0.8 behavior).
- The output filename pattern `output/stix_bundle_<bundle-id-last-12>.json`
  is unchanged.
- The STIX extraction prompt is unchanged for the `--no-pir` (default)
  case. When `--pir` is supplied, the prompt is augmented with PIR
  context (L3) and the bundle is decorated with `x_trace_*` metadata
  (L4) — see TRACE `high-level-design.md` §6.

## Verification

After the migration:

- `BEACON/make check` — green (255 tests pass after removing the
  migrated tests).
- `TRACE/make check` — green (13 tests pass — the migrated
  `test_stix_extractor.py` suite, byte-equivalent behavior).
- `pip-audit` clean in both projects.
