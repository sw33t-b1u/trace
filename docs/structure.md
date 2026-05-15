# TRACE Directory Structure

Japanese translation: [`docs/structure.ja.md`](structure.ja.md)

This document records TRACE's top-level layout and the rationale for the
places where it deviates from the suggested structure in `docs/RULES.md`
Rule 26. The rule explicitly allows adaptation; this file is that
adaptation's authoritative record.

## Layout

```
TRACE/
├── cmd/                # CLI entry points (crawl_single, crawl_batch,
│                       #   validate_stix, enrich_bundle, …). One file per
│                       #   command; each calls into src/trace_engine.
├── docs/               # English documentation + .ja.md translations
│                       #   (Rule 11). Includes high-level-design.md
│                       #   (gitignored per maintainer policy; see
│                       #   `.gitignore` entry `docs/high-level-design.md`).
├── input/              # Operator-managed inputs (sources.yaml, sample
│                       #   STIX bundles). Runtime artifacts — gitignored.
├── output/             # Crawl state, generated bundles, validation
│                       #   reports. Runtime artifacts — gitignored.
├── schema/             # JSON schemas (pir.schema.json,
│                       #   threat_taxonomy.cached.json, etc.).
├── scripts/            # Helper scripts (e.g., check_pir_schema_drift.py
│                       #   used by `make check`). Not imported by the
│                       #   src package.
├── src/                # Python source root (see "src layout" below).
├── tests/              # pytest suite (unit + integration markers).
├── .githooks/          # pre-commit / pre-push hooks installed by
│                       #   `make setup` (Rule 20).
├── CHANGELOG.md        # Keep a Changelog format (Rule 22).
├── LICENSE
├── Makefile            # Quality gate: vet → lint → test → audit (Rule 20).
├── pyproject.toml      # uv-managed Python project (Rule 15).
├── README.md / README.ja.md
└── uv.lock             # Committed lock file (Rule 15).
```

## src layout (deviation from Rule 26)

Rule 26 suggests Go-style `internal/` and `pkg/` for source code. TRACE
uses `src/trace_engine/` instead. Reasons:

1. **Python convention.** `src/<package>/` is the canonical packaging
   layout for `pyproject.toml`-based Python projects and is what
   `setuptools.packages.find` consumes via `where = ["src"]`. Splitting
   into `internal/` and `pkg/` would force an import-name change and
   yield no isolation benefit (Python imports are not bound by directory
   name).
2. **Single-distribution scope.** TRACE is a single distribution with no
   public re-usable subpackages today. The "internal vs. public" split
   has no consumer yet.
3. **Mirrors BEACON / SAGE.** All three sibling projects use the same
   `src/<package_name>/` shape so contributors do not context-switch.

### Subpackages under `src/trace_engine/`

| Path | Responsibility |
|------|----------------|
| `cli/` | Shared helpers used by `cmd/*` entry points (argparse glue, metrics). |
| `config.py` | `Config.from_env()` — environment-driven settings (Rule 24). |
| `crawler/` | Batch fetch, state, taxonomy auto-sync. |
| `ingest/` | Report → Markdown adapters (`report_reader.py`). |
| `llm/` | Vertex AI Gemini client + prompt assets. Duplicated from BEACON; see [`beacon_handoff.md`](beacon_handoff.md). |
| `pir/` | L2 PIR relevance gate. |
| `review/` | Human-review handoff (Markdown / GHE Issue). |
| `stix/` | L3 extraction, L4 bundle assembly, taxonomy enrichment, external-ref hashing. |
| `validate/` | Schema + semantic validators (PIR, assets, STIX). |

## Mapping to Rule 26's suggested directories

| Rule 26 dir | TRACE equivalent | Notes |
|-------------|------------------|-------|
| `api/` | `schema/` | TRACE exposes JSON schemas, not OpenAPI/protobuf. |
| `cmd/` | `cmd/` | Same. One file per executable entry point. |
| `internal/` | `src/trace_engine/` | Python has no enforced `internal/` mechanism. |
| `pkg/` | (none) | No public re-usable library surface today. |
| `scripts/` | `scripts/` | Same. Helper scripts only; not imported by `src/`. |

## Out-of-tree expectations

TRACE assumes the BEACON sibling repo lives at `../BEACON` when present
(used by `make check-pir-schema-drift` and the taxonomy auto-sync in
`src/trace_engine/crawler/taxonomy_sync.py`). Both paths are overridable
via env (`TRACE_BEACON_TAXONOMY_SOURCE`) and degrade gracefully when the
sibling is absent so TRACE-only contributors can still run `make check`.
