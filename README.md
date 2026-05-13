# TRACE

**Threat Report Analyzer & Crawling Engine**

Collects CTI from public web sources (vendor blogs, news articles, PDF reports), filters each article against the organization's PIRs, and converts the relevant ones into [SAGE](https://github.com/sw33t-b1u/sage)-compatible **STIX 2.1 bundles** using Google Gen AI (Gemini). TRACE also acts as the validation gate that BEACON's `assets.json` / `pir_output.json` and TRACE's own STIX bundles must clear before SAGE ingestion.

[日本語版 README はこちら](README.ja.md)

> TRACE owns three responsibilities: PIR-driven web collection, STIX 2.1 bundle generation, and the SAGE input validation gate. SAGE only ingests artifacts that TRACE has validated.

## Overview

```
  URL or PDF (single)                input/sources.yaml (batch list)
         │                                       │
         └───────────────┬───────────────────────┘
                         │
                         ▼
              cmd/crawl_single.py / crawl_batch.py
                         │   --pir <BEACON pir_output.json>
                         │   ├── L2 relevance gate (flash-lite)
                         │   ├── L3 PIR-conditioned STIX extraction (Gemini)
                         │   └── L4 bundle metadata (matched_pir_ids, score)
                         ▼
              output/stix_bundle_*.json
                         │
                         ▼
              cmd/validate_stix.py  (cti-stix-validator + local refcheck)
                         │
                         ▼
                   [SAGE ETL]


  BEACON output (assets.json, pir_output.json,
                 identity_assets.json, user_accounts.json)
         │
         └───► cmd/validate_assets.py            (Pydantic + semantic refcheck)
         │
         └───► cmd/validate_pir.py               (Pydantic + taxonomy + asset-tag match)
         │
         └───► cmd/validate_identity_assets.py   (Identity + has_access cross-ref vs assets.json;
         │                                        Initiative A / Initiative C Phase 2 flags)
         │
         └───► cmd/validate_user_accounts.py     (UserAccount + account_on_asset cross-ref;
         │                                        Initiative B)
         │
         └───► cmd/validate_all.py               (one combined Markdown report)
                         │
                         ▼
              cmd/submit_review.py [--open-issue]
```

**Modes:**

| Mode | Input | LLM | Use case |
|------|-------|-----|----------|
| `crawl_single` | URL or PDF + (optional) PIR | flash-lite (gate) + Gemini (extract) | Analyst-driven on-demand ingestion |
| `crawl_batch`  | `input/sources.yaml` + (optional) PIR | flash-lite (gate) + Gemini (extract) | Periodic crawl with content-hash dedupe and PIR-driven filtering |
| `validate_*`   | JSON / STIX bundle | None | Pre-SAGE quality gate |

When `--pir` is supplied, articles are filtered through a lightweight relevance gate (L2) before STIX extraction, the extraction prompt is conditioned with PIR context (L3), and resulting bundles carry `x_trace_matched_pir_ids` / `x_trace_relevance_score` metadata (L4). Without `--pir`, the gate is bypassed and every article is fully extracted (useful for experimentation).

## Validation layers

1. **Schema** — Pydantic v2 models matching SAGE's input contract (`SAGE/cmd/load_assets.py`, `SAGE/src/sage/pir/filter.py`). STIX bundles go through OASIS [`stix2-validator`](https://github.com/oasis-open/cti-stix-validator).
2. **Semantic** — id uniqueness, reference integrity (e.g. `asset.network_segment_id` resolves), `threat_actor_tags` exist in the cached threat taxonomy, PIR `asset_weight_rules.tag` matches at least one asset tag.
3. **Human review** — every validation run produces a deterministic `output/validation_report_*.md`. `cmd/submit_review.py --open-issue` optionally posts the report to GitHub Enterprise.

## Documentation

| Document | EN / JA | Description |
|----------|---------|-------------|
| Setup | [setup.md](docs/setup.md) / [ja](docs/setup.ja.md) | Prerequisites, installation, environment variables, GCP authentication, CLI quick reference |
| Data model | [data-model.md](docs/data-model.md) / [ja](docs/data-model.ja.md) | Validation contracts: `assets.json`, `pir_output.json`, STIX bundle, `ValidationFinding` |
| Crawl design | [crawl_design.md](docs/crawl_design.md) / [ja](docs/crawl_design.ja.md) | `sources.yaml` schema (with annotated example), `crawl_state.json` semantics, L2/L3/L4 flow, dedupe strategy |
| Dependencies | [dependencies.md](docs/dependencies.md) / [ja](docs/dependencies.ja.md) | Dependency rationale and license information |
| BEACON handoff | [beacon_handoff.md](docs/beacon_handoff.md) | What moved out of BEACON and why |
| `high-level-design.md` | local-only; gitignored | Architecture, data model, algorithms |

## Quick Start

```bash
cd TRACE
uv sync --extra dev
make setup              # Install Git hooks
cp .env.example .env    # Fill in GCP_PROJECT_ID and other variables
```

See [docs/setup.md](docs/setup.md) for the full setup procedure and
[docs/crawl_design.md](docs/crawl_design.md) for the `input/sources.yaml`
schema before running `crawl_batch`.

## Development

```bash
make setup     # Install Git hooks (run once after cloning)
make check     # lint + test + audit (full quality gate)
make vet       # ruff check
make lint      # ruff format --check
make format    # ruff format + fix
make test      # pytest (unit tests)
make audit     # pip-audit
```

## References

- [OASIS STIX 2.1 specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [`oasis-open/cti-stix-validator`](https://github.com/oasis-open/cti-stix-validator)
- [SAGE](https://github.com/sw33t-b1u/sage) — downstream consumer
- BEACON — sibling tool that generates `assets.json` / `pir_output.json`

## License

Apache-2.0 — see [LICENSE](LICENSE)
