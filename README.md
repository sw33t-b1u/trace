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
              StorageBackend stix/ (default) or --output / --output-dir path
              output/stix/stix_bundle_<YYYYMMDDHHmm>.json
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

## Documentation

| Document | Description |
|----------|-------------|
| [docs/setup.md](docs/setup.md) | Clone, install, configure, test, first run |
| [docs/deploy.md](docs/deploy.md) | Cloud Run Job deployment and Cloud Scheduler |
| [docs/usage.md](docs/usage.md) | CLI commands, crawl workflows, operations, troubleshooting |
| [docs/data-model.md](docs/data-model.md) | Validation schemas, STIX bundle format |
| [docs/crawl_design.md](docs/crawl_design.md) | Crawler architecture, L2-L4 pipeline |
| [docs/structure.md](docs/structure.md) | Project directory layout |
| [docs/dependencies.md](docs/dependencies.md) | Dependency rationale and licenses |
| [docs/api-stability.md](docs/api-stability.md) | API stability policy and BC guarantees |

Cross-project:
- [BEACON pipeline-guide.md](https://github.com/sw33t-b1u/beacon/blob/main/docs/pipeline-guide.md) — End-to-end CTI pipeline
- [BEACON citations.md](https://github.com/sw33t-b1u/beacon/blob/main/docs/citations.md) — External citations and license inventory
- [SAGE ir-feedback-flow.md](https://github.com/sw33t-b1u/sage/blob/main/docs/ir-feedback-flow.md) — IR feedback loop and scoring formulas

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
