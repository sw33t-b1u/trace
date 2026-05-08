# TRACE Dependencies

Per RULES.md Rule 18, every runtime dependency carries a justification. This
document is the canonical record. The list mirrors `pyproject.toml`; if you
add a new dependency, update both files in the same commit.

## Runtime

| Package | Min version | Why TRACE needs it | License |
|---------|-------------|--------------------|---------|
| `pydantic` | `>=2.0` | Schema layer for `assets.json`, `pir_output.json`, `sources.yaml`, and the `ValidationFinding` data model. v2 is required for `RootModel` and the post-init `model_validator(mode="after")` we use to enforce `valid_from < valid_until`. | MIT |
| `google-genai` | `>=1.0` | Vertex AI Gemini client for the L2 PIR relevance gate (`gemini-2.5-flash-lite`) and L3 STIX extraction (`gemini-2.5-flash` / `pro`). Same SDK BEACON uses, so the duplicated `llm/client.py` stays in sync at the SDK boundary. | Apache-2.0 |
| `structlog` | `>=24.4.0` | Structured JSON logging across all entry points; Rule 19 mandates structured logs. | MIT / Apache-2.0 |
| `httpx` | `>=0.27.0` | Synchronous HTTP client for the batch crawler's `fetcher.py` and the GHE Issue client in `review/github.py`. | BSD-3 |
| `cryptography` | `>=46.0.7` | Pin to the CVE-2026-39892 fix. Transitive via `google-genai` and TLS validation in `httpx`. Mirrors BEACON's pin. | Apache-2.0 / BSD |
| `markitdown[pdf]` | `>=0.1.0` | Converts PDF / URL inputs to clean Markdown for the L3 prompt. The `[pdf]` extra pulls in `pdfminer.six`. Migrated from BEACON 0.8.x. | MIT |
| `stix2-validator` | `>=3.2` | OASIS `cti-stix-validator`. Schema + best-practice checks on STIX 2.1 bundles before they enter SAGE. We layer local id/refcheck/kill-chain checks on top in `validate/semantic/stix_refcheck.py`. | BSD-3 |
| `pyyaml` | `>=6.0` | Parser for `input/sources.yaml` (loaded via `crawler/sources.py`). | MIT |
| `python-dotenv` | `>=1.0` | Load `.env` into `os.environ` at CLI startup so `GCP_PROJECT_ID`, `TRACE_GHE_TOKEN`, etc. are picked up without exporting manually. | BSD-3 |

## Development

| Package | Min version | Why | License |
|---------|-------------|-----|---------|
| `ruff` | `>=0.6.0` | Lint + format. Configured in `pyproject.toml`. | MIT |
| `pytest` | `>=9.0.3` | Test runner. Integration tests are gated behind `-m integration`. | MIT |
| `pytest-cov` | `>=5.0.0` | Coverage reporting (used by Makefile when requested). | MIT |
| `pip-audit` | `>=2.7.0` | Vulnerability scan in `make check` (Rule 21). | Apache-2.0 |

## Intentionally NOT pulled in

| Package | Reason |
|---------|--------|
| `feedparser` | RSS / Atom expansion is not in the MVP. `sources.yaml` is a flat URL list. Re-evaluate when batch crawl operators ask for it. |
| `sqlite3` (separate dep) | A single JSON state file with `tmp + os.replace` is sufficient at MVP scale. Re-evaluate if concurrent batch crawls become a requirement. |
| `fastapi` / `uvicorn` | Web UI is deferred to Phase 2 of TRACE. Keeping the dependency surface small until that's actually built. |
| `stix2` | TRACE assembles bundles as plain `dict` objects keyed by the STIX 2.1 spec; we don't need the full `stix2` object model. The OASIS validator covers spec compliance. |

## Duplication with BEACON

`src/trace_engine/llm/client.py` is a verbatim copy of
`BEACON/src/beacon/llm/client.py`. Likewise, `src/trace_engine/review/github.py`
mirrors `BEACON/src/beacon/review/github.py` with a TRACE-flavored
`submit_validation_report` (one Issue per validation report) instead of
BEACON's per-PIR `submit_pirs_for_review`.

The duplication is deliberate (Rule 26: `internal/` packages cannot be
imported across project boundaries). Once SAGE also acquires an LLM-callable
component, we will extract the client into a shared package and remove the
duplication in lockstep across all three projects.

## CVE history

| CVE | Package | Fix | Notes |
|-----|---------|-----|-------|
| CVE-2026-39892 | `cryptography` | `>=46.0.7` | Pinned at TRACE 0.1.0 to match BEACON's pin. |
