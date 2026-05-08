# TRACE Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). Versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.2.0] — 2026-05-09

### Changed — STIX extraction split into LLM-extract + code-build (BREAKING)

The L3 pipeline no longer asks the LLM to emit STIX 2.1 objects directly.
Instead the LLM returns a structured ``Extraction`` (entities and
relationships keyed by short ``local_id`` aliases) and TRACE's code
assembles the STIX 2.1 bundle. This eliminates the wire-format mistakes
that the LLM kept making — non-UUIDv4 ids, ``HH:mm:ss:sss`` timestamps,
duplicate ids, dangling cross-references — by removing the LLM's chance
to make them at all.

**Public API changes** (any caller importing from `trace_engine.stix.extractor`):

- Removed `extract_stix_objects(text, ...) -> list[dict]`.
  Replaced by `extract_entities(text, ..., pir_doc=None) -> Extraction`.
- Removed `build_stix_bundle(objects, ...) -> dict`.
  Replaced by `build_stix_bundle_from_extraction(extraction, source_url=None,
  collected_at=None, matched_pir_ids=None, relevance_score=None,
  relevance_rationale=None) -> dict`.
- New dataclasses exported: `Extraction`, `ExtractedEntity`,
  `ExtractedRelationship`.
- Module constant rename: `_VALID_STIX_TYPES` → `_VALID_ENTITY_TYPES`
  (now excludes `relationship`, which is no longer an entity type).
  Added `_VALID_RELATIONSHIP_TYPES = {"uses", "exploits", "indicates"}`.

**Prompt change**: `src/trace_engine/llm/prompts/stix_extraction.md` was
fully rewritten. The LLM is now asked for
`{entities: [{local_id, type, name, …}], relationships: [{source, target,
relationship_type}]}` only — no `id`, `spec_version`, `created`,
`modified`, or `source_ref`/`target_ref` fields.

### Added

- ``Extraction`` / ``ExtractedEntity`` / ``ExtractedRelationship`` dataclasses
  in `trace_engine.stix.extractor` to model the LLM's structured output.
- L2 partial-JSON salvage: when Gemini truncates the verdict JSON
  (typically inside `rationale`), `pir.relevance.evaluate` now extracts
  `score` and `matched_pir_ids` via regex and proceeds with a real
  decision instead of failing open. Verdicts where the rationale was
  cut off are recorded as `rationale="(truncated)"`.

### Removed

- `_normalize_stix_objects` post-processing in `stix.extractor` is gone.
  UUIDv4 ids and millisecond-precise timestamps are now produced by
  construction in `build_stix_bundle_from_extraction`, so there is
  nothing left to coerce.
- Tests `tests/test_stix_postprocess.py` (post-processor is gone).

### Fixed

- OASIS `{103}` UUIDv4 validity errors caused by LLM emitting sequential
  or non-v4 ids (`12345678-90ab-cdef-1234-…`).
- STIX timestamp format errors caused by LLM writing
  `2026-04-11T00:00:00:000Z` (colon) instead of the spec's
  `2026-04-11T00:00:00.000Z` (dot).
- Duplicate STIX ids in a single bundle when the LLM reused the same id
  across multiple objects.
- L2 relevance gate failing open on every article whose response Gemini
  truncated mid-`rationale` (the prior cause of bundles being generated
  for clearly off-topic articles when `--pir` was supplied).

### Documentation

- HLD §5.2 (STIX bundle output schema), §6.1 (single-URL pipeline), and
  §6.3 (L2 verdict shape) rewritten to describe the new flow.
- `docs/data-model.md` STIX section reorganised around "LLM extracts,
  code builds".
- `docs/crawl_design.md` §4 split into L3 (entity extraction) + §4a
  (L4 bundle assembly).

---

## [0.1.0] — 2026-05-08

### Added — Initial scope

**PIR-driven web collection (URL / PDF → STIX 2.1 bundle):**
- `cmd/crawl_single.py` — on-demand single URL or PDF ingestion
- `cmd/crawl_batch.py` — list-driven batch crawl from `input/sources.yaml`
  with URL × content-SHA256 deduplication via `output/crawl_state.json`
- L2 relevance gate (`src/trace_engine/pir/relevance.py`) — when `--pir` is
  supplied, articles below the configurable relevance threshold are
  skipped before STIX extraction (`gemini-2.5-flash-lite` by default).
  Skip decisions are recorded in `crawl_state.json` with the originating
  PIR set's hash so re-evaluation is possible after PIR updates
  (`crawl_batch --recheck-on-pir-change`).
- L3 PIR-conditioned extraction — when a PIR document is loaded, the
  STIX extraction prompt is augmented with the PIR's `threat_actor_tags`,
  `notable_groups`, and `collection_focus` to bias the LLM towards
  relevant entities.
- L4 bundle metadata — every emitted bundle carries
  `x_trace_source_url`, `x_trace_collected_at`, and (when the gate ran)
  `x_trace_matched_pir_ids`, `x_trace_relevance_score`, and
  `x_trace_relevance_rationale`. SAGE ignores unknown `x_*` properties.
- Migrated from BEACON: `report_reader` (markitdown-based PDF/URL extraction),
  `stix_extractor` (Vertex AI Gemini → STIX object array),
  `prompts/stix_extraction.md`. The previous BEACON CLI
  `cmd/stix_from_report.py` is replaced with a deprecation stub for one
  release before deletion.

**Validation gate (BEACON / TRACE outputs → SAGE):**
- `cmd/validate_assets.py` — Pydantic schema check against SAGE's
  `assets.json` contract (`SAGE/cmd/load_assets.py`,
  `SAGE/tests/fixtures/sample_assets.json`) plus reference-integrity checks
  (id uniqueness, `network_segment_id` / `security_control_ids` /
  `asset_connections.{src,dst}` / `asset_vulnerabilities.asset_id` resolve)
- `cmd/validate_pir.py` — Pydantic schema check against SAGE's PIR contract
  (`SAGE/src/sage/pir/filter.py:25-39`) plus taxonomy presence check for
  `threat_actor_tags`, asset-tag match for `asset_weight_rules.tag`, and
  `valid_from < valid_until`. **Supersedes BEACON's
  `cmd/validate_pir.py`** (which performed schema-only validation);
  BEACON keeps a deprecation stub for one release.
- `cmd/validate_stix.py` — OASIS `stix2-validator` plus local checks for
  bundle id uniqueness, `relationship.{source_ref,target_ref}` resolution,
  `kill_chain_name == "mitre-attack"`, and `bundle.spec_version == "2.1"`
- `cmd/validate_all.py` — aggregate runner producing a single Markdown
  report at `output/validation_report_<ts>.md`

**Human review support:**
- `cmd/submit_review.py` — emits the Markdown report; opt-in
  `--open-issue` posts the report as a GitHub Enterprise issue (mirrors
  BEACON's `cmd/submit_for_review.py` pattern, duplicated rather than
  imported)

**Auxiliary tooling:**
- `cmd/generate_schemas.py` — exports Pydantic models to
  `schema/*.schema.json`
- `cmd/update_taxonomy_cache.py` — refreshes
  `schema/threat_taxonomy.cached.json` from BEACON's authoritative file

### Documentation

- `high-level-design.md` (Japanese, mirrors BEACON convention)
- `README.md` / `README.ja.md`
- `docs/setup.{md,ja.md}`, `docs/data-model.{md,ja.md}`,
  `docs/crawl_design.{md,ja.md}`, `docs/dependencies.{md,ja.md}`,
  `docs/beacon_handoff.md`

### Project layout

- `pyproject.toml` (uv + ruff, name=`trace`, Python ≥ 3.12)
- `Makefile` with `check / vet / lint / test / audit / format / setup`
  targets matching BEACON
- `.githooks/` for pre-commit (`make vet lint`) and pre-push (`make check`)

### Notes

- The Python import package is named **`trace_engine`** even though the
  distribution name is `trace`. Python's stdlib ships a built-in `trace`
  module that would shadow our package; `trace_engine` borrows the
  "Engine" from "Threat Report Analyzer & Crawling Engine" to keep the
  project's brand while avoiding the conflict.
- BEACON `0.8.x → 0.9.0` (minor bump) accompanies this release: removes
  URL→STIX extraction (`cmd/stix_from_report.py`, `src/beacon/ingest/{report_reader,stix_extractor}.py`,
  the `markitdown[pdf]` dependency, and the corresponding tests). The
  schema-only `BEACON/cmd/validate_pir.py` remains in 0.9.0 and will be
  replaced by TRACE's richer `validate_pir.py` in a follow-up release
  (Phase C of TRACE).
- BEACON output artifact schemas (`assets.json`, `pir_output.json`) are
  unchanged.
- Web UI (FastAPI single-URL form) is deferred to a follow-up release.
- RSS/atom feed expansion in `sources.yaml` is deferred. MVP supports
  flat URL lists only.
- Relevance gate fails open: if the LLM relevance call errors out, the
  article proceeds to STIX extraction (rather than being silently
  dropped) so the failure is visible in the validation report.
