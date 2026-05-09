# TRACE Changelog

All notable changes to this project will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). Versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.0.2] — 2026-05-09

### Fixed — `{401}` vulnerability.aliases + `{202}` actor-source exploits

Real-URL FIN7 verification on TRACE 1.0.1 produced `errors=0
warnings=2`. Both warnings traced to LLM choices that the bundle
assembler now corrects.

#### `{401}` vulnerability.aliases → labels

STIX 2.1 §4.18 vulnerability does not define `aliases`. The L3 LLM
occasionally puts CVE alternate names ("ProxyLogon", "EternalBlue")
under that key. Added a vulnerability branch in
`_apply_required_property_defaults` that demotes the list into
`labels` (open vocab on common SDO properties) so the alternate names
survive without the {401} flag. Existing `labels` entries are
preserved with order; merged values dedupe.

New helper `_demote_list_to_labels` covers the list-shaped
counterpart of 0.5.2's `_demote_property_to_labels`.

#### `{202}` `intrusion-set / threat-actor / campaign exploits` → drop

STIX 2.1 §4.13 lists `malware` as the only suggested source for
`exploits`. Actor-side "exploits vulnerability" semantics are
expressed via `targets` (`intrusion-set targets vulnerability`,
already in the table). Tightened
`_RELATIONSHIP_TYPE_TABLE`:

```python
# Before
("malware", "exploits"): frozenset({"vulnerability"}),
("intrusion-set", "exploits"): frozenset({"vulnerability"}),
("threat-actor", "exploits"): frozenset({"vulnerability"}),
("campaign", "exploits"): frozenset({"vulnerability"}),

# After
("malware", "exploits"): frozenset({"vulnerability"}),
```

LLM-emitted `intrusion-set exploits vuln` falls through the existing
`relationship_type_mismatch_dropped` guard. The L3 prompt already
points actors at `targets`, so a follow-up prompt edit is unnecessary.

### Tests

- 6 new cases:
  - `TestVulnerabilityAliasesDemotion` (2): aliases moves to labels,
    existing labels preserved with merge dedupe.
  - `TestExploitsSourceTightening` (4): malware-exploits-vuln kept,
    intrusion-set-exploits-vuln dropped, intrusion-set-targets-vuln
    kept (the canonical replacement), threat-actor-exploits-vuln
    dropped.

### Compliance

Combined with all prior 0.x.x and 1.0.x defenses, FIN7-class bundles
now produce `errors=0` and only the documented SHOULD-level `{202}`
accepted warnings remain (`tool uses {malware,tool}` and
`attack-pattern uses attack-pattern`).

---

## [1.0.1] — 2026-05-09

### Fixed — Residual {215} / {303} warnings on FIN7-class bundles

Real-URL FIN7 verification on TRACE 1.0.0 produced a 177-object bundle
that validated `errors=0 warnings=19`. Three warning categories
remained, two of them mechanically fixable.

#### {215} `identity.sectors` outside `industry-sector-ov`

Same demote-to-labels pattern as 0.5.1 / 0.5.2:
`_STIX21_INDUSTRY_SECTOR_OV` constant added (33 STIX 2.1 §6.6 values),
`_filter_open_vocab` invoked in the identity branch of
`_apply_required_property_defaults`. Out-of-vocab values like
`fintech`, `card-payments`, `electronic-money` move to `labels`;
in-vocab values stay in `sectors`.

#### {303} indicator missing `name` / `description`

STIX 2.1 §4.7 SHOULD: indicators carry both. The L3 LLM frequently
emits `pattern` only. Added defaults in
`_apply_required_property_defaults`:

- `name` → `_derive_indicator_name(pattern)` synthesises a short
  label from the SCO type and first quoted value
  (`[ipv4-addr:value = '198.51.100.1']` → `ipv4-addr: 198.51.100.1`).
  Falls back to `Indicator: <type>` when the pattern uses quoted
  property names like `hashes.'SHA-256'` that don't match the simple
  pattern parser.
- `description` → `"Indicator extracted from CTI report"` (generic
  fallback). Existing values from the LLM win via `setdefault`.

### Documented — `attack-pattern uses attack-pattern` accepted

`{202}` warnings for this combination are now in the
"Accepted OASIS validator warnings" section of
`docs/data-model.{md,ja.md}`. The relationship is the canonical way
to express MITRE ATT&CK sub-technique chaining; dropping it would
erase the technique hierarchy from the attack graph. Same SHOULD-level
acceptance as the 0.5.2 `tool uses {malware,tool}` cases.

### Tests

- 7 new cases in `tests/test_stix_extractor.py`:
  - `TestIdentitySectorsDemotion` (2): in-vocab preserved,
    out-of-vocab demoted to labels.
  - `TestIndicatorNameDescriptionDefaults` (4): IPv4 pattern → name
    derived, file-hash pattern → type fallback name, existing name
    preserved, existing description preserved.
- Existing `TestRequiredPropertyDefaults::test_indicator_gets_pattern_type_default`
  still passes — the new name/description defaults don't override
  prior LLM output.

### Compliance

Combined with 0.3.2 / 0.4.0 / 0.5.x / 0.6.x / 0.7.0 / 0.8.0 / 1.0.0,
FIN7-class bundles now produce `errors=0` and only the documented
SHOULD-level `{202}` accepted warnings remain.

---

## [1.0.0] — 2026-05-09

### Added — `identity` SDO + `targets` relationship (paired with SAGE 0.5.0)

Verizon DBIR 2025 (stolen credentials = #1 initial access at 22%) and
CrowdStrike GTR 2025 (valid account abuse = #1 cloud vector at 35%)
made the credential / org-targeting blind spot unavoidable. 1.0.0
extends the L3 extraction vocabulary so reports about FIN7 spear-
phishing the CFO, or APT29 targeting a specific finance department,
land in SAGE's attack graph as a real edge instead of being lost in
prose.

#### Entity vocabulary

- `_VALID_ENTITY_TYPES += "identity"` — STIX 2.1 §4.4 SDO. The
  L3 prompt now describes when to extract identity records and how to
  pick `identity_class` from the §6.7 vocabulary.

#### Relationship vocabulary

- `_VALID_RELATIONSHIP_TYPES += "targets"` — STIX 2.1 §4.13. Source
  vocabulary: `attack-pattern, campaign, intrusion-set, malware,
  threat-actor, tool`. Target vocabulary: `identity, location,
  vulnerability, infrastructure`.

`_RELATIONSHIP_TYPE_TABLE` extended with six `("<source>", "targets")`
entries enumerating the suggested target types. Source/target pairs
outside the table are dropped at bundle assembly time with the
existing structured-log warning (`relationship_type_mismatch_dropped`).

#### Open-vocab demotion for `identity_class`

Same pattern as 0.5.1 (`tool_types`, `malware_types`) and 0.5.2
(`sophistication`): when the LLM picks an identity class outside
STIX 2.1 §6.7 (e.g., "executive"), demote it to `labels` (open vocab)
and clear the field. Information survives, validator stays clean.

`_demote_scalar_to_labels_if_outside` is the new helper for scalar
properties with an open-vocab guard.

### SAGE coordination

- SAGE 0.5.0 ships in lockstep, adding the `Identity` Spanner table
  and the `ActorTargetsIdentity` edge.
- SAGE only stores `targets` edges sourced from `threat-actor` /
  `intrusion-set`. Other valid sources (`malware`, `tool`,
  `attack-pattern`, `campaign`) survive TRACE's bundle but are
  dropped at SAGE's `map_relationship` with a structured-log warning.
  This is documented as a 0.6.0+ extension point on the SAGE side.

### L3 prompt update

`stix_extraction.md` gained an `identity` section explaining when to
extract (named victims, targeted roles, affected organisations) and
how to pick `identity_class`. The relationship-type list now includes
the `targets` row covering source / target combinations TRACE
accepts.

### Tests

- Updated existing
  `test_valid_entity_and_relationship_vocabularies_are_disjoint` —
  asserts `targets` is now in the relationship vocabulary and
  `identity` is in the entity vocabulary.
- 7 new cases:
  - `TestIdentityEntity` (3) — minimal identity, in-vocab class
    preserved, out-of-vocab class demoted to labels.
  - `TestTargetsRelationship` (4) — actor → identity kept, threat-
    actor → vulnerability kept, identity → actor (reversed) dropped,
    indicator → identity (invalid source) dropped.

### BREAKING (vocabulary expansion)

Any downstream consumer that filtered on the previous tight
relationship-type set (`uses`, `exploits`, `indicates`) will now
encounter `targets` records and `identity` objects. SAGE 0.5.0 is the
canonical consumer; other consumers must add identity/targets handling
or filter explicitly.

### Future scope (deferred to 1.1.0+)

- `user-account` SCO support via `observed-data` SDO — credential-
  level granularity finer than the per-person Identity node.
- `attributed-to` relationship for actor → identity attribution.
- `impersonates` relationship for actor → identity (BEC use case).
- BEACON-side identity-asset metadata to populate
  `Identity → Asset HasAccess` edges in SAGE.

---

## [0.8.0] — 2026-05-09

### Added — Concurrent batch crawl

Sequential `crawl_batch` execution dominated wall-clock time on
list-driven runs — every URL waited on Gemini round-trips before the
next URL even started. Per-URL work is mostly I/O-bound (httpx fetches,
Gemini calls, ATT&CK URL hashing), so a small thread pool yields
near-linear speedup until the Vertex AI quota is the bottleneck.

`crawl_batch(...)` now accepts `max_workers` (defaults to
`Config.crawl_concurrency`, env `TRACE_CRAWL_CONCURRENCY`, default 4):

- `max_workers <= 1` keeps the legacy sequential generator behaviour —
  bit-for-bit identical for existing callers and tests.
- `> 1` dispatches sources to a `ThreadPoolExecutor` and yields outcomes
  in **completion order** (not source order). Each worker thread runs
  a self-contained `_process_source` invocation.

#### Per-URL work refactored to `_process_source`

The big inline for-loop body that previously lived inside
`crawl_batch` is now a top-level helper. The function returns one
`BatchOutcome` per source. The main `crawl_batch` either calls it in a
plain loop (sequential) or submits it to the executor.

The new `BatchOutcome.metrics` field carries the per-URL
`_RunMetrics` when a metrics collector is registered. The CLI driver
no longer manages metrics lifecycle inline — it just collects
`outcome.metrics` from each yielded record.

### Changed — `MetricsCollector` is thread-local

The 0.7.0 collector held a single active run on the instance, which
would have collapsed concurrent worker runs into one shared bag. The
0.8.0 collector keeps an active run **per thread id** (`dict[int,
_RunMetrics]`, lock-protected). `start_run` / `finish_run` /
`__call__` all consult the current thread's entry. Single-threaded
callers see no behaviour change.

### Changed — `CrawlState` is concurrency-safe

`get` / `upsert` mutations are now serialised through a
`threading.Lock`. The atomic `tempfile + os.replace` write in `save()`
already protected disk consistency; the new lock protects the
in-memory `entries` dict during concurrent worker access.

### Tests

- 2 new cases in `tests/test_crawl_batch.py`:
  - `test_concurrent_crawl_processes_all_sources` — 8 URLs through 4
    workers; every URL emits exactly one outcome.
  - `test_concurrent_state_upserts_dont_corrupt` — 20 URLs through 8
    workers; every URL has a state entry afterwards (no race losses).
- 1 new case in `tests/test_cli_metrics.py::TestThreadLocalRuns` —
  two threads run independent runs simultaneously without interfering.

### Operational notes

- Vertex AI per-tier QPM caps are not actively rate-limited by TRACE.
  Bumping `crawl_concurrency` past Vertex AI's `gemini-2.5-flash`
  quota will surface as `google.api_core.exceptions.ResourceExhausted`
  errors logged at `extract_entities` call sites; the worker's outcome
  will be `extraction_failed`. Recommended range 1..8.
- Outcome order is no longer deterministic for `max_workers > 1`. The
  state file and bundle outputs are unchanged; only the order of CLI
  log lines and per-URL summaries differ run-to-run.

---

## [0.7.0] — 2026-05-09

### Added — Per-run metrics collection

Chunked extraction (0.3.0) multiplied the number of LLM calls per
crawl, but operators had no way to see token consumption, parse
failures, or defense activations except by reading raw structured
logs. 0.7.0 adds a non-intrusive metrics layer.

#### `MetricsCollector` (`src/trace_engine/cli/_metrics.py`)

- Registered as a structlog **processor** in
  ``cli/_logging.py`` so existing log call sites are unaffected.
- Inspects each log record's ``event`` field and updates an in-memory
  ``_RunMetrics`` for the active run (lifecycle: ``start_run`` /
  ``finish_run``).
- Records that arrive while no run is active are passed through
  untouched — non-CLI callers (tests, library use) see no behaviour
  change.

#### Tracked counters

- **L2**: model_tier, score, matched_pir_ids, salvaged / failed flags.
- **L3**: model, task, chunks, chunk_chars_max, llm_calls,
  llm_output_chars_total, parse_failures, raw_entities,
  merged_entities, raw_relationships, merged_relationships.
- **Defenses**: indicators_dropped_invalid_pattern,
  relationships_dropped_unresolved,
  relationships_dropped_type_mismatch, external_ref_fetched,
  external_ref_fetch_failed.
- **Per-tier LLM totals**: `simple` / `medium` / `complex` calls and
  output character counts (rolling totals).
- **Bundle**: path, entities, relationships, object_count.

#### `crawl_single` integration

- Starts a run on entry, finishes on bundle write.
- Prints a human-readable summary to stdout after the bundle line:

  ```
  === Run summary ===
  Input:        https://example.com/post (8,000 body / 10,000 raw chars)
  L2:           score=0.60 → kept matched=PIR-001
  L3:           3 chunks, 3 LLM calls, 30,000 output chars, 0 parse failures
                raw 60/45 → merged 46/45 (entities/relationships)
  Bundle:       92 objects (46 entities, 45 relationships) → output/bundle.json
  Defenses:     2 ATT&CK URLs hashed, 1 indicators dropped (bad pattern)
  Duration:     12.3s
  Metrics:      output/run_metrics_<ts>_<id8>.json
  ```

- Persists the full structured payload as JSON in
  ``output/run_metrics_<ts>_<id8>.json``.

#### `crawl_batch` integration

- Starts a run **per source URL** (option (a) of the design poll). The
  generator-driven loop calls ``finish_run`` on each yielded outcome
  and ``start_run`` for the next URL before resuming.
- All per-URL summaries print to stdout in order, followed by a
  combined ``output/run_metrics_batch_<ts>.json`` containing every
  run plus a ``summary`` section with batch-level totals.

### Tests

- 13 new cases in `tests/test_cli_metrics.py` covering full
  lifecycle observation, L2 failure / salvage paths, parse-failure
  counting, processor pass-through semantics, atomic JSON write,
  batch-summary aggregation, and unknown-event resilience.

### Compatibility

- No public API changes. Library callers
  (`extract_entities`, `build_stix_bundle_from_extraction`,
  `validate_*` modules) behave identically. Metrics collection is
  opt-in via ``_metrics.install_collector()`` from CLI entry points
  only.

---

## [0.6.1] — 2026-05-09

### Fixed — Defensive guards for the more permissive 0.6.0 prompt

The 0.6.0 prompt strengthening lifted FIN7-class extraction from 40 to
61 entities (+52%) but exposed three classes of LLM mistake the bundle
assembler had not previously needed to defend against. Real-URL
verification regressed validation from `errors=0 warnings=0` to
`errors=5 warnings=4`. 0.6.1 adds three structural defenses; the
validator now returns to `errors=0` (and {202} warnings limited to the
two TRACE-accepted exceptions documented in 0.5.2).

#### 1. Empty-array scrub

`_scrub_empty_arrays` strips keys whose value is an empty list. STIX
2.1 disallows `aliases: []` / `labels: []` / `kill_chain_phases: []`
etc.; the LLM emitted these when nothing was known about the field.
Removing the key entirely satisfies the validator.

#### 2. STIX patterning syntax validation

`_validate_indicator_pattern` parses the indicator's `pattern` with
`stix2patterns.v21.pattern.Pattern` (transitive dep of
`stix2-validator`). Indicators with malformed STIX patterns are
dropped with a structured-log warning; relationships pointing at the
dropped indicator fall through the existing dangling-ref guard.

Only `pattern_type == "stix"` is parsed — YARA, Snort, PCRE patterns
pass through untouched (the OASIS validator handles those languages).

#### 3. Relationship type table (STIX 2.1 §4.13)

`_RELATIONSHIP_TYPE_TABLE` enumerates the suggested
`(source_type, relationship_type) → {target_types}` mapping for the
three relationships TRACE emits (`uses`, `exploits`, `indicates`).
`_is_relationship_suggested` filters out violators before bundle
assembly with a structured-log warning. The two 0.5.2-accepted
exceptions (`tool uses malware`, `tool uses tool`) are encoded as
table allow-list entries.

This drops common LLM mistakes:

- `malware indicates X` → only indicator may indicate (drop)
- `attack-pattern exploits X` → only malware/intrusion-set/threat-actor/campaign may exploit (drop)
- `indicator indicates indicator` → indicator is not in the suggested target set for `indicates` (drop)

### Tests

- 11 new cases in `tests/test_stix_extractor.py` covering all three
  defenses: empty-array scrub (preserved vs removed), pattern
  validation (valid/malformed/YARA/dangling-rel cascade), and the
  relationship type table (kept/dropped per source-target combo).

---

## [0.6.0] — 2026-05-09

### Changed — L3 prompt strengthened against PIR-induced under-extraction

Real-URL verification with a single-PIR `pir_output.json`
(`financial_crime` family only) showed the L3 LLM occasionally returning
empty `{entities: [], relationships: []}` even when the source report
clearly named threats. The behaviour traced back to the prior PIR
context wording — "*guidance only — do not invent*" — being read as a
filter signal, with the model dropping real entities that didn't
overlap with the (sparse) PIR set.

The prompt now states the policy explicitly in two places:

- **`stix_extraction.md` header** gains a *Critical extraction policy*
  block: be exhaustive, PIR is a priority hint not a filter, do not
  invent.
- **`_render_pir_context_block`** now emits a header
  `## PIR Context (priority hint, NOT a filter)` plus a *Required
  behaviour* list that:
  - mandates extraction of every named entity regardless of PIR overlap,
  - reframes PIRs as ranking input only (when long reports force a
    choice in detail),
  - retains the existing "do not invent" guardrail.

Behaviour for callers:

- No API change. `extract_entities(text, pir_doc=...)` signature
  unchanged.
- Empty-output regression risk on sparse-PIR runs is reduced; no
  hallucination surface added (the *don't invent* guardrail moved with
  the wording, not removed).

### Tests

- New
  `tests/test_stix_pir_context.py::test_pir_context_block_explicitly_describes_priority_not_filter`
  pins the strengthened wording so future prompt edits do not silently
  weaken it.

---

## [0.5.2] — 2026-05-09

### Fixed — `{401} sophistication` on intrusion-set

The L3 LLM occasionally emits `sophistication` on intrusion-set
objects. STIX 2.1 §4.5 defines `sophistication` for `threat-actor`
only; on intrusion-set it is a custom property that triggers `{401}`.
The bundle assembler now demotes it to `labels` (open vocab) — same
pattern as the 0.5.1 vocab demotion. The semantic survives without
the warning.

`threat-actor.sophistication` is preserved untouched.

### Documented — Accepted `{202}` suggested-target warnings

Two `{202}` warnings (`tool uses malware` and `tool uses tool`) are
now explicitly accepted in `docs/data-model.{md,ja.md}` under a new
"Accepted OASIS validator warnings" section. STIX 2.1 §4.13 lists
these as SHOULD rather than MUST, and dropping the relationships
would discard valid attack-graph edges that incident reports
regularly carry. Major consumers (MISP, OpenCTI) ingest these without
complaint. Users who want to gate on them can run
`validate_stix --strict` to promote to errors.

### Tests

- 3 new cases in
  `tests/test_stix_extractor.py::TestSophisticationDemotion`:
  intrusion-set demotion, dedup against existing labels, and
  threat-actor preservation.

### Compliance

Combined with 0.3.2 / 0.4.0 / 0.5.0 / 0.5.1, FIN7-class bundles now
pass the OASIS validator with **errors=0** and **warnings=2** (the
two intentionally-accepted `{202}` cases).

---

## [0.5.1] — 2026-05-09

### Fixed — Remaining warnings on FIN7-class bundles

Real-URL FIN7 verification on TRACE 0.5.0 produced a clean bundle —
errors=0 — but nine residual warnings remained:

- `{306} For extensions of the 'toplevel-property-extension' type, the
  'extension_properties' property SHOULD include one or more property
  names.` — TRACE's `extension-definition` object did not list the
  property names it introduces.
- `{216} malware_types contains a value not in the malware-type-ov
  vocabulary.` — Gemini emitted values like `loader` not present in
  the STIX 2.1 §6.4 open vocabulary.
- `{222} tool_types contains a value not in the tool-type-ov
  vocabulary.` — Same pattern for STIX 2.1 §6.5 tool vocabulary.

#### Fix 1: `extension_properties` enumeration

Added a stable ``_TRACE_EXTENSION_PROPERTIES`` constant listing the
five `x_trace_*` field names; the bundle assembler injects it into
the extension-definition object. SHOULD requirement satisfied.

#### Fix 2: Open-vocab demotion to `labels`

`_filter_open_vocab` (called from `_apply_required_property_defaults`)
splits `tool_types` / `malware_types` into vocab-conforming and non-
conforming sublists. Conforming values stay in place; non-conforming
values move to the `labels` field (also open vocab) where they
remain visible to downstream tools without violating the type-specific
vocabulary constraint.

- Empty conforming list removes the field entirely (no empty array
  in the bundle).
- Existing `labels` are preserved with order; demoted values append
  without duplicating.
- Conforming-only input passes through unchanged; no `labels` is
  spuriously created.

The STIX 2.1 vocabulary tables ship as in-module constants
(`_STIX21_TOOL_TYPE_OV`, `_STIX21_MALWARE_TYPE_OV`) — they're stable
across the spec's minor revisions and cheap to keep in sync.

### Tests

- 6 new cases in
  `tests/test_stix_extractor.py::TestExtensionPropertiesAndVocabDemotion`
  covering the extension-properties listing, mixed vocab demotion for
  both tools and malware, all-non-conforming field removal, existing
  labels preserved, and conforming-only passthrough.

### Compliance

Combined with 0.3.2 / 0.4.0 / 0.5.0, FIN7-class bundles now produce
**zero errors and zero warnings** against the OASIS validator (modulo
fetch-time {302} fallback when an ATT&CK URL is uncached and offline).

---

## [0.5.0] — 2026-05-09

### Added — SHA-256 augmentation for `external_references`

The OASIS validator emits `{302} External reference '<source>' has a
URL but no hash` for every entry that includes `url` without `hashes`.
On a typical FIN7 bundle that's a dozen+ warnings against ATT&CK
references. 0.5.0 fetches each external-reference URL once, hashes
the response body with SHA-256, and writes
`hashes: {"SHA-256": "<hex>"}` back into the entry.

- New module `src/trace_engine/stix/external_ref_hash.py` implements
  `augment_external_references(objects, cache_path, ttl_days,
  user_agent, enabled)`.
- On-disk JSON cache (default `output/external_ref_hash_cache.json`,
  configurable via `TRACE_EXTERNAL_REF_HASH_CACHE`) keyed by URL,
  storing `{sha256, fetched_at, status}`. Subsequent bundles reuse
  cached hashes without a network round-trip.
- TTL default 30 days
  (`Config.external_ref_hash_ttl_days`, env
  `TRACE_EXTERNAL_REF_HASH_TTL_DAYS`). MITRE ATT&CK pages are stable
  enough that monthly refresh is safe.
- Offline fallback: cache miss + fetch failure leaves the reference
  unchanged. The `{302}` warning re-appears for that one reference
  but the bundle remains usable. We deliberately prefer
  "warning + good bundle" over "failed bundle assembly".
- Lazy `httpx.Client` construction — bundles that hit the cache for
  every URL never open a network handle.
- Master switch
  `Config.external_ref_hash_enabled` (env
  `TRACE_EXTERNAL_REF_HASH_ENABLED=false`) for air-gapped use.

`build_stix_bundle_from_extraction` now accepts an optional
`config: Config | None` parameter so tests and air-gapped callers can
disable the augmentation step explicitly without environment fiddling.

### Tests

- 8 new cases in `tests/test_external_ref_hash.py` covering disabled
  switch, no-URL skip, hashes-already-present skip, cache-miss fetch,
  cache-hit no-network, stale-cache re-fetch, offline fallback, and
  no-external-references-shortcircuit.

### Compliance

Combined with 0.3.2 and 0.4.0, the FIN7-class bundle now validates
clean: zero {103} UUIDv4 errors, zero required-property errors, zero
{401} envelope warnings, and zero {302} hash warnings on cached or
freshly-fetched ATT&CK references.

---

## [0.4.0] — 2026-05-09

### Changed (BREAKING) — Bundle envelope drops deprecated fields

STIX 2.1 §3 deprecated `spec_version` and `created` on the bundle
envelope (they live on each object instead). TRACE 0.x kept them on
the envelope to satisfy a SAGE-side check, which produced two
non-compliant `{401}` warnings on every bundle. SAGE's parser
(`SAGE/src/sage/stix/parser.py`) actually iterates `bundle.objects[]`
and reads per-object `spec_version`, so the fields were never necessary.

- Removed `bundle.spec_version` and `bundle.created` from the envelope.
- Removed the local `BUNDLE_SPEC_VERSION` check from
  `validate/stix/validator.py`.
- Per-object `spec_version` and `created`/`modified` continue to be
  emitted on every entity, relationship, and the new
  `extension-definition` object.

Any downstream consumer that read the envelope `spec_version` /
`created` directly must read them from `bundle.objects[*]` instead.

### Changed (BREAKING) — `x_trace_*` metadata wrapped in STIX extension

The previous bare-`x_trace_*` properties triggered five `{401}`
custom-property warnings per bundle. Migrated to a STIX 2.1 §7.3
toplevel-property extension:

- A new `extension-definition` object with **stable id**
  `extension-definition--c1e4d6a7-2f3b-4e8c-9a5f-1b8d7e6c4a3f` is
  prepended to `objects[]` whenever any `x_trace_*` metadata is
  supplied. The id is hardcoded so consumers can recognise the
  extension across emissions without per-bundle discovery.
- `bundle.extensions[<ext-id>] = { extension_type:
  "toplevel-property-extension" }` is added at the bundle root.
- `x_trace_source_url`, `x_trace_collected_at`,
  `x_trace_matched_pir_ids`, `x_trace_relevance_score`, and
  `x_trace_relevance_rationale` continue to live at the bundle root —
  now permitted under the extension.
- Bundles emitted without any L4 metadata (raw extraction, no PIR or
  source URL) skip the extension definition entirely.

Combined with 0.3.2, FIN7-class bundles now validate clean against the
OASIS validator: no {103} UUIDv4 errors, no required-property errors,
no {401} custom-property warnings on the envelope.

### Documentation

- `docs/data-model.{md,ja.md}` rewritten "TRACE bundle metadata
  extension (L4)" section explaining the extension definition and
  the rationale for the fixed id.
- `docs/crawl_design.{md,ja.md}` §4a / §5 updated to describe the new
  bundle assembly steps (extension-definition prepend, `extensions`
  map, envelope deprecation).

### SAGE coordination

SAGE's parser already reads per-object `spec_version` and ignores the
envelope, so no SAGE-side change is required. SAGE consumes the
extension-definition object as a regular STIX object — it is not in
the supported-types list and will be skipped, which is the desired
behaviour.

### Tests

- 6 new cases in `tests/test_stix_extractor.py::TestBundleExtensionMigration`
  covering envelope field omission, conditional extension emission,
  stable id across emissions, required-fields presence, and `x_trace_*`
  retention at bundle root.
- `tests/test_validate_stix.py::test_wrong_spec_version_caught` removed
  (the local check it asserted no longer exists).
- `tests/test_stix_pir_context.py` updated: bundle-envelope
  `spec_version` assertion replaced with extension-object
  `spec_version` assertion.

---

## [0.3.2] — 2026-05-09

### Fixed — STIX 2.1 type-specific required-property defaults

Real-URL FIN7 verification on TRACE 0.3.1 produced a 93-object bundle
that the OASIS validator rejected with 10 hard errors:

- 7 × `malware` objects missing required `is_family` boolean.
- 3 × `indicator` objects missing required `valid_from` timestamp (and
  also `pattern_type`).

The L3 prompt asks the LLM for domain knowledge — it does not know
which STIX wire-format fields are mandatory per object type. The
bundle assembler now fills in conservative defaults via
`_apply_required_property_defaults`:

- `malware.is_family` defaults to `false` (instance, not family) —
  incident reports usually describe a single deployment.
- `indicator.valid_from` defaults to the bundle timestamp.
- `indicator.pattern_type` defaults to `"stix"` — STIX patterning is
  the only language reliably emitted by the L3 prompt.

`setdefault` semantics: anything the LLM did supply wins. A YARA
indicator with explicit `pattern_type: "yara"` is preserved.

### Tests

- 6 new cases in `tests/test_stix_extractor.py::TestRequiredPropertyDefaults`
  covering malware default, malware LLM override, indicator
  `valid_from` default, indicator `pattern_type` default, indicator
  LLM override, and confirmation that other types receive no extra
  defaults.

---

## [0.3.1] — 2026-05-09

### Fixed — Per-chunk output truncation on dense reports

0.3.0 split long reports into paragraph-aligned chunks so a single LLM
call would not blow past `max_output_tokens`, but the per-chunk output
ceiling was still 8,192 tokens and that turned out to be insufficient
for entity-dense chunks of CTI articles. Real-URL verification on a
24,750-char Picus FIN7 report saw chunks 0 and 1 truncate mid-property
and mid-relationship-array respectively, leaving the merged extraction
empty.

Two layered mitigations:

- **Per-chunk `max_output_tokens` raised from 8,192 to 32,768.** Gemini
  2.5 flash supports up to 65,535 output tokens; 32,768 leaves headroom
  while still bounding cost per call. This handles the common case.
- **Bracket-balanced salvage in `_extract_json_from_text`.** When a
  chunk's response is still truncated past 32,768 tokens, walk the
  raw text, find each `"entities":` / `"relationships":` array, and
  extract whatever complete `{...}` records are well-formed. The
  partial result feeds the merge stage rather than being discarded.

Together with the chunked input pipeline shipped in 0.3.0, this gives
TRACE a structural answer to long, dense reports: input is chunked,
output is bounded with headroom, and any residual truncation is
salvaged rather than dropped.

### Tests

- 5 new salvage cases in `tests/test_stix_extractor.py` covering
  mid-property cut, mid-relationship-array cut, well-formed JSON
  passthrough, no-recoverable-arrays guard, and embedded-brace string
  handling.

---

## [0.3.0] — 2026-05-09

### Added — Chunked L3 extraction for long reports

Long CTI reports (multi-page advisories, dense vendor PDFs) hit Gemini's
`max_output_tokens` ceiling and produced a JSON response that was truncated
mid-stream, causing `extract_entities` to return zero objects. The fix is
structural: split the article on paragraph boundaries (`\n\n`) into chunks
no larger than `Config.extraction_chunk_chars` (default `12000`, env
`TRACE_EXTRACTION_CHUNK_CHARS`) and run the L3 prompt once per chunk.

- Per-chunk `local_id`s are namespaced (`c0_actor_1`, `c1_actor_1`) to
  prevent cross-chunk alias collisions.
- `_merge_extractions` deduplicates entities by
  `(type, name.strip().lower())` (or `(type, pattern)` for indicators),
  unions list-valued properties (`labels`, `aliases`,
  `kill_chain_phases`, `external_references`, `malware_types`,
  `tool_types`), rewrites relationship `source` / `target` through the
  merge alias map, and collapses identical
  `(source, target, relationship_type)` triples.
- A single chunk failing to parse is logged with `chunk_index` and
  skipped — other chunks still contribute their entities. An extraction
  fails only when *every* chunk fails.
- Short articles (`len(text) <= chunk_chars`) bypass the chunk loop and
  preserve 0.2.0's single-call behavior.

### Added — Config field and env variable

- `Config.extraction_chunk_chars: int = 12000` (env
  `TRACE_EXTRACTION_CHUNK_CHARS`).

### Changed — `extract_entities` signature

`config: Config | None = None` is now an explicit parameter type
(previously untyped). Behavior unchanged when omitted (`load_config()`).

### Added — `cmd/update_taxonomy_cache.py`

The CLI was promised by `docs/data-model.md` and the
`validate/semantic/taxonomy.py` docstring since 0.1.0 but never landed.
Copies `BEACON/schema/threat_taxonomy.json` into
`TRACE/schema/threat_taxonomy.cached.json` atomically (`tempfile +
os.replace`), validates the expected top-level shape (`_metadata`,
`actor_categories` non-empty, `geography_threat_map`), and stamps a
TRACE-side `_trace_cache` block recording when and from where the
snapshot was taken (so future runs can show drift in `--dry-run`).

### Documentation

- `docs/crawl_design.md` and `docs/crawl_design.ja.md` document the
  chunking strategy under §4 ("Chunked extraction for long reports").

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
