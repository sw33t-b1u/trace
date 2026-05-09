# TRACE — Crawl Design

Japanese translation: [`docs/crawl_design.ja.md`](crawl_design.ja.md)

End-to-end reference for TRACE's two collection modes, the per-source schema,
and the persistent state that powers idempotent batch crawls.

For data-flow context, see `high-level-design.md` §2.3 / §6 and
[`docs/data-model.md`](data-model.md).

---

## 1. Two crawl modes

| Mode | Driver | Use case |
|------|--------|----------|
| Single | `cmd/crawl_single.py` | Analyst hands TRACE a URL or PDF on demand |
| Batch | `cmd/crawl_batch.py` | Scheduled (cron / host scheduler) crawl over `input/sources.yaml` |

Both modes share the same internal pipeline:

```
 1. fetch        — httpx GET (UA + timeout from Config)
 2. read_report  — markitdown URL/PDF → clean Markdown (max_chars clip)
 3. L2 gate      — pir.relevance.evaluate (--pir given, otherwise skipped)
 4. L3 extract   — stix.extractor.extract_entities returns Extraction
                   (entities + relationships with local_id aliases)
 5. L4 bundle    — build_stix_bundle_from_extraction mints STIX UUIDs +
                   timestamps + spec_version, translates local_id refs,
                   stamps x_trace_* metadata
 6. write        — output/stix_bundle_<slug>.json (atomic via tmp+os.replace)
```

---

## 2. `input/sources.yaml` schema

The file is validated by `SourcesDocument` in
`src/trace_engine/validate/schema/models.py`. The directory `input/` is
**gitignored**, so each operator maintains a local copy.

### Top level

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `version` | int | `1` | Bump when an incompatible change is needed |
| `sources` | list[`SourceEntry`] | required | One entry per URL |

### `SourceEntry`

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `url` | str (http(s)) | required | Fed verbatim to httpx + markitdown |
| `label` | str / null | null | Human-readable; appears in logs |
| `task` | `simple` / `medium` / `complex` | `medium` | LLM tier for L3 extraction |
| `max_chars` | int > 0 | `30000` | Override the default markitdown clip |
| `pir_ids` | list[str] | `[]` | When non-empty, the L2 gate evaluates only these PIRs for this URL |

Unknown fields are rejected (`extra="forbid"`) — a typo on `task` or
`max_chars` will fail loudly rather than silently being ignored.

### Annotated example

```yaml
# input/sources.yaml — minimum to maximum.
version: 1

sources:
  # Minimum: just a URL. Defaults to task=medium, no PIR pinning.
  - url: https://example.com/cti-blog/post-42

  # Typical: URL + human-readable label.
  - url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-001a
    label: CISA Advisory AA25-001A

  # Long, dense report — bump task tier and char budget.
  - url: https://example-vendor.com/research/q4-threat-report.pdf
    label: ExampleVendor Q4 Threat Report
    task: complex
    max_chars: 60000

  # Pin which PIRs the L2 gate considers for this source.
  - url: https://example.com/regional-bulletin
    label: Regional Threat Bulletin
    pir_ids:
      - PIR-2026-001
      - PIR-2026-004
```

> **Common mistake:** writing one URL per line **without** the `version:` /
> `sources:` envelope. The validator rejects this with
> `Input should be a valid dictionary or instance of SourcesDocument`.
> Always wrap URLs in the structure shown above.

---

## 3. L2 PIR relevance gate

When `--pir <path>` is supplied:

1. The PIR file is loaded into `PIRDocument` and a SHA-256 of its bytes is
   recorded as `pir_set_hash`.
2. For each article, `pir.relevance.evaluate(text, pir_doc)` calls the
   `simple`-tier LLM (default `gemini-2.5-flash-lite`) with a JSON-only
   prompt, requesting `{score, matched_pir_ids[], rationale}`.
3. The score is clamped to `[0.0, 1.0]`. If the response can't be parsed —
   even after fence-stripping — the gate **fails open**: the article still
   goes through L3, with `decision="extraction_failed"` recorded in state and
   `x_trace_relevance_rationale="parse_failed: …"` on the bundle. We
   intentionally prefer noise over silently dropping reports.
4. Otherwise: if `score >= TRACE_RELEVANCE_THRESHOLD` (default `0.5`), the
   article proceeds to L3. Below the threshold it's skipped and recorded as
   `decision="skipped_below_threshold"`.

Per-source `pir_ids` (above) is the knob for restricting L2 to a subset of
PIRs — useful when one source is a regional bulletin that should only be
triaged against region-specific PIRs.

---

## 4. L3 entity extraction (PIR context injection)

`stix/extractor.extract_entities(text, task, pir_doc=...)` does:

1. Loads `prompts/stix_extraction.md`.
2. Substitutes `{{REPORT_TEXT}}` with the article text.
3. When `pir_doc` is non-empty, substitutes `{{PIR_CONTEXT_BLOCK}}` with a
   `## PIR Context` section enumerating each PIR's `intelligence_level`,
   `description`, `threat_actor_tags`, `notable_groups`, `collection_focus`,
   and `prioritized_asset_tags`.
4. Calls Gemini in `json_mode=True` requesting
   `{entities: [...], relationships: [...]}` — **not** STIX objects. The
   LLM never sees a `<type>--<uuid4>` field and never has to invent
   timestamps or `spec_version`.
5. Recovers JSON via `_extract_json_from_text` (fence-stripping fallback).
6. Drops entities whose `type` is outside the allowed vocabulary
   (`threat-actor`, `intrusion-set`, `attack-pattern`, `malware`, `tool`,
   `vulnerability`, `indicator`).
7. Drops relationships whose `relationship_type` is outside `{uses,
   exploits, indicates}`.

The PIR context is a **hint** — the prompt explicitly tells the model not to
invent entities purely to satisfy a PIR. Filtering already happened at L2.

### Chunked extraction for long reports

A single Gemini call has a hard `max_output_tokens` ceiling, so a 30k-char
threat report can produce a JSON response that gets truncated mid-stream and
fails to parse. To avoid that, `extract_entities` splits the article on
paragraph boundaries (`\n\n`) into chunks no larger than
`Config.extraction_chunk_chars` (default `12000`, env
`TRACE_EXTRACTION_CHUNK_CHARS`) and runs the L3 prompt once per chunk.

- A paragraph that on its own exceeds the limit is hard-cut at the boundary.
- Each chunk's `local_id`s are namespaced (`c0_actor_1`, `c1_actor_1`) so
  identical aliases from different chunks don't collide.
- A single chunk that fails to parse is logged with `chunk_index` and
  skipped; the remaining chunks still contribute their entities.

The per-chunk results are merged by `_merge_extractions`:

| Step | Behavior |
|------|----------|
| Entity dedupe | `(type, name.strip().lower())` for everything except `indicator`, which uses `(type, pattern)`. Properties from the second occurrence union into the first; list fields (`labels`, `aliases`, `kill_chain_phases`, `external_references`, `malware_types`, `tool_types`) are deduplicated. Same name + different type → kept as separate entities. |
| Relationship rewrite | `source` / `target` are remapped through the merge alias map so cross-chunk relationships resolve. |
| Relationship dedupe | Identical `(source, target, relationship_type)` triples are collapsed. |
| Hallucinated endpoints | Dropped (alias map miss); counted in the `extractions_merged` log line. |

For short articles (`len(text) <= chunk_chars`) the chunk loop is bypassed
and behavior is identical to the pre-0.3.0 single-call path.

## 4a. L4 bundle assembly (code builds STIX)

`stix/extractor.build_stix_bundle_from_extraction(extraction, ...)` is
deterministic Python. It:

1. Mints a fresh `<type>--<uuid4>` per entity and records a
   `local_id → STIX id` map.
2. Stamps every object (and the bundle envelope) with one shared `created`
   timestamp in `YYYY-MM-DDTHH:mm:ss.000Z` form, plus
   `spec_version = "2.1"`.
3. For each relationship, mints `relationship--<uuid4>` and rewrites
   `source_ref` / `target_ref` from `local_id` to the new STIX ids. Any
   relationship whose endpoint isn't in the map (LLM hallucinated a
   `local_id`) is dropped with a structured-log warning.
4. Adds the L4 `x_trace_*` envelope properties (see §5).

This split is what guarantees bundles always pass the OASIS validator's
`{103}` UUIDv4 check and timestamp format check — the LLM never gets to
emit those fields.

---

## 5. L4 bundle envelope

`build_stix_bundle` adds these properties to the bundle root:

| Property | Set by |
|----------|--------|
| `x_trace_source_url` | `source_url` argument (CLI passes `--input`) |
| `x_trace_collected_at` | `collected_at` argument (defaults to "now (UTC)") |
| `x_trace_matched_pir_ids` | L2 verdict, when the gate ran |
| `x_trace_relevance_score` | L2 verdict |
| `x_trace_relevance_rationale` | L2 verdict |

SAGE silently ignores unknown `x_*` keys, so adding more is
forward-compatible.

---

## 6. `output/crawl_state.json` schema

Persistent batch dedupe state, written atomically via `tempfile +
os.replace`. Schema (version `1`):

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
no_pir}`.

---

## 7. Dedupe strategy

Per source, on every `crawl_batch` run:

1. `fetch(url)` → raw bytes.
2. `content_sha256 = sha256(bytes)`.
3. Look up `state.entries[url]`. Skip when:
   - the recorded `content_sha256` matches **and**
   - either `--recheck-on-pir-change` is off, or the recorded
     `pir_set_hash` matches the current PIR file.
4. Otherwise process: read → L2 → L3 → bundle → state upsert.

`fetch` failures and `extraction_failed` outcomes are reported as outcome
records but do not write a bundle and do not poison the state. The next run
will retry.

`first_seen` is preserved across upserts; `last_seen` updates every time the
URL is touched. This makes it easy to ask "when did we first see this story?"
later.

---

## 8. Single-URL extras

`cmd/crawl_single.py` is the on-demand counterpart. It does **not** persist
to `crawl_state.json` — it's intentionally stateless, since the main use case
is "an analyst handed me a URL, give me a bundle." All of L2 + L3 + L4
behaves identically.

```bash
uv run python cmd/crawl_single.py --input '<url-or-pdf-path>' \
  --pir ../BEACON/output/pir_output.json \
  [--task complex] [--relevance-threshold 0.6]
```

When the L2 gate skips an article, `crawl_single` prints
`Skipped (relevance score X.XX < threshold Y.YY)` and exits `0` (the skip is
the success path).

---

## 9. Tuning the gate

| Knob | Where | Default | When to touch |
|------|-------|---------|---------------|
| Threshold | `--relevance-threshold` or `TRACE_RELEVANCE_THRESHOLD` | `0.5` | Many obvious noise articles passing → raise; relevant ones being skipped → lower |
| Model tier | `TRACE_RELEVANCE_MODEL_TIER` | `simple` | Switch to `medium` if `flash-lite` keeps mis-scoring |
| Per-source PIR pinning | `sources.yaml: pir_ids` | `[]` | A specific feed only matters for one PIR — narrow the scope |

If `x_trace_relevance_rationale` shows `parse_failed` / `call_failed`, the
gate didn't make a real decision. Investigate the LLM call path before
trusting the threshold.
