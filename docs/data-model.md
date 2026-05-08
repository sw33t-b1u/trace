# TRACE — Validation Data Model

Japanese translation: [`docs/data-model.ja.md`](data-model.ja.md)

This document is the canonical reference for what TRACE validates and against
what contract. The shapes here match SAGE's runtime expectations; if a field
diverges between SAGE and TRACE, SAGE wins and TRACE is updated to match.

For the validation algorithm narrative, see `high-level-design.md` §5–§6. The
authoritative type definitions live in
`src/trace_engine/validate/schema/models.py`.

---

## 1. Inputs TRACE validates

| Artifact | SAGE source of truth | TRACE entry point |
|----------|---------------------|-------------------|
| `assets.json` | `SAGE/cmd/load_assets.py`, `SAGE/tests/fixtures/sample_assets.json` | `cmd/validate_assets.py` |
| `pir_output.json` | `SAGE/src/sage/pir/filter.py:25-39`, `SAGE/tests/fixtures/sample_pir.json` | `cmd/validate_pir.py` |
| STIX 2.1 bundle | OASIS STIX 2.1 spec + `SAGE/src/sage/stix/parser.py` | `cmd/validate_stix.py` |

A combined report covering all three is produced by `cmd/validate_all.py`.

---

## 2. `assets.json` schema (`AssetsDocument`)

Top-level dict with the following lists. Unknown top-level keys are tolerated
(`extra="allow"`) so BEACON's `_comment` annotations round-trip.

| Field | Type | Notes |
|-------|------|-------|
| `network_segments[]` | `NetworkSegment` | id / name / cidr / zone — all required |
| `security_controls[]` | `SecurityControl` | id / name required; `control_type` and `coverage[]` optional |
| `assets[]` | `Asset` | see below |
| `asset_vulnerabilities[]` | `AssetVulnerability` | `asset_id`, `vuln_stix_id_ref`, `remediation_status` (default `open`) |
| `asset_connections[]` | `AssetConnection` | `src`, `dst`, optional `protocol`, `port` ∈ `[0, 65535]` |
| `actor_targets[]` | `ActorTarget` | `actor_stix_id_ref`, `asset_id`, optional `confidence` ∈ `[0, 100]` |

### `Asset`

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `id` | str | required | unique within `assets[]` |
| `name` | str | required | |
| `asset_type` | str / null | null | |
| `environment` | str / null | null | |
| `criticality` | float | `5.0` | range `[0.0, 10.0]` (Pydantic + semantic check) |
| `owner` | str / null | null | |
| `network_segment_id` | str / null | null | must resolve to `network_segments[*].id` if set |
| `exposed_to_internet` | bool | `false` | |
| `tags` | list[str] | `[]` | |
| `security_control_ids` | list[str] | `[]` | each must resolve to `security_controls[*].id` |

### Semantic checks (`validate/semantic/assets.py`)

| Code | Severity | Trigger |
|------|----------|---------|
| `ID_NOT_UNIQUE` | error | duplicate id within `network_segments` / `security_controls` / `assets` |
| `ASSET_REF_SEGMENT` | error | `assets[].network_segment_id` not in `network_segments[*].id` |
| `ASSET_REF_CONTROL` | error | `assets[].security_control_ids[*]` not in `security_controls[*].id` |
| `CONNECTION_REF_ASSET` | error | `asset_connections[].{src,dst}` not in `assets[*].id` |
| `VULN_REF_ASSET` | error | `asset_vulnerabilities[].asset_id` not in `assets[*].id` |
| `ACTOR_TARGET_REF_ASSET` | error | `actor_targets[].asset_id` not in `assets[*].id` |

---

## 3. `pir_output.json` schema (`PIRDocument` / `PIRItem`)

The file is a JSON list. A single-object payload is normalized to a one-element
list before validation (`PIRDocument.from_payload`). `PIRItem` accepts extra
fields (`extra="allow"`) so BEACON-emitted enrichments (`risk_score`,
`rationale`, `notable_groups`, `collection_focus` …) round-trip without loss.

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `pir_id` | str | yes | unique across the document |
| `threat_actor_tags` | list[str] | yes (may be empty) | every value SHOULD be a key in the threat taxonomy snapshot |
| `asset_weight_rules[]` | list[`AssetWeightRule`] | yes (may be empty) | `tag` (str) + `criticality_multiplier` (float, > 0) |
| `valid_from` | ISO date | yes | must be < `valid_until` |
| `valid_until` | ISO date | yes | strictly after `valid_from` |
| `organizational_scope` | str / null | no | |
| `description` | str / null | no | |
| `intelligence_level` | str / null | no | typically `strategic` / `operational` / `tactical` |

### Semantic checks (`validate/semantic/pir.py`)

| Code | Severity | Trigger |
|------|----------|---------|
| `PIR_ID_NOT_UNIQUE` | error | duplicate `pir_id` |
| `PIR_TAG_NOT_IN_TAXONOMY` | warning | `threat_actor_tags[*]` absent from `schema/threat_taxonomy.cached.json` (analyst-authored vocabulary is allowed but flagged) |
| `PIR_RULE_TAG_UNUSED` | error (when `--assets` is supplied) | `asset_weight_rules[*].tag` matches no tag in any `assets[*].tags` |
| validity-window violation | error | `valid_from >= valid_until` (raised by Pydantic `model_validator`) |

The taxonomy snapshot is refreshed via `cmd/update_taxonomy_cache.py`. See
[`crawl_design.md`](crawl_design.md) for how the same taxonomy plays into the
L2 relevance gate.

---

## 4. STIX 2.1 bundle schema

OASIS `stix2-validator` (PyPI `stix2-validator>=3.2`) is the spec-compliance
authority. TRACE invokes it through `validate/stix/validator.py`, then layers
local checks that the OASIS validator does not cover.

### What `cti-stix-validator` covers

- Object-level type / required fields, vocabulary checks, timestamp formats,
  id format (`<type>--<uuid4>`), and best-practice warnings (`{2xx}` /
  `{3xx}` / `{4xx}` codes).

### Local checks (`validate/stix/validator.py:check_stix_bundle`)

| Code | Severity | Trigger |
|------|----------|---------|
| `BUNDLE_TYPE` | error | top-level `type != "bundle"` |
| `BUNDLE_SPEC_VERSION` | error | `bundle.spec_version != "2.1"` (TRACE intentionally emits this even though STIX 2.1 deprecated it at the bundle envelope; SAGE relies on it — the OASIS validator surfaces a `{401}` warning that we accept) |
| `STIX_ID_NOT_UNIQUE` | error | duplicate `id` within `objects[]` |
| `REL_REF_MISSING` | error | `relationship` lacks `source_ref` or `target_ref` |
| `REL_REF_UNRESOLVED` | error | `relationship.{source_ref,target_ref}` does not match any `objects[*].id` |
| `KILL_CHAIN_NAME` | warning | `kill_chain_phases[*].kill_chain_name != "mitre-attack"` (SAGE drops these) |

### TRACE-specific bundle envelope (L4 metadata)

`build_stix_bundle_from_extraction` adds these to the **bundle root** when
supplied. SAGE ignores unknown `x_*` properties so this is
forward-compatible.

| Property | When | Meaning |
|----------|------|---------|
| `x_trace_source_url` | always (when called from CLIs) | origin URL or input path |
| `x_trace_collected_at` | always | ISO-8601 timestamp |
| `x_trace_matched_pir_ids` | L2 gate ran | list of PIR ids the article was deemed relevant to |
| `x_trace_relevance_score` | L2 gate ran | float `[0.0, 1.0]` |
| `x_trace_relevance_rationale` | L2 gate ran | short LLM-authored justification (or `parse_failed`/`call_failed` when the gate fell open) |

### Bundle assembly: LLM extracts, code builds

TRACE does **not** ask the LLM to emit STIX 2.1 objects. The LLM returns
domain knowledge only — entity names, types, descriptions, labels, and
which entities relate to each other — keyed by short `local_id` aliases:

```json
{
  "entities": [
    {"local_id": "actor_1", "type": "intrusion-set", "name": "FIN7", ...},
    {"local_id": "tool_1", "type": "tool", "name": "Cobalt Strike", ...}
  ],
  "relationships": [
    {"source": "actor_1", "target": "tool_1", "relationship_type": "uses"}
  ]
}
```

`stix.extractor.build_stix_bundle_from_extraction` then assembles a STIX
2.1 bundle entirely in Python:

- Mints `id = "<type>--" + uuid.uuid4()` per entity and per relationship
  (UUIDv4-clean by construction);
- Stamps a single shared `created` / `modified` timestamp in the spec's
  millisecond format;
- Sets `spec_version = "2.1"` on every object;
- Translates `relationships[*].{source,target}` from `local_id` to the
  freshly-minted STIX ids;
- Drops relationships whose endpoints don't resolve (LLM hallucination)
  with a structured-log warning rather than emitting dangling refs.

This eliminates the two failure modes that plagued the earlier
LLM-emits-STIX approach: malformed UUIDs (LLM output sequential or non-v4
ids) and timestamp format violations (`HH:mm:ss:sss` vs `.sss`). Anything
remaining (vocabulary mismatches in `labels` / `malware_types` /
`tool_types`, missing `description`, ATT&CK external references without
hashes) is best-practice level and reported as a warning by the OASIS
validator.

---

## 5. `ValidationFinding` and the report format

Every check — schema, semantic, STIX — produces one or more
`ValidationFinding` records. The `Markdown` renderer
(`review/markdown_report.py`) formats them into a deterministic per-section
report.

```python
@dataclass(frozen=True)
class ValidationFinding:
    severity: Literal["error", "warning", "info"]
    code: str           # e.g. "PIR_TAG_NOT_IN_TAXONOMY"
    location: str       # JSON path: "$.pirs[0].threat_actor_tags[2]"
    message: str
```

A run is `PASS` iff zero `error`-severity findings exist across all sections.
Warnings are listed but do not affect the overall verdict (use
`validate_stix --strict` to promote OASIS warnings to errors).
