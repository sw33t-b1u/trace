"""Search ``crawl_state.json`` for a specific IoC (Initiative G Phase 5).

The Phase 4 LLM-driven IoC extractor persists per-article ``iocs[]``
into ``output/crawl_state.json``. This CLI walks that index so an IR
analyst can answer "have we crawled an article that mentioned
``evil.example.com`` already?" without re-running the LLM.

Usage::

    uv run python -m cmd.search_iocs --ioc evil.example.com [--type fqdn]
        [--tlp-max amber|green|clear] [--state-path <path>] [--json]

TLP filter (plan §2.6, default ``--tlp-max=amber``):

* Each match's STIX bundle is inspected for an ``object_marking_refs``
  entry pointing at one of the canonical TLP marking-definition UUIDs
  (TLP 1.0 + 2.0). The strictest level wins.
* If the bundle file is missing or carries no TLP marking, the match
  is treated as **TLP:CLEAR** (visible at all ``--tlp-max`` levels) so
  legacy bundles aren't silently hidden.
* ``--tlp-max=amber`` hides only TLP:RED — the default keeps the
  analyst-facing answer set wide while preventing accidental sharing
  of RED-tagged material.

Exit codes:

* ``0`` — query executed successfully (match OR no-match are both 0).
* ``2`` — state file missing / unreadable / version mismatch.

.. deprecated:: TRACE 1.12.0

    Direct invocation as ``python -m cmd.search_iocs`` /
    ``python cmd/search_iocs.py`` is deprecated. Use the unified
    ``trace search-iocs`` entry (Initiative H Phase 6). Removal is
    scheduled for TRACE 2.0.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click
import structlog

# Match sibling CLIs that put src/ on sys.path before importing trace_engine.*
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from trace_engine.config import load_config  # noqa: E402
from trace_engine.crawler.state import CrawlState, StateEntry  # noqa: E402
from trace_engine.ingest.ioc_extractor import IoCType  # noqa: E402

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    # Route logs to stderr so they do not corrupt ``--json`` stdout
    # output. The other CLIs use the implicit stdout factory because
    # they emit human-readable text; this CLI emits JSON when --json
    # is set and the structlog payload must not interleave.
    logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
)
logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# TLP plumbing
# ---------------------------------------------------------------------------

# Canonical TLP marking-definition UUIDs, both v1 and v2 — see FIRST.org's
# TLP 1.0 / 2.0 specs. Each maps to its level so the resolver can compare
# across spec versions without caring which one a producer chose.
_TLP_MARKING_REFS: dict[str, str] = {
    # TLP 2.0 (current)
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487": "clear",
    "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb": "green",
    "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421": "amber",
    "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003": "amber",  # AMBER+STRICT
    "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1": "red",
    # TLP 1.0 (legacy)
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "clear",  # WHITE→CLEAR
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "amber",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "red",
}

# Ordered from least to most restrictive — index = comparable rank.
_TLP_LEVELS: list[str] = ["clear", "green", "amber", "red"]


def _tlp_rank(level: str) -> int:
    return _TLP_LEVELS.index(level)


def read_bundle_tlp(bundle_path: str | Path | None) -> str:
    """Return the most restrictive TLP level referenced by the bundle.

    Defaults to ``clear`` when the bundle file is missing, unreadable,
    not a STIX bundle, or carries no recognised TLP marking-definition
    reference. The downstream filter treats ``clear`` as universally
    visible so the default keeps legacy / un-tagged content surface-able.
    """
    if not bundle_path:
        return "clear"
    path = Path(bundle_path)
    if not path.exists():
        logger.warning("search_iocs_bundle_missing", bundle_path=str(path))
        return "clear"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning(
            "search_iocs_bundle_unreadable",
            bundle_path=str(path),
            error=str(exc),
        )
        return "clear"
    if not isinstance(payload, dict):
        return "clear"

    found_levels: set[str] = set()
    # STIX 2.1: object_marking_refs may appear on the bundle itself (rare)
    # or on individual objects. Scan both.
    for ref in payload.get("object_marking_refs") or []:
        if isinstance(ref, str) and ref in _TLP_MARKING_REFS:
            found_levels.add(_TLP_MARKING_REFS[ref])
    for obj in payload.get("objects") or []:
        if not isinstance(obj, dict):
            continue
        for ref in obj.get("object_marking_refs") or []:
            if isinstance(ref, str) and ref in _TLP_MARKING_REFS:
                found_levels.add(_TLP_MARKING_REFS[ref])

    if not found_levels:
        return "clear"
    # Most restrictive wins (a single RED in any object → bundle is RED).
    return max(found_levels, key=_tlp_rank)


def _is_visible(bundle_tlp: str, tlp_max: str) -> bool:
    """``True`` when ``bundle_tlp`` is at or below the analyst's max."""
    return _tlp_rank(bundle_tlp) <= _tlp_rank(tlp_max)


# ---------------------------------------------------------------------------
# Match construction
# ---------------------------------------------------------------------------


def _normalise(value: str) -> str:
    """Exact-match comparator: case-insensitive + whitespace-stripped.

    FQDNs / CVE-IDs are case-insensitive by convention; hashes are
    historically lowercase but uppercase variants are common in copy /
    paste. Normalising both sides avoids surprises without conflating
    truly distinct indicators.
    """
    return value.strip().lower()


def _build_match(
    *,
    url: str,
    entry: StateEntry,
    ioc: dict[str, Any],
    bundle_tlp: str,
) -> dict[str, Any]:
    return {
        "type": ioc.get("type"),
        "matched_url": url,
        "value": ioc.get("value"),
        "confidence": ioc.get("confidence"),
        "context_snippet": ioc.get("context_snippet", ""),
        "first_seen": entry.first_seen,
        "last_seen": entry.last_seen,
        "bundle_path": entry.bundle_path,
        "bundle_tlp": bundle_tlp,
    }


def search(
    state: CrawlState,
    *,
    ioc: str,
    ioc_type: str | None,
    tlp_max: str,
    tlp_resolver=read_bundle_tlp,
) -> list[dict[str, Any]]:
    """Walk ``state.entries`` and return all matching IoC records.

    ``tlp_resolver`` is injected so tests can stub bundle TLP lookup
    without writing real STIX files. Defaults to :func:`read_bundle_tlp`.
    """
    target_value = _normalise(ioc)
    target_type = ioc_type.lower() if ioc_type else None

    matches: list[dict[str, Any]] = []
    for url, entry in state.entries.items():
        for ioc_entry in entry.iocs or []:
            if not isinstance(ioc_entry, dict):
                continue
            entry_type = str(ioc_entry.get("type", "")).lower()
            if target_type is not None and entry_type != target_type:
                continue
            entry_value = ioc_entry.get("value")
            if not isinstance(entry_value, str):
                continue
            if _normalise(entry_value) != target_value:
                continue
            bundle_tlp = tlp_resolver(entry.bundle_path)
            if not _is_visible(bundle_tlp, tlp_max):
                logger.info(
                    "search_iocs_tlp_filtered",
                    matched_url=url,
                    bundle_tlp=bundle_tlp,
                    tlp_max=tlp_max,
                )
                continue
            matches.append(_build_match(url=url, entry=entry, ioc=ioc_entry, bundle_tlp=bundle_tlp))
    return matches


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

_TABLE_COLUMNS = [
    ("type", 10),
    ("matched_url", 60),
    ("first_seen", 22),
    ("bundle_tlp", 10),
    ("confidence", 11),
    ("context_snippet", 50),
    ("bundle_path", 40),
]


def _format_table(matches: list[dict[str, Any]]) -> str:
    if not matches:
        return "No matches."
    header = " | ".join(name.ljust(width) for name, width in _TABLE_COLUMNS)
    sep = "-+-".join("-" * width for _, width in _TABLE_COLUMNS)
    lines = [header, sep]
    for m in matches:
        row_cells = []
        for name, width in _TABLE_COLUMNS:
            raw = m.get(name)
            cell = "" if raw is None else str(raw)
            cell = cell[:width].ljust(width)
            row_cells.append(cell)
        lines.append(" | ".join(row_cells))
    return "\n".join(lines)


def _default_state_path() -> Path:
    cfg = load_config()
    return Path(cfg.state_path)


@click.command(
    help=(
        "Search the TRACE IoC index (crawl_state.json) for a specific "
        "indicator value. Exact match; case-insensitive. TLP filter "
        "defaults to amber so TLP:RED bundles are hidden — pass "
        "--tlp-max=red explicitly only when you intend to view them."
    ),
)
@click.option("--ioc", "ioc", required=True, help="IoC value to search for.")
@click.option(
    "--type",
    "ioc_type",
    type=click.Choice([t.value for t in IoCType], case_sensitive=False),
    default=None,
    help="Restrict to a specific IoC type (case-insensitive).",
)
@click.option(
    "--tlp-max",
    type=click.Choice(["clear", "green", "amber", "red"], case_sensitive=False),
    default="amber",
    show_default=True,
    help=(
        "Maximum TLP level to surface. Default 'amber' hides RED. "
        "Use 'red' explicitly when sensitive content is needed."
    ),
)
@click.option(
    "--state-path",
    "state_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Override crawl_state.json location (default: $TRACE_STATE_PATH).",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    default=False,
    help="Emit a machine-readable JSON list instead of a human table.",
)
def main(
    ioc: str,
    ioc_type: str | None,
    tlp_max: str,
    state_path: Path | None,
    json_output: bool,
) -> None:
    """Implements the CLI; see module docstring for behaviour."""
    resolved_path = state_path or _default_state_path()
    if not resolved_path.exists():
        click.echo(f"error: crawl_state.json not found at {resolved_path}", err=True)
        sys.exit(2)

    try:
        state = CrawlState.load(resolved_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        click.echo(f"error: failed to load {resolved_path}: {exc}", err=True)
        sys.exit(2)

    # Pass the resolver explicitly so ``patch.object(search_iocs,
    # "read_bundle_tlp", ...)`` in tests replaces the call target —
    # default-argument binding would freeze the original at import time.
    matches = search(
        state,
        ioc=ioc,
        ioc_type=ioc_type,
        tlp_max=tlp_max.lower(),
        tlp_resolver=read_bundle_tlp,
    )

    if json_output:
        click.echo(json.dumps(matches, indent=2, default=str))
    else:
        click.echo(_format_table(matches))
        click.echo(f"\n{len(matches)} match(es).")
    # Exit 0 in both match and no-match cases per plan §2.6 + Phase 5.
    sys.exit(0)


if __name__ == "__main__":
    sys.stderr.write(
        "DeprecationWarning: 'python -m cmd.search_iocs' / "
        "'python cmd/search_iocs.py' is deprecated as of TRACE 1.12.0. "
        "Use 'trace search-iocs' instead; cmd/* invocations are "
        "scheduled for removal in TRACE 2.0.\n"
    )
    main()
