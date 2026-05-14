"""Refresh ``schema/threat_taxonomy.cached.json`` from BEACON's authoritative
``schema/threat_taxonomy.json``.

BEACON owns the threat taxonomy lifecycle (it generates the file from MITRE
ATT&CK + MISP Galaxy via ``cmd/update_taxonomy.py``). TRACE keeps a snapshot
in ``schema/threat_taxonomy.cached.json`` so validators run offline and so
TRACE doesn't depend on BEACON being importable. This CLI copies the file
across, validates the expected top-level shape, and stamps a TRACE-side
``_trace_cache`` block recording when and from where the snapshot was taken.

Usage:
    # Default: ../BEACON/schema/threat_taxonomy.json → schema/threat_taxonomy.cached.json
    uv run python cmd/update_taxonomy_cache.py

    # Explicit source / destination
    uv run python cmd/update_taxonomy_cache.py \\
        --source ../BEACON/schema/threat_taxonomy.json \\
        --output schema/threat_taxonomy.cached.json

    # Dry-run: report what would change without writing
    uv run python cmd/update_taxonomy_cache.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

import structlog

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from trace_engine.cli._logging import configure as configure_logging  # noqa: E402
from trace_engine.crawler.taxonomy_sync import _sync_taxonomy  # noqa: E402

configure_logging()
logger = structlog.get_logger(__name__)

_REQUIRED_KEYS: frozenset[str] = frozenset(
    {"_metadata", "actor_categories", "geography_threat_map"}
)
_DEFAULT_SOURCE = (
    Path(__file__).resolve().parent.parent.parent / "BEACON" / "schema" / "threat_taxonomy.json"
)
_DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "schema" / "threat_taxonomy.cached.json"


def _validate_shape(data: object) -> dict:
    """Reject anything that doesn't look like a BEACON taxonomy export."""
    if not isinstance(data, dict):
        raise ValueError(f"taxonomy root must be a JSON object, got {type(data).__name__}")
    missing = _REQUIRED_KEYS - data.keys()
    if missing:
        raise ValueError(f"taxonomy is missing required top-level keys: {sorted(missing)}")
    actor_cats = data.get("actor_categories")
    if not isinstance(actor_cats, dict) or not actor_cats:
        raise ValueError("`actor_categories` must be a non-empty object")
    return data


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp"
    ) as tmp:
        json.dump(payload, tmp, indent=2, ensure_ascii=False, sort_keys=False)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Copy BEACON's threat_taxonomy.json into TRACE's cached snapshot, "
            "stamping when and from where it was taken."
        )
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=_DEFAULT_SOURCE,
        help=f"BEACON taxonomy path (default: {_DEFAULT_SOURCE})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=_DEFAULT_OUTPUT,
        help=f"TRACE cached snapshot path (default: {_DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change without writing the snapshot.",
    )
    args = parser.parse_args()

    if not args.source.exists():
        logger.error("source_not_found", path=str(args.source))
        sys.exit(2)

    try:
        data = json.loads(args.source.read_text(encoding="utf-8"))
        _validate_shape(data)
    except (json.JSONDecodeError, ValueError) as exc:
        logger.error("source_invalid", path=str(args.source), error=str(exc))
        sys.exit(3)

    upstream_meta = data.get("_metadata", {}) if isinstance(data.get("_metadata"), dict) else {}
    actor_count = sum(
        len(v) if isinstance(v, dict) else 1 for v in data["actor_categories"].values()
    )
    geo_count = len(data.get("geography_threat_map") or {})

    if args.dry_run:
        prev_sync = None
        if args.output.exists():
            try:
                existing = json.loads(args.output.read_text(encoding="utf-8"))
                prev_sync = (existing.get("_trace_cache") or {}).get("upstream_last_auto_sync")
            except json.JSONDecodeError:
                prev_sync = "(unreadable)"
        logger.info(
            "dry_run",
            source=str(args.source),
            output=str(args.output),
            previous_upstream_sync=prev_sync,
            new_upstream_sync=upstream_meta.get("last_auto_sync"),
            actor_categories=actor_count,
            geographies=geo_count,
        )
        print(
            f"[dry-run] would write {args.output} "
            f"(actor_categories={actor_count}, geographies={geo_count}, "
            f"upstream_sync={upstream_meta.get('last_auto_sync')})"
        )
        return

    _sync_taxonomy(args.source, args.output)
    print(
        f"Cached {args.source} → {args.output}\n"
        f"  actor_categories={actor_count}, geographies={geo_count}, "
        f"upstream_sync={upstream_meta.get('last_auto_sync')}"
    )


if __name__ == "__main__":
    main()
