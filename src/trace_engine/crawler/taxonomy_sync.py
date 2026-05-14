"""Ensure the local threat-taxonomy cache is fresh.

``ensure_taxonomy_fresh`` is the shared sync path used by both
``cmd/update_taxonomy_cache.py`` (the explicit CLI) and the crawl entry
points (``crawl_single``, ``crawl_batch``) that auto-sync at startup.

Best-effort: if the BEACON source is unavailable the existing cached
snapshot is returned and a ``taxonomy_sync_skipped`` warning is logged.
An exception is raised only when *neither* a fresh source nor any
existing cache is available.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import structlog

from trace_engine.config import Config

logger = structlog.get_logger(__name__)

_REQUIRED_KEYS: frozenset[str] = frozenset(
    {"_metadata", "actor_categories", "geography_threat_map"}
)


def _validate_shape(data: object) -> dict:
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


def _sync_taxonomy(source: Path, output: Path) -> Path:
    """Copy *source* to *output* with a ``_trace_cache`` stamp.

    If *source* does not exist or cannot be read, logs
    ``taxonomy_sync_skipped`` and returns *output* unchanged (using whatever
    snapshot is already there).  Raises ``FileNotFoundError`` only when both
    source and output are absent.

    Returns the path to the (possibly unchanged) cache file.
    """
    if not source.exists():
        if output.exists():
            logger.warning(
                "taxonomy_sync_skipped",
                reason="source_not_found",
                source=str(source),
                using_cache=str(output),
            )
            return output
        raise FileNotFoundError(
            f"Taxonomy source not found ({source}) and no cached fallback at {output}"
        )

    try:
        data = json.loads(source.read_text(encoding="utf-8"))
        _validate_shape(data)
    except (json.JSONDecodeError, ValueError, OSError) as exc:
        if output.exists():
            logger.warning(
                "taxonomy_sync_skipped",
                reason="source_invalid",
                source=str(source),
                error=str(exc),
                using_cache=str(output),
            )
            return output
        raise

    upstream_meta = data.get("_metadata", {}) if isinstance(data.get("_metadata"), dict) else {}
    data["_trace_cache"] = {
        "source": str(source),
        "cached_at": datetime.now(tz=UTC).isoformat(timespec="seconds"),
        "upstream_last_auto_sync": upstream_meta.get("last_auto_sync"),
        "upstream_generator": upstream_meta.get("generator"),
    }

    _atomic_write_json(output, data)
    logger.info(
        "taxonomy_cache_updated",
        source=str(source),
        output=str(output),
        upstream_last_auto_sync=upstream_meta.get("last_auto_sync"),
    )
    return output


def ensure_taxonomy_fresh(config: Config) -> Path:
    """Sync the taxonomy cache using paths from *config*.

    Delegates to ``_sync_taxonomy`` using
    ``config.beacon_taxonomy_source_path`` and
    ``config.threat_taxonomy_cache_path``.  Best-effort: logs
    ``taxonomy_sync_skipped`` when the BEACON source is unavailable and
    returns the existing cache path.
    """
    return _sync_taxonomy(
        config.beacon_taxonomy_source_path,
        config.threat_taxonomy_cache_path,
    )
