"""SHA-256 hash augmentation for STIX ``external_references`` entries.

The OASIS STIX 2.1 validator emits ``{302} External reference '<source>'
has a URL but no hash`` for any external reference that includes ``url``
without ``hashes``. The fix is to fetch the URL, hash the body, and add
``hashes: {"SHA-256": "<hex>"}``. This module owns that workflow.

Design notes
------------
- **On-disk cache**: every successful fetch writes
  ``{url: {sha256, fetched_at, status}}`` to a JSON file
  (``Config.external_ref_hash_cache_path``, default
  ``output/external_ref_hash_cache.json``). Subsequent bundles reuse
  the cached hash without a network round-trip.
- **TTL**: cache entries older than ``Config.external_ref_hash_ttl_days``
  (default 30) are re-fetched. ATT&CK pages are stable enough that
  monthly refresh is safe.
- **Offline fallback**: if the URL has never been fetched (cache miss)
  and the network call fails for any reason, the reference is left
  unchanged. The {302} warning re-appears for that one reference, but
  the bundle remains usable. We deliberately prefer "warning + good
  bundle" over "failed bundle assembly".
- **No per-process retries**: a fetch failure is logged once and the
  caller moves on. The next bundle assembly will retry the URL via
  cache miss.

The hash covers the *response body bytes*, not a normalised
representation. STIX 2.1 §3.4 requires the hash match the resource
returned by the URL at hash-computation time.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import structlog

logger = structlog.get_logger(__name__)

_DEFAULT_TIMEOUT_SECONDS: float = 10.0


def augment_external_references(
    objects: list[dict],
    *,
    cache_path: Path,
    ttl_days: int,
    user_agent: str,
    enabled: bool = True,
) -> None:
    """Mutate ``objects[*].external_references[*]`` in place, adding
    ``hashes: {"SHA-256": "<hex>"}`` for each entry that has ``url`` but
    no ``hashes``.

    ``enabled=False`` is a quick offline switch (still safe to call —
    nothing happens, no network access).
    """
    if not enabled:
        return

    cache = _load_cache(cache_path)
    cutoff = datetime.now(tz=UTC) - timedelta(days=ttl_days)
    cache_dirty = False
    client: httpx.Client | None = None
    try:
        for obj in objects:
            refs = obj.get("external_references")
            if not isinstance(refs, list):
                continue
            for ref in refs:
                if not isinstance(ref, dict):
                    continue
                url = ref.get("url")
                if not isinstance(url, str) or not url:
                    continue
                if isinstance(ref.get("hashes"), dict) and ref["hashes"]:
                    continue
                cached = cache.get(url)
                if cached and _is_cache_fresh(cached, cutoff):
                    if cached.get("sha256"):
                        ref["hashes"] = {"SHA-256": cached["sha256"]}
                    continue
                # Cache miss or stale → fetch. Lazy client construction so
                # an all-cached run never opens a network handle.
                if client is None:
                    client = httpx.Client(
                        headers={"User-Agent": user_agent},
                        timeout=_DEFAULT_TIMEOUT_SECONDS,
                        follow_redirects=True,
                    )
                sha = _fetch_and_hash(client, url)
                if sha is not None:
                    ref["hashes"] = {"SHA-256": sha}
                    cache[url] = {
                        "sha256": sha,
                        "fetched_at": datetime.now(tz=UTC).isoformat(timespec="seconds"),
                        "status": "ok",
                    }
                    cache_dirty = True
                else:
                    cache[url] = {
                        "sha256": None,
                        "fetched_at": datetime.now(tz=UTC).isoformat(timespec="seconds"),
                        "status": "fetch_failed",
                    }
                    cache_dirty = True
    finally:
        if client is not None:
            client.close()

    if cache_dirty:
        _save_cache(cache_path, cache)


def _fetch_and_hash(client: httpx.Client, url: str) -> str | None:
    try:
        resp = client.get(url)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("external_ref_fetch_failed", url=url, error=str(exc))
        return None
    sha = hashlib.sha256(resp.content).hexdigest()
    logger.info("external_ref_hashed", url=url, sha256=sha[:16] + "…")
    return sha


def _is_cache_fresh(entry: dict, cutoff: datetime) -> bool:
    fetched_at = entry.get("fetched_at")
    if not isinstance(fetched_at, str):
        return False
    try:
        ts = datetime.fromisoformat(fetched_at)
    except ValueError:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts >= cutoff


def _load_cache(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("external_ref_cache_unreadable", path=str(path), error=str(exc))
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def _save_cache(path: Path, cache: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp"
    ) as tmp:
        json.dump(cache, tmp, indent=2, ensure_ascii=False, sort_keys=True)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)
