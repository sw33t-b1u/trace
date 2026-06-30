"""Resolve TRACE CLI inputs from local files, storage keys, or GCS URIs.

TRACE command inputs accept one consistent reference format across artifact
classes:

1. ``gs://bucket/key`` reads that exact GCS object.
2. An existing local filesystem path reads locally.
3. Otherwise the value is interpreted as a StorageBackend key in the supplied
   category.  Bare filenames, ``category/filename``, and
   ``<TRACE_STORAGE_PREFIX>/category/filename`` are normalized to ``filename``
   before calling ``storage.load(category, filename)``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


@dataclass(frozen=True)
class ResolvedInput:
    """Resolved input content plus display metadata."""

    category: str
    reference: str
    text: str
    filename: str
    source: str

    @property
    def display_name(self) -> str:
        return self.filename or Path(self.reference).name or self.reference


def resolve_json_input(
    config: object, category: str, value: str | Path
) -> tuple[object, ResolvedInput]:
    """Resolve *value* and parse it as JSON."""
    resolved = resolve_input(config, category, value)
    return json.loads(resolved.text), resolved


def resolve_input(config: object, category: str, value: str | Path) -> ResolvedInput:
    """Return UTF-8 text for a TRACE input reference.

    Args:
        config: ``trace_engine.config.Config`` or compatible object.
        category: StorageBackend category (``pir``, ``assets``, ``stix``, ``input``).
        value: local path, ``gs://`` URI, or storage key.

    Raises:
        FileNotFoundError: when the reference cannot be resolved.
    """
    raw = str(value)
    if not raw:
        raise FileNotFoundError("empty input reference")

    if raw.startswith("gs://"):
        text = _load_gcs_uri(raw)
        return ResolvedInput(
            category=category,
            reference=raw,
            text=text,
            filename=Path(urlparse(raw).path).name,
            source="gcs-uri",
        )

    path = Path(raw)
    if path.exists():
        return ResolvedInput(
            category=category,
            reference=raw,
            text=path.read_text(encoding="utf-8"),
            filename=path.name,
            source="local",
        )

    filename = normalize_storage_filename(config, category, raw)
    try:
        from trace_engine.storage import create_storage_backend

        storage = create_storage_backend(config)
        text = storage.load(category, filename)
    except FileNotFoundError as exc:
        raise FileNotFoundError(raw) from exc
    return ResolvedInput(
        category=category,
        reference=raw,
        text=text,
        filename=Path(filename).name,
        source="storage",
    )


def normalize_storage_filename(config: object, category: str, value: str) -> str:
    """Normalize a storage reference to the filename part for *category*.

    Accepts bare filenames, ``category/filename``, and
    ``<TRACE_STORAGE_PREFIX>/category/filename``.  Prefix matching is based on
    the active TRACE storage prefix and is ignored when empty.
    """
    ref = value.strip().lstrip("/")
    prefix = str(getattr(config, "trace_storage_prefix", "") or "").strip("/")
    if prefix and ref == prefix:
        return ""
    if prefix and ref.startswith(prefix + "/"):
        ref = ref[len(prefix) + 1 :]
    category_prefix = category.strip("/") + "/"
    if ref.startswith(category_prefix):
        ref = ref[len(category_prefix) :]
    return ref


def _load_gcs_uri(uri: str) -> str:
    parsed = urlparse(uri)
    if parsed.scheme != "gs" or not parsed.netloc or not parsed.path.strip("/"):
        raise FileNotFoundError(uri)
    try:
        from google.cloud import storage as gcs  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError(
            "GCS input references require 'google-cloud-storage'. "
            "Install it with: pip install google-cloud-storage"
        ) from exc

    bucket_name = parsed.netloc
    blob_name = parsed.path.lstrip("/")
    client = gcs.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)
    if not blob.exists():
        raise FileNotFoundError(uri)
    return blob.download_as_text(encoding="utf-8")
