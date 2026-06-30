"""Loader for ``input/sources.yaml``.

The YAML payload is validated by ``SourcesDocument`` (Pydantic). Errors raise
``pydantic.ValidationError`` with field-level paths.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from trace_engine.validate.schema import SourcesDocument


def load_sources(path: str | Path) -> SourcesDocument:
    return load_sources_text(Path(path).read_text(encoding="utf-8"))


def load_sources_text(text: str) -> SourcesDocument:
    payload = yaml.safe_load(text) or {}
    return SourcesDocument.model_validate(payload)
