"""Loader for ``input/sources.yaml``.

The YAML payload is validated by ``SourcesDocument`` (Pydantic). Errors raise
``pydantic.ValidationError`` with field-level paths.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from trace_engine.validate.schema import SourcesDocument


def load_sources(path: str | Path) -> SourcesDocument:
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return SourcesDocument.model_validate(payload)
