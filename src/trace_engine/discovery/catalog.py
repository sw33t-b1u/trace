"""Source catalog loading for PIR-driven article discovery."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class CatalogSource(BaseModel):
    """One RSS/Atom source that can be searched for article candidates."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1)
    url: str = Field(min_length=1)
    type: Literal["rss", "atom"] = "rss"
    category: str | None = None
    enabled: bool = True
    max_entries: int | None = Field(default=None, gt=0)

    @field_validator("url")
    @classmethod
    def _check_http_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("catalog source url must be http(s)")
        return value


class CatalogDocument(BaseModel):
    """Top-level source catalog document."""

    model_config = ConfigDict(extra="forbid")

    version: int = Field(default=1, ge=1)
    sources: list[CatalogSource] = Field(default_factory=list)

    @property
    def enabled_sources(self) -> list[CatalogSource]:
        """Return only sources enabled for discovery."""
        return [source for source in self.sources if source.enabled]


def load_catalog(path: str | Path) -> CatalogDocument:
    """Load and validate a discovery source catalog YAML file."""
    return load_catalog_text(Path(path).read_text(encoding="utf-8"))


def load_catalog_text(text: str) -> CatalogDocument:
    """Load and validate a discovery source catalog YAML document."""
    payload = yaml.safe_load(text) or {}
    return CatalogDocument.model_validate(payload)
