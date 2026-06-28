"""Candidate article models for PIR-driven discovery."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ArticleCandidate(BaseModel):
    """One article candidate discovered before human approval."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1)
    title: str | None = None
    source_name: str | None = None
    published_at: datetime | None = None
    matched_pir_ids: list[str] = Field(default_factory=list)
    matched_terms: list[str] = Field(default_factory=list)
    score: float = Field(ge=0.0, le=1.0)
    summary: str | None = None


class CandidateDocument(BaseModel):
    """JSON envelope emitted by ``trace discover-pir``."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0.0"
    generated_at: datetime
    pir_path: str
    window: dict[str, str]
    candidates: list[ArticleCandidate] = Field(default_factory=list)

    def to_jsonable(self) -> dict[str, Any]:
        """Return a JSON-serialisable dictionary with ISO datetimes."""
        return self.model_dump(mode="json")
