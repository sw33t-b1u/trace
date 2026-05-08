"""TRACE configuration — environment-variable based."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Literal

RelevanceTier = Literal["simple", "medium", "complex"]


@dataclass
class Config:
    # GCP / Vertex AI
    gcp_project_id: str = field(default_factory=lambda: os.environ.get("GCP_PROJECT_ID", ""))
    vertex_location: str = field(
        default_factory=lambda: os.environ.get("VERTEX_LOCATION", "us-central1")
    )

    # LLM model selection (overridable per environment)
    llm_model_simple: str = field(
        default_factory=lambda: os.environ.get("TRACE_LLM_SIMPLE", "gemini-2.5-flash-lite")
    )
    llm_model_medium: str = field(
        default_factory=lambda: os.environ.get("TRACE_LLM_MEDIUM", "gemini-2.5-flash")
    )
    llm_model_complex: str = field(
        default_factory=lambda: os.environ.get("TRACE_LLM_COMPLEX", "gemini-2.5-pro")
    )

    # PIR relevance gate (L2)
    relevance_model_tier: RelevanceTier = field(
        default_factory=lambda: os.environ.get("TRACE_RELEVANCE_MODEL_TIER", "simple")  # type: ignore[return-value]
    )
    relevance_threshold: float = field(
        default_factory=lambda: float(os.environ.get("TRACE_RELEVANCE_THRESHOLD", "0.5"))
    )

    # Crawler
    crawl_user_agent: str = field(
        default_factory=lambda: os.environ.get(
            "TRACE_CRAWL_USER_AGENT", "TRACE/0.1 (+https://github.com/sw33t-b1u/sage)"
        )
    )
    state_path: str = field(
        default_factory=lambda: os.environ.get("TRACE_STATE_PATH", "output/crawl_state.json")
    )

    # GitHub / GHE review workflow
    ghe_token: str = field(default_factory=lambda: os.environ.get("TRACE_GHE_TOKEN", ""))
    ghe_repo: str = field(default_factory=lambda: os.environ.get("GHE_REPO", ""))
    ghe_api_base: str = field(
        default_factory=lambda: os.environ.get("GHE_API_BASE", "https://api.github.com")
    )


def load_config() -> Config:
    return Config()
