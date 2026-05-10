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

    # L3 extraction — chunk long reports so a single LLM call doesn't blow
    # past max_output_tokens. Paragraph-aligned splits, results merged in code.
    extraction_chunk_chars: int = field(
        default_factory=lambda: int(os.environ.get("TRACE_EXTRACTION_CHUNK_CHARS", "12000"))
    )

    # External-reference SHA-256 augmentation (0.5.0). Removes the OASIS
    # validator's {302} "URL but no hash" warning by fetching each external
    # reference URL and recording the SHA-256 of the response bytes. Cached
    # to a JSON file with TTL so consecutive bundles don't re-fetch.
    external_ref_hash_enabled: bool = field(
        default_factory=lambda: (
            os.environ.get("TRACE_EXTERNAL_REF_HASH_ENABLED", "true").lower()
            not in ("0", "false", "no", "off")
        )
    )
    external_ref_hash_cache_path: str = field(
        default_factory=lambda: os.environ.get(
            "TRACE_EXTERNAL_REF_HASH_CACHE", "output/external_ref_hash_cache.json"
        )
    )
    external_ref_hash_ttl_days: int = field(
        default_factory=lambda: int(os.environ.get("TRACE_EXTERNAL_REF_HASH_TTL_DAYS", "30"))
    )

    # Crawler
    # The pre-1.4.1 default carried a bot-identifying tool string (the
    # project's own name + URL). Cloudflare-fronted CTI sites (Trend
    # Micro, others) reliably blocked that pattern with 429 / 403 — see
    # TRACE 1.4.1 changelog. The current default is a widely-deployed
    # Firefox-on-macOS string that passes typical commercial
    # bot-detection heuristics. Override via TRACE_CRAWL_USER_AGENT when
    # a more identifying UA is operationally required (e.g. internal
    # honeypots that whitelist CTI collectors).
    crawl_user_agent: str = field(
        default_factory=lambda: os.environ.get(
            "TRACE_CRAWL_USER_AGENT",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.1; rv:136.0) "
            "Gecko/20100101 Firefox/136.0",
        )
    )
    state_path: str = field(
        default_factory=lambda: os.environ.get("TRACE_STATE_PATH", "output/crawl_state.json")
    )

    # Concurrency for crawl_batch (TRACE 0.8.0). 1 = sequential (legacy
    # behaviour). >1 dispatches per-source work to a ThreadPoolExecutor
    # with that many workers. Bumping this without considering Vertex AI
    # quota (per-tier QPM) can cause rate-limit errors; recommended
    # range 1..8.
    crawl_concurrency: int = field(
        default_factory=lambda: int(os.environ.get("TRACE_CRAWL_CONCURRENCY", "4"))
    )

    # GitHub / GHE review workflow
    ghe_token: str = field(default_factory=lambda: os.environ.get("TRACE_GHE_TOKEN", ""))
    ghe_repo: str = field(default_factory=lambda: os.environ.get("GHE_REPO", ""))
    ghe_api_base: str = field(
        default_factory=lambda: os.environ.get("GHE_API_BASE", "https://api.github.com")
    )


def load_config() -> Config:
    return Config()
