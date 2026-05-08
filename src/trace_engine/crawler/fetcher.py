"""HTTP fetcher used by the batch crawler.

Thin wrapper over httpx that applies UA and timeout from ``Config`` and exposes
``fetch(url) -> FetchResult``. Errors are surfaced as ``FetchError`` so the
batch driver can record a warning per source without aborting the run.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx
import structlog

from trace_engine.config import Config, load_config

logger = structlog.get_logger(__name__)

DEFAULT_TIMEOUT = 30.0


class FetchError(RuntimeError):
    """Raised when a URL cannot be retrieved."""


@dataclass(frozen=True)
class FetchResult:
    url: str
    status_code: int
    content: bytes
    content_type: str | None


def fetch(
    url: str,
    *,
    config: Config | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> FetchResult:
    cfg = config or load_config()
    headers = {"User-Agent": cfg.crawl_user_agent}
    logger.info("fetch_start", url=url)
    try:
        response = httpx.get(url, headers=headers, timeout=timeout, follow_redirects=True)
    except httpx.HTTPError as exc:
        raise FetchError(f"network error fetching {url}: {exc}") from exc

    if response.status_code >= 400:
        raise FetchError(f"HTTP {response.status_code} fetching {url}")

    logger.info(
        "fetch_done",
        url=url,
        status=response.status_code,
        bytes=len(response.content),
    )
    return FetchResult(
        url=url,
        status_code=response.status_code,
        content=response.content,
        content_type=response.headers.get("content-type"),
    )
