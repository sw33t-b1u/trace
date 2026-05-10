"""Convert CTI reports (PDF, URL, text) to Markdown text for STIX extraction.

Uses markitdown (Microsoft) to convert inputs to clean Markdown.  Compared to
plain-text extraction, Markdown output:
- Discards navigation bars, footers, ads, and sidebars (lower noise)
- Preserves document structure: headings, tables, lists
- Produces 3–5× fewer characters for the same article content

Supported sources:
- https?:// URL   — markitdown fetches and converts the article
- .pdf file       — markitdown extracts text via pdfminer.six
- Any other file  — read as plain text (no conversion needed)
"""

from __future__ import annotations

import re
from pathlib import Path

import structlog

from trace_engine.config import Config, load_config

logger = structlog.get_logger(__name__)

# Target character limit for the LLM prompt (~7.5 k tokens).
# markitdown's clean Markdown output typically fits a full CTI blog post within
# this limit.  Use read_report(source, max_chars=...) to override.
_MAX_CHARS = 30_000


def _markitdown_convert(source: str, *, config: Config | None = None) -> str:
    """Convert a URL or file path to Markdown using markitdown.

    1.4.1: TRACE-configured ``crawl_user_agent`` is now propagated into
    markitdown's URL fetch via a custom ``requests.Session``. The
    upstream library's default behaviour does not set a User-Agent at
    all, so the underlying ``requests`` library sends
    ``python-requests/X.Y.Z`` — Cloudflare-fronted CTI sites
    (Trend Micro, others) reliably reject that with 429/403. Passing a
    realistic browser UA from ``Config.crawl_user_agent`` resolves it.

    Raises:
        RuntimeError: If markitdown is not installed.
    """
    try:
        import requests  # noqa: PLC0415
        from markitdown import MarkItDown  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError("markitdown is required for PDF/URL input. Run: uv sync") from exc

    cfg = config or load_config()
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": cfg.crawl_user_agent,
            # Mirror markitdown's own preference so we don't lose the
            # markdown-friendly Accept negotiation.
            "Accept": "text/markdown, text/html;q=0.9, text/plain;q=0.8, */*;q=0.1",
        }
    )
    md = MarkItDown(requests_session=session)
    result = md.convert(source)
    return result.text_content or ""


def _find_article_start(text: str) -> int:
    """Return the character offset where the article body likely begins.

    Blog pages converted by markitdown typically start with navigation links,
    menus, and cookie banners before the actual article.  This function skips
    that boilerplate by finding the first H1 or H2 heading after the opening
    navigation section (heuristically the first 500 characters).

    Returns 0 if no heading is found (fall back to full text).
    """
    # Skip the very first chars that are almost always nav/skip-links
    search_from = min(500, len(text))
    match = re.search(r"\n#{1,2} .+", text[search_from:])
    if match:
        return search_from + match.start() + 1  # +1 to skip the leading \n
    return 0


def read_report(
    source: str | Path,
    max_chars: int = _MAX_CHARS,
    *,
    config: Config | None = None,
) -> str:
    """Convert a CTI report to Markdown text and truncate to max_chars.

    Detects source type:
    - https?:// URL     → markitdown fetches and converts the article
    - .pdf file         → markitdown extracts and converts via pdfminer.six
    - any other file    → read as plain text (no conversion needed)

    Args:
        source: URL string, PDF path, or plain-text/Markdown file path.
        max_chars: Maximum characters returned (default: _MAX_CHARS = 30,000).
                   Increase for lengthy technical reports.
        config: Optional ``Config`` instance. The CLI passes its already-
            loaded config so the URL fetch shares the same User-Agent
            settings as everywhere else. Falls back to ``load_config()``
            when omitted.

    Returns:
        Extracted text, truncated to max_chars.

    Raises:
        FileNotFoundError: If a local file does not exist.
        RuntimeError: If markitdown is not installed.
    """
    s = str(source)

    if s.lower().startswith(("http://", "https://")):
        text = _markitdown_convert(s, config=config)
        start = _find_article_start(text)
        body = text[start:]
        logger.info("url_converted", url=s, chars=len(text), body_start=start, body_chars=len(body))
        return body[:max_chars]

    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"Report file not found: {path}")

    if path.suffix.lower() == ".pdf":
        text = _markitdown_convert(str(path), config=config)
        logger.info("pdf_converted", path=str(path), chars=len(text))
        return text[:max_chars]

    # Plain text / Markdown — no conversion needed
    text = path.read_text(encoding="utf-8")
    logger.info("text_read", path=str(path), chars=len(text))
    return text[:max_chars]
