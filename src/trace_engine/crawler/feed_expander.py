"""Parse RSS / Atom payloads into a list of crawlable per-entry URLs.

Used by ``crawler/batch.py`` after ``feed_detector`` classifies a source
as ``rss`` or ``atom``. Each ``FeedEntry`` becomes its own URL in the
crawl loop; downstream dedup (``crawler/state.py``) and the L2 PIR gate
operate per entry.

Malformed feeds raise ``FeedParseError`` so the batch driver can attribute
the failure to feed parsing (not to network/fetch) and log a structured
root cause before moving on to the next source.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from time import struct_time

import feedparser

__all__ = ["FeedEntry", "FeedParseError", "expand_feed"]


class FeedParseError(RuntimeError):
    """Raised when feedparser cannot turn the payload into a feed.

    Distinguishes parser failure from network/fetch failure so the batch
    driver records the right structured-log root cause.
    """


@dataclass(frozen=True)
class FeedEntry:
    url: str
    title: str | None
    published: datetime | None


def expand_feed(content: bytes, *, feed_url: str | None = None) -> list[FeedEntry]:
    """Parse an RSS/Atom payload and return its entries in feed order.

    ``feed_url`` is informational only — included in ``FeedParseError``
    messages so logs can attribute failure to the source.
    """
    parsed = feedparser.parse(content)
    if parsed.bozo and not parsed.entries:
        exc = parsed.bozo_exception
        reason = str(exc) if exc else "unknown parser error"
        location = f" ({feed_url})" if feed_url else ""
        raise FeedParseError(f"feedparser failed to parse feed{location}: {reason}")

    entries: list[FeedEntry] = []
    for raw in parsed.entries:
        url = _entry_url(raw)
        if not url:
            continue
        entries.append(
            FeedEntry(
                url=url,
                title=_clean(raw.get("title")),
                published=_entry_published(raw),
            )
        )
    return entries


def _entry_url(raw) -> str | None:
    """Pick the best canonical URL for a feed entry.

    RSS uses ``link``. Atom uses an ``<entry><link rel="alternate"/></entry>``
    element, which feedparser exposes as ``link`` (string) and ``links``
    (list of dicts). Prefer the alternate link when explicit; fall back to
    bare ``link``.
    """
    links = raw.get("links") or []
    for link in links:
        rel = (link.get("rel") or "alternate").lower()
        href = link.get("href")
        if rel == "alternate" and href:
            return href.strip()
    link = raw.get("link")
    if isinstance(link, str) and link.strip():
        return link.strip()
    return None


def _entry_published(raw) -> datetime | None:
    """Convert feedparser's ``published_parsed`` / ``updated_parsed`` to UTC datetime."""
    for key in ("published_parsed", "updated_parsed"):
        ts = raw.get(key)
        if isinstance(ts, struct_time):
            return datetime(*ts[:6], tzinfo=UTC)
    return None


def _clean(value) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None
