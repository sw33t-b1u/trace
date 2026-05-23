"""Feed-type detection for the batch crawler.

Given a fetched URL response (``content_type`` header + content prefix),
classify the source as ``html``, ``rss``, or ``atom`` so the batch driver
can decide whether to expand the payload via ``feed_expander`` before
running the L2 PIR relevance gate.

The Content-Type response header is the source of truth. ``sources.yaml``
exposes an optional ``feed_type`` field that overrides detection — used
when an upstream server returns a wrong/generic Content-Type (e.g. plain
``text/xml`` for an Atom feed, or ``application/octet-stream`` for an RSS
file).
"""

from __future__ import annotations

from typing import Literal

FeedType = Literal["html", "rss", "atom"]

_RSS_CONTENT_TYPES: tuple[str, ...] = (
    "application/rss+xml",
    "application/rdf+xml",  # RSS 1.0
)
_ATOM_CONTENT_TYPES: tuple[str, ...] = ("application/atom+xml",)
_GENERIC_XML_CONTENT_TYPES: tuple[str, ...] = (
    "application/xml",
    "text/xml",
)


def detect_feed_type(
    *,
    content_type: str | None,
    content: bytes | None = None,
    override: FeedType | None = None,
) -> FeedType:
    """Return the classification for a fetched source.

    Resolution order:

    1. ``override`` — when ``sources.yaml.feed_type`` is set, trust the
       operator without consulting Content-Type or payload.
    2. ``Content-Type`` header — RSS/Atom-specific MIME types map
       directly; generic XML (``text/xml`` / ``application/xml``) is
       sniffed against ``content`` to disambiguate.
    3. Default — ``html``.
    """
    if override is not None:
        return override

    mime = _mime_only(content_type)

    if mime in _RSS_CONTENT_TYPES:
        return "rss"
    if mime in _ATOM_CONTENT_TYPES:
        return "atom"
    if mime in _GENERIC_XML_CONTENT_TYPES and content is not None:
        sniffed = _sniff_xml(content)
        if sniffed is not None:
            return sniffed
    return "html"


def _mime_only(content_type: str | None) -> str:
    """Strip any ``; charset=…`` parameters and lowercase."""
    if not content_type:
        return ""
    return content_type.split(";", 1)[0].strip().lower()


def _sniff_xml(content: bytes) -> FeedType | None:
    """Inspect the leading bytes of an XML payload to distinguish RSS vs Atom.

    Looks at the first ~2 KiB only — enough to clear the XML prolog and
    reach the root element on every well-formed feed observed in the wild.
    Returns ``None`` if neither marker is found (caller falls back to
    ``html``).
    """
    head = content[:2048].lower()
    if b"<feed" in head and b"http://www.w3.org/2005/atom" in head:
        return "atom"
    if b"<rss" in head or b"<rdf:rdf" in head:
        return "rss"
    return None
