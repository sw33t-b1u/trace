"""RSS/Atom based article discovery for BEACON PIRs."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from time import struct_time
from typing import Any

import feedparser

from trace_engine.config import Config, load_config
from trace_engine.crawler.fetcher import fetch
from trace_engine.discovery.candidates import ArticleCandidate
from trace_engine.discovery.catalog import CatalogDocument, CatalogSource
from trace_engine.discovery.query import SearchTerm, build_search_terms
from trace_engine.validate.schema import PIRDocument

FetchFeed = Callable[[str, Config], bytes]


@dataclass(frozen=True)
class _ParsedFeedEntry:
    url: str
    title: str | None
    summary: str | None
    published_at: datetime | None


def discover_candidates(
    pir_doc: PIRDocument,
    catalog: CatalogDocument,
    *,
    start_date: date,
    end_date: date,
    config: Config | None = None,
    max_candidates: int = 50,
    fetch_feed: FetchFeed | None = None,
) -> list[ArticleCandidate]:
    """Discover candidate articles for ``pir_doc`` from RSS/Atom catalog sources.

    The function performs no LLM calls. It fetches each enabled catalog feed,
    filters entries to the requested date window when a published timestamp is
    present, scores lightweight title/summary/url term matches, deduplicates by
    URL, and returns candidates sorted by score and recency.
    """
    cfg = config or load_config()
    terms = build_search_terms(pir_doc)
    if not terms or max_candidates <= 0:
        return []

    do_fetch = fetch_feed or _fetch_feed
    candidates: dict[str, ArticleCandidate] = {}
    for source in catalog.enabled_sources:
        payload = do_fetch(source.url, cfg)
        for entry in _parse_feed(payload):
            if not _in_window(entry.published_at, start_date=start_date, end_date=end_date):
                continue
            candidate = _score_entry(
                entry,
                source=source,
                terms=terms,
                start_date=start_date,
                end_date=end_date,
            )
            if candidate is None:
                continue
            key = _normalise_url(candidate.url)
            existing = candidates.get(key)
            candidates[key] = (
                candidate if existing is None else _merge_candidates(existing, candidate)
            )

    return sorted(
        candidates.values(),
        key=lambda c: (c.score, c.published_at or datetime.min.replace(tzinfo=UTC), c.title or ""),
        reverse=True,
    )[:max_candidates]


def _fetch_feed(url: str, cfg: Config) -> bytes:
    return fetch(url, config=cfg).content


def _parse_feed(content: bytes) -> list[_ParsedFeedEntry]:
    parsed = feedparser.parse(content)
    entries: list[_ParsedFeedEntry] = []
    for raw in parsed.entries:
        url = _entry_url(raw)
        if not url:
            continue
        entries.append(
            _ParsedFeedEntry(
                url=url,
                title=_clean(raw.get("title")),
                summary=_clean(raw.get("summary") or raw.get("description")),
                published_at=_entry_published(raw),
            )
        )
    return entries


def _entry_url(raw: Any) -> str | None:
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


def _entry_published(raw: Any) -> datetime | None:
    for key in ("published_parsed", "updated_parsed"):
        ts = raw.get(key)
        if isinstance(ts, struct_time):
            return datetime(*ts[:6], tzinfo=UTC)
    return None


def _clean(value: object) -> str | None:
    if isinstance(value, str):
        text = re.sub(r"<[^>]+>", " ", value)
        text = re.sub(r"\s+", " ", text).strip()
        return text or None
    return None


def _in_window(published_at: datetime | None, *, start_date: date, end_date: date) -> bool:
    # Keep undated feed entries: many CTI feeds omit reliable pubdates, and
    # BEACON still presents them for human approval before extraction.
    if published_at is None:
        return True
    start = datetime.combine(start_date, time.min, tzinfo=UTC)
    end = datetime.combine(end_date, time.max, tzinfo=UTC)
    return start <= published_at <= end


def _score_entry(
    entry: _ParsedFeedEntry,
    *,
    source: CatalogSource,
    terms: list[SearchTerm],
    start_date: date,
    end_date: date,
) -> ArticleCandidate | None:
    text = " ".join(part for part in (entry.title, entry.summary, entry.url) if part)
    title = entry.title or ""
    matched_terms: list[str] = []
    matched_pir_ids: set[str] = set()
    score = 0.0

    for term in terms:
        if not _contains_term(text, term.term):
            continue
        matched_terms.append(term.term)
        matched_pir_ids.add(term.pir_id)
        score += term.weight
        if title and _contains_term(title, term.term):
            score += 0.2

    if not matched_terms:
        return None

    score += _recency_bonus(entry.published_at, start_date=start_date, end_date=end_date)
    return ArticleCandidate(
        url=entry.url,
        title=entry.title,
        source_name=source.name,
        published_at=entry.published_at,
        matched_pir_ids=sorted(matched_pir_ids),
        matched_terms=sorted(set(matched_terms)),
        score=round(min(1.0, score), 3),
        summary=entry.summary,
    )


def _contains_term(text: str, term: str) -> bool:
    haystack = _normalise_match_text(text)
    needle = _normalise_match_text(term)
    if needle in haystack:
        return True
    return needle.replace("-", " ") in haystack.replace("-", " ")


def _normalise_match_text(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[_\s]+", " ", value)
    return re.sub(r"\s+", " ", value)


def _recency_bonus(published_at: datetime | None, *, start_date: date, end_date: date) -> float:
    if published_at is None:
        return 0.0
    start = datetime.combine(start_date, time.min, tzinfo=UTC)
    end = datetime.combine(end_date, time.max, tzinfo=UTC)
    span = max((end - start).total_seconds(), 1.0)
    age_position = max(0.0, min(1.0, (published_at - start).total_seconds() / span))
    return age_position * 0.1


def _normalise_url(url: str) -> str:
    return url.strip().rstrip("/").lower()


def _merge_candidates(left: ArticleCandidate, right: ArticleCandidate) -> ArticleCandidate:
    base = left if left.score >= right.score else right
    other = right if base is left else left
    return base.model_copy(
        update={
            "matched_pir_ids": sorted(set(base.matched_pir_ids) | set(other.matched_pir_ids)),
            "matched_terms": sorted(set(base.matched_terms) | set(other.matched_terms)),
            "score": max(base.score, other.score),
        }
    )
