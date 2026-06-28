"""Build lightweight search terms from BEACON PIR documents."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from trace_engine.validate.schema import PIRDocument, PIRItem

_TERM_MAX_CHARS = 80
_DEFAULT_MAX_TERMS_PER_PIR = 24
_DESCRIPTION_KEYWORD_LIMIT = 6
_STOPWORDS = {
    "about",
    "against",
    "also",
    "and",
    "campaign",
    "collection",
    "from",
    "into",
    "monitor",
    "related",
    "report",
    "risk",
    "target",
    "targeting",
    "that",
    "the",
    "their",
    "threat",
    "this",
    "with",
}


@dataclass(frozen=True)
class SearchTerm:
    """A normalised term tied to the PIR that produced it."""

    pir_id: str
    term: str
    category: str
    weight: float


def build_search_terms(
    pir_doc: PIRDocument,
    *,
    max_terms_per_pir: int = _DEFAULT_MAX_TERMS_PER_PIR,
) -> list[SearchTerm]:
    """Return weighted search terms derived from every PIR item."""
    terms: list[SearchTerm] = []
    for item in pir_doc.root:
        terms.extend(_terms_for_item(item, max_terms=max_terms_per_pir))
    return terms


def _terms_for_item(item: PIRItem, *, max_terms: int) -> list[SearchTerm]:
    seen: set[str] = set()
    out: list[SearchTerm] = []

    def add(raw: object, category: str, weight: float) -> None:
        if len(out) >= max_terms:
            return
        term = _normalise_term(raw)
        if term is None or term in seen:
            return
        seen.add(term)
        out.append(SearchTerm(pir_id=item.pir_id, term=term, category=category, weight=weight))

    payload = item.model_dump(mode="python")

    for actor in item.prioritized_actors:
        add(actor.name, "actor", 0.5)
        for alias in actor.aliases:
            add(alias, "actor_alias", 0.5)

    for tag in item.threat_actor_tags:
        add(tag, "threat_actor_tag", 0.3)

    for key in ("notable_groups", "collection_focus"):
        for value in _as_list(payload.get(key)):
            add(value, key, 0.2)

    for rule in item.asset_weight_rules:
        add(rule.tag, "asset_tag", 0.1)

    for keyword in _description_keywords(item.description or ""):
        add(keyword, "description", 0.1)

    return out


def _normalise_term(raw: object) -> str | None:
    if raw is None:
        return None
    term = str(raw).strip().lower()
    term = re.sub(r"[_\s]+", " ", term)
    term = re.sub(r"\s+", " ", term).strip(" -_.,;:()[]{}\t\n\r")
    if len(term) < 3 or len(term) > _TERM_MAX_CHARS:
        return None
    if term in _STOPWORDS:
        return None
    return term


def _description_keywords(description: str) -> list[str]:
    words = re.findall(r"[A-Za-z][A-Za-z0-9-]{3,}", description.lower())
    out: list[str] = []
    seen: set[str] = set()
    for word in words:
        if word in _STOPWORDS or word in seen:
            continue
        seen.add(word)
        out.append(word)
        if len(out) >= _DESCRIPTION_KEYWORD_LIMIT:
            break
    return out


def _as_list(value: Any) -> list[object]:
    if isinstance(value, list):
        return value
    return []
