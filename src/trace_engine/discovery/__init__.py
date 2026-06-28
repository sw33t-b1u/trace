"""PIR-driven article discovery helpers for TRACE."""

from trace_engine.discovery.candidates import ArticleCandidate, CandidateDocument
from trace_engine.discovery.catalog import CatalogDocument, CatalogSource
from trace_engine.discovery.feed_search import discover_candidates
from trace_engine.discovery.query import SearchTerm, build_search_terms

__all__ = [
    "ArticleCandidate",
    "CandidateDocument",
    "CatalogDocument",
    "CatalogSource",
    "SearchTerm",
    "build_search_terms",
    "discover_candidates",
]
