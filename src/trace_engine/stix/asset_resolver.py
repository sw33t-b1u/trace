"""Resolve LLM-supplied asset references against a BEACON ``assets.json``.

Initiative A §6.2: TRACE is the single choke point for asset id
resolution. Analyst manual review is not an acceptable fallback —
unresolved references are dropped at bundle assembly with a structured-
log warning.

The resolver implements a 4-tier matching ladder (decided 2026-05-10):

| Tier | Match | Confidence |
|------|-------|------------|
| 1 | ``Asset.name`` exact (case-insensitive) | 80 |
| 2 | ``Asset.name`` substring overlap ≥ 4 chars | 50 |
| 3 | Single ``Asset.tags`` exact match | 30 |
| 4 | No match | drop |

The ladder is short-circuit: the first tier with a match returns. When
multiple assets match at the same tier (rare for tier 1, common for
tier 3 if a tag is generic), the resolver returns ``None`` and logs
``asset_resolution_ambiguous`` — better to drop than to bind the LLM's
output to an arbitrary winner.
"""

from __future__ import annotations

from dataclasses import dataclass

import structlog

logger = structlog.get_logger(__name__)

# Minimum substring overlap (in characters) for tier 2 to fire. Lower
# values produce false positives ("ID" / "DB" / "API" overlap with too
# many asset names); 4 is the smallest length that filters out
# non-content-bearing tokens like "core" / "main" / "data".
_TIER2_MIN_OVERLAP = 4


@dataclass(frozen=True)
class AssetResolution:
    """Result of resolving an LLM asset hint to a known asset.

    ``confidence`` follows the design doc table: 80 / 50 / 30 / drop.
    """

    asset_id: str
    confidence: int
    tier: int  # 1 / 2 / 3 — useful for logging which rung matched


def resolve_asset_reference(
    reference: str,
    assets: list[dict],
) -> AssetResolution | None:
    """Resolve a free-form LLM ``reference`` against the given assets.

    ``assets`` is the contents of ``assets.json``'s ``assets[]`` —
    each entry must have at least ``id``, ``name``; ``tags`` is consulted
    when present.

    Returns ``None`` to signal "drop the relationship", with a structured
    log entry describing why (no match, or ambiguous match).
    """
    cleaned = (reference or "").strip()
    if not cleaned:
        logger.warning("asset_resolution_empty_reference")
        return None

    cleaned_lower = cleaned.lower()

    # Tier 1: exact case-insensitive match against asset.name.
    tier1 = [a for a in assets if (a.get("name") or "").strip().lower() == cleaned_lower]
    if len(tier1) == 1:
        return AssetResolution(asset_id=tier1[0]["id"], confidence=80, tier=1)
    if len(tier1) > 1:
        logger.warning(
            "asset_resolution_ambiguous",
            tier=1,
            reference=cleaned,
            candidates=[a["id"] for a in tier1],
        )
        return None

    # Tier 2: substring overlap (≥ _TIER2_MIN_OVERLAP). Bidirectional —
    # the reference may be a fragment of the name or vice versa.
    tier2 = []
    for a in assets:
        name = (a.get("name") or "").strip().lower()
        if not name:
            continue
        if cleaned_lower in name and len(cleaned_lower) >= _TIER2_MIN_OVERLAP:
            tier2.append(a)
            continue
        if name in cleaned_lower and len(name) >= _TIER2_MIN_OVERLAP:
            tier2.append(a)
    if len(tier2) == 1:
        return AssetResolution(asset_id=tier2[0]["id"], confidence=50, tier=2)
    if len(tier2) > 1:
        logger.warning(
            "asset_resolution_ambiguous",
            tier=2,
            reference=cleaned,
            candidates=[a["id"] for a in tier2],
        )
        return None

    # Tier 3: single asset whose tags[] contains the reference (lower).
    tier3 = []
    for a in assets:
        tags = a.get("tags") or []
        if any((t or "").strip().lower() == cleaned_lower for t in tags if isinstance(t, str)):
            tier3.append(a)
    if len(tier3) == 1:
        return AssetResolution(asset_id=tier3[0]["id"], confidence=30, tier=3)
    if len(tier3) > 1:
        logger.warning(
            "asset_resolution_ambiguous",
            tier=3,
            reference=cleaned,
            candidates=[a["id"] for a in tier3],
        )
        return None

    logger.warning("asset_resolution_no_match", reference=cleaned)
    return None
