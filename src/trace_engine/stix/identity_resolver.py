"""Resolve LLM-supplied identity references against a BEACON ``identity_assets.json``.

Initiative C §3.2: TRACE resolves impersonation and attribution identity
references using a 4-tier ladder modeled on ``asset_resolver``.

| Tier | Match strategy                              | Confidence |
|------|---------------------------------------------|------------|
| 1    | Exact name match (case-insensitive)         | 80         |
| 2    | Substring match in name (≥4 chars)          | 50         |
| 3    | Tag / sector / role substring match         | 30         |
| 4    | No match — drop with structured-log warning | —          |

Same drop-on-ambiguity rule as ``asset_resolver``: when multiple identities
match at the same tier, the resolver returns ``None`` and logs
``identity_resolution_ambiguous``.
"""

from __future__ import annotations

from dataclasses import dataclass

import structlog

logger = structlog.get_logger(__name__)

# Minimum substring length for tier-2 to fire. Matches asset_resolver's
# rationale: tokens shorter than 4 chars ("ID", "DB", "DHL"[:3]) are too
# ambiguous to bind to a single identity.
_TIER2_MIN_OVERLAP = 4


@dataclass(frozen=True)
class Resolution:
    """Result of resolving an LLM identity hint to a known BEACON identity.

    ``confidence`` follows the design table: 80 / 50 / 30 / drop.
    """

    identity_id: str
    tier: int  # 1 / 2 / 3 — which rung matched
    confidence: int


def resolve_identity_reference(
    reference: str,
    identities: list[dict],
) -> Resolution | None:
    """Resolve a free-form LLM ``reference`` against the given identities.

    ``identities`` is the flat list of identity entries extracted from
    ``identity_assets.json[*].identities[]`` — each entry must have at least
    ``id`` and ``name``; ``roles`` and ``sectors`` are consulted at tier 3.

    Returns ``None`` to signal "drop the relationship", with a structured-log
    entry describing why (no match, or ambiguous match).
    """
    cleaned = (reference or "").strip()
    if not cleaned:
        logger.warning("identity_reference_empty")
        return None

    cleaned_lower = cleaned.lower()

    # Tier 1: exact case-insensitive match against identity.name.
    tier1 = [i for i in identities if (i.get("name") or "").strip().lower() == cleaned_lower]
    if len(tier1) == 1:
        return Resolution(identity_id=tier1[0]["id"], tier=1, confidence=80)
    if len(tier1) > 1:
        logger.warning(
            "identity_resolution_ambiguous",
            tier=1,
            reference=cleaned,
            candidates=[i["id"] for i in tier1],
        )
        return None

    # Tier 2: bidirectional substring overlap (≥ _TIER2_MIN_OVERLAP).
    tier2 = []
    for ident in identities:
        name = (ident.get("name") or "").strip().lower()
        if not name:
            continue
        if cleaned_lower in name and len(cleaned_lower) >= _TIER2_MIN_OVERLAP:
            tier2.append(ident)
            continue
        if name in cleaned_lower and len(name) >= _TIER2_MIN_OVERLAP:
            tier2.append(ident)
    if len(tier2) == 1:
        return Resolution(identity_id=tier2[0]["id"], tier=2, confidence=50)
    if len(tier2) > 1:
        logger.warning(
            "identity_resolution_ambiguous",
            tier=2,
            reference=cleaned,
            candidates=[i["id"] for i in tier2],
        )
        return None

    # Tier 3: substring match within roles[] ∪ sectors[]. description is
    # excluded as too noisy (decided 2026-05-11 per HLD §3.2).
    tier3 = []
    for ident in identities:
        fields: list[str] = []
        roles = ident.get("roles") or []
        if isinstance(roles, list):
            fields.extend(str(r) for r in roles if r)
        sectors = ident.get("sectors") or []
        if isinstance(sectors, list):
            fields.extend(str(s) for s in sectors if s)
        if any(cleaned_lower in f.lower() for f in fields):
            tier3.append(ident)
    if len(tier3) == 1:
        return Resolution(identity_id=tier3[0]["id"], tier=3, confidence=30)
    if len(tier3) > 1:
        logger.warning(
            "identity_resolution_ambiguous",
            tier=3,
            reference=cleaned,
            candidates=[i["id"] for i in tier3],
        )
        return None

    # Tier 4: no match.
    logger.warning("identity_reference_unresolved", reference=cleaned)
    return None
