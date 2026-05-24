"""Validate IoC entries emitted by the L2 PIR-relevance LLM call.

Initiative G Phase 4 piggy-backs IoC extraction on the existing
relevance-gate Vertex call: a single LLM round-trip per article emits
both the L2 verdict and an ``iocs`` list. This module is the strict
validator over that list — it converts the raw LLM output into a
deterministic ``list[dict]`` suitable for persistence in
``crawl_state.json``.

Design choices:

* **Strict Pydantic per entry**: each IoC is validated independently.
  A single malformed entry never poisons the whole list; the helper
  drops it and emits a structured-log warning so the operator can see
  what was rejected.
* **Plan §2.6 fixes 7 types**: ipv4, ipv6, fqdn, sha256, sha1, md5,
  cve_id. Any other ``type`` value is rejected; the LLM may include
  it but we drop it here so downstream search is bounded.
* **No regex extraction**: the 2026-05-23 user policy rejected regex
  IoC pickup because of the false-positive rate on real CTI articles.
  This module does NOT attempt fallback extraction when the LLM emits
  no ``iocs`` field — that case is treated as "no IoCs found".
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

logger = structlog.get_logger(__name__)

# Per plan §2.6 / §3 — bounded to the seven types BEACON's IR-boost
# loop cares about. Adding a new type requires a producer (LLM prompt)
# update + a SAGE / BEACON consumer update, so it is deliberately
# narrow.
_CONTEXT_SNIPPET_MAX_CHARS = 50
_VALUE_MAX_CHARS = 512


class IoCType(StrEnum):
    """Controlled vocabulary for ``IoC.type`` (plan §2.6)."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    FQDN = "fqdn"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    CVE_ID = "cve_id"


class IoC(BaseModel):
    """One IoC entry as emitted by the L2 LLM call."""

    model_config = ConfigDict(extra="forbid")
    type: IoCType
    value: str = Field(..., min_length=1, max_length=_VALUE_MAX_CHARS)
    confidence: float = Field(..., ge=0.0, le=1.0)
    # ``context_snippet`` is not gated by ``max_length`` so that an
    # over-long LLM snippet is *truncated* by the validator below
    # rather than rejected outright — the IoC itself is the load-bearing
    # field and an over-long context blurb should not drop the whole
    # entry from the index.
    context_snippet: str = Field(default="")

    @field_validator("value")
    @classmethod
    def _strip_value(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("value must not be empty after stripping whitespace")
        return stripped

    @field_validator("context_snippet")
    @classmethod
    def _collapse_whitespace(cls, v: str) -> str:
        # Plan §2.6 says context_snippet is up to 50 chars with newlines
        # collapsed to single spaces. The LLM may forget; collapse here.
        collapsed = " ".join(v.split())
        return collapsed[:_CONTEXT_SNIPPET_MAX_CHARS]


def extract_iocs(
    raw: Any,
    *,
    article_url: str | None = None,
) -> list[dict[str, Any]]:
    """Validate the LLM-emitted IoC list, dropping malformed entries.

    Returns a list of dicts (not Pydantic models) so the result is
    JSON-serialisable directly into ``crawl_state.json`` and survives
    a round-trip without an additional model dump step.

    A non-list input (None, dict, etc.) is treated as "no IoCs" and an
    empty list is returned. Each individual entry that fails Pydantic
    validation is dropped with a structured-log warning carrying the
    original entry preview and the offending article URL.
    """
    if raw is None:
        return []
    if not isinstance(raw, list):
        logger.warning(
            "ioc_extractor_non_list_payload",
            article_url=article_url,
            type=type(raw).__name__,
        )
        return []
    validated: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            logger.warning(
                "ioc_entry_dropped_non_object",
                article_url=article_url,
                index=index,
                type=type(item).__name__,
            )
            continue
        try:
            ioc = IoC.model_validate(item)
        except ValidationError as exc:
            logger.warning(
                "ioc_entry_dropped_invalid",
                article_url=article_url,
                index=index,
                error=str(exc).splitlines()[0],
                preview=str(item)[:200],
            )
            continue
        validated.append(ioc.model_dump(mode="json"))
    return validated
