"""Tests for Initiative H §2 Decision H-12b — per-version reject messaging.

When TRACE 1.12.0 rejects a wrapped ``pir_output.json`` because its
``schema_version`` is outside ``SUPPORTED_PIR_SCHEMA_VERSIONS = {"1.0.0"}``,
the error message takes one of two forms:

1. **Historical pre-1.0 version** (``0.16.0`` / ``0.17.0`` / ``0.18.0``) —
   name the TRACE minor that last accepted the version and direct the
   operator to re-emit with BEACON 1.0.0+:

       schema_version "0.18.0" was supported in TRACE 1.11.0; please
       re-emit with BEACON 1.0.0+ output.

2. **Any other unrecognised version** (``0.15.0``, ``1.1.0``, etc.) —
   generic message naming the current TRACE version and the supported
   set:

       schema_version "1.1.0" is not supported by TRACE 1.12.0;
       supported: {1.0.0}.

The mapping is the operator-facing migration story called out in the
Initiative H CHANGELOG (Decision 12 — Migration guide section).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from trace_engine.validate.schema.models import (
    PIROutputDocument,
)

FIXTURES = Path(__file__).parent / "fixtures" / "legacy_rejected"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Pre-1.0 versions — per-version "was supported in TRACE X.Y.Z" message.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture_name", "schema_version", "expected_trace_version"),
    [
        ("pir_016_actor_triage.json", "0.16.0", "1.9.0"),
        ("pir_017_renamed_recency.json", "0.17.0", "1.10.0"),
        ("pir_018_ir_factors.json", "0.18.0", "1.11.0"),
    ],
)
class TestLegacyVersionRejectMessage:
    def test_legacy_version_rejected_with_per_version_message(
        self, fixture_name, schema_version, expected_trace_version
    ):
        payload = _load(fixture_name)
        with pytest.raises(ValidationError) as exc:
            PIROutputDocument.model_validate(payload)
        msg = str(exc.value)
        assert f'"{schema_version}"' in msg
        assert f"TRACE {expected_trace_version}" in msg
        assert "please re-emit with BEACON 1.0.0+ output" in msg

    def test_legacy_version_message_omits_generic_supported_clause(
        self, fixture_name, schema_version, expected_trace_version
    ):
        """The per-version message is the *migration* message — it directs
        operators to a re-emit step, not to a supported-set listing."""
        payload = _load(fixture_name)
        with pytest.raises(ValidationError) as exc:
            PIROutputDocument.model_validate(payload)
        msg = str(exc.value)
        assert "supported: {" not in msg


# ---------------------------------------------------------------------------
# Unknown / future versions — generic message naming current TRACE version.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "schema_version",
    ["0.15.0", "1.1.0", "1.0.1", "2.0.0", "0.0.1"],
)
class TestGenericFutureRejectMessage:
    def _payload(self, schema_version: str) -> dict:
        return {
            "schema_version": schema_version,
            "pirs": [
                {
                    "pir_id": "PIR-REJECT-001",
                    "intelligence_level": "operational",
                    "threat_actor_tags": ["apt-china"],
                    "asset_weight_rules": [
                        {"tag": "external-facing", "criticality_multiplier": 2.0}
                    ],
                    "valid_from": "2026-05-24",
                    "valid_until": "2027-05-24",
                    "prioritized_actors": [],
                }
            ],
        }

    def test_unknown_version_rejected_with_generic_message(self, schema_version):
        with pytest.raises(ValidationError) as exc:
            PIROutputDocument.model_validate(self._payload(schema_version))
        msg = str(exc.value)
        assert f'"{schema_version}"' in msg
        assert "is not supported by TRACE" in msg
        assert "supported: {1.0.0}" in msg

    def test_generic_message_names_current_trace_version(self, schema_version):
        """Sanity check: the message references TRACE 1.12.0 — the version
        that ships Initiative H. Phase 7 will bump ``_TRACE_VERSION`` and
        this assertion will need to track the bump."""
        with pytest.raises(ValidationError) as exc:
            PIROutputDocument.model_validate(self._payload(schema_version))
        assert "TRACE 1.12.0" in str(exc.value)


# ---------------------------------------------------------------------------
# Smoke test — the two branches don't cross-talk.
# ---------------------------------------------------------------------------


class TestRejectMessageBranchIsolation:
    def test_pre_1_0_message_does_not_mention_current_trace_version(self):
        """A 0.18.0 reject should name TRACE 1.11.0 (the historical last
        supporter), not TRACE 1.12.0 (the current rejector)."""
        payload = _load("pir_018_ir_factors.json")
        with pytest.raises(ValidationError) as exc:
            PIROutputDocument.model_validate(payload)
        msg = str(exc.value)
        assert "TRACE 1.11.0" in msg
        assert "TRACE 1.12.0" not in msg

    def test_unknown_version_message_does_not_mention_historical_trace_version(self):
        """A 1.1.0 reject should name TRACE 1.12.0 only — there is no
        historical version mapping for 1.1.0."""
        payload = {
            "schema_version": "1.1.0",
            "pirs": [
                {
                    "pir_id": "PIR-FUT-001",
                    "intelligence_level": "operational",
                    "threat_actor_tags": [],
                    "asset_weight_rules": [],
                    "valid_from": "2026-05-24",
                    "valid_until": "2027-05-24",
                    "prioritized_actors": [],
                }
            ],
        }
        with pytest.raises(ValidationError) as exc:
            PIROutputDocument.model_validate(payload)
        msg = str(exc.value)
        assert "TRACE 1.12.0" in msg
        for legacy in ("1.9.0", "1.10.0", "1.11.0"):
            assert f"TRACE {legacy}" not in msg
