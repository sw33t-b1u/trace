"""Common finding type emitted by every validation layer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Severity = Literal["error", "warning", "info"]


@dataclass(frozen=True)
class ValidationFinding:
    """A single validation result.

    Severities:
      - ``error``: blocks SAGE ingestion.
      - ``warning``: surfaced for analyst review; does not block by default.
      - ``info``: contextual note (e.g., "0 PIRs loaded").
    """

    severity: Severity
    code: str
    location: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "code": self.code,
            "location": self.location,
            "message": self.message,
        }


def has_errors(findings: list[ValidationFinding]) -> bool:
    return any(f.severity == "error" for f in findings)
