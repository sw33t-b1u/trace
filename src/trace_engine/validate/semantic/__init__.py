"""Semantic / referential checks layered on top of schema validation."""

from trace_engine.validate.semantic.findings import (
    Severity,
    ValidationFinding,
)

__all__ = ["Severity", "ValidationFinding"]
