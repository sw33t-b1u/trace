"""Shared structlog configuration for TRACE CLI entry points."""

from __future__ import annotations

import structlog

from trace_engine.cli._metrics import get_collector


def _metrics_processor(logger, method_name: str, event_dict: dict) -> dict:
    """Forward log records to the active ``MetricsCollector``, if any.

    Decoupled from a direct ``MetricsCollector.__call__`` reference so the
    collector can be swapped in / out without re-configuring structlog.
    """
    collector = get_collector()
    if collector is not None:
        collector(logger, method_name, event_dict)
    return event_dict


def configure() -> None:
    structlog.configure(
        processors=[
            _metrics_processor,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
    )
