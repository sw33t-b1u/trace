"""Shared structlog configuration for TRACE CLI entry points."""

from __future__ import annotations

import structlog


def configure() -> None:
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
    )
