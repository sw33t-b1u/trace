"""Retry helper for transient feed fetch/parse failures.

Initiative F (TRACE 1.10.0) introduced feed expansion that adds an extra
remote dependency per source (the feed payload itself). The batch driver
uses ``retry_with_backoff`` so a single 502 or transient TCP reset
doesn't drop a whole feed for the run.

Persistent failures (all retries exhausted) are logged as a structured
event with the underlying exception chain attached so operators can
identify the root cause from logs without re-running the crawl.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import structlog

logger = structlog.get_logger(__name__)

DEFAULT_BACKOFF_SECONDS: tuple[float, ...] = (1.0, 2.0, 4.0)


def retry_with_backoff[T](
    fn: Callable[[], T],
    *,
    exceptions: tuple[type[BaseException], ...],
    backoff_seconds: tuple[float, ...] = DEFAULT_BACKOFF_SECONDS,
    operation: str,
    context: dict | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    """Call ``fn`` until it succeeds or retries are exhausted.

    ``backoff_seconds`` is the wait between attempts; ``len(backoff_seconds)
    + 1`` total attempts are made (the default 3-tuple gives 4 attempts
    total = 1 initial + 3 retries with 1s/2s/4s waits).

    On retryable exception: structured ``feed_fetch_retry`` warning logged.
    On final failure: structured ``feed_fetch_giveup`` error logged with
    ``error`` (str) + ``error_type``; original exception re-raised so the
    caller can attribute the outcome (e.g. skip the feed and continue with
    other sources).

    Non-retryable exceptions propagate immediately without retry.

    ``sleep`` is injectable so tests can verify backoff timing without
    actually pausing.
    """
    attempts = len(backoff_seconds) + 1
    last_exc: BaseException | None = None
    extra = context or {}
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except exceptions as exc:
            last_exc = exc
            if attempt >= attempts:
                logger.error(
                    "feed_fetch_giveup",
                    operation=operation,
                    attempts=attempt,
                    error=str(exc),
                    error_type=type(exc).__name__,
                    **extra,
                )
                raise
            wait = backoff_seconds[attempt - 1]
            logger.warning(
                "feed_fetch_retry",
                operation=operation,
                attempt=attempt,
                next_wait_seconds=wait,
                error=str(exc),
                error_type=type(exc).__name__,
                **extra,
            )
            sleep(wait)
    # Defensive — loop always returns or raises; this keeps type-checkers happy.
    assert last_exc is not None
    raise last_exc
