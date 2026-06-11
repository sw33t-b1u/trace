"""Shared test configuration.

Scrubs ambient proxy environment variables for every test: an inherited
SOCKS/HTTP proxy (e.g. ``ALL_PROXY=socks5h://...``) redirects httpx and
requires the optional ``socksio`` dependency, turning hermetic unit tests
into environment-dependent failures (observed: 9 ``test_crawl_batch*``
ImportError failures under a SOCKS proxy shell). Tests that need a proxy
must set it explicitly via ``monkeypatch.setenv``.
"""

from __future__ import annotations

import pytest

_PROXY_ENV_TO_SCRUB = (
    "ALL_PROXY",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "all_proxy",
    "http_proxy",
    "https_proxy",
)


@pytest.fixture(autouse=True)
def _scrub_proxy_env(monkeypatch):
    """Remove ambient proxy variables so httpx never routes through a proxy."""
    for _key in _PROXY_ENV_TO_SCRUB:
        monkeypatch.delenv(_key, raising=False)
