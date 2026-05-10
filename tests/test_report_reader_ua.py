"""Tests for ingest/report_reader.py User-Agent propagation (TRACE 1.4.1).

Guards the regression that prompted 1.4.1: the pre-1.4.1
`_markitdown_convert` did not pass any session to MarkItDown, so the
underlying `requests` library sent its default
``python-requests/X.Y.Z`` UA — Cloudflare-fronted CTI sites blocked
that with 429 / 403. The fix is to inject a `requests.Session` with
the configured ``crawl_user_agent`` header.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from trace_engine.config import Config


def _config_with_ua(ua: str) -> Config:
    cfg = Config()
    object.__setattr__(cfg, "crawl_user_agent", ua)
    return cfg


class TestMarkitdownReceivesSession:
    def test_session_carries_user_agent_from_config(self):
        from trace_engine.ingest.report_reader import _markitdown_convert

        cfg = _config_with_ua(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 11.1; rv:136.0) "
            "Gecko/20100101 Firefox/136.0"
        )
        captured: dict = {}

        class _FakeMD:
            def __init__(self, requests_session=None, **_):
                captured["session"] = requests_session

            def convert(self, source):
                m = MagicMock()
                m.text_content = "ok"
                return m

        with patch("markitdown.MarkItDown", _FakeMD):
            out = _markitdown_convert("https://example.com/a", config=cfg)
        assert out == "ok"
        session = captured["session"]
        assert session is not None
        assert "Firefox/136.0" in session.headers["User-Agent"]
        # No tool-name leakage: the configured UA is the only UA on the
        # session, and the marketdown-friendly Accept negotiation is
        # preserved.
        assert "Accept" in session.headers
        assert "text/markdown" in session.headers["Accept"]

    def test_default_config_ua_is_browser_string_not_tool_name(self):
        import os

        # Clear any operator-side override so we exercise the in-code default.
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TRACE_CRAWL_USER_AGENT", None)
            cfg = Config()
        assert "Firefox" in cfg.crawl_user_agent or "Chrome" in cfg.crawl_user_agent
        # Regression guard: pre-1.4.1 default leaked the project name.
        # The current default must not.
        for forbidden in ("TRACE/", "trace/", "github.com/sw33t-b1u"):
            assert forbidden not in cfg.crawl_user_agent

    def test_env_var_override_wins(self):
        import os

        custom = (
            "Mozilla/5.0 (X11; Linux x86_64; rv:137.0) "
            "Gecko/20100101 Firefox/137.0"
        )
        with patch.dict(os.environ, {"TRACE_CRAWL_USER_AGENT": custom}):
            cfg = Config()
        assert cfg.crawl_user_agent == custom


class TestReadReportPassesConfig:
    def test_url_path_forwards_config_to_markitdown(self):
        from trace_engine.ingest import report_reader

        cfg = _config_with_ua("custom-ua-token")
        with patch.object(report_reader, "_markitdown_convert") as conv:
            conv.return_value = "body text"
            report_reader.read_report("https://example.com/x", config=cfg)
        # The CLI calls read_report(..., config=cfg); read_report must
        # forward that to _markitdown_convert (not silently fall back to
        # load_config()).
        kwargs = conv.call_args.kwargs
        assert kwargs.get("config") is cfg

    def test_url_path_loads_config_when_omitted(self):
        from trace_engine.ingest import report_reader

        with patch.object(report_reader, "_markitdown_convert") as conv:
            conv.return_value = "body"
            report_reader.read_report("https://example.com/x")
        kwargs = conv.call_args.kwargs
        # Default behaviour: _markitdown_convert is called without an
        # explicit config — it loads its own.
        assert kwargs.get("config") is None
