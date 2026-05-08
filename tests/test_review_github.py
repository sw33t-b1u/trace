"""Tests for ``trace_engine.review.github``."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from trace_engine.review.github import GHEClient, _truncate, submit_validation_report


class TestGHEClientInit:
    def test_raises_if_token_missing(self) -> None:
        with pytest.raises(ValueError, match="TRACE_GHE_TOKEN"):
            GHEClient(token="", repo="owner/repo")

    def test_raises_if_repo_missing(self) -> None:
        with pytest.raises(ValueError, match="GHE_REPO"):
            GHEClient(token="tok123", repo="")

    def test_strips_trailing_slash_from_api_base(self) -> None:
        c = GHEClient(token="t", repo="o/r", api_base="https://ghe.example.com/")
        assert c._api_base == "https://ghe.example.com"


class TestCreateIssue:
    def _client(self) -> GHEClient:
        return GHEClient(token="tok123", repo="owner/repo")

    def test_posts_to_issues_endpoint_with_auth_header(self) -> None:
        client = self._client()
        with patch("trace_engine.review.github.httpx.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=201,
                json=lambda: {"number": 42, "html_url": "https://gh/issue/42"},
                raise_for_status=lambda: None,
            )
            client.create_issue("title", "body", labels=["x"])

        url, kwargs = mock_post.call_args.args[0], mock_post.call_args.kwargs
        assert url == "https://api.github.com/repos/owner/repo/issues"
        assert kwargs["headers"]["Authorization"] == "Bearer tok123"
        assert kwargs["json"]["labels"] == ["x"]

    def test_truncates_title_and_body(self) -> None:
        client = self._client()
        long_title = "T" * 500
        long_body = "B" * 70_000
        with patch("trace_engine.review.github.httpx.post") as mock_post:
            mock_post.return_value = MagicMock(
                json=lambda: {"number": 1, "html_url": "u"},
                raise_for_status=lambda: None,
            )
            client.create_issue(long_title, long_body)
        sent = mock_post.call_args.kwargs["json"]
        assert len(sent["title"]) <= 256
        assert len(sent["body"]) <= 65_536
        assert sent["body"].endswith("[...truncated by TRACE]")


class TestSubmitValidationReport:
    def test_posts_one_issue_with_default_label(self) -> None:
        client = MagicMock()
        client.create_issue.return_value = {
            "number": 7,
            "html_url": "https://gh/issue/7",
        }
        result = submit_validation_report(
            client,
            "# TRACE Validation Report\n\nOverall: **PASS**",
            title="TRACE Validation 2026-05-08",
        )
        assert result.issue_number == 7
        assert result.html_url == "https://gh/issue/7"
        kwargs = client.create_issue.call_args.kwargs
        assert kwargs["title"] == "TRACE Validation 2026-05-08"
        assert kwargs["labels"] == ["trace-review"]
        assert "Overall: **PASS**" in kwargs["body"]


def test_truncate_helper() -> None:
    assert _truncate("abc", 10) == "abc"
    truncated = _truncate("a" * 100, 50)
    assert len(truncated) == 50
    assert truncated.endswith("[...truncated by TRACE]")
