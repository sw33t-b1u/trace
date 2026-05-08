"""GitHub / GitHub Enterprise issue client for the TRACE review workflow.

Mirrors ``BEACON/src/beacon/review/github.py`` (intentionally duplicated rather
than imported — see ``docs/dependencies.md``). The TRACE flavor posts a single
*validation report* as one Issue, where BEACON posts one Issue per PIR.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

# GitHub's hard limits for issue title and body.
_MAX_TITLE_CHARS = 256
_MAX_BODY_CHARS = 65_536


@dataclass
class IssueResult:
    issue_number: int
    html_url: str


class GHEClient:
    """Thin HTTP client for creating GitHub / GHE Issues."""

    def __init__(self, token: str, repo: str, api_base: str = "https://api.github.com") -> None:
        if not token:
            raise ValueError(
                "TRACE_GHE_TOKEN is not set. Cannot create Issues without authentication."
            )
        if not repo:
            raise ValueError("GHE_REPO is not set. Specify as 'owner/repo'.")
        self._token = token
        self._repo = repo
        self._api_base = api_base.rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def create_issue(
        self,
        title: str,
        body: str,
        labels: list[str] | None = None,
    ) -> dict:
        """POST /repos/{owner}/{repo}/issues and return the response JSON."""
        url = f"{self._api_base}/repos/{self._repo}/issues"
        payload: dict[str, Any] = {
            "title": _truncate(title, _MAX_TITLE_CHARS),
            "body": _truncate(body, _MAX_BODY_CHARS),
        }
        if labels:
            payload["labels"] = labels

        logger.info("creating_ghe_issue", repo=self._repo, title=payload["title"])
        resp = httpx.post(url, json=payload, headers=self._headers(), timeout=15)
        resp.raise_for_status()
        return resp.json()


def submit_validation_report(
    client: GHEClient,
    report_markdown: str,
    *,
    title: str,
    labels: list[str] | None = None,
) -> IssueResult:
    """Create a single Issue carrying the rendered TRACE validation report.

    The body is the verbatim Markdown returned by ``review.markdown_report``;
    GitHub renders it natively. Truncation happens silently inside
    ``GHEClient.create_issue`` to stay under the 64 KiB body limit.
    """
    data = client.create_issue(
        title=title,
        body=report_markdown,
        labels=labels or ["trace-review"],
    )
    result = IssueResult(issue_number=data["number"], html_url=data["html_url"])
    logger.info(
        "validation_report_issue_created",
        issue_number=result.issue_number,
        url=result.html_url,
    )
    return result


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    suffix = "\n\n[...truncated by TRACE]"
    return text[: limit - len(suffix)] + suffix
