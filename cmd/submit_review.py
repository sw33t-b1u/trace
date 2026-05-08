"""Hand a TRACE validation report to a human reviewer.

By default prints the Markdown report to stdout. With ``--open-issue``,
creates a GitHub / GitHub Enterprise Issue carrying the report.

Usage:
    # echo the rendered report
    uv run python cmd/submit_review.py --report output/validation_report.md

    # post to the GHE repo configured in env (TRACE_GHE_TOKEN, GHE_REPO,
    # optionally GHE_API_BASE) as one Issue with label "trace-review"
    uv run python cmd/submit_review.py --report output/validation_report.md \\
        --open-issue --title "TRACE validation 2026-05-08"

Exit codes: 0 success / 2 input/argument or auth-config error.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

import structlog
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from trace_engine.cli._logging import configure as configure_logging  # noqa: E402
from trace_engine.config import load_config  # noqa: E402
from trace_engine.review.github import GHEClient, submit_validation_report  # noqa: E402

load_dotenv()
configure_logging()
logger = structlog.get_logger(__name__)


def _default_title(report_name: str) -> str:
    ts = datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%MZ")
    return f"TRACE validation report — {report_name} ({ts})"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Print or submit a TRACE validation report for human review"
    )
    parser.add_argument(
        "--report",
        type=Path,
        required=True,
        help="Path to a Markdown validation report (produced by validate_all.py)",
    )
    parser.add_argument(
        "--open-issue",
        action="store_true",
        help=(
            "Create a GitHub/GHE Issue carrying the report. Requires "
            "TRACE_GHE_TOKEN and GHE_REPO env vars."
        ),
    )
    parser.add_argument(
        "--title",
        default=None,
        help="Issue title (default: 'TRACE validation report — <name> (<ts>)')",
    )
    parser.add_argument(
        "--label",
        action="append",
        dest="labels",
        default=None,
        help="Issue label (repeatable; default: ['trace-review'])",
    )
    args = parser.parse_args()

    if not args.report.exists():
        logger.error("report_not_found", path=str(args.report))
        sys.exit(2)

    body = args.report.read_text(encoding="utf-8")

    if not args.open_issue:
        sys.stdout.write(body)
        if not body.endswith("\n"):
            sys.stdout.write("\n")
        return

    cfg = load_config()
    try:
        client = GHEClient(token=cfg.ghe_token, repo=cfg.ghe_repo, api_base=cfg.ghe_api_base)
    except ValueError as exc:
        logger.error("ghe_config_error", error=str(exc))
        sys.exit(2)

    title = args.title or _default_title(args.report.name)
    result = submit_validation_report(
        client,
        body,
        title=title,
        labels=args.labels,
    )
    print(f"Issue created: #{result.issue_number} {result.html_url}")


if __name__ == "__main__":
    main()
