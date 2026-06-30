"""Discover candidate CTI articles from BEACON PIRs.

This command performs discovery only. It emits candidate article metadata for
human approval and does not run STIX extraction. Approved candidates should be
passed to the existing ``trace crawl-batch --pir`` workflow.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from trace_engine.config import load_config  # noqa: E402
from trace_engine.discovery.candidates import CandidateDocument  # noqa: E402
from trace_engine.discovery.catalog import load_catalog, load_catalog_text  # noqa: E402
from trace_engine.discovery.feed_search import discover_candidates  # noqa: E402
from trace_engine.io.inputs import ResolvedInput, resolve_input  # noqa: E402
from trace_engine.pir.loader import load_pir_text  # noqa: E402

load_dotenv()

_ROOT = Path(__file__).parent.parent
_DEFAULT_CATALOG = _ROOT / "input" / "source_catalog.yaml"
_EXAMPLE_CATALOG = _ROOT / "input" / "source_catalog.example.yaml"


def main() -> int:
    cfg = load_config()
    parser = argparse.ArgumentParser(
        description="Discover candidate CTI articles from BEACON pir_output.json"
    )
    parser.add_argument(
        "--pir",
        "-p",
        required=True,
        help="Path, gs:// URI, or pir/ storage key for BEACON pir_output.json.",
    )
    parser.add_argument(
        "--catalog",
        default=None,
        help=(
            "Path, gs:// URI, or input/ storage key for discovery source catalog YAML "
            f"(default: {_DEFAULT_CATALOG.relative_to(_ROOT)}, with example fallback)."
        ),
    )
    parser.add_argument(
        "--from",
        dest="from_date",
        type=_parse_date,
        default=None,
        metavar="YYYY-MM-DD",
        help="Start date for feed entries. Defaults to today minus --since-days.",
    )
    parser.add_argument(
        "--to",
        dest="to_date",
        type=_parse_date,
        default=None,
        metavar="YYYY-MM-DD",
        help="End date for feed entries. Defaults to today (UTC).",
    )
    parser.add_argument(
        "--since-days",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Relative discovery window in days when --from is omitted "
            f"(default: TRACE_FEED_SINCE_DAYS / ACTIVITY_WINDOW_DAYS = {cfg.feed_since_days})."
        ),
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=50,
        metavar="N",
        help="Maximum number of candidates to emit (default: 50).",
    )
    parser.add_argument(
        "--include-recent",
        action="store_true",
        help=(
            "Append recent in-window feed entries even when no PIR term matched. "
            "Fallback candidates have score 0.0 and empty matched_pir_ids."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the full candidate document as JSON.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        help="Optional path to write the candidate JSON document.",
    )
    parser.add_argument(
        "--no-sync-taxonomy",
        action="store_true",
        help="Accepted for workflow symmetry; discovery does not sync taxonomy.",
    )
    args = parser.parse_args()

    try:
        pir_input = resolve_input(cfg, "pir", args.pir)
    except FileNotFoundError:
        print(f"pir_not_found: {args.pir}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"pir_invalid: {exc}", file=sys.stderr)
        return 2

    catalog_input = _resolve_catalog_input(cfg, args.catalog)
    if catalog_input is None:
        print(
            f"catalog_not_found: {_DEFAULT_CATALOG} (or example fallback {_EXAMPLE_CATALOG})",
            file=sys.stderr,
        )
        return 2

    try:
        start_date, end_date = _resolve_window(
            from_date=args.from_date,
            to_date=args.to_date,
            since_days=args.since_days,
            default_since_days=cfg.feed_since_days,
        )
    except ValueError as exc:
        print(f"invalid_window: {exc}", file=sys.stderr)
        return 2

    try:
        pir_doc, _ = load_pir_text(pir_input.text)
        catalog = (
            load_catalog_text(catalog_input.text)
            if catalog_input is not None
            else load_catalog(_EXAMPLE_CATALOG)
        )
        candidates = discover_candidates(
            pir_doc,
            catalog,
            start_date=start_date,
            end_date=end_date,
            config=cfg,
            max_candidates=args.max_candidates,
            include_recent=args.include_recent,
        )
    except Exception as exc:  # noqa: BLE001 - CLI must convert all setup failures to exit 2.
        print(f"discover_pir_failed: {exc}", file=sys.stderr)
        return 2

    doc = CandidateDocument(
        generated_at=datetime.now(UTC),
        pir_path=str(args.pir),
        window={"from": start_date.isoformat(), "to": end_date.isoformat()},
        candidates=candidates,
    )
    payload = json.dumps(doc.to_jsonable(), ensure_ascii=False, indent=2)

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")

    if args.json:
        print(payload)
    else:
        _print_summary(doc, output_path=args.output)
    return 0


def _parse_date(raw: str) -> date:
    try:
        return date.fromisoformat(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected YYYY-MM-DD") from exc


def _resolve_catalog_input(config: object, explicit: str | None) -> ResolvedInput | None:
    if explicit is not None:
        try:
            return resolve_input(config, "input", explicit)
        except FileNotFoundError:
            return None
    if _DEFAULT_CATALOG.exists():
        return ResolvedInput(
            category="input",
            reference=str(_DEFAULT_CATALOG),
            text=_DEFAULT_CATALOG.read_text(encoding="utf-8"),
            filename=_DEFAULT_CATALOG.name,
            source="local",
        )
    if _EXAMPLE_CATALOG.exists():
        return ResolvedInput(
            category="input",
            reference=str(_EXAMPLE_CATALOG),
            text=_EXAMPLE_CATALOG.read_text(encoding="utf-8"),
            filename=_EXAMPLE_CATALOG.name,
            source="local",
        )
    return None


def _resolve_window(
    *,
    from_date: date | None,
    to_date: date | None,
    since_days: int | None,
    default_since_days: int,
) -> tuple[date, date]:
    today = datetime.now(UTC).date()
    end = to_date or today
    if from_date is not None:
        start = from_date
    else:
        days = default_since_days if since_days is None else since_days
        if days <= 0:
            raise ValueError("--since-days must be positive")
        start = end - timedelta(days=days)
    if start > end:
        raise ValueError("--from must be earlier than or equal to --to")
    return start, end


def _print_summary(doc: CandidateDocument, *, output_path: Path | None) -> None:
    print(
        "Discovered "
        f"{len(doc.candidates)} candidate article(s) for "
        f"{doc.window['from']}..{doc.window['to']}"
    )
    if output_path is not None:
        print(f"Candidate JSON written: {output_path}")
    for index, candidate in enumerate(doc.candidates, start=1):
        title = candidate.title or "(untitled)"
        published = candidate.published_at.isoformat() if candidate.published_at else "unknown date"
        pirs = ", ".join(candidate.matched_pir_ids) or "n/a"
        print(f"[{index}] {candidate.score:.2f} {published} {candidate.source_name or ''}")
        print(f"    {title}")
        print(f"    PIR: {pirs}")
        print(f"    URL: {candidate.url}")


if __name__ == "__main__":
    sys.exit(main())
