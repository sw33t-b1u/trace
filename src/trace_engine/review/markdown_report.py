"""Render a deterministic Markdown report from validation findings."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from trace_engine.validate.semantic.findings import ValidationFinding


def render_report(
    sections: Iterable[tuple[str, list[ValidationFinding]]],
    *,
    timestamp: datetime | None = None,
) -> str:
    """Render Markdown report. ``sections`` is ``(title, findings)`` pairs.

    Section order is preserved. Within each section findings are listed in
    insertion order (validators already produce stable orderings).
    """
    ts = (timestamp or datetime.now(tz=UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines: list[str] = [
        "# TRACE Validation Report",
        "",
        f"_Generated: {ts}_",
        "",
    ]

    section_list = list(sections)
    summary_rows: list[tuple[str, int, int, int]] = []
    for title, findings in section_list:
        errors = sum(1 for f in findings if f.severity == "error")
        warnings = sum(1 for f in findings if f.severity == "warning")
        infos = sum(1 for f in findings if f.severity == "info")
        summary_rows.append((title, errors, warnings, infos))

    lines.append("## Summary")
    lines.append("")
    lines.append("| Section | Errors | Warnings | Info |")
    lines.append("|---------|-------:|---------:|-----:|")
    for title, e, w, i in summary_rows:
        lines.append(f"| {title} | {e} | {w} | {i} |")
    total_e = sum(r[1] for r in summary_rows)
    total_w = sum(r[2] for r in summary_rows)
    total_i = sum(r[3] for r in summary_rows)
    lines.append(f"| **Total** | **{total_e}** | **{total_w}** | **{total_i}** |")
    lines.append("")

    overall = "**PASS**" if total_e == 0 else "**FAIL**"
    lines.append(f"Overall: {overall}")
    lines.append("")

    for title, findings in section_list:
        lines.append(f"## {title}")
        lines.append("")
        if not findings:
            lines.append("_No findings._")
            lines.append("")
            continue
        lines.append("| Severity | Code | Location | Message |")
        lines.append("|----------|------|----------|---------|")
        for f in findings:
            msg = f.message.replace("|", r"\|").replace("\n", " ")
            location = f.location.replace("|", r"\|")
            lines.append(f"| {f.severity} | `{f.code}` | `{location}` | {msg} |")
        lines.append("")

    return "\n".join(lines)
