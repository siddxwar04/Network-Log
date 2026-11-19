"""Turns a report into terminal text or Markdown.

The terminal output is plain ASCII, so it displays correctly in Windows PowerShell with
its default console encoding as well as in any other terminal.

Everything that comes from a log line (titles containing usernames, the evidence lines
themselves) is treated as untrusted text: control characters are removed for the
terminal, and Markdown characters are escaped, so a log line cannot inject formatting.
"""

from __future__ import annotations

import re
import textwrap
from datetime import datetime

from netlog.detection.finding import format_duration
from netlog.report.build import Report, ReportFinding

_WIDTH = 100
_MAX_LINE = 180

_COLORS = {
    "critical": "\x1b[1;91m",  # bright red, bold
    "high": "\x1b[31m",  # red
    "medium": "\x1b[33m",  # yellow
    "low": "\x1b[36m",  # cyan
    "info": "\x1b[2m",  # dim
}
_BOLD, _RESET = "\x1b[1m", "\x1b[0m"

# Metrics worth a line in the report, with the label to show.
_DETAILS = (
    ("related_reason", "cause"),
    ("reason", "reason"),
    ("related_error_meaning", "meaning"),
    ("username", "user"),
    ("src_ip", "from"),
    ("process", "process"),
    ("succeeded_username", "logged in as"),
    ("distinct_username", "usernames tried"),
    ("distinct_mac", "devices affected"),
)

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _clean(text: str) -> str:
    """Remove control characters, so a log line cannot move the cursor or change colors."""
    return _CONTROL.sub("?", text)


def _shorten(text: str, limit: int = _MAX_LINE) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _time(moment: datetime) -> str:
    return f"{moment:%Y-%m-%d %H:%M:%S}"


def _when(item: ReportFinding) -> str:
    finding = item.finding
    if finding.duration_seconds < 1:
        return f"{_time(finding.start)} UTC"
    same_day = finding.start.date() == finding.end.date()
    end = f"{finding.end:%H:%M:%S}" if same_day else _time(finding.end)
    return f"{_time(finding.start)} to {end} UTC ({format_duration(finding.duration_seconds)})"


def _details(item: ReportFinding) -> list[str]:
    metrics = item.finding.metrics
    out = [f"{label}: {metrics[key]}" for key, label in _DETAILS if metrics.get(key) is not None]
    hosts = metrics.get("hosts")
    if isinstance(hosts, list) and len(hosts) > 1:
        out.append(f"devices: {', '.join(hosts)}")
    if item.finding.flags:
        out.append(f"noted: {', '.join(flag.replace('_', ' ') for flag in item.finding.flags)}")
    return out


def _verdict(report: Report) -> str:
    shown = {level: 0 for level in report.counts}
    for item in report.findings:
        shown[item.finding.severity] += 1
    parts = [f"{n} {level}" for level, n in shown.items() if n]
    if not parts:
        return f"No problems found at {report.min_severity} severity or above."
    total = len(report.findings)
    return f"{total} finding{'s' if total != 1 else ''}: {', '.join(parts)}"


def _hidden_note(report: Report) -> str | None:
    if not report.hidden:
        return None
    return (
        f"{report.hidden} lower-severity finding{'s' if report.hidden != 1 else ''} not shown "
        "(routine events such as config changes); use --min-severity info to list them."
    )


def _time_span(report: Report) -> str:
    if not report.time_range:
        return "unknown"
    first, last = report.time_range
    length = format_duration((last - first).total_seconds())
    return f"{_time(first)} to {_time(last)} UTC ({length})"


# --- Terminal text -----------------------------------------------------------------------


def render_text(report: Report, color: bool = False) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    upload = report.upload
    out: list[str] = []
    title = f"netlog report: {_clean(upload.filename)}"
    out += [paint(title, _BOLD), "=" * len(title), ""]

    out.append(paint("File", _BOLD))
    coverage = f"{upload.percent_parsed:.1f}% parsed"
    if upload.line_count:
        coverage += f", {100.0 * upload.classified / upload.line_count:.1f}% classified"
    out.append(f"  Lines      {upload.line_count:,} ({coverage})")
    names = ", ".join(_clean(host) for host, _ in report.hosts)
    out.append(_shorten(f"  Devices    {len(report.hosts)}: {names}", _WIDTH))
    out.append(f"  Time span  {_time_span(report)}")
    out.append(
        f"  Templates  {report.template_count} "
        f"({report.lines_per_template:,.0f} lines per template)"
    )
    out.append("")

    out.append(paint("Verdict", _BOLD))
    worst = report.findings[0].finding.severity if report.findings else None
    out.append("  " + paint(_verdict(report), _COLORS[worst] if worst else _BOLD))
    if note := _hidden_note(report):
        out += textwrap.wrap(note, _WIDTH, initial_indent="  ", subsequent_indent="  ")
    out.append("")

    if report.findings:
        out.append(paint("Findings", _BOLD))
        for item in report.findings:
            finding = item.finding
            badge = paint(f"[{finding.severity.upper()}]", _COLORS[finding.severity])
            out.append(f"  {badge} {_clean(finding.title)}")
            out.append(f"      When      {_when(item)}")
            out += _wrapped("Why", _clean(finding.severity_reason))
            for detail in _details(item):
                out += _wrapped("Detail", _clean(detail))
            shown = len(item.lines)
            of = "" if shown == item.evidence_count else f" (showing {shown})"
            out.append(f"      Evidence  {item.evidence_count} line(s){of}")
            for position, line in enumerate(item.lines):
                skipped = item.evidence_count - shown
                if skipped and position == shown - shown // 2:
                    out.append(f"          ...  {skipped} more ...")
                out.append(_shorten(f"        {line.line_no:>6}  {_clean(line.text)}"))
            out.append("")

    if report.top_templates:
        out.append(paint("Most frequent messages", _BOLD))
        for template in report.top_templates:
            out.append(_shorten(f"  {template.count:>7,}  {_clean(template.pattern)}", _WIDTH + 20))
        out.append("")

    notes = [("Assumption", text) for text in report.assumptions]
    notes += [("Warning", text) for text in report.warnings]
    if notes:
        out.append(paint("Notes", _BOLD))
        for label, text in notes:
            code = _COLORS["medium"] if label == "Warning" else ""
            lines = textwrap.wrap(
                f"{label}: {_clean(text)}", _WIDTH, initial_indent="  ", subsequent_indent="    "
            )
            if code:
                lines[0] = lines[0].replace(f"{label}:", paint(f"{label}:", code), 1)
            out += lines
        out.append("")
    return "\n".join(out)


def _wrapped(label: str, text: str) -> list[str]:
    """A labelled line of a finding, wrapped so long reasons stay readable."""
    indent = " " * 16
    return textwrap.wrap(
        text, _WIDTH, initial_indent=f"      {label:<10}", subsequent_indent=indent
    ) or [f"      {label}"]


# --- Markdown ----------------------------------------------------------------------------

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>#|~])")


def _md(text: str) -> str:
    """Escape Markdown, so text from a log line is shown as it is and formats nothing."""
    return _MD_SPECIAL.sub(r"\\\1", _clean(text))


def _code_block(lines: list[str]) -> list[str]:
    """A fenced block whose fence is longer than any run of backticks inside it."""
    longest = max((len(run) for line in lines for run in re.findall(r"`+", line)), default=0)
    fence = "`" * max(3, longest + 1)
    return [f"{fence}text", *lines, fence]


def render_markdown(report: Report) -> str:
    upload = report.upload
    out = [f"# Log report: {_md(upload.filename)}", ""]

    out += ["## File", "", "| | |", "|---|---|"]
    classified = 100.0 * upload.classified / upload.line_count if upload.line_count else 0.0
    out.append(
        f"| Lines | {upload.line_count:,} ({upload.percent_parsed:.1f}% parsed, "
        f"{classified:.1f}% classified) |"
    )
    names = ", ".join(_md(host) for host, _ in report.hosts)
    out.append(f"| Devices | {len(report.hosts)}: {names} |")
    out.append(f"| Time span | {_time_span(report)} |")
    out.append(
        f"| Templates | {report.template_count} "
        f"({report.lines_per_template:,.0f} lines per template) |"
    )
    out.append("")

    out += ["## Verdict", "", f"**{_verdict(report)}**", ""]
    if note := _hidden_note(report):
        out += [note, ""]

    if report.findings:
        out += ["## Findings", ""]
        for item in report.findings:
            finding = item.finding
            out += [f"### {finding.severity.capitalize()}: {_md(finding.title)}", ""]
            out.append(f"- **When:** {_when(item)}")
            out.append(f"- **Why this severity:** {_md(finding.severity_reason)}")
            for detail in _details(item):
                label, _, value = detail.partition(": ")
                out.append(f"- **{label.capitalize()}:** {_md(value)}")
            shown = len(item.lines)
            of = "" if shown == item.evidence_count else f", {shown} shown"
            out += [f"- **Evidence:** {item.evidence_count} line(s){of}", ""]
            out += _code_block([f"{line.line_no:>6}  {_clean(line.text)}" for line in item.lines])
            out.append("")

    if report.top_templates:
        out += ["## Most frequent messages", ""]
        out += ["| Count | Message type | Pattern |", "|---:|---|---|"]
        for template in report.top_templates:
            key = _md(template.event_key or "")
            out.append(f"| {template.count:,} | {key} | {_md(template.pattern)} |")
        out.append("")

    if report.assumptions or report.warnings:
        out += ["## Notes", ""]
        out += [f"- **Assumption:** {_md(text)}" for text in report.assumptions]
        out += [f"- **Warning:** {_md(text)}" for text in report.warnings]
        out.append("")
    return "\n".join(out)
