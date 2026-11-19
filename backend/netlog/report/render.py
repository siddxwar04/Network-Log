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

from netlog.detection.finding import Finding, format_duration
from netlog.report.build import Report, ReportIncident, StoryRow

_WIDTH = 100
_MAX_LINE = 180

_COLORS = {
    "critical": "\x1b[1;91m",  # bright red, bold
    "high": "\x1b[31m",  # red
    "medium": "\x1b[33m",  # yellow
    "low": "\x1b[36m",  # cyan
    "info": "\x1b[2m",  # dim
}
_BOLD, _DIM, _RESET = "\x1b[1m", "\x1b[2m", "\x1b[0m"

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


def _span(start: datetime, end: datetime) -> str:
    seconds = (end - start).total_seconds()
    if seconds < 1:
        return f"{_time(start)} UTC"
    finish = f"{end:%H:%M:%S}" if start.date() == end.date() else _time(end)
    return f"{_time(start)} to {finish} UTC ({format_duration(seconds)})"


def _details(finding: Finding) -> list[str]:
    metrics = finding.metrics
    out = [f"{label}: {metrics[key]}" for key, label in _DETAILS if metrics.get(key) is not None]
    hosts = metrics.get("hosts")
    if isinstance(hosts, list) and len(hosts) > 1:
        out.append(f"devices: {', '.join(hosts)}")
    if finding.flags:
        out.append(f"noted: {', '.join(flag.replace('_', ' ') for flag in finding.flags)}")
    return out


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def _verdict(report: Report) -> str:
    shown = {level: 0 for level in report.incident_counts}
    for item in report.incidents:
        shown[item.incident.severity] += 1
    parts = [f"{n} {level}" for level, n in shown.items() if n]
    if not parts:
        return f"No problems found at {report.min_severity} severity or above."
    findings = sum(len(item.findings) for item in report.incidents)
    devices = len({d for item in report.incidents for d in item.incident.devices})
    return (
        f"{_plural(len(report.incidents), 'incident')}: {', '.join(parts)} "
        f"({_plural(findings, 'finding')} on {_plural(devices, 'device')})"
    )


def _routine_note(report: Report) -> str | None:
    if not report.routine_count:
        return None
    note = (
        f"{_plural(report.routine_count, 'routine finding')} recorded "
        "(config changes, interfaces that went down)"
    )
    if report.attached_count:
        note += f"; {report.attached_count} attached to incidents as context"
    if not report.lists_routine:
        note += ". Use --min-severity info to list them"
    return note + "."


def _time_span(report: Report) -> str:
    if not report.time_range:
        return "unknown"
    first, last = report.time_range
    length = format_duration((last - first).total_seconds())
    return f"{_time(first)} to {_time(last)} UTC ({length})"


def _kinds(item: ReportIncident) -> str:
    total = len(item.findings)
    if total == 1:
        return "1 finding"
    return f"{total} findings: " + ", ".join(f"{n} {label}" for label, n in item.kinds)


def _cause_label(item: ReportIncident) -> str:
    root = item.incident.root_cause
    return "Suspect" if root and root.kind == "config_change" else "Likely cause"


def _row_text(row: StoryRow) -> str:
    text = row.label
    if row.when:
        text += f" ({row.when})"
    if row.certainty and row.certainty != "direct":
        text += f" [{row.certainty}]"
    return text


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
    worst = report.incidents[0].incident.severity if report.incidents else None
    out.append("  " + paint(_verdict(report), _COLORS[worst] if worst else _BOLD))
    if note := _routine_note(report):
        out += textwrap.wrap(note, _WIDTH, initial_indent="  ", subsequent_indent="  ")
    out.append("")

    if report.incidents:
        out.append(paint("Incidents", _BOLD))
        for item in report.incidents:
            out += _incident_text(item, report.show_findings, paint)

    if report.lists_routine and report.routine_count:
        out.append(paint("Routine findings", _BOLD))
        for entry in report.findings:
            finding = entry.finding
            if finding.severity != "info":
                continue
            badge = paint("[INFO]", _COLORS["info"])
            attached = "  (context for an incident)" if entry.role == "context" else ""
            out.append(
                _shorten(
                    f"  {badge} {finding.start:%H:%M:%S}  {_clean(finding.title)}{attached}",
                    _WIDTH + 20,
                )
            )
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


def _incident_text(item: ReportIncident, show_findings: bool, paint) -> list[str]:
    incident = item.incident
    badge = paint(f"[{incident.severity.upper()}]", _COLORS[incident.severity])
    out = [f"  {badge} {_clean(item.headline)}"]
    out.append(f"      When          {_span(incident.start, incident.end)}")
    out += _wrapped("Devices", ", ".join(_clean(d) for d in incident.devices))
    out += _wrapped("Findings", _kinds(item))
    if incident.root_cause:
        out += _wrapped(_cause_label(item), _clean(incident.root_cause.summary))
        out += _wrapped(
            "Confidence", f"{incident.confidence.capitalize()}: {incident.confidence_reason}."
        )
    out += _wrapped("Severity", _clean(incident.severity_reason))
    if len(item.findings) == 1:
        for detail in _details(item.findings[0]):
            out += _wrapped("Detail", _clean(detail))

    out.append("      What happened")
    unexplained_shown = False
    for row in item.story:
        if not row.explained and not unexplained_shown:
            out.append("        Also in this incident, not explained by the cause above:")
            unexplained_shown = True
        pad = " " * (8 + 3 * row.depth)
        arrow = "-> " if row.depth else ""
        out += textwrap.wrap(
            _clean(_row_text(row)),
            _WIDTH,
            initial_indent=pad + arrow,
            subsequent_indent=pad + " " * len(arrow),
        )
        body = pad + " " * len(arrow)
        if row.explanation:
            out += textwrap.wrap(
                _clean(row.explanation),
                _WIDTH,
                initial_indent=body + "Why: ",
                subsequent_indent=body + "     ",
            )
        for line in row.lines:
            out.append(_shorten(f"{body}{line.line_no:>6}  {_clean(line.text)}"))

    if incident.unknowns:
        out.append("      Not known from these logs")
        for unknown in incident.unknowns:
            out += textwrap.wrap(
                _clean(unknown), _WIDTH, initial_indent="        - ", subsequent_indent="          "
            )

    if show_findings and len(item.findings) > 1:
        out.append("      Findings in this incident")
        for finding in sorted(item.findings, key=lambda f: (f.start, f.id)):
            at = f"{finding.start:%H:%M:%S}"
            line = f"        {finding.severity:<8} {at}  {_clean(finding.title)}"
            out.append(_shorten(line, _WIDTH + 20))
    out.append("")
    return out


def _wrapped(label: str, text: str) -> list[str]:
    """A labelled line, wrapped so long reasons stay readable."""
    indent = " " * 20
    return textwrap.wrap(
        text, _WIDTH, initial_indent=f"      {label:<14}", subsequent_indent=indent
    ) or [f"      {label}"]


# --- Markdown ----------------------------------------------------------------------------

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]<>#|~])")


def _md(text: str) -> str:
    """Escape Markdown, so text from a log line is shown as it is and formats nothing."""
    return _MD_SPECIAL.sub(r"\\\1", _clean(text))


def _code_block(lines: list[str], indent: str = "") -> list[str]:
    """A fenced block whose fence is longer than any run of backticks inside it."""
    longest = max((len(run) for line in lines for run in re.findall(r"`+", line)), default=0)
    fence = "`" * max(3, longest + 1)
    return [f"{indent}{fence}text", *(indent + line for line in lines), f"{indent}{fence}"]


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
    if note := _routine_note(report):
        out += [note, ""]

    if report.incidents:
        out += ["## Incidents", ""]
        for item in report.incidents:
            incident = item.incident
            out += [f"### {incident.severity.capitalize()}: {_md(item.headline)}", ""]
            out.append(f"- **When:** {_span(incident.start, incident.end)}")
            out.append(f"- **Devices:** {', '.join(_md(d) for d in incident.devices)}")
            out.append(f"- **Findings:** {_kinds(item)}")
            if incident.root_cause:
                out.append(f"- **{_cause_label(item)}:** {_md(incident.root_cause.summary)}")
                out.append(
                    f"- **Confidence:** {incident.confidence.capitalize()}: "
                    f"{incident.confidence_reason}."
                )
            out.append(f"- **Severity:** {_md(incident.severity_reason)}")
            if len(item.findings) == 1:
                for detail in _details(item.findings[0]):
                    label, _, value = detail.partition(": ")
                    out.append(f"- **{label.capitalize()}:** {_md(value)}")
            out += ["", "**What happened**", ""]
            unexplained_shown = False
            for row in item.story:
                if not row.explained and not unexplained_shown:
                    out += ["", "Also in this incident, not explained by the cause above:", ""]
                    unexplained_shown = True
                pad = "  " * row.depth
                out.append(f"{pad}- {_md(_row_text(row))}")
                if row.explanation:
                    out.append(f"{pad}  *Why:* {_md(row.explanation)}")
                if row.lines:
                    lines = [f"{line.line_no:>6}  {_clean(line.text)}" for line in row.lines]
                    out += ["", *_code_block(lines, pad + "  "), ""]
            if incident.unknowns:
                out += ["", "**Not known from these logs**", ""]
                out += [f"- {_md(unknown)}" for unknown in incident.unknowns]
            if report.show_findings and len(item.findings) > 1:
                out += ["", "**Findings in this incident**", ""]
                out += ["| Severity | Time | Finding |", "|---|---|---|"]
                for finding in sorted(item.findings, key=lambda f: (f.start, f.id)):
                    at = f"{finding.start:%H:%M:%S}"
                    out.append(f"| {finding.severity} | {at} | {_md(finding.title)} |")
            out.append("")

    if report.lists_routine and report.routine_count:
        out += ["## Routine findings", "", "| Time | Finding | |", "|---|---|---|"]
        for entry in report.findings:
            finding = entry.finding
            if finding.severity == "info":
                attached = "context for an incident" if entry.role == "context" else ""
                out.append(f"| {finding.start:%H:%M:%S} | {_md(finding.title)} | {attached} |")
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
