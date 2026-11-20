"""The post-mortem of one incident, as a Markdown document a team can file.

Teams write a post-mortem after an outage: what happened, when, why, what was done, and
what to do next. This drafts one from what the tool already knows: the facts the rules
decided, the explanation, and the log lines behind both. It says at the top that it was
drafted automatically and needs human review, and it leaves the follow-up actions as a
checklist for the team, since only they can decide who does what.

Everything from a log line or from the explanation is escaped, so it reads as plain text
in any Markdown viewer and cannot add links, images or formatting. Log lines themselves
go in fenced blocks, exactly as they appear in the file.
"""

from __future__ import annotations

from datetime import datetime

from netlog.report.build import Cited, Report, ReportExplanation, to_json
from netlog.report.render import _clean, _code_block, _md
from netlog.storage.database import Database, Upload

# How many lines of each finding go into the appendix: the first ones show how it began,
# the last ones where it ended or recovered. The rest are counted, not listed.
FIRST_LINES = 3
LAST_LINES = 2

CHECKLIST = (
    "Confirm the root cause with the people who were on call",
    "Decide on a permanent fix, if one is needed",
    "Add monitoring or an alert that would catch this earlier",
    "Share this post-mortem with the team and the people affected",
)


def _time(iso: str | None) -> str:
    if not iso:
        return "unknown"
    return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M:%S UTC")


def _clock(iso: str | None) -> str:
    return datetime.fromisoformat(iso).strftime("%H:%M:%S") if iso else "?"


def _duration(seconds: float) -> str:
    total = round(seconds)
    if total < 60:
        return "under a minute" if total < 1 else f"{total}s"
    minutes, rest = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m {rest}s" if rest else f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m" if minutes else f"{hours}h"


def _lines(numbers: list[int]) -> str:
    if not numbers:
        return ""
    shown = ", ".join(str(n) for n in numbers[:8])
    more = f" and {len(numbers) - 8} more" if len(numbers) > 8 else ""
    return f" (line{'s' if len(numbers) > 1 else ''} {shown}{more})"


def _recovered(finding: dict) -> tuple[str, float | None] | None:
    """When a finding's problem went away, if the logs show it: a session or adjacency
    that came back, or an interface that was up again after an outage."""
    metrics = finding["metrics"]
    if metrics.get("recovered_at"):
        return metrics["recovered_at"], metrics.get("recovered_after_seconds")
    if metrics.get("outage_seconds") and finding.get("end") != finding.get("start"):
        return finding["end"], metrics["outage_seconds"]
    return None


def _cited(item: Cited) -> str:
    return _md(item.text) + _lines(item.lines)


def postmortem_markdown(
    db: Database,
    upload: Upload,
    report: Report,
    incident_id: str,
    explanation: ReportExplanation,
) -> str:
    """The post-mortem of one incident of an analyzed upload."""
    data = to_json(report)
    entry = next((e for e in data["incidents"] if e["id"] == incident_id), None)
    if entry is None:
        raise KeyError(incident_id)
    findings = [f for f in data["findings"] if f["incident"] == incident_id]
    root = entry["root_cause"]
    suspect = bool(root and root["kind"] == "config_change")

    out: list[str] = [f"# Post-mortem: {_md(entry['headline'])}", ""]
    out += [
        "> **Drafted automatically by netlog. Review every statement before filing it.**",
        "> The facts come from deterministic rules applied to the log file; the explanation",
        f"> was written by {_md(explanation.written_by)}. Line numbers refer to the uploaded",
        f"> file {_md(upload.filename)}.",
        "",
        "| | |",
        "|---|---|",
        f"| Severity | **{entry['severity'].capitalize()}**. {_md(entry['severity_reason'])} |",
        f"| Started | {_time(entry['start'])} |",
        f"| Ended | {_time(entry['end'])} |",
        f"| Duration | {_duration(entry['duration_seconds'])} |",
        f"| Devices | {_md(', '.join(entry['devices']))} |",
        f"| Incident | {_md(entry['id'])} |",
        "",
    ]

    out += ["## Summary", "", _md(explanation.summary), ""]

    out += ["## Impact", ""]
    if explanation.impact:
        out += [f"- {_cited(item)}" for item in explanation.impact]
    else:
        out.append("- Not stated by the explanation. Fill in who and what was affected.")
    out.append("")

    out += ["## Timeline", "", "All times UTC, from the devices' own clocks.", ""]
    out += ["| Time | Device | What happened | Lines |", "|---|---|---|---|"]
    rows: list[tuple[str, str, str, str, str]] = []
    for finding in findings:
        first = [item["line"] for item in finding["evidence"][:1]]
        rows.append(
            (finding["start"], _clock(finding["start"]), _md(finding["host"] or ""),
             _md(finding["title"]), ", ".join(map(str, first)))
        )  # fmt: skip
        back = _recovered(finding)
        if back:
            recovered = back[0]
            rows.append(
                (recovered, _clock(recovered), _md(finding["host"] or ""),
                 f"Recovered: {_md(finding['title'])}",
                 str(finding["evidence"][-1]["line"]) if finding["evidence"] else "")
            )  # fmt: skip
    for _, clock, host, text, lines in sorted(rows, key=lambda row: (row[0], row[3])):
        out.append(f"| {clock} | {host} | {text} | {lines} |")
    out.append("")

    out += ["## Likely root cause", ""]
    if root:
        label = "Possible cause (not proven)" if suspect else "Root cause"
        out.append(f"**{label}:** {_md(root['summary'])}")
        out.append("")
        out.append(
            f"Confidence: **{entry['confidence']}**, because {_md(entry['confidence_reason'])}. "
            f"It accounts for {root['explains']} of the incident's "
            f"{len(entry['findings'])} findings."
        )
    else:
        out.append("The logs do not point to one cause.")
    out.append("")
    for hypothesis in explanation.hypotheses:
        out.append(f"- {_cited(hypothesis)}")
        if hypothesis.against:
            out.append(f"  - Against it: lines {', '.join(map(str, hypothesis.against))}")
    if explanation.hypotheses:
        out.append("")

    out += ["## Contributing factors", ""]
    steps = [step for step in entry["story"][1:] if step.get("explanation")]
    for step in steps:
        certainty = f" ({step['certainty']})" if step.get("certainty") else ""
        when = f", {step['when']}" if step.get("when") else ""
        out.append(f"- {_md(step['label'])}{when}{certainty}: {_md(step['explanation'])}")
    for other in entry["alternatives"]:
        out.append(f"- Also possible: {_md(other['summary'])}")
    if not steps and not entry["alternatives"]:
        out.append("- None found in these logs beyond the root cause.")
    out.append("")

    out += ["## What was done, and what should be done", ""]
    recoveries = sorted(
        ((back, finding) for finding in findings if (back := _recovered(finding))),
        key=lambda pair: (pair[0][0], pair[1]["title"]),
    )
    if recoveries:
        out.append("Seen in the logs:")
        out.append("")
        for (when, after), finding in recoveries:
            later = f", {_duration(after)} after it began" if after else ""
            out.append(f"- {_md(finding['title'])}: recovered at {_clock(when)}{later}")
        out.append("")
    if explanation.fix_steps:
        out.append("Recommended:")
        out.append("")
        for i, (text, changes) in enumerate(explanation.fix_steps, 1):
            flag = "**REVIEW BEFORE RUNNING:** " if changes else ""
            out.append(f"{i}. {flag}{_md(text)}")
        out.append("")
    if explanation.commands:
        out.append("To check that it is fixed (these commands only read):")
        out.append("")
        for command, healthy in explanation.commands:
            out += _code_block([command])
            out.append(f"Healthy: {_md(healthy)}")
            out.append("")

    out += ["## What cannot be determined from these logs", ""]
    unknowns = list(dict.fromkeys([*entry["unknowns"], *explanation.unknowns]))
    out += [f"- {_md(item)}" for item in unknowns] or ["- Nothing noted."]
    out.append("")

    out += ["## Follow-up actions", "", "For the team to fill in: who, and by when.", ""]
    out += [f"- [ ] {item}. Owner: ____ Due: ____" for item in CHECKLIST]
    out.append("")

    out += ["## Appendix: evidence", ""]
    by_id = {finding.id: finding for finding in db.findings(upload.id)}
    wanted: dict[int, None] = {}
    left_out = 0
    for finding in findings:
        evidence = by_id[finding["id"]].evidence
        chosen = list(dict.fromkeys([*evidence[:FIRST_LINES], *evidence[-LAST_LINES:]]))
        left_out += len(evidence) - len(chosen)
        wanted.update(dict.fromkeys(chosen))
    events = db.events_by_id(list(wanted))
    cited = {n for item in [*explanation.timeline, *explanation.hypotheses, *explanation.impact]
             for n in [*item.lines, *item.against]}  # fmt: skip
    have = {event.line_no for event in events}
    events += db.events_by_line(upload.id, sorted(cited - have))
    events.sort(key=lambda event: event.line_no)
    width = len(str(max((e.line_no for e in events), default=0)))
    rows_text = [f"{event.line_no:>{width}}  {_clean(event.raw)}" for event in events]
    out.append(f"The log lines behind this incident, by line number in {_md(upload.filename)}.")
    if left_out:
        out.append(
            f"For each finding the first {FIRST_LINES} and last {LAST_LINES} lines are shown; "
            f"{left_out} more are in the file."
        )
    out.append("")
    out += _code_block(rows_text)
    out.append("")
    return "\n".join(out)
