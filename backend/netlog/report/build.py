"""Collects everything a report shows about one analyzed log file.

This module gathers the facts; `render.py` decides how they look. The JSON output is
this data as it is, so other programs get exactly what the text report is built from.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from netlog.detection.finding import Finding
from netlog.detection.rules import LEVELS
from netlog.parsers.pipeline import line_shape
from netlog.storage.database import Database, EventFilter, Template, Upload

JSON_VERSION = 1
# Parse coverage below this is called out in the report.
COVERAGE_WARNING_BELOW = 95.0


@dataclass
class EvidenceLine:
    line_no: int
    text: str


@dataclass
class ReportFinding:
    finding: Finding
    # A few key lines: the first ones and the last ones, which is where a recovery or a
    # successful login sits.
    lines: list[EvidenceLine]
    evidence_count: int


@dataclass
class Report:
    upload: Upload
    hosts: list[tuple[str, int]]
    time_range: tuple[datetime, datetime] | None
    template_count: int
    top_templates: list[Template]
    min_severity: str
    findings: list[ReportFinding]
    # Every finding by level, including those below `min_severity`.
    counts: dict[str, int]
    assumptions: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def hidden(self) -> int:
        """Findings below the minimum severity, which the report does not list."""
        return sum(self.counts.values()) - len(self.findings)

    @property
    def lines_per_template(self) -> float:
        return self.upload.line_count / self.template_count if self.template_count else 0.0


def _key_lines(db: Database, finding: Finding, limit: int) -> list[EvidenceLine]:
    events = db.events_by_id(finding.evidence)
    if len(events) > limit:
        head = limit - limit // 2
        events = events[:head] + events[-(limit - head) :]
    return [EvidenceLine(e.line_no, e.raw) for e in events]


def build_report(
    db: Database,
    upload_id: int,
    *,
    min_severity: str = "low",
    year: int | None = None,
    assumed_year: int | None = None,
    timezone: str | None = None,
    evidence_lines: int = 5,
    top_templates: int = 10,
) -> Report:
    """Gather the report for an upload that has been parsed, mined and run through detection.

    `year` and `timezone` are what the user asked for, or None if they left it to the
    default; `assumed_year` is the year that was used in that case.
    """
    upload = db.get_upload(upload_id)
    findings = db.findings(upload_id)
    floor = LEVELS.index(min_severity)

    counts = {level: 0 for level in reversed(LEVELS)}
    for finding in findings:
        counts[finding.severity] += 1
    shown = [f for f in findings if LEVELS.index(f.severity) >= floor]
    shown.sort(key=lambda f: (-LEVELS.index(f.severity), f.start, f.id))

    report = Report(
        upload=upload,
        hosts=sorted((host, n) for host, n in db.count_by(upload_id, "host") if host),
        time_range=db.time_range(upload_id),
        template_count=db.count_templates(upload_id),
        top_templates=db.templates(upload_id, limit=top_templates),
        min_severity=min_severity,
        findings=[
            ReportFinding(f, _key_lines(db, f, evidence_lines), len(f.evidence)) for f in shown
        ],
        counts=counts,
    )

    year_assumed, tz_assumed = db.count_assumed(upload_id)
    if year_assumed:
        if year is None:
            report.assumptions.append(
                f"The log lines carry no year, so {assumed_year} (the current year) was "
                "assumed. Use --year to set it."
            )
        else:
            report.assumptions.append(f"The log lines carry no year; {year} was used, as given.")
    if tz_assumed:
        if timezone is None:
            report.assumptions.append(
                "The log lines carry no timezone, so UTC was assumed. Use --timezone to set it."
            )
        else:
            report.assumptions.append(
                f"The log lines carry no timezone; {timezone} was used, as given."
            )

    if upload.line_count and upload.percent_parsed < COVERAGE_WARNING_BELOW:
        unparsed = db.events(upload_id, EventFilter(parse_status="unparsed"), limit=5000)
        shapes = Counter(line_shape(e.raw) for e in unparsed).most_common(3)
        examples = "; ".join(f'"{shape}" ({n})' for shape, n in shapes)
        report.warnings.append(
            f"Only {upload.percent_parsed:.1f}% of lines were understood, so problems may have "
            f"been missed. Most common lines not understood: {examples}"
        )
    return report


def _iso(moment: datetime | None) -> str | None:
    return None if moment is None else moment.isoformat().replace("+00:00", "Z")


def to_json(report: Report) -> dict:
    """The report as plain data. Field names here are a stable interface: add, never rename."""
    upload = report.upload
    return {
        "version": JSON_VERSION,
        "file": {
            "name": upload.filename,
            "size_bytes": upload.size_bytes,
            "lines": upload.line_count,
            "blank_lines": upload.blank,
            "parsed": upload.parsed,
            "partial": upload.partial,
            "unparsed": upload.unparsed,
            "classified": upload.classified,
            "percent_parsed": round(upload.percent_parsed, 2),
            "start": _iso(report.time_range[0]) if report.time_range else None,
            "end": _iso(report.time_range[1]) if report.time_range else None,
            "devices": [{"host": host, "lines": n} for host, n in report.hosts],
            "templates": report.template_count,
        },
        "summary": {
            "min_severity": report.min_severity,
            "by_severity": report.counts,
            "shown": len(report.findings),
            "hidden": report.hidden,
        },
        "findings": [
            {
                "severity": item.finding.severity,
                "severity_reason": item.finding.severity_reason,
                "rule": item.finding.rule,
                "incident_type": item.finding.incident_type,
                "title": item.finding.title,
                "host": item.finding.host,
                "group": item.finding.group,
                "start": _iso(item.finding.start),
                "end": _iso(item.finding.end),
                "duration_seconds": item.finding.duration_seconds,
                "strength": item.finding.strength,
                "flags": item.finding.flags,
                "metrics": item.finding.metrics,
                "evidence_count": item.evidence_count,
                "evidence": [{"line": e.line_no, "text": e.text} for e in item.lines],
            }
            for item in report.findings
        ],
        "templates": [
            {
                "pattern": t.pattern,
                "count": t.count,
                "event_key": t.event_key,
                "source_type": t.source_type,
                "hosts": list(t.hosts),
            }
            for t in report.top_templates
        ],
        "assumptions": report.assumptions,
        "warnings": report.warnings,
    }
