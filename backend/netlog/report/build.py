"""Collects everything a report shows about one analyzed log file.

This module gathers the facts; `render.py` decides how they look. The JSON output is
this data as it is, so other programs get exactly what the text report is built from.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from netlog.correlation.incident import CausalStep, Incident
from netlog.detection.finding import Finding, format_duration
from netlog.detection.rules import LEVELS
from netlog.parsers.pipeline import line_shape
from netlog.storage.database import Database, EventFilter, Template, Upload

JSON_VERSION = 1
# Parse coverage below this is called out in the report.
COVERAGE_WARNING_BELOW = 95.0

# Short names for the built-in rules, used where several findings are shown as one line.
RULE_LABELS = {
    "link_flap": "Interface flapping",
    "interface_down": "Interface down",
    "bgp_session_down": "BGP session down",
    "ospf_adjacency_loss": "OSPF adjacency lost",
    "dhcp_exhaustion": "DHCP pool exhausted",
    "config_change": "Configuration changed",
    "brute_force_login": "Brute-force login",
    "cpu_hog": "CPU hog",
    "memory_allocation_failure": "Memory allocation failure",
    "device_reload": "Reload requested",
    "device_restart": "Device restarted",
    "mac_flapping": "MAC addresses flapping",
}


def rule_label(rule: str) -> str:
    return RULE_LABELS.get(rule) or rule.replace("_", " ").capitalize()


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
    incident_id: str | None = None
    # "problem" (part of an incident), "context" (attached to one) or None.
    role: str | None = None


@dataclass
class StoryRow:
    """One line of an incident's story: the cause, or a group of like effects under it."""

    depth: int
    label: str
    # When it happened relative to the start of the story: "at once", "+35s to +41s".
    when: str
    finding_ids: list[int]
    lines: list[EvidenceLine]
    certainty: str | None = None  # direct, plausible or suspect; None for the first row
    explanation: str | None = None
    # False for a finding in the incident that the root cause does not account for.
    explained: bool = True


@dataclass
class Cited:
    """A statement of an explanation with the log lines it rests on."""

    text: str
    lines: list[int]  # line numbers in the original file
    ids: list[str]  # the evidence ids as cited: E3, F1, C2
    # For a hypothesis: what speaks against it.
    against: list[int] = field(default_factory=list)
    against_ids: list[str] = field(default_factory=list)


@dataclass
class ReportExplanation:
    """The plain-English explanation of one incident, ready to show: real names put back,
    citations turned into line numbers."""

    source: str  # llm, cache or fallback
    written_by: str  # the same, as a phrase for the reader
    mode: str  # junior or senior
    provider: str
    model: str
    reason: str | None  # why the LLM's explanation was not used, for a fallback
    summary: str
    timeline: list[Cited]
    hypotheses: list[Cited]
    impact: list[Cited]
    fix_steps: list[tuple[str, bool]]  # text, and whether it changes a device
    commands: list[tuple[str, str]]  # command, and what a healthy result looks like
    unknowns: list[str]
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    requests: int = 0  # requests made to the LLM for this explanation
    leftover_tokens: list[str] = field(default_factory=list)


@dataclass
class ReportIncident:
    incident: Incident
    headline: str
    # How many findings of each kind, such as [("BGP session down", 6), ...].
    kinds: list[tuple[str, int]]
    story: list[StoryRow]
    findings: list[Finding]
    context: list[Finding]
    explanation: ReportExplanation | None = None


@dataclass
class Report:
    upload: Upload
    hosts: list[tuple[str, int]]
    time_range: tuple[datetime, datetime] | None
    template_count: int
    top_templates: list[Template]
    min_severity: str
    incidents: list[ReportIncident]
    findings: list[ReportFinding]
    # Every finding by level, whether or not it is listed.
    counts: dict[str, int]
    # Every incident by level.
    incident_counts: dict[str, int]
    show_findings: bool = False
    show_usage: bool = False
    assumptions: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def lines_per_template(self) -> float:
        return self.upload.line_count / self.template_count if self.template_count else 0.0

    @property
    def routine_count(self) -> int:
        """Info-level findings: config changes, interfaces that went down."""
        return self.counts.get("info", 0)

    @property
    def attached_count(self) -> int:
        return sum(len(item.context) for item in self.incidents)

    @property
    def lists_routine(self) -> bool:
        return self.min_severity == "info"

    @property
    def has_something(self) -> bool:
        """Whether the report lists anything, which decides the command's exit code."""
        return bool(self.incidents) or (self.lists_routine and self.routine_count > 0)


def _key_lines(db: Database, finding: Finding, limit: int) -> list[EvidenceLine]:
    events = db.events_by_id(finding.evidence)
    if len(events) > limit:
        head = limit - limit // 2
        events = events[:head] + events[-(limit - head) :]
    return [EvidenceLine(e.line_no, e.raw) for e in events]


def _first_lines(db: Database, findings: list[Finding], limit: int) -> list[EvidenceLine]:
    """The earliest evidence line of each finding, then more from the first, up to a limit."""
    ids: list[int] = []
    for finding in sorted(findings, key=lambda f: (f.start, f.id)):
        if finding.evidence and len(ids) < limit:
            ids.append(finding.evidence[0])
    if len(findings) == 1:
        ids = findings[0].evidence[:limit]
        if len(findings[0].evidence) > limit:  # keep the last line: a recovery or a success
            ids = findings[0].evidence[: limit - 1] + findings[0].evidence[-1:]
    return [EvidenceLine(e.line_no, e.raw) for e in db.events_by_id(ids)]


def _offsets(findings: list[Finding], origin: datetime) -> str:
    delays = sorted((f.start - origin).total_seconds() for f in findings)
    first, last = delays[0], delays[-1]
    if last < 1:
        return "at once"
    if last - first < 1:
        return f"+{format_duration(last)}"
    low = "at once" if first < 1 else f"+{format_duration(first)}"
    return f"{low} to +{format_duration(last)}"


def _group_label(findings: list[Finding]) -> str:
    if len(findings) == 1:
        return findings[0].title
    hosts = sorted({f.host for f in findings if f.host})
    label = f"{rule_label(findings[0].rule)} on {', '.join(hosts)}"
    if len(findings) > len(hosts):
        label += f" ({len(findings)} findings)"
    return label


def _story(db: Database, incident: Incident, by_id: dict[int, Finding]) -> list[StoryRow]:
    """An incident as an indented story: the cause first, each group of effects under
    what caused it. Like effects (three routers losing the same neighbor) share a line."""
    root = incident.root_cause
    children: dict[int, list[CausalStep]] = {}
    for step in incident.chain:
        children.setdefault(step.cause, []).append(step)

    root_findings = [by_id[i] for i in (root.finding_ids if root else [])]
    origin = min((f.start for f in root_findings), default=incident.start)
    rows: list[StoryRow] = []
    seen: set[int] = set()

    def add_effects(cause_ids: list[int], depth: int, explained: bool = True) -> None:
        buckets: dict[tuple[str, str], list[CausalStep]] = {}
        for cause_id in cause_ids:
            for step in children.get(cause_id, []):
                buckets.setdefault((by_id[step.effect].rule, step.prior), []).append(step)
        ordered = sorted(
            buckets.values(), key=lambda steps: min(by_id[s.effect].start for s in steps)
        )
        for steps in ordered:
            effects = [by_id[s.effect] for s in steps]
            seen.update(f.id for f in effects)
            rows.append(
                StoryRow(
                    depth=depth,
                    label=_group_label(effects),
                    when=_offsets(effects, origin),
                    finding_ids=[f.id for f in effects],
                    lines=_first_lines(db, effects, 2),
                    certainty=steps[0].certainty,
                    explanation=steps[0].explanation,
                    explained=explained,
                )
            )
            add_effects([f.id for f in effects], depth + 1, explained)

    if root:
        seen.update(root.finding_ids)
        rows.append(
            StoryRow(
                depth=0,
                label=root.summary,
                when="",
                finding_ids=list(root.finding_ids),
                lines=_first_lines(db, root_findings, 3) if root_findings else [],
            )
        )
        add_effects(list(root.finding_ids), 1)

    # Problems the root cause leads to without being a finding itself (a neighbor that
    # went silent), then anything in the incident it does not account for.
    members = [by_id[i] for i in incident.finding_ids]
    has_cause = {step.effect for step in incident.chain}

    def add_tops(tops: list[Finding], explained: bool) -> None:
        by_rule: dict[str, list[Finding]] = {}
        for finding in tops:
            by_rule.setdefault(finding.rule, []).append(finding)
        for group in sorted(by_rule.values(), key=lambda fs: min(f.start for f in fs)):
            seen.update(f.id for f in group)
            rows.append(
                StoryRow(
                    depth=1,
                    label=_group_label(group),
                    when=_offsets(group, origin),
                    finding_ids=[f.id for f in group],
                    lines=_first_lines(db, group, 2),
                    explained=explained,
                )
            )
            add_effects([f.id for f in group], 2, explained)

    if root and not root.finding_ids:
        lost_it = [
            f
            for f in members
            if f.id not in has_cause and f.group.get("neighbor_ip") == root.entity
        ]
        add_tops(lost_it, explained=True)
    add_tops([f for f in members if f.id not in seen and f.id not in has_cause], explained=False)
    return rows


def _headline(incident: Incident, members: list[Finding]) -> str:
    root = incident.root_cause
    # A suspect is not what happened; lead with the failure and name the suspect below.
    if root is None or root.kind == "config_change":
        worst = max(members, key=lambda f: (LEVELS.index(f.severity), -f.start.timestamp()))
        return worst.title
    return root.summary


def build_report(
    db: Database,
    upload_id: int,
    *,
    min_severity: str = "low",
    year: int | None = None,
    assumed_year: int | None = None,
    timezone: str | None = None,
    show_findings: bool = False,
    show_usage: bool = False,
    explanations: dict[str, ReportExplanation] | None = None,
    evidence_lines: int = 5,
    top_templates: int = 10,
) -> Report:
    """Gather the report for an upload that has been parsed, mined, run through detection
    and correlated.

    `year` and `timezone` are what the user asked for, or None if they left it to the
    default; `assumed_year` is the year that was used in that case. `explanations` holds
    the explanation of each incident by its id, from `report.explain`.
    """
    upload = db.get_upload(upload_id)
    findings = db.findings(upload_id)
    by_id = {f.id: f for f in findings}
    floor = LEVELS.index(min_severity)

    counts = {level: 0 for level in reversed(LEVELS)}
    for finding in findings:
        counts[finding.severity] += 1

    incident_counts = {level: 0 for level in reversed(LEVELS)}
    shown_incidents: list[ReportIncident] = []
    role: dict[int, tuple[str, str]] = {}
    for incident in db.incidents(upload_id):
        incident_counts[incident.severity] += 1
        if LEVELS.index(incident.severity) < floor:
            continue
        members = [by_id[i] for i in incident.finding_ids]
        context = [by_id[i] for i in incident.context_ids]
        role.update({f.id: (incident.id, "problem") for f in members})
        role.update({f.id: (incident.id, "context") for f in context})
        kinds = Counter(rule_label(f.rule) for f in members).most_common()
        shown_incidents.append(
            ReportIncident(
                incident=incident,
                headline=_headline(incident, members),
                kinds=kinds,
                story=_story(db, incident, by_id),
                findings=members,
                context=context,
                explanation=(explanations or {}).get(incident.id),
            )
        )
    shown_incidents.sort(
        key=lambda item: (-LEVELS.index(item.incident.severity), item.incident.start)
    )

    listed = [f for f in findings if LEVELS.index(f.severity) >= floor or f.id in role]
    listed.sort(key=lambda f: (-LEVELS.index(f.severity), f.start, f.id))

    report = Report(
        upload=upload,
        hosts=sorted((host, n) for host, n in db.count_by(upload_id, "host") if host),
        time_range=db.time_range(upload_id),
        template_count=db.count_templates(upload_id),
        top_templates=db.templates(upload_id, limit=top_templates),
        min_severity=min_severity,
        incidents=shown_incidents,
        findings=[
            ReportFinding(
                f, _key_lines(db, f, evidence_lines), len(f.evidence), *role.get(f.id, (None, None))
            )
            for f in listed
        ],
        counts=counts,
        incident_counts=incident_counts,
        show_findings=show_findings,
        show_usage=show_usage,
    )
    for item in shown_incidents:
        if item.explanation and item.explanation.leftover_tokens:
            report.warnings.append(
                f"The explanation of incident {item.incident.id} still contains stand-ins "
                f"that could not be replaced: {', '.join(item.explanation.leftover_tokens)}."
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


def _root_json(root) -> dict | None:
    if root is None:
        return None
    return {
        "kind": root.kind,
        "summary": root.summary,
        "devices": root.devices,
        "entity": root.entity,
        "findings": root.finding_ids,
        "explains": root.explains,
    }


def _cited_json(item: Cited, hypothesis: bool = False) -> dict:
    data = {"text": item.text, "lines": item.lines, "evidence": item.ids}
    if hypothesis:
        data["against_lines"], data["against"] = item.against, item.against_ids
    return data


def _explanation_json(explanation: ReportExplanation | None) -> dict | None:
    if explanation is None:
        return None
    return {
        "source": explanation.source,
        "written_by": explanation.written_by,
        "audience": explanation.mode,
        "provider": explanation.provider,
        "model": explanation.model,
        "fallback_reason": explanation.reason,
        "summary": explanation.summary,
        "timeline": [_cited_json(item) for item in explanation.timeline],
        "hypotheses": [_cited_json(item, hypothesis=True) for item in explanation.hypotheses],
        "impact": [_cited_json(item) for item in explanation.impact],
        "fix_steps": [
            {"text": text, "review_before_running": changes}
            for text, changes in explanation.fix_steps
        ],
        "verification_commands": [
            {"command": command, "purpose": purpose} for command, purpose in explanation.commands
        ],
        "unknowns": explanation.unknowns,
        "usage": {
            "requests": explanation.requests,
            "input_tokens": explanation.input_tokens,
            "output_tokens": explanation.output_tokens,
            "latency_ms": explanation.latency_ms,
        },
    }


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
            "incidents": len(report.incidents),
            "incidents_by_severity": report.incident_counts,
            "by_severity": report.counts,
            "shown": len(report.findings),
            "hidden": sum(report.counts.values()) - len(report.findings),
        },
        "incidents": [
            {
                "id": item.incident.id,
                "headline": item.headline,
                "title": item.incident.title,
                "severity": item.incident.severity,
                "severity_reason": item.incident.severity_reason,
                "start": _iso(item.incident.start),
                "end": _iso(item.incident.end),
                "duration_seconds": item.incident.duration_seconds,
                "devices": item.incident.devices,
                "root_cause": _root_json(item.incident.root_cause),
                "alternatives": [_root_json(root) for root in item.incident.alternatives],
                "confidence": item.incident.confidence,
                "confidence_reason": item.incident.confidence_reason,
                "unknowns": item.incident.unknowns,
                "findings": item.incident.finding_ids,
                "context": item.incident.context_ids,
                "chain": [
                    {
                        "cause": step.cause,
                        "effect": step.effect,
                        "prior": step.prior,
                        "certainty": step.certainty,
                        "explanation": step.explanation,
                        "delay_seconds": step.delay_seconds,
                    }
                    for step in item.incident.chain
                ],
                "story": [
                    {
                        "depth": row.depth,
                        "label": row.label,
                        "when": row.when,
                        "certainty": row.certainty,
                        "explanation": row.explanation,
                        "explained": row.explained,
                        "findings": row.finding_ids,
                        "evidence": [{"line": e.line_no, "text": e.text} for e in row.lines],
                    }
                    for row in item.story
                ],
                "explanation": _explanation_json(item.explanation),
            }
            for item in report.incidents
        ],
        "findings": [
            {
                "id": item.finding.id,
                "incident": item.incident_id,
                "role": item.role,
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
