"""The evidence pack: the short, numbered case file about one incident.

It is the only thing an LLM is ever shown. It holds what the code already decided (the
severity, the root cause, the confidence, the chain of cause and effect) and a handful
of log lines that prove it, instead of the thousands of raw lines the incident came from.

Every item has a short id the explanation can cite:

    F1, F2 ...  findings: one rule noticing one problem
    C1, C2 ...  chain steps: one mechanism of cause and effect, with the findings it links
    T1, T2 ...  templates: the message patterns involved, with counts
    E1, E2 ...  evidence: actual log lines, with their line number in the file

Two properties matter as much as the content:

  - The same incident always gives the same pack, byte for byte. Nothing in it depends
    on database ids, on the clock or on the order things were read, so the pack's hash
    can be used as a cache key.
  - The pack never grows past its size limit. When an incident is too large, the
    earliest evidence for each chain step is kept and the rest is summarized as counts
    under "omitted".

`build_pack` gives the pack with real addresses and names, for use on this machine.
`outgoing_pack` gives the pack as it may be sent: redacted, and within the limit after
redaction.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field, replace
from datetime import datetime

from netlog.config import load_config
from netlog.correlation.incident import Incident, RootCause
from netlog.detection.finding import Finding
from netlog.redaction.redactor import Redactor
from netlog.schema import Event
from netlog.storage.database import Database

PACK_VERSION = 1
CONFIG_CHANGE = "config_change"
_CUT = "..."


class PackTooLarge(ValueError):
    """The size limit is set so low that not even the bare facts of the incident fit."""


@dataclass
class EvidencePack:
    # The content. Plain data: dictionaries, lists, text and numbers.
    data: dict
    chars_per_token: float = 4.0
    # Which database row each id stands for, and the line number in the original file
    # of each evidence line. Kept beside the pack, never inside it.
    finding_ids: dict[str, int] = field(default_factory=dict)
    event_ids: dict[str, int] = field(default_factory=dict)
    line_numbers: dict[str, int] = field(default_factory=dict)
    # The hostnames and usernames that occur in the incident, for redaction.
    hostnames: tuple[str, ...] = ()
    usernames: tuple[str, ...] = ()
    redacted: bool = False

    def to_json(self, indent: int | None = None) -> str:
        """The pack as text. Without `indent` this is the exact form that is measured,
        hashed and sent."""
        if indent is None:
            return json.dumps(self.data, ensure_ascii=False, separators=(",", ":"))
        return json.dumps(self.data, ensure_ascii=False, indent=indent)

    @property
    def hash(self) -> str:
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()

    @property
    def size_chars(self) -> int:
        return len(self.to_json())

    @property
    def tokens(self) -> int:
        """An estimate. The real count depends on the model that reads the pack."""
        return math.ceil(self.size_chars / self.chars_per_token)

    @property
    def ids(self) -> set[str]:
        """Every id an explanation may cite."""
        sections = ("findings", "chain", "templates", "evidence")
        return {item["id"] for name in sections for item in self.data[name]}

    @property
    def trimmed(self) -> bool:
        """Whether anything other than surplus log lines had to be left out."""
        return bool(set(self.data.get("omitted", {})) - {"evidence_lines"})


@dataclass(frozen=True)
class _Limits:
    """How much of each kind of item one attempt at building the pack may hold."""

    findings: int
    links: int
    templates: int
    lines: int
    examples: int
    line_chars: int
    text_chars: int
    details: bool = True
    context: bool = True


@dataclass
class _Source:
    """Everything about an incident that a pack can draw on, read from the database once."""

    incident: Incident
    findings: dict[int, Finding]  # members and context
    events: list[Event]  # every evidence event, in time order
    order: dict[int, int]  # event id -> its position in `events`
    # A template's id for each event; an event that was never mined is grouped by its
    # event key instead.
    template_of: dict[int, str]
    patterns: dict[str, tuple[str, str | None]]  # template id -> (pattern, event key)
    omit_details: frozenset[str]
    hostnames: tuple[str, ...]
    usernames: tuple[str, ...]


def _iso(moment: datetime) -> str:
    """`2026-03-03T02:46:11.719Z`: to the millisecond, which is as fine as devices log."""
    precision = "milliseconds" if moment.microsecond else "seconds"
    return moment.isoformat(timespec=precision).replace("+00:00", "Z")


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: max(limit - len(_CUT), 0)] + _CUT


def _settings(config: dict | None) -> dict:
    settings = (config or load_config())["evidence"]
    for name in ("max_tokens", "chars_per_token", "examples_per_template"):
        if settings[name] <= 0:
            raise ValueError(f"evidence.{name} must be greater than zero")
    return settings


def _ladder(settings: dict):
    """The attempts, from the fullest pack to the barest. The first that fits is used.

    Log lines go first, because the counts in the templates still tell how many there
    were. The facts the code decided go last.
    """
    limits = _Limits(
        findings=max(int(settings["max_findings"]), 1),
        links=max(int(settings["max_chain_links"]), 0),
        templates=max(int(settings["max_templates"]), 1),
        lines=max(int(settings["max_evidence_lines"]), 1),
        examples=int(settings["examples_per_template"]),
        line_chars=int(settings["max_line_chars"]),
        text_chars=int(settings["max_text_chars"]),
    )
    yield limits
    while limits.examples > 1:
        limits = replace(limits, examples=limits.examples - 1)
        yield limits
    limits = replace(limits, details=False)
    yield limits
    limits = replace(limits, context=False)
    yield limits
    while (limits.findings, limits.links, limits.templates, limits.lines) != (1, 0, 1, 1):
        limits = replace(
            limits,
            findings=max(limits.findings // 2, 1),
            links=limits.links // 2,
            templates=max(limits.templates // 2, 1),
            lines=max(limits.lines // 2, 1),
        )
        yield limits
    for chars in (160, 80, 40):
        yield replace(
            limits,
            line_chars=min(limits.line_chars, chars),
            text_chars=min(limits.text_chars, chars),
        )


# --- Reading the incident ----------------------------------------------------------------


def _usernames(finding: Finding) -> list[str]:
    values = [finding.group.get("username")]
    values += [value for key, value in finding.metrics.items() if "username" in key]
    flat = []
    for value in values:
        flat += value if isinstance(value, list) else [value]
    return [value for value in flat if isinstance(value, str) and value]


def _gather(db: Database, upload_id: int, incident: Incident, settings: dict) -> _Source:
    wanted = set(incident.finding_ids) | set(incident.context_ids)
    findings = {f.id: f for f in db.findings(upload_id) if f.id in wanted}
    missing = wanted - set(findings)
    if missing:
        raise ValueError(f"incident {incident.id} names findings that are not stored")

    event_ids = sorted({event_id for f in findings.values() for event_id in f.evidence})
    events = db.events_by_id(event_ids)
    events.sort(key=lambda e: (e.timestamp is not None, e.timestamp, e.line_no))

    template_of, patterns = {}, {}
    for event in events:
        key = event.template_id or f"key:{event.event_key or event.app or ''}"
        template_of[event.id] = key
        if key not in patterns:
            template = db.get_template(upload_id, key) if event.template_id else None
            pattern = template.pattern if template else (event.event_key or "(not recognized)")
            patterns[key] = (pattern, event.event_key)

    hostnames = {host for host, _ in db.count_by(upload_id, "host", limit=100_000) if host}
    hostnames.update(incident.devices)
    for root in [incident.root_cause, *incident.alternatives]:
        hostnames.update(root.devices if root else ())
    usernames: set[str] = set()
    for finding in findings.values():
        hostnames.update([finding.host] if finding.host else [])
        listed = finding.metrics.get("hosts")
        hostnames.update(h for h in (listed if isinstance(listed, list) else []) if h)
        usernames.update(_usernames(finding))
    for event in events:
        if event.entities.username:
            usernames.add(event.entities.username)
        if event.entities.extra.get("hostname"):  # the name a DHCP client gave itself
            hostnames.add(event.entities.extra["hostname"])

    return _Source(
        incident=incident,
        findings=findings,
        events=events,
        order={event.id: position for position, event in enumerate(events)},
        template_of=template_of,
        patterns=patterns,
        omit_details=frozenset(settings["omit_details"]),
        hostnames=tuple(sorted(hostnames)),
        usernames=tuple(sorted(usernames)),
    )


# --- Building one attempt ----------------------------------------------------------------


def _finding_order(finding: Finding) -> tuple:
    return (finding.start, finding.end, finding.rule, finding.title, finding.id)


def _pick_findings(source: _Source, limits: _Limits) -> tuple[list[Finding], dict[str, int]]:
    """Which findings go in, in time order, and how many of each rule were left out.

    When there is no room for all, the root cause is kept first, then the problems, then
    configuration changes, then the other context.
    """
    incident = source.incident
    roots = set(incident.root_cause.finding_ids) if incident.root_cause else set()
    context = set(incident.context_ids)

    def rank(finding: Finding) -> int:
        if finding.id in roots:
            return 0
        if finding.id not in context:
            return 1
        return 2 if finding.incident_type == CONFIG_CHANGE else 3

    ranked = sorted(source.findings.values(), key=lambda f: (rank(f), *_finding_order(f)))
    if not limits.context:
        ranked = [f for f in ranked if rank(f) < 3]
    kept = sorted(ranked[: limits.findings], key=_finding_order)

    kept_ids = {f.id for f in kept}
    omitted: dict[str, int] = {}
    for finding in sorted(source.findings.values(), key=lambda f: f.rule):
        if finding.id not in kept_ids:
            omitted[finding.rule] = omitted.get(finding.rule, 0) + 1
    return kept, omitted


def _details(finding: Finding, source: _Source, limits: _Limits) -> dict:
    details = {}
    for key in sorted(finding.metrics):
        value = finding.metrics[key]
        if key in source.omit_details:
            continue
        if isinstance(value, float):
            value = round(value, 1)
        elif isinstance(value, str):
            value = _clip(value, limits.text_chars)
        elif isinstance(value, list):
            shown = [_clip(str(item), limits.text_chars) for item in value[:10]]
            value = shown + ([f"and {len(value) - 10} more"] if len(value) > 10 else [])
        details[key] = value
    return details


def _examples(events: list[Event], already: list[Event], count: int) -> list[Event]:
    """Up to `count` lines of one template: lines already chosen, then the earliest line
    from each device, then the earliest of what is left. `events` is in time order."""
    chosen = list(already)
    hosts = {event.host for event in chosen}
    ids = {event.id for event in chosen}
    for event in events:
        if len(chosen) >= count:
            break
        if event.host not in hosts:
            chosen.append(event)
            hosts.add(event.host)
            ids.add(event.id)
    for event in events:
        if len(chosen) >= count:
            break
        if event.id not in ids:
            chosen.append(event)
            ids.add(event.id)
    return chosen


def _root_data(root: RootCause, names: dict[int, str], members: int, limits: _Limits) -> dict:
    return {
        "kind": root.kind,
        "summary": _clip(root.summary, limits.text_chars),
        "devices": list(root.devices),
        "entity": None if root.entity is None else _clip(root.entity, limits.text_chars),
        "findings": [names[i] for i in root.finding_ids if i in names],
        "explains": root.explains,
        "of": members,
    }


def _assemble(source: _Source, limits: _Limits, chars_per_token: float) -> EvidencePack:
    incident = source.incident
    roots = set(incident.root_cause.finding_ids) if incident.root_cause else set()
    context = set(incident.context_ids)

    kept, omitted_findings = _pick_findings(source, limits)
    names = {finding.id: f"F{n}" for n, finding in enumerate(kept, 1)}
    by_id = {event.id: event for event in source.events}

    def position(event: Event) -> int:
        return source.order[event.id]

    def first_line(finding: Finding) -> Event | None:
        events = [by_id[i] for i in finding.evidence if i in by_id]
        return min(events, key=position) if events else None

    # Chain steps: one per mechanism, holding every cause-and-effect pair it explains.
    groups: dict[tuple[str, str, str], list] = {}
    for step in incident.chain:
        if step.cause in names and step.effect in names:
            key = (step.prior, step.certainty, step.explanation)
            groups.setdefault(key, []).append(step)

    def effect_order(step) -> tuple:
        return (*_finding_order(source.findings[step.effect]), step.cause)

    for steps in groups.values():
        steps.sort(key=effect_order)
    ordered = sorted(groups.items(), key=lambda item: (effect_order(item[1][0]), item[0]))
    chain, room = [], limits.links
    for (_, certainty, explanation), steps in ordered:
        steps = steps[:room]
        room -= len(steps)
        if steps:
            chain.append((certainty, explanation, steps))
    kept_links = sum(len(steps) for _, _, steps in chain)
    omitted_links = len(incident.chain) - kept_links

    # Log lines that must be there: the first line of the root cause, the first line of
    # the earliest cause and of the earliest effect of each chain step, and the line of
    # each configuration change. Without a chain, the first line of each problem.
    must: list[Event] = []

    def require(finding: Finding) -> None:
        event = first_line(finding)
        if event is not None and all(event.id != other.id for other in must):
            must.append(event)

    for finding in kept:
        if finding.id in roots:
            require(finding)
    for _, _, steps in chain:
        require(min((source.findings[s.cause] for s in steps), key=_finding_order))
        require(source.findings[steps[0].effect])
    for finding in kept:
        if finding.incident_type == CONFIG_CHANGE and finding.id in context:
            require(finding)
    if not chain:
        for finding in kept:
            if finding.id not in context:
                require(finding)
    must = must[: limits.lines]

    # Templates in the order they first appear in the incident, each with its examples.
    members: dict[str, list[Event]] = {}
    for event in source.events:
        members.setdefault(source.template_of[event.id], []).append(event)
    template_keys = list(members)[: limits.templates]
    chosen = list(must)
    chosen_ids = {event.id for event in chosen}
    examples: dict[str, list[Event]] = {}
    for key in template_keys:
        already = [event for event in chosen if source.template_of[event.id] == key]
        picked = _examples(members[key], already, limits.examples)
        for event in picked:
            if event.id not in chosen_ids and len(chosen) < limits.lines:
                chosen.append(event)
                chosen_ids.add(event.id)
        examples[key] = [event for event in picked if event.id in chosen_ids]

    chosen.sort(key=position)
    line_names = {event.id: f"E{n}" for n, event in enumerate(chosen, 1)}

    def lines_of(finding: Finding) -> list[str]:
        shown = [by_id[i] for i in finding.evidence if i in line_names]
        return [line_names[e.id] for e in sorted(shown, key=position)]

    data: dict = {
        "version": PACK_VERSION,
        "incident": {
            "id": incident.id,
            "title": _clip(incident.title, limits.text_chars),
            "types": sorted(
                {f.incident_type for f in source.findings.values() if f.id not in context}
            ),
            "severity": incident.severity,
            "severity_reason": _clip(incident.severity_reason, limits.text_chars),
            "start": _iso(incident.start),
            "end": _iso(incident.end),
            "duration_seconds": round(incident.duration_seconds, 1),
            "devices": list(incident.devices),
            "confidence": incident.confidence,
            "confidence_reason": _clip(incident.confidence_reason, limits.text_chars),
            "evidence_lines": len(source.events),
        },
        "root_cause": (
            _root_data(incident.root_cause, names, len(incident.finding_ids), limits)
            if incident.root_cause
            else None
        ),
        "alternatives": [
            _root_data(root, names, len(incident.finding_ids), limits)
            for root in incident.alternatives[:3]
        ],
        "unknowns": [_clip(text, limits.text_chars) for text in incident.unknowns[:8]],
        "findings": [],
        "chain": [],
        "config_changes": [],
        "templates": [],
        "evidence": [],
    }

    for finding in kept:
        if finding.id in roots:
            role = "root_cause"
        else:
            role = "context" if finding.id in context else "problem"
        item = {
            "id": names[finding.id],
            "rule": finding.rule,
            "role": role,
            "title": _clip(finding.title, limits.text_chars),
            "device": finding.host,
            "severity": finding.severity,
            "start": _iso(finding.start),
        }
        # Left out when they would say nothing, to keep the pack short: a finding that
        # is one moment has no separate end, and most findings carry no flags.
        if finding.end != finding.start:
            item["end"] = _iso(finding.end)
        if finding.flags:
            item["flags"] = list(finding.flags)
        # How many log lines the finding rests on, and which of them are in this pack.
        item["evidence_lines"] = len(finding.evidence)
        item["evidence"] = lines_of(finding)
        if limits.details:
            item["details"] = _details(finding, source, limits)
        data["findings"].append(item)

        if finding.incident_type == CONFIG_CHANGE and finding.id in context:
            user = finding.group.get("username") or finding.metrics.get("username")
            data["config_changes"].append(
                {
                    "finding": names[finding.id],
                    "device": finding.host,
                    "user": None if user is None else _clip(str(user), limits.text_chars),
                    "from": finding.metrics.get("src_ip"),
                    "time": _iso(finding.start),
                    "seconds_before_incident": round(
                        (incident.start - finding.start).total_seconds(), 1
                    ),
                    "evidence": lines_of(finding),
                }
            )

    for number, (certainty, explanation, steps) in enumerate(chain, 1):
        data["chain"].append(
            {
                "id": f"C{number}",
                "certainty": certainty,
                "explanation": _clip(explanation, limits.text_chars),
                "links": [
                    {
                        "cause": names[step.cause],
                        "effect": names[step.effect],
                        "delay_seconds": round(step.delay_seconds, 1),
                    }
                    for step in steps
                ],
            }
        )

    for number, key in enumerate(template_keys, 1):
        events = members[key]
        timed = [event.timestamp for event in events if event.timestamp is not None]
        pattern, event_key = source.patterns[key]
        data["templates"].append(
            {
                "id": f"T{number}",
                "pattern": _clip(pattern, limits.line_chars),
                "event_key": event_key,
                "count": len(events),
                "first_seen": _iso(min(timed)) if timed else None,
                "last_seen": _iso(max(timed)) if timed else None,
                "devices": sorted({event.host for event in events if event.host}),
                "examples": [line_names[e.id] for e in sorted(examples[key], key=position)],
            }
        )

    for event in chosen:
        data["evidence"].append(
            {
                "id": line_names[event.id],
                "line": event.line_no,
                "time": None if event.timestamp is None else _iso(event.timestamp),
                "text": _clip(event.raw, limits.line_chars),
            }
        )

    omitted: dict = {}
    if len(source.events) > len(chosen):
        omitted["evidence_lines"] = len(source.events) - len(chosen)
    if omitted_findings:
        omitted["findings"] = omitted_findings
    if omitted_links:
        omitted["chain_links"] = omitted_links
    if len(members) > len(template_keys):
        omitted["templates"] = len(members) - len(template_keys)
    if not limits.details:
        omitted["finding_details"] = True
    if omitted:
        data["omitted"] = omitted

    return EvidencePack(
        data=data,
        chars_per_token=chars_per_token,
        finding_ids={name: finding_id for finding_id, name in names.items()},
        event_ids={name: event_id for event_id, name in line_names.items()},
        line_numbers={line_names[event.id]: event.line_no for event in chosen},
        hostnames=source.hostnames,
        usernames=source.usernames,
    )


# --- The two ways in ---------------------------------------------------------------------


def redact_pack(pack: EvidencePack, redactor: Redactor) -> EvidencePack:
    """The pack with addresses and names replaced and secrets removed."""
    redactor.add_known("HOST", pack.hostnames)
    redactor.add_known("USER", pack.usernames)
    return replace(
        pack,
        data=redactor.redact_data(pack.data),
        hostnames=(),
        usernames=(),
        redacted=redactor.enabled,
    )


def _fit(
    db: Database,
    upload_id: int,
    incident: Incident,
    config: dict | None,
    redactor: Redactor | None,
) -> EvidencePack:
    settings = _settings(config)
    source = _gather(db, upload_id, incident, settings)
    per_token = float(settings["chars_per_token"])
    budget = int(settings["max_tokens"]) * per_token
    for limits in _ladder(settings):
        pack = _assemble(source, limits, per_token)
        if redactor is None:
            if pack.size_chars <= budget:
                return pack
        # The size that counts is the size after redaction, so try on a copy first and
        # hand out real tokens only for the pack that is kept.
        elif redact_pack(pack, redactor.fork()).size_chars <= budget:
            return redact_pack(pack, redactor)
    raise PackTooLarge(
        f"evidence.max_tokens = {settings['max_tokens']} is too small to hold even the "
        f"bare facts of incident {incident.id}"
    )


def build_pack(
    db: Database, upload_id: int, incident: Incident, config: dict | None = None
) -> EvidencePack:
    """The evidence pack for an incident, with real addresses and names.

    For use on this machine only. What may be sent comes from `outgoing_pack`.
    """
    return _fit(db, upload_id, incident, config, None)


def outgoing_pack(
    db: Database,
    upload_id: int,
    incident: Incident,
    redactor: Redactor,
    config: dict | None = None,
) -> EvidencePack:
    """The evidence pack as it may leave this machine: secrets removed, addresses and
    names replaced unless redaction is switched off, and within the size limit."""
    return _fit(db, upload_id, incident, config, redactor)


def outgoing_packs(
    db: Database, upload_id: int, config: dict | None = None
) -> tuple[list[tuple[Incident, EvidencePack]], Redactor]:
    """The outgoing pack of every incident of an upload, and the redactor that can put
    the real values back into an explanation.

    Incidents are taken in the order they started, so the same log always hands out the
    same tokens. The token map is stored in the database before returning.
    """
    config = config or load_config()
    redactor = Redactor.load(db, upload_id, config)
    packs = [
        (incident, outgoing_pack(db, upload_id, incident, redactor, config))
        for incident in db.incidents(upload_id)
    ]
    redactor.save(db, upload_id)
    return packs, redactor
