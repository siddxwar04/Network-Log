"""The detection engine: runs rules over an upload's events and produces findings.

The engine contains no knowledge of any particular problem. It knows three things:
  - threshold: how to count events per group in a sliding window;
  - sequence:  how to spot one event followed by another;
  - absence:   how to spot an event that is not followed by its counterpart in time,
               such as an interface going down and not coming back.
Which events, which groups, which thresholds and how serious the result is all come from
the rule files.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta

from netlog.config import load_config
from netlog.detection.finding import Finding, format_duration
from netlog.detection.rules import Matcher, Rule, field_value, load_rules, metric_name
from netlog.detection.severity import score
from netlog.schema import Event
from netlog.storage.database import Database, EventFilter

_RUNNERS = {}


def detect(
    db: Database,
    upload_id: int,
    rules: list[Rule] | None = None,
    config: dict | None = None,
    *,
    until: datetime | None = None,
) -> list[Finding]:
    """Run every enabled rule over an upload, store the findings and return them.

    Running it again replaces the previous findings. `until` is when observation ended,
    if later than the last message: for live messages it is now, so something that went
    down and has not come back counts as down until now, not until the last message.
    """
    settings = config if config is not None else load_config()
    findings: list[Finding] = []
    for rule in rules if rules is not None else load_rules():
        if not rule.enabled:
            continue
        if rule.kind == "absence":
            found = _run_absence(db, upload_id, rule, until)
        else:
            found = _RUNNERS[rule.kind](db, upload_id, rule)
        for finding in found:
            score(finding, rule, settings)
        findings += found
    findings.sort(key=lambda f: (f.start, f.rule, sorted(f.group.items(), key=str)))
    db.save_findings(upload_id, findings)
    return db.findings(upload_id)


def _matching(db: Database, upload_id: int, matcher: Matcher) -> list[Event]:
    """Events a matcher accepts, in time order. Events with no time cannot be placed."""
    candidates = db.iter_events(upload_id, EventFilter(event_keys=matcher.event_keys))
    return [e for e in candidates if e.timestamp is not None and matcher.matches(e)]


def _group_key(event: Event, fields: tuple[str, ...]) -> tuple | None:
    """The values an event is grouped by, or None if it lacks one of them."""
    values = tuple(field_value(event, name) for name in fields)
    return None if any(value is None for value in values) else values


def _grouped(events: list[Event], fields: tuple[str, ...]) -> dict[tuple, list[Event]]:
    groups: dict[tuple, list[Event]] = defaultdict(list)
    for event in events:
        key = _group_key(event, fields)
        if key is not None:
            groups[key].append(event)
    return groups


def hot_ranges(
    times: list[datetime], window: timedelta, threshold: int
) -> list[tuple[int, int, int, int]]:
    """Find the stretches of `times` where the rule's threshold is met.

    A window is "hot" when it holds at least `threshold` events. Hot windows that
    overlap, or that follow each other within one window length, are joined: an
    interface flapping for half an hour is one problem, not six.

    Returns (first index, last index, largest count in any one window, index of the
    event at which the threshold was first reached) for each stretch.
    """
    ranges: list[list[int]] = []
    oldest = 0
    for newest, moment in enumerate(times):
        while moment - times[oldest] > window:
            oldest += 1
        count = newest - oldest + 1
        if count < threshold:
            continue
        previous = ranges[-1] if ranges else None
        if previous and (oldest <= previous[1] or times[oldest] - times[previous[1]] <= window):
            previous[1] = newest
            previous[2] = max(previous[2], count)
        else:
            ranges.append([oldest, newest, count, newest])
    return [tuple(r) for r in ranges]


def _strength(peak: float, threshold: float, strong_at: float) -> float:
    """0 to 1. A finding at exactly the threshold scores 1/strong_at; at `strong_at`
    times the threshold or more it scores 1."""
    return round(min(1.0, peak / (threshold * strong_at)), 3)


def _single_host(events: list[Event]) -> str | None:
    hosts = {e.host for e in events}
    return hosts.pop() if len(hosts) == 1 else None


def _capture(events: list[Event], fields: tuple[str, ...], metrics: dict, prefix: str = "") -> None:
    """Record the most common value of each field among the events, where there is one."""
    for name in fields:
        seen = Counter(v for e in events if (v := field_value(e, name)) is not None)
        if seen:
            metrics[prefix + metric_name(name)] = seen.most_common(1)[0][0]


def _run_threshold(db: Database, upload_id: int, rule: Rule) -> list[Finding]:
    window = timedelta(seconds=rule.window_seconds)
    groups = _grouped(_matching(db, upload_id, rule.matcher), rule.group_by)

    later: dict[tuple, list[Event]] = {}
    if rule.followed_by:
        later = _grouped(_matching(db, upload_id, rule.followed_by.matcher), rule.followed_by.same)
    related: dict[tuple, list[Event]] = {}
    if rule.related:
        related = _grouped(_matching(db, upload_id, rule.related.matcher), rule.related.same)

    findings = []
    for key, events in groups.items():
        times = [e.timestamp for e in events]
        for first, last, peak, crossed in hot_ranges(times, window, rule.threshold):
            evidence = events[first : last + 1]
            group = dict(zip(rule.group_by, key, strict=True))
            duration = (times[last] - times[first]).total_seconds()
            metrics: dict = {
                "count": len(evidence),
                "peak_count": peak,
                "threshold": rule.threshold,
                "window_seconds": rule.window_seconds,
                "rate_per_minute": round(len(evidence) / max(duration / 60, 1.0), 2),
            }
            for name in rule.distinct:
                seen = (field_value(e, name) for e in evidence)
                values = sorted({str(value) for value in seen if value is not None})
                metrics[f"distinct_{metric_name(name)}"] = len(values)
                if name == "host":
                    metrics["hosts"] = values
            _capture(evidence, rule.capture, metrics)
            flags = [t.name for t in rule.tags if metrics.get(t.metric, 0) >= t.at_least]

            evidence_ids = [e.id for e in evidence]
            if rule.related:
                shared = tuple(group[name] for name in rule.related.same)
                margin = timedelta(seconds=rule.related.margin_seconds)
                nearby = [
                    e
                    for e in related.get(shared, [])
                    if times[first] - margin <= e.timestamp <= times[last] + margin
                ]
                evidence_ids += [e.id for e in nearby]
                _capture(nearby, rule.related.capture, metrics, prefix="related_")
            if rule.followed_by:
                shared = tuple(group[name] for name in rule.followed_by.same)
                deadline = times[last] + timedelta(seconds=rule.followed_by.within_seconds)
                # By default only an event after the threshold was reached counts: a login
                # that succeeds before the guessing started proves nothing. A recovery
                # must come after the last drop, or the thing is not up.
                earliest = times[last] if rule.followed_by.after == "last" else times[crossed]
                hit = next(
                    (e for e in later.get(shared, []) if earliest <= e.timestamp <= deadline),
                    None,
                )
                if hit:
                    flag = rule.followed_by.flag
                    flags.append(flag)
                    evidence_ids.append(hit.id)
                    metrics[f"{flag}_at"] = hit.timestamp.isoformat()
                    metrics[f"{flag}_after_seconds"] = round(
                        (hit.timestamp - times[first]).total_seconds(), 3
                    )
                    if hit.entities.username:
                        metrics[f"{flag}_username"] = hit.entities.username

            host = group.get("host") or _single_host(evidence)
            findings.append(
                Finding(
                    rule=rule.name,
                    incident_type=rule.incident_type,
                    title=_title(rule, group, host, metrics, duration),
                    host=host,
                    group=group,
                    start=times[first],
                    end=times[last],
                    metrics=metrics,
                    flags=flags,
                    evidence=evidence_ids,
                    strength=_strength(peak, rule.threshold, rule.strong_at),
                )
            )
    return findings


def _run_sequence(db: Database, upload_id: int, rule: Rule) -> list[Finding]:
    limit = timedelta(seconds=rule.within_seconds)
    firsts = _grouped(_matching(db, upload_id, rule.first), rule.same)
    thens = _grouped(_matching(db, upload_id, rule.then), rule.same)

    findings = []
    for key, later_events in thens.items():
        earlier = firsts.get(key, [])
        for then in later_events:
            # The most recent "first" event before this one, if it is recent enough.
            before = [e for e in earlier if e.timestamp <= then.timestamp and e.id != then.id]
            if not before or then.timestamp - before[-1].timestamp > limit:
                continue
            first = before[-1]
            delay = (then.timestamp - first.timestamp).total_seconds()
            group = dict(zip(rule.same, key, strict=True))
            host = group.get("host") or _single_host([first, then])
            metrics = {"count": 2, "delay": round(delay, 3), "within_seconds": rule.within_seconds}
            findings.append(
                Finding(
                    rule=rule.name,
                    incident_type=rule.incident_type,
                    title=_title(rule, group, host, metrics, delay),
                    host=host,
                    group=group,
                    start=first.timestamp,
                    end=then.timestamp,
                    metrics=metrics,
                    flags=[],
                    evidence=[first.id, then.id],
                    # The sooner the second event follows, the stronger the link.
                    strength=round(max(0.1, 1.0 - delay / rule.within_seconds), 3),
                )
            )
    return findings


def _run_absence(
    db: Database, upload_id: int, rule: Rule, until: datetime | None = None
) -> list[Finding]:
    """`first` happened and `then` did not follow within the time allowed.

    Used for outages: something went down (`first`) and did not come back (`then`) soon
    enough. The finding lasts from the first event until the recovery, or until the end
    of the log if there was none.
    """
    limit = timedelta(seconds=rule.within_seconds)
    firsts = _grouped(_matching(db, upload_id, rule.first), rule.same)
    thens = _grouped(_matching(db, upload_id, rule.then), rule.same)
    span = db.time_range(upload_id)
    log_end = span[1] if span else None
    if until is not None and (log_end is None or until > log_end):
        log_end = until

    findings = []
    for key, starts in firsts.items():
        timeline = sorted(
            [(e.timestamp, e.line_no, True, e) for e in starts]
            + [(e.timestamp, e.line_no, False, e) for e in thens.get(key, [])],
            key=lambda item: item[:2],
        )
        outages: list[tuple[Event, Event | None]] = []
        open_since: Event | None = None
        for _, _, is_start, event in timeline:
            if is_start and open_since is None:
                open_since = event  # a second "down" while already down is the same outage
            elif not is_start and open_since is not None:
                outages.append((open_since, event))
                open_since = None
        if open_since is not None:
            outages.append((open_since, None))

        for began, recovered in outages:
            end = recovered.timestamp if recovered else log_end
            lasted = end - began.timestamp
            if lasted <= limit:
                continue
            seconds = lasted.total_seconds()
            group = dict(zip(rule.same, key, strict=True))
            host = group.get("host") or began.host
            metrics = {
                "count": 1,
                "outage_seconds": round(seconds, 3),
                "within_seconds": rule.within_seconds,
            }
            findings.append(
                Finding(
                    rule=rule.name,
                    incident_type=rule.incident_type,
                    title=_title(rule, group, host, metrics, seconds),
                    host=host,
                    group=group,
                    start=began.timestamp,
                    end=end,
                    metrics=metrics,
                    flags=[] if recovered else ["not_recovered"],
                    evidence=[began.id] + ([recovered.id] if recovered else []),
                    strength=_strength(seconds, rule.within_seconds, rule.strong_at),
                )
            )
    return findings


_RUNNERS.update(threshold=_run_threshold, sequence=_run_sequence, absence=_run_absence)


def _title(rule: Rule, group: dict, host: str | None, metrics: dict, duration: float) -> str:
    # A group field such as `extra.network` is written {network} in a title.
    named = {metric_name(name): value for name, value in group.items()}
    values = {**metrics, **named, "duration": format_duration(duration)}
    values.setdefault("host", host or "several devices")
    return rule.title.format_map(values)
