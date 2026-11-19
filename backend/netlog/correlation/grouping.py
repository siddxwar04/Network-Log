"""Grouping: findings that belong to the same problem become one incident.

Two findings are put together only when they are close in time AND connected. Time
alone is never enough: a brute-force attack and a failed link in the same minute are two
incidents.

Routine findings (Info level: a config change, an interface that went down) never start
an incident and never bridge two problems. They are attached to an incident afterwards,
as context, when they concern the same device or link.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta

from netlog.config import load_config
from netlog.correlation.causality import explain_causes
from netlog.correlation.incident import Incident, Link
from netlog.correlation.priors import Prior, load_priors
from netlog.correlation.topology import Topology, build_topology
from netlog.detection.finding import Finding
from netlog.detection.rules import LEVELS
from netlog.storage.database import Database, EventFilter

_CONFIG_CHANGE = "config_change"


def _hosts(finding: Finding) -> set[str]:
    if finding.host:
        return {finding.host}
    hosts = finding.metrics.get("hosts")
    return set(hosts) if isinstance(hosts, list) else set()


def _interface(finding: Finding) -> str | None:
    return finding.group.get("interface") or finding.metrics.get("interface")


def _distance(a: Finding, b: Finding) -> timedelta:
    """How far apart two findings are in time. Zero when they overlap."""
    return max(timedelta(0), b.start - a.end, a.start - b.end)


class _Correlator:
    def __init__(self, settings: dict, topology: Topology) -> None:
        self.topology = topology
        self.skew = timedelta(seconds=settings["clock_skew_seconds"])
        self.reach = timedelta(seconds=settings["gap_seconds"]) + self.skew
        self.same_problem_reach = (
            timedelta(seconds=settings["same_problem_gap_seconds"]) + self.skew
        )
        self.lookback = timedelta(seconds=settings["config_change_lookback_seconds"])
        self.many_devices = int(settings["many_devices"])
        self.security_types = set(settings["security_types"])

    def is_security(self, finding: Finding) -> bool:
        return finding.incident_type in self.security_types

    def connection(self, a: Finding, b: Finding) -> str | None:
        """Why two findings concern the same thing, or None if nothing connects them."""
        if self.is_security(a) or self.is_security(b):
            # Findings about people are joined by an address, never by a device alone:
            # an attack on a server and a fault on that server are different stories.
            address = self._shared_source(a, b)
            return f"both involve the address {address}" if address else None

        if shared := _hosts(a) & _hosts(b):
            return f"both on {sorted(shared)[0]}"

        neighbor_a, neighbor_b = a.group.get("neighbor_ip"), b.group.get("neighbor_ip")
        if neighbor_a and neighbor_a == neighbor_b:
            return f"both lost the neighbor {neighbor_a}"
        for one, other, neighbor in ((a, b, neighbor_a), (b, a, neighbor_b)):
            owner = self.topology.owner(neighbor)
            if owner and owner in _hosts(other):
                how = "inferred from the logs" if neighbor in self.topology.inferred else "known"
                return f"{one.host}'s neighbor {neighbor} is {owner} ({how})"

        for one, other in ((a, b), (b, a)):
            peer = self.topology.peer(one.host, _interface(one))
            if peer and peer[0] in _hosts(other):
                their_interface = _interface(other)
                if their_interface is None or their_interface == peer[1]:
                    return (
                        f"{_interface(one)} on {one.host} is connected to "
                        f"{peer[1]} on {peer[0]}"
                    )
        return None

    @staticmethod
    def _shared_source(a: Finding, b: Finding) -> str | None:
        sources = []
        for finding in (a, b):
            source = finding.group.get("src_ip") or finding.metrics.get("src_ip")
            sources.append(source)
        return sources[0] if sources[0] and sources[0] == sources[1] else None

    # --- Grouping the problems ------------------------------------------------------

    def group(self, findings: list[Finding]) -> list[tuple[list[Finding], list[Link]]]:
        """Split findings into groups that are connected, directly or through a chain."""
        parent = list(range(len(findings)))

        def root(index: int) -> int:
            while parent[index] != index:
                parent[index] = parent[parent[index]]
                index = parent[index]
            return index

        links: list[tuple[int, int, str]] = []
        for i, first in enumerate(findings):
            for j in range(i + 1, len(findings)):
                second = findings[j]
                # The same kind of problem on the same device is allowed a longer gap.
                same_problem = first.incident_type == second.incident_type and bool(
                    _hosts(first) & _hosts(second)
                )
                reach = self.same_problem_reach if same_problem else self.reach
                if _distance(first, second) > reach:
                    continue
                if reason := self.connection(first, second):
                    links.append((i, j, reason))
                    parent[root(i)] = root(j)

        groups: dict[int, list[Finding]] = {}
        for index, finding in enumerate(findings):
            groups.setdefault(root(index), []).append(finding)
        return [
            (
                members,
                [
                    Link(findings[i].id, findings[j].id, reason)
                    for i, j, reason in links
                    if root(i) == key
                ],
            )
            for key, members in groups.items()
        ]

    # --- Attaching context ----------------------------------------------------------

    def context_reason(
        self, routine: Finding, members: list[Finding], start: datetime, end: datetime
    ) -> str | None:
        """Why a routine finding belongs with an incident, or None."""
        hosts = set().union(*(_hosts(m) for m in members))
        if routine.rule == _CONFIG_CHANGE:
            security = [m for m in members if self.is_security(m)]
            if security:
                # A change made from the attacker's address, during or after the attack.
                shared = next((s for m in security if (s := self._shared_source(routine, m))), None)
                if shared and start - self.skew <= routine.start <= end + self.lookback:
                    return f"configuration changed from {shared}, the address in this incident"
                return None
            if routine.host in hosts and start - self.lookback <= routine.start <= end + self.skew:
                return f"configuration of {routine.host} changed shortly before or during"
            return None

        if any(self.is_security(m) for m in members):
            return None
        if max(timedelta(0), start - routine.end, routine.start - end) > self.reach:
            return None
        interface = _interface(routine)
        for member in members:
            if routine.host in _hosts(member):
                # On the same device it must be the interface the problem is about, unless
                # the problem concerns the whole device (a reload, a starved CPU).
                device_wide = not _interface(member) and not member.group.get("neighbor_ip")
                if device_wide or (interface and interface == _interface(member)):
                    return f"same device and interface as a finding on {routine.host}"
            peer = self.topology.peer(routine.host, interface)
            if peer and peer[0] in _hosts(member):
                return f"{interface} on {routine.host} is connected to {peer[1]} on {peer[0]}"
            # An interface failing on the very device that others lost as a neighbor.
            neighbor = member.group.get("neighbor_ip")
            if neighbor and self.topology.owner(neighbor) == routine.host:
                return f"{routine.host} is the neighbor {neighbor} that {member.host} lost"
        return None

    # --- Building incidents ---------------------------------------------------------

    def severity(self, members: list[Finding], devices: set[str]) -> tuple[str, str]:
        worst = max(members, key=lambda f: (LEVELS.index(f.severity), -f.start.timestamp()))
        level = worst.severity
        reason = f"{level.capitalize()}: the most serious finding is \"{worst.title}\""
        if len(devices) >= self.many_devices and level != LEVELS[-1]:
            level = LEVELS[LEVELS.index(level) + 1]
            reason = (
                f"{level.capitalize()}: raised from {worst.severity} because "
                f"{len(devices)} devices are affected; the most serious finding is "
                f"\"{worst.title}\""
            )
        return level, reason + "."


def _incident_id(members: list[Finding]) -> str:
    """The same findings always give the same id, whatever order they were found in."""
    parts = sorted(
        json.dumps([f.rule, f.group, f.start.isoformat()], sort_keys=True) for f in members
    )
    return "inc-" + hashlib.sha1("\n".join(parts).encode()).hexdigest()[:10]


def _title(members: list[Finding], devices: set[str]) -> str:
    lead = max(members, key=lambda f: (LEVELS.index(f.severity), -f.start.timestamp()))
    if len(members) == 1:
        return lead.title
    others = len(members) - 1
    where = ", ".join(sorted(devices))
    return f"{lead.title}, with {others} related finding{'s' if others != 1 else ''} on {where}"


def correlate(
    db: Database,
    upload_id: int,
    config: dict | None = None,
    hints: Topology | None = None,
    priors: list[Prior] | None = None,
) -> list[Incident]:
    """Group an upload's findings into incidents, work out cause and effect inside each,
    store them and return them.

    `hints` is the user's topology file, if they gave one. Running it again replaces the
    previous incidents.
    """
    settings = (config if config is not None else load_config())["correlation"]
    topology = build_topology(db, upload_id, settings, hints)
    correlator = _Correlator(settings, topology)

    findings = db.findings(upload_id)
    problems = [f for f in findings if f.severity != "info"]
    routine = [f for f in findings if f.severity == "info"]

    incidents: list[Incident] = []
    grouped = []
    for members, links in correlator.group(problems):
        members.sort(key=lambda f: (f.start, f.id))
        start, end = min(f.start for f in members), max(f.end for f in members)
        grouped.append((members, links, start, end))

    # Each routine finding goes to at most one incident: the first it belongs with.
    context: dict[int, list[tuple[Finding, str]]] = {i: [] for i in range(len(grouped))}
    for finding in routine:
        for index, (members, _, start, end) in enumerate(grouped):
            if reason := correlator.context_reason(finding, members, start, end):
                context[index].append((finding, reason))
                break

    for index, (members, links, start, end) in enumerate(grouped):
        affected = set().union(*(_hosts(f) for f in members))
        attached = context[index]
        devices = affected | set().union(
            *(_hosts(f) for f, _ in attached if f.rule != _CONFIG_CHANGE)
        )
        level, reason = correlator.severity(members, affected)
        neighbors = sorted(
            {n for f in members if (n := f.group.get("neighbor_ip")) and not topology.owner(n)}
        )
        notes = []
        if neighbors:
            notes.append(
                "Neighbor addresses not matched to a device in these logs: "
                + ", ".join(neighbors)
                + ". List them in a topology file to say which device each one is."
            )
        incidents.append(
            Incident(
                id=_incident_id(members),
                title=_title(members, affected),
                severity=level,
                severity_reason=reason,
                start=start,
                end=end,
                devices=sorted(devices),
                finding_ids=[f.id for f in members],
                context_ids=[f.id for f, _ in attached],
                links=links + [Link(members[0].id, f.id, why) for f, why in attached],
                notes=notes,
            )
        )

    by_id = {f.id: f for f in findings}
    reach = correlator.reach

    def host_has_logs(host: str, start: datetime, end: datetime) -> bool:
        window = EventFilter(host=host, start=start - reach, end=end + reach)
        return db.count_events(upload_id, window) > 0

    causal_priors = priors if priors is not None else load_priors()
    for incident in incidents:
        explain_causes(incident, by_id, topology, causal_priors, settings, host_has_logs)

    incidents.sort(key=lambda i: (i.start, i.id))
    db.save_incidents(upload_id, incidents)
    return db.incidents(upload_id)
