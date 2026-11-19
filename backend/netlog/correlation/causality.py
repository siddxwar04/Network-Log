"""Cause and effect inside an incident: which finding started it, and what followed.

Grouping says "these findings belong together". This step puts them in order using the
causal priors in `config/causal_priors.toml`, names the most likely root cause, says how
confident that is, and lists what the logs cannot tell.

Nothing here is a guess dressed up as a fact. A step is only drawn where a prior applies
and the timing fits. Confidence follows fixed criteria (see `_confidence`). Where the
logs cannot decide, the incident says so in `unknowns`.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta

from netlog.correlation.incident import CausalStep, Incident, RootCause
from netlog.correlation.priors import CERTAINTIES, Prior
from netlog.correlation.topology import Topology
from netlog.detection.finding import Finding, format_duration

_INTERFACE_RULES = ("interface_down", "link_flap")
_CONFIG_CHANGE = "config_change"

# Which value names the thing at the root, by rule. Anything else is named by its device.
_ENTITY_FIELDS = {
    "interface_down": "interface",
    "link_flap": "interface",
    "brute_force_login": "src_ip",
    "dhcp_exhaustion": "extra.network",
    "config_change": "username",
    "bgp_session_down": "neighbor_ip",
    "ospf_adjacency_loss": "neighbor_ip",
}

HostHasLogs = Callable[[str, datetime, datetime], bool]


def _hosts(finding: Finding) -> set[str]:
    if finding.host:
        return {finding.host}
    hosts = finding.metrics.get("hosts")
    return set(hosts) if isinstance(hosts, list) else set()


def _interface(finding: Finding) -> str | None:
    return finding.group.get("interface") or finding.metrics.get("interface")


class _Analysis:
    def __init__(
        self,
        incident: Incident,
        findings: dict[int, Finding],
        topology: Topology,
        priors: list[Prior],
        settings: dict,
        host_has_logs: HostHasLogs,
    ) -> None:
        self.incident = incident
        self.topology = topology
        self.priors = priors
        self.skew = timedelta(seconds=settings["clock_skew_seconds"])
        self.host_has_logs = host_has_logs
        self.members = [findings[i] for i in incident.finding_ids]
        self.context = [findings[i] for i in incident.context_ids]
        self.nodes = {f.id: f for f in self.members + self.context}
        self.member_ids = set(incident.finding_ids)
        # effect id -> (cause finding, prior, delay)
        self.cause_of: dict[int, tuple[Finding, Prior, float]] = {}

    # --- Does a prior apply between two findings? -----------------------------------

    def related(self, prior: Prior, cause: Finding, effect: Finding) -> bool:
        if prior.relation == "same_host":
            return bool(_hosts(cause) & _hosts(effect))
        if prior.relation == "same_interface":
            interface = _interface(cause)
            return bool(
                interface and interface == _interface(effect) and cause.host == effect.host
            )
        if prior.relation == "neighbor_is_cause":
            owner = self.topology.owner(effect.group.get("neighbor_ip"))
            return bool(owner and owner in _hosts(cause) and owner not in _hosts(effect))
        if prior.relation == "link_peer":
            peer = self.topology.peer(effect.host, _interface(effect))
            if not peer or peer[0] not in _hosts(cause):
                return False
            cause_interface = _interface(cause)
            return cause_interface is None or cause_interface == peer[1]
        return False

    def in_time(self, prior: Prior, cause: Finding, effect: Finding) -> bool:
        """The effect must start after the cause, within the prior's limit. Device clocks
        disagree by a few seconds, so an effect logged slightly before its cause is still
        accepted."""
        earliest = cause.start - self.skew - timedelta(seconds=prior.effect_before_seconds)
        measured_from = cause.end if prior.during else cause.start
        latest = measured_from + timedelta(seconds=prior.max_delay_seconds) + self.skew
        return earliest <= effect.start <= latest

    def is_ancestor(self, candidate: Finding, of: Finding) -> bool:
        """Whether `candidate` is already downstream of `of`, which would make a loop."""
        current = candidate
        while current.id in self.cause_of:
            current = self.cause_of[current.id][0]
            if current.id == of.id:
                return True
        return False

    def find_causes(self) -> None:
        """Give each finding its single best cause, where one applies."""
        linked = self.link_groups()
        for effect in sorted(self.nodes.values(), key=lambda f: (f.start, f.id)):
            if effect.rule == _CONFIG_CHANGE:
                continue  # a change is something people do; nothing in the logs causes it
            best = None
            for cause in self.nodes.values():
                if cause.id == effect.id or linked.get(cause.id, cause.id) == linked.get(effect.id):
                    continue
                for prior in self.priors:
                    if cause.rule not in prior.cause or effect.rule not in prior.effect:
                        continue
                    if not self.related(prior, cause, effect) or not self.in_time(
                        prior, cause, effect
                    ):
                        continue
                    if self.is_ancestor(cause, effect):
                        continue
                    rank = (
                        -CERTAINTIES.index(prior.certainty),
                        prior.priority,
                        # Between equals, the cause about the same neighbor, then the
                        # most recent one.
                        cause.group.get("neighbor_ip") == effect.group.get("neighbor_ip"),
                        cause.start,
                        -cause.id,
                    )
                    if best is None or rank > best[0]:
                        best = (rank, cause, prior)
            if best:
                _, cause, prior = best
                delay = (effect.start - cause.start).total_seconds()
                self.cause_of[effect.id] = (cause, prior, delay)

    def link_groups(self) -> dict[int, int]:
        """Findings that are the two ends of one link going down together.

        Neither end caused the other, so they are treated as one root. Returns a map from
        finding id to the id that stands for its group.
        """
        groups: dict[int, int] = {}
        candidates = [f for f in self.nodes.values() if f.rule in _INTERFACE_RULES]
        for a in candidates:
            peer = self.topology.peer(a.host, _interface(a))
            for b in candidates:
                if a.id < b.id and peer == (b.host, _interface(b)):
                    if abs(a.start - b.start) <= self.skew * 2:
                        group = groups.get(a.id, a.id)
                        groups[a.id] = groups[b.id] = group
        return groups

    # --- Roots ----------------------------------------------------------------------

    def descendants(self, root_ids: set[int]) -> set[int]:
        """Member findings that a set of root findings accounts for, themselves included."""
        return self.reached(root_ids) & self.member_ids

    def reached(self, root_ids: set[int]) -> set[int]:
        """Every finding downstream of a set of root findings, themselves included.

        This includes routine findings attached as context, such as a neighbor's
        interface that went down: they are not problems to be explained, but they are
        another device reporting the same event.
        """
        reached = set(root_ids)
        changed = True
        while changed:
            changed = False
            for effect_id, (cause, _, _) in self.cause_of.items():
                if cause.id in reached and effect_id not in reached:
                    reached.add(effect_id)
                    changed = True
        return reached

    def root_causes(self) -> list[RootCause]:
        linked = self.link_groups()
        has_effects = {cause.id for cause, _, _ in self.cause_of.values()}
        top = [
            f
            for f in self.nodes.values()
            if f.id not in self.cause_of and (f.id in self.member_ids or f.id in has_effects)
        ]

        roots: list[RootCause] = []
        handled: set[int] = set()

        # Both ends of one link.
        for finding in top:
            group = linked.get(finding.id)
            if group is None or finding.id in handled:
                continue
            ends = sorted(
                (f for f in top if linked.get(f.id) == group), key=lambda f: (f.host, f.id)
            )
            if len(ends) < 2:
                continue
            handled |= {f.id for f in ends}
            where = " and ".join(f"{_interface(f)} on {f.host}" for f in ends)
            roots.append(
                RootCause(
                    kind="link_failure",
                    summary=f"The link between {where} went down",
                    devices=sorted({f.host for f in ends}),
                    entity=f"link between {where}",
                    finding_ids=[f.id for f in ends],
                    explains=len(self.descendants({f.id for f in ends})),
                )
            )

        # Several devices losing the same neighbor, with nothing in the logs to explain it:
        # the neighbor itself went away, and it is not among the findings.
        by_neighbor: dict[str, list[Finding]] = {}
        for finding in top:
            neighbor = finding.group.get("neighbor_ip")
            if neighbor and finding.id in self.member_ids and finding.id not in handled:
                by_neighbor.setdefault(neighbor, []).append(finding)
        for neighbor, losers in sorted(by_neighbor.items()):
            devices = sorted({f.host for f in losers if f.host})
            if len(devices) < 2:
                continue
            handled |= {f.id for f in losers}
            owner = self.topology.owner(neighbor)
            who = f"{owner} ({neighbor})" if owner else f"The device at {neighbor}"
            roots.append(
                RootCause(
                    kind="neighbor_unreachable",
                    summary=f"{who} became unreachable for {len(devices)} devices",
                    devices=[owner] if owner else [],
                    entity=neighbor,
                    finding_ids=[],
                    explains=len(self.descendants({f.id for f in losers})),
                )
            )

        for finding in top:
            if finding.id in handled:
                continue
            roots.append(
                RootCause(
                    kind=finding.rule,
                    summary=self.summary(finding),
                    devices=sorted(_hosts(finding)),
                    entity=self.entity(finding),
                    finding_ids=[finding.id],
                    explains=len(self.descendants({finding.id})),
                )
            )

        starts = {
            id(r): min((self.nodes[i].start for i in r.finding_ids), default=self.incident.start)
            for r in roots
        }
        roots.sort(key=lambda r: (-r.explains, starts[id(r)], r.summary))
        return roots

    @staticmethod
    def entity(finding: Finding) -> str | None:
        name = _ENTITY_FIELDS.get(finding.rule)
        value = finding.group.get(name) if name else None
        return str(value) if value is not None else finding.host

    @staticmethod
    def summary(finding: Finding) -> str:
        if finding.rule == _CONFIG_CHANGE:
            source = finding.metrics.get("src_ip")
            where = f" from {source}" if source else ""
            return (
                f"The configuration of {finding.host} was changed by "
                f"{finding.group.get('username')}{where} shortly before the failure"
            )
        return finding.title

    # --- Confidence -----------------------------------------------------------------

    def confidence(self, root: RootCause) -> tuple[str, str]:
        """How sure the root cause is, by fixed criteria.

        High    every finding is accounted for by known cause and effect, the timing
                fits, and more than one device reports it.
        Medium  the explanation fits but is not confirmed: it rests on one device, it
                leaves some findings unexplained, the cause is a suspect (a config
                change) or is not itself in the logs, or the timing is within the few
                seconds by which device clocks disagree.
        Low     the findings were grouped, but no known cause and effect links them.
        """
        total = len(self.members)
        if root.kind == _CONFIG_CHANGE:
            return "medium", (
                "the change came shortly before the failure, which makes it the first thing "
                "to check, but the logs do not show what was changed"
            )
        if root.kind == "neighbor_unreachable":
            return "medium", (
                f"{root.explains} findings agree that it became unreachable, but nothing in "
                "these logs shows what happened to it"
            )
        if total == 1 and not self.cause_of:
            return "medium", (
                "it is a single finding on one device; nothing else in these logs confirms "
                "or explains it"
            )
        if not self.cause_of:
            return "low", (
                "the findings happened close together on connected devices, but no known "
                "cause and effect links them"
            )
        if root.explains < total:
            return "medium", (
                f"it accounts for {root.explains} of the {total} findings; the others are "
                "not explained by it"
            )
        devices = set().union(*(_hosts(self.nodes[i]) for i in self.reached(set(root.finding_ids))))
        if len(devices) < 2:
            return "medium", "the whole chain rests on what one device logged"
        # Effects on other devices that come through a protocol timer. A cabled link going
        # down with its peer is physical and immediate, so it is not held to this test.
        elsewhere = [
            delay
            for effect_id, (cause, prior, delay) in self.cause_of.items()
            if cause.id in root.finding_ids
            and prior.relation != "link_peer"
            and not _hosts(cause) & _hosts(self.nodes[effect_id])
        ]
        if elsewhere and all(abs(delay) <= self.skew.total_seconds() for delay in elsewhere):
            return "medium", (
                "the other devices reacted within the few seconds by which device clocks "
                "disagree, so the order of events is not certain"
            )
        return "high", (
            f"every finding is accounted for, the timing matches how the protocols behave, "
            f"and {len(devices)} devices report it"
        )

    # --- What the logs cannot tell ----------------------------------------------------

    def unknowns(self, root: RootCause, alternatives: list[RootCause]) -> list[str]:
        out: list[str] = []
        first = self.nodes[root.finding_ids[0]] if root.finding_ids else None

        if root.kind == "link_failure":
            out.append(
                "Which end failed. Both ends of the link reported it down, so the fault could "
                "be either port, either optic or the cable between them."
            )
        elif root.kind in _INTERFACE_RULES:
            out.append(
                "Why the interface went down. The logs show that it did, not whether a cable, "
                "an optic or the device at the other end was at fault."
            )
        elif root.kind == "neighbor_unreachable":
            owner = root.devices[0] if root.devices else None
            if owner is None:
                out.append(
                    f"Which device {root.entity} is. No device in these logs matches that "
                    "address, so its own account of what happened is missing."
                )
            elif self.host_has_logs(owner, self.incident.start, self.incident.end):
                out.append(
                    f"What happened to {owner}. Other devices lost it, but its own log lines "
                    "from that period show nothing that explains why."
                )
            else:
                out.append(
                    f"What happened to {owner}. Other devices lost it at the same moment and "
                    "there are no log lines from it in that period: it may have failed, lost "
                    "power or been cut off from the log collector."
                )
        elif root.kind == _CONFIG_CHANGE and first is not None:
            effect = min(
                (self.nodes[i] for i, (c, _, _) in self.cause_of.items() if c.id == first.id),
                key=lambda f: f.start,
                default=None,
            )
            gap = (
                f"{format_duration((effect.start - first.start).total_seconds())} before"
                if effect
                else "shortly before"
            )
            out.append(
                f"Whether the change caused the failure. The logs show only that "
                f"{first.group.get('username')} changed the configuration of {first.host} "
                f"{gap}, not what was changed."
            )
        elif root.kind == "device_restart":
            out.append(
                "Why the device restarted. No reload was requested in these logs, so it may "
                "have crashed or lost power."
            )
        elif root.kind == "brute_force_login" and first is not None:
            if "succeeded" in first.flags:
                out.append(
                    "What was done with the account after the login succeeded. That needs "
                    "the server's own command and session logs."
                )

        if alternatives:
            names = "; ".join(a.summary for a in alternatives[:3])
            out.append(f"Whether something else was the cause. Also possible: {names}.")
        return out + list(self.incident.notes)


def explain_causes(
    incident: Incident,
    findings: dict[int, Finding],
    topology: Topology,
    priors: list[Prior],
    settings: dict,
    host_has_logs: HostHasLogs,
) -> None:
    """Fill in an incident's chain, root cause, confidence and unknowns."""
    analysis = _Analysis(incident, findings, topology, priors, settings, host_has_logs)
    analysis.find_causes()

    incident.chain = [
        CausalStep(
            cause=cause.id,
            effect=effect_id,
            prior=prior.name,
            certainty=prior.certainty,
            explanation=prior.explanation,
            delay_seconds=round(delay, 3),
        )
        for effect_id, (cause, prior, delay) in sorted(
            analysis.cause_of.items(), key=lambda item: (analysis.nodes[item[0]].start, item[0])
        )
    ]
    roots = analysis.root_causes()
    incident.root_cause = roots[0] if roots else None
    incident.alternatives = roots[1:]
    if incident.root_cause:
        incident.confidence, incident.confidence_reason = analysis.confidence(incident.root_cause)
        incident.unknowns = analysis.unknowns(incident.root_cause, incident.alternatives)
