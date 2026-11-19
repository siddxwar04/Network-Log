"""Severity: how serious a finding is, and a one-line reason.

Severity is decided here by fixed rules and nowhere else. Each rule in the rule file
names a base level and the conditions that raise it. The language model that writes
explanations later is told the result; it never sets or changes it.
"""

from __future__ import annotations

from netlog.detection.finding import Finding
from netlog.detection.rules import LEVELS, Rule


def _rank(level: str) -> int:
    return LEVELS.index(level)


def score(finding: Finding, rule: Rule, settings: dict) -> None:
    """Set `severity` and `severity_reason` on a finding.

    Three things decide the level:
      1. the rule's base level;
      2. the rule's `severity_when` conditions that hold, the most serious one winning;
      3. whether the device or interface is listed as critical in the settings, which
         raises the result by one level.
    """
    level = rule.severity
    because = rule.severity_because or f"the default for {rule.incident_type.replace('_', ' ')}"
    reasons = [because]

    raised = None
    for escalation in rule.severity_when:
        holds = (
            escalation.flag in finding.flags
            if escalation.flag is not None
            else finding.strength >= escalation.strength_at_least
        )
        if holds and _rank(escalation.level) > _rank(raised.level if raised else level):
            raised = escalation
    if raised:
        reasons.append(f"raised from {level} because {raised.because}")
        level = raised.level

    critical = settings.get("severity", {})
    interface = finding.group.get("interface")
    listed = None
    if finding.host and finding.host in critical.get("critical_devices", []):
        listed = f"{finding.host} is listed as a critical device"
    elif interface and any(
        entry.get("host") == finding.host and entry.get("interface") == interface
        for entry in critical.get("critical_interfaces", [])
    ):
        listed = f"{interface} on {finding.host} is listed as a critical interface"
    if listed and level != LEVELS[-1]:
        level = LEVELS[_rank(level) + 1]
        reasons.append(f"raised one level because {listed}")
    elif interface and not listed and not critical.get("critical_interfaces"):
        # With no topology knowledge the tool cannot tell an uplink from a desk port.
        reasons.append("no critical interfaces are configured, so its importance is not known")

    finding.severity = level
    finding.severity_reason = f"{level.capitalize()}: {'; '.join(reasons)}."
