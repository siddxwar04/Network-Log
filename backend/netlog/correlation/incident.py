"""An incident: related findings grouped into one story, with its likely cause."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Link:
    """Why two findings were put in the same incident."""

    a: int  # finding id
    b: int  # finding id
    reason: str


@dataclass
class CausalStep:
    """One step of cause and effect inside an incident."""

    cause: int  # finding id
    effect: int  # finding id
    prior: str  # the name of the causal prior that applies
    certainty: str  # direct, plausible or suspect
    explanation: str
    # How long after the cause the effect started. Slightly negative when the two devices'
    # clocks disagree.
    delay_seconds: float


@dataclass
class RootCause:
    # What kind of thing started it: a rule name, or "link_failure" when both ends of a
    # link report it, or "neighbor_unreachable" when a device went silent.
    kind: str
    summary: str
    devices: list[str]
    # The interface, address, user or network at the root, when there is one.
    entity: str | None
    # The findings that are the root. Empty when the cause is not itself in the logs.
    finding_ids: list[int]
    # How many of the incident's findings this cause accounts for.
    explains: int


@dataclass
class Incident:
    # Derived from the findings inside, so the same log always gives the same id.
    id: str
    title: str
    severity: str
    severity_reason: str
    # First and last moment of the findings that make up the incident.
    start: datetime
    end: datetime
    devices: list[str]
    # The findings that are the problem.
    finding_ids: list[int]
    # Routine findings attached for context: a config change shortly before, or an
    # interface that went down. Not problems in themselves, but possible causes.
    context_ids: list[int] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    # What could not be established, such as an address that matches no known device.
    notes: list[str] = field(default_factory=list)
    upload_id: int | None = None

    # Cause and effect, filled in after grouping.
    chain: list[CausalStep] = field(default_factory=list)
    root_cause: RootCause | None = None
    # Other possible root causes, most likely first.
    alternatives: list[RootCause] = field(default_factory=list)
    confidence: str = "low"  # high, medium or low
    confidence_reason: str = ""
    # What these logs cannot tell.
    unknowns: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return (self.end - self.start).total_seconds()
