"""An incident: related findings grouped into one story."""

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

    @property
    def duration_seconds(self) -> float:
        return (self.end - self.start).total_seconds()
