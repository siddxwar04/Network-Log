"""A finding: one rule noticing one problem."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class Finding:
    rule: str
    incident_type: str
    title: str
    # The device, when the finding concerns exactly one. A brute force against several
    # servers has none; the devices are then listed in `metrics["hosts"]`.
    host: str | None
    # The values the events were grouped by, for example {"host": "R1", "interface": "..."}.
    group: dict[str, str | int]
    # Time of the first and last event that is evidence.
    start: datetime
    end: datetime
    # The numbers that triggered the rule: count, peak_count, threshold and so on.
    metrics: dict[str, float | int | str | list[str]]
    # Extra facts the rule established, such as "succeeded" or "password_spraying".
    flags: list[str]
    # Ids of every event that is evidence, in time order.
    evidence: list[int]
    # From 0 to 1: how far past the threshold the finding went.
    strength: float
    id: int | None = None
    upload_id: int | None = None
    # Filled in by severity scoring.
    severity: str | None = None
    severity_reason: str | None = None

    @property
    def duration_seconds(self) -> float:
        return (self.end - self.start).total_seconds()


def format_duration(seconds: float) -> str:
    """`272` -> `4m 32s`."""
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {seconds}s" if seconds else f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m" if minutes else f"{hours}h"
