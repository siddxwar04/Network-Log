"""Dedup: repeats of one template on one device are shown as a single run with a count.

    "DHCPDISCOVER ... no free leases" x153 on dhcp1, 03:14:38 to 03:34:21

A run is a view over the stored events, not a replacement: every event stays in the
database. A run continues while each repeat comes within the allowed gap of the one
before, and ends when the gap is exceeded. Other messages in between do not end it, so
an interface going down and up twelve times shows as "down x12" and "up x12", not as
twenty-four separate runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from netlog.config import load_config
from netlog.storage.database import Database


@dataclass(frozen=True)
class Run:
    template_id: str
    host: str | None
    count: int
    first_seen: datetime
    last_seen: datetime
    first_event_id: int
    last_event_id: int


def find_runs(db: Database, upload_id: int, max_gap_seconds: float | None = None) -> list[Run]:
    """Every run in an upload, in the order they started."""
    if max_gap_seconds is None:
        max_gap_seconds = load_config()["dedup"]["max_gap_seconds"]
    max_gap = timedelta(seconds=max_gap_seconds)

    runs: list[Run] = []
    current: list | None = None  # [template_id, host, count, first, last, first_id, last_id]
    for host, template_id, moment, event_id in db.iter_template_sequence(upload_id):
        same_run = (
            current is not None
            and current[0] == template_id
            and current[1] == host
            and moment - current[4] <= max_gap
        )
        if same_run:
            current[2] += 1
            current[4], current[6] = moment, event_id
        else:
            if current is not None:
                runs.append(Run(*current))
            current = [template_id, host, 1, moment, moment, event_id, event_id]
    if current is not None:
        runs.append(Run(*current))

    runs.sort(key=lambda run: (run.first_seen, run.first_event_id))
    return runs
