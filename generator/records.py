"""Log records and how they are turned into the lines of a file."""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta

from generator import topology as topo
from generator.messages import stamp, stamp_ms


def sec(seconds: float) -> timedelta:
    return timedelta(seconds=seconds)


@dataclass
class Rec:
    """One log line before formatting.

    `t` is the true time the event happened. What ends up printed depends on the
    device: its clock may be slightly off, and a syslog collector adds its own time.
    """

    t: datetime
    host: str
    body: str
    incident: str | None = None
    # Noise bookkeeping, so scenarios can remove noise that would contradict them.
    kind: str = ""
    group_t: datetime | None = None
    # Cisco only: the device has just booted and prints this unsynchronized time.
    boot_clock: datetime | None = None
    # Cisco only: the message counter restarts here (the device rebooted).
    reset_seq: bool = False


@dataclass
class Rendered:
    lines: list[str]
    incident_lines: dict[str, list[int]]
    incident_times: dict[str, tuple[datetime, datetime]]


def render(recs: list[Rec], rng: random.Random) -> Rendered:
    """Format records into log lines, ordered as a syslog collector would write them.

    Cisco lines look like:   Mar  3 02:14:07 R1 1042: Mar  3 02:14:07.123: %LINK-3-...
      - the first timestamp is the collector's receive time,
      - 1042 is the device's message counter,
      - the second timestamp is the device's own clock.
    Linux lines look like:   Mar  3 02:20:11 srv1 sshd[2417]: Failed password ...
      - the timestamp is the server's own clock.
    """
    hosts = topo.CISCO_HOSTS + topo.LINUX_HOSTS
    # Every device's clock is off by a fixed amount of up to 2 seconds.
    skew = {h: sec(rng.uniform(-2.0, 2.0)) for h in hosts}
    # Network delay to the collector, fixed per device so one device's lines keep their order.
    delay = {h: sec(rng.uniform(0.005, 0.3)) for h in topo.CISCO_HOSTS}
    seq = {h: rng.randrange(1000, 90000) for h in topo.CISCO_HOSTS}
    # The firewall and the resolver are drawn last, so every file without them stays
    # exactly as it was before they existed. The ASA's lines are written like a Linux
    # host's: the collector's time, the name, the message.
    skew.update({h: sec(rng.uniform(-2.0, 2.0)) for h in topo.EDGE_HOSTS})

    def written_at(rec: Rec) -> datetime:
        if rec.host in delay:
            return rec.t + delay[rec.host]
        return rec.t + skew[rec.host]

    ordered = sorted(enumerate(recs), key=lambda pair: (written_at(pair[1]), pair[0]))

    lines: list[str] = []
    incident_lines: dict[str, list[int]] = {}
    incident_times: dict[str, tuple[datetime, datetime]] = {}

    for _, rec in ordered:
        when = written_at(rec)
        if rec.host in delay:
            if rec.reset_seq:
                seq[rec.host] = 0
            seq[rec.host] += 1
            if rec.boot_clock is not None:
                device_time = "*" + stamp_ms(rec.boot_clock)
            else:
                device_time = stamp_ms(rec.t + skew[rec.host])
            line = f"{stamp(when)} {rec.host} {seq[rec.host]}: {device_time}: {rec.body}"
        else:
            line = f"{stamp(when)} {rec.host} {rec.body}"
        lines.append(line)

        if rec.incident:
            incident_lines.setdefault(rec.incident, []).append(len(lines))
            first, last = incident_times.get(rec.incident, (rec.t, rec.t))
            incident_times[rec.incident] = (min(first, rec.t), max(last, rec.t))

    return Rendered(lines, incident_lines, incident_times)
