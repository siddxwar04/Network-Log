"""What is known about the network: which address belongs to which device, and which
interfaces are connected to each other.

The logs never say this outright. A router reports "lost neighbor 10.255.0.1" without
saying who 10.255.0.1 is. There are two sources of knowledge:

  1. A topology file the user writes, which is trusted.
  2. Inference from the logs: when two routers form or lose an adjacency, both of them
     log it at the same moment, so the device that always logs something of its own
     whenever others report an address is that address's owner.

Where neither settles it, the address stays unknown. Nothing is guessed.
"""

from __future__ import annotations

import tomllib
from bisect import bisect_left
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from netlog.schema import normalize_interface
from netlog.storage.database import Database, EventFilter

# Messages that report an adjacency with a neighbor forming or being lost.
ADJACENCY_EVENT_KEYS = ("BGP-5-ADJCHANGE", "OSPF-5-ADJCHG")

Endpoint = tuple[str, str]  # (device, interface)


class TopologyError(ValueError):
    """A topology file has a mistake."""


@dataclass
class Topology:
    # address -> device
    owners: dict[str, str] = field(default_factory=dict)
    # (device, interface) -> (device, interface) at the other end, in both directions
    links: dict[Endpoint, Endpoint] = field(default_factory=dict)
    # Addresses whose owner was worked out from the logs, not stated by the user.
    inferred: set[str] = field(default_factory=set)

    def owner(self, address: str | None) -> str | None:
        return self.owners.get(address) if address else None

    def peer(self, host: str | None, interface: str | None) -> Endpoint | None:
        """The other end of the link an interface belongs to, if known."""
        if not host or not interface:
            return None
        return self.links.get((host, interface))

    def add_link(self, a: Endpoint, b: Endpoint) -> None:
        self.links[a] = b
        self.links[b] = a


def load_topology(path: str | Path) -> Topology:
    """Read a topology file.

        [[device]]
        name = "R1"
        addresses = ["10.255.0.1", "10.0.0.1"]

        [[link]]
        a = { host = "R3", interface = "GigabitEthernet0/3" }
        b = { host = "SW1", interface = "GigabitEthernet0/1" }

    Both sections are optional; write only what you know.
    """
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError:
        raise TopologyError(f"topology file not found: {path}") from None
    except tomllib.TOMLDecodeError as error:
        raise TopologyError(f"topology file {path} is not valid TOML: {error}") from None

    topology = Topology()
    for number, device in enumerate(data.get("device", []), 1):
        name = device.get("name") if isinstance(device, dict) else None
        if not isinstance(name, str) or not name:
            raise TopologyError(f"topology file {path}: device {number} has no name")
        addresses = device.get("addresses", [])
        if not isinstance(addresses, list) or not all(isinstance(a, str) for a in addresses):
            raise TopologyError(f"topology file {path}: addresses of {name} must be a list")
        for address in addresses:
            if topology.owners.get(address, name) != name:
                other = topology.owners[address]
                raise TopologyError(
                    f"topology file {path}: {address} is listed for both {other} and {name}"
                )
            topology.owners[address] = name

    for number, link in enumerate(data.get("link", []), 1):
        ends = []
        for side in ("a", "b"):
            end = link.get(side) if isinstance(link, dict) else None
            if not isinstance(end, dict) or not end.get("host") or not end.get("interface"):
                raise TopologyError(
                    f"topology file {path}: link {number} needs {side} = "
                    '{ host = "...", interface = "..." }'
                )
            ends.append((end["host"], normalize_interface(end["interface"])))
        topology.add_link(ends[0], ends[1])
    return topology


def _has_event_near(times: list[datetime], moment: datetime, tolerance: timedelta) -> bool:
    position = bisect_left(times, moment - tolerance)
    return position < len(times) and times[position] <= moment + tolerance


def infer_owners(
    db: Database, upload_id: int, tolerance_seconds: float, min_support: float
) -> dict[str, str]:
    """Work out which device owns which neighbor address, from adjacency messages alone.

    When an adjacency between A and B forms, A logs "neighbor <B's address> up" and B
    logs "neighbor <A's address> up" at the same moment. So for an address X that other
    devices report, its owner is a device that:
      - never reports X as a neighbor itself (a device is not its own neighbor), and
      - has an adjacency message of its own, in the same protocol, beside at least
        `min_support` of the messages about X, and at least two of them.
    If exactly one device fits, it is the owner. If none or several fit, X is left
    unknown.
    """
    tolerance = timedelta(seconds=tolerance_seconds)
    about: dict[str, list[tuple[str, str, datetime]]] = defaultdict(list)
    by_host: dict[tuple[str, str], list[datetime]] = defaultdict(list)
    reporters: dict[str, set[str]] = defaultdict(set)

    events = db.iter_events(upload_id, EventFilter(event_keys=ADJACENCY_EVENT_KEYS))
    for event in events:
        address = event.entities.neighbor_ip
        if not address or not event.host or event.timestamp is None:
            continue
        protocol = event.entities.protocol or event.event_key
        about[address].append((event.host, protocol, event.timestamp))
        by_host[(event.host, protocol)].append(event.timestamp)
        reporters[address].add(event.host)
    hosts = {host for host, _ in by_host}

    owners: dict[str, str] = {}
    for address, mentions in about.items():
        fitting = []
        for candidate in sorted(hosts - reporters[address]):
            beside = sum(
                _has_event_near(by_host.get((candidate, protocol), []), moment, tolerance)
                for _, protocol, moment in mentions
            )
            if beside >= 2 and beside / len(mentions) >= min_support:
                fitting.append(candidate)
        if len(fitting) == 1:
            owners[address] = fitting[0]
    return owners


def build_topology(
    db: Database, upload_id: int, settings: dict, hints: Topology | None = None
) -> Topology:
    """The user's topology file, completed with what the logs themselves reveal.

    What the user states always wins over what is inferred.
    """
    topology = Topology(
        owners=dict(hints.owners) if hints else {},
        links=dict(hints.links) if hints else {},
    )
    inferred = infer_owners(
        db, upload_id, settings["clock_skew_seconds"], settings["owner_min_support"]
    )
    for address, host in inferred.items():
        if address not in topology.owners:
            topology.owners[address] = host
            topology.inferred.add(address)
    return topology
