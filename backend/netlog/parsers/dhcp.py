"""DHCP server logs in ISC dhcpd style.

A normal handout is four messages: the client asks who is out there (DISCOVER), the
server offers an address (OFFER), the client asks for it (REQUEST), and the server
confirms (ACK). When the pool is empty the server logs "no free leases" instead of
making an offer.

In these events `mac` is the client, and `dst_ip` is the address being handed out.
The hostname a client reports is chosen by the client, so it is never trusted and the
patterns read the interface from the end of the line.
"""

from __future__ import annotations

from netlog.parsers.patterns import PatternSet, clean, is_ip
from netlog.schema import Event, ParseStatus, SourceType

PROGRAMS = ("dhcpd",)

_DHCPD = PatternSet()

_CLIENT = r"(?P<mac>\S+)(?: \((?P<hostname>.*)\))?"
_VIA = r" via (?P<via>\S+?)"
_TAIL = r"(?:: (?P<tail>.*))?$"


def _fields(match, **extra) -> dict:
    groups = match.groupdict()
    via = groups.get("via")
    interface = via
    if via and is_ip(via):  # the request came through a relay agent, not a local interface
        extra["relay"], interface = via, None
    extra["hostname"] = groups.get("hostname")
    return {
        "protocol": "dhcp",
        "mac": groups.get("mac"),
        "dst_ip": groups.get("ip"),
        "interface": interface,
        "reason": groups.get("tail") or None,
        "extra": clean(extra),
    }


@_DHCPD.rule("dhcp.discover", r"^DHCPDISCOVER from " + _CLIENT + _VIA + _TAIL)
def _discover(m):
    tail = m["tail"] or ""
    if "no free leases" in tail:
        network = tail.split("network ", 1)[1].split(":", 1)[0] if "network " in tail else None
        return {**_fields(m, network=network), "event_key": "dhcp.no_free_leases"}
    return _fields(m)


@_DHCPD.rule("dhcp.offer", r"^DHCPOFFER on (?P<ip>\S+) to " + _CLIENT + _VIA + r"$")
def _offer(m):
    return _fields(m)


@_DHCPD.rule(
    "dhcp.request",
    r"^DHCPREQUEST for (?P<ip>\S+)(?: \((?P<server>\S+)\))? from " + _CLIENT + _VIA + _TAIL,
)
def _request(m):
    return _fields(m, server_id=m["server"])


@_DHCPD.rule("dhcp.ack", r"^DHCPACK on (?P<ip>\S+) to " + _CLIENT + _VIA + r"$")
def _ack(m):
    return _fields(m)


@_DHCPD.rule("dhcp.nak", r"^DHCPNAK on (?P<ip>\S+) to " + _CLIENT + _VIA + r"$")
def _nak(m):
    return _fields(m)


@_DHCPD.rule(
    "dhcp.release",
    r"^DHCPRELEASE of (?P<ip>\S+) from " + _CLIENT + _VIA + r"(?: \((?P<found>[\w ]+)\))?$",
)
def _release(m):
    return _fields(m, lease=m["found"])


@_DHCPD.rule("dhcp.decline", r"^DHCPDECLINE of (?P<ip>\S+) from " + _CLIENT + _VIA + _TAIL)
def _decline(m):
    return _fields(m)


def apply(event: Event) -> Event:
    """Recognize a line from dhcpd. Other events are returned untouched."""
    if event.parse_status is ParseStatus.UNPARSED or (event.app or "").lower() not in PROGRAMS:
        return event
    event.source_type = SourceType.DHCP
    _DHCPD.apply(event)
    return event
