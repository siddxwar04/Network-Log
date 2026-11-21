"""Firewall logs: Cisco ASA messages and Linux iptables (and UFW) packet logs.

Every firewall event says what the firewall did with a connection or a packet, in
`extra.action`:

  deny      refused or dropped
  allow     let through (an ASA "Built" connection, an iptables ACCEPT rule)
  teardown  a connection that had been let through has ended
  log       logged by an iptables rule whose prefix does not say what it did

and, where the message gives them, `protocol` (tcp, udp, icmp ...), `src_ip` and
`extra.src_port` for who started it, `dst_ip` and `port` for where it was going, and
`interface` for where it arrived (an ASA interface name such as `outside`, or a Linux
one such as `eth0`).

Cisco ASA: the Cisco parser has already read `%ASA-4-106023: text` and set the event key
to `ASA-4-106023`. This parser recognizes the message by its number and changes the key
to `ASA-106023`, without the severity: an ASA administrator can change the level of any
message, and a rule should not stop matching when they do. The level is still in
`severity`.

iptables: the kernel logs a packet as `PREFIX IN=eth0 OUT= ... SRC=... DST=...`. The
prefix is whatever the rule's author chose, so the action is read from words in it
(BLOCK, DROP, DENY, REJECT; ACCEPT, ALLOW). UFW writes `[UFW BLOCK]` and `[UFW ALLOW]`.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from pydantic import ValidationError

from netlog.parsers.patterns import Span, clean, free_text_spans, is_ip
from netlog.schema import Entities, Event, ParseStatus, SourceType

# --- Cisco ASA ------------------------------------------------------------------------------

_ASA_KEY = re.compile(r"^(?:ASA|FTD)-[0-7]-(?P<id>\d{6})$")

# `outside:203.0.113.5/40000`, with the optional identity or FQDN that follows in brackets.
_END = (
    r"(?P<{n}_if>[^\s:]+):(?P<{n}_ip>[0-9A-Fa-f.:]+)(?:/(?P<{n}_port>\d+))?"
    r"(?: ?\((?!type \d)[^)]*\))?"
)
_SRC = _END.format(n="src")
_DST = _END.format(n="dst")
_ADDR_PORT = r"(?P<{n}_ip>[0-9A-Fa-f.:]+)/(?P<{n}_port>\d+)"

AsaBuilder = Callable[[re.Match[str]], dict]
_ASA: dict[str, list[tuple[re.Pattern[str], AsaBuilder]]] = {}


def _asa(message_id: str, pattern: str):
    """Register how to read one ASA message. Several patterns may share an id."""
    compiled = re.compile(pattern)

    def register(build: AsaBuilder) -> AsaBuilder:
        _ASA.setdefault(message_id, []).append((compiled, build))
        return build

    return register


def _ends(m: re.Match[str], action: str, **extra) -> dict:
    """The usual fields: source and destination with their ports, and the interface."""
    groups = m.groupdict()
    dst_port = groups.get("dst_port")
    return {
        "protocol": (groups.get("proto") or "").lower() or None,
        "src_ip": groups.get("src_ip"),
        "dst_ip": groups.get("dst_ip"),
        "port": int(dst_port) if dst_port else None,
        "interface": groups.get("src_if") or groups.get("iface"),
        "extra": clean(
            {
                "action": action,
                "src_port": groups.get("src_port"),
                "dst_interface": groups.get("dst_if"),
                **extra,
            }
        ),
    }


@_asa(
    "106001",
    r"^Inbound (?P<proto>\w+) connection denied from "
    + _ADDR_PORT.format(n="src")
    + r" to "
    + _ADDR_PORT.format(n="dst")
    + r" flags (?P<flags>.*?) on interface (?P<iface>\S+)",
)
def _asa_106001(m):
    return _ends(m, "deny", flags=m["flags"])


@_asa(
    "106006",
    r"^Deny inbound (?P<proto>\w+) from "
    + _ADDR_PORT.format(n="src")
    + r" to "
    + _ADDR_PORT.format(n="dst")
    + r" on interface (?P<iface>[^\s.]+)",
)
def _asa_106006(m):
    return _ends(m, "deny")


@_asa(
    "106007",
    r"^Deny inbound (?P<proto>\w+) from "
    + _ADDR_PORT.format(n="src")
    + r" to "
    + _ADDR_PORT.format(n="dst")
    + r" due to (?P<reason>.+?)\.?$",
)
def _asa_106007(m):
    return {**_ends(m, "deny"), "reason": m["reason"]}


@_asa("106010", r"^Deny inbound (?P<proto>\w+) src " + _SRC + r" dst " + _DST)
def _asa_106010(m):
    return _ends(m, "deny")


@_asa(
    "106014",
    r"^Deny inbound (?P<proto>icmp) src "
    + _SRC
    + r" ?dst "
    + _DST
    + r"(?: \(type (?P<type>\d+), code (?P<code>\d+)\))?",
)
def _asa_106014(m):
    return _ends(m, "deny", icmp_type=m["type"], icmp_code=m["code"])


@_asa(
    "106015",
    r"^Deny (?P<proto>\w+) \(no connection\) from "
    + _ADDR_PORT.format(n="src")
    + r" to "
    + _ADDR_PORT.format(n="dst")
    + r" flags (?P<flags>.*?) on interface (?P<iface>\S+)",
)
def _asa_106015(m):
    return _ends(m, "deny", flags=m["flags"], reason="no connection")


@_asa(
    "106021",
    r"^Deny (?P<proto>\w+) reverse path check from (?P<src_ip>[0-9A-Fa-f.:]+) to "
    r"(?P<dst_ip>[0-9A-Fa-f.:]+) on interface (?P<iface>\S+)",
)
def _asa_106021(m):
    return {**_ends(m, "deny"), "reason": "reverse path check"}


@_asa(
    "106023",
    r"^Deny (?P<proto>\w+) src "
    + _SRC
    + r" dst "
    + _DST
    + r"(?: \(type (?P<type>\d+), code (?P<code>\d+)\))?"
    r".*? by access-group \"(?P<acl>[^\"]*)\"",
)
def _asa_106023(m):
    return _ends(m, "deny", acl=m["acl"], icmp_type=m["type"], icmp_code=m["code"])


@_asa(
    "106100",
    r"^access-list (?P<acl>\S+) (?P<verdict>permitted|denied|est-allowed) (?P<proto>\w+) "
    r"(?P<src_if>[^\s/]+)/(?P<src_ip>[0-9A-Fa-f.:]+)\((?P<src_port>\d+)\)(?: \([^)]*\))? "
    r"(?:-> )?(?P<dst_if>[^\s/]+)/(?P<dst_ip>[0-9A-Fa-f.:]+)\((?P<dst_port>\d+)\)",
)
def _asa_106100(m):
    return _ends(m, "deny" if m["verdict"] == "denied" else "allow", acl=m["acl"])


def _built(m: re.Match[str]) -> dict:
    """`Built inbound`: the first address started the connection. `Built outbound`: the
    second one did (an inside machine connecting out), so the two are swapped."""
    fields = _ends(m, "allow", connection=m["conn"], direction=m["direction"])
    if m["direction"] == "outbound":
        extra = fields["extra"]
        fields.update(
            src_ip=m["dst_ip"],
            dst_ip=m["src_ip"],
            port=int(m["src_port"]) if m["src_port"] else None,
            interface=m["dst_if"],
        )
        extra.update(clean({"src_port": m["dst_port"], "dst_interface": m["src_if"]}))
    return fields


for _id in ("302013", "302015"):
    _asa(
        _id,
        r"^Built (?P<direction>inbound|outbound) (?P<proto>\w+) connection (?P<conn>\d+) for "
        + _SRC
        + r"(?: \([^)]*\))? to "
        + _DST,
    )(_built)


def _teardown(m: re.Match[str]) -> dict:
    """The two ends are kept in the order the message prints them: it does not say which
    side started the connection."""
    return _ends(
        m, "teardown", connection=m["conn"], duration=m["duration"], bytes=m["bytes"],
        reason=(m["reason"] or "").strip() or None,
    )  # fmt: skip


for _id in ("302014", "302016"):
    _asa(
        _id,
        r"^Teardown (?P<proto>\w+) connection (?P<conn>\d+) for "
        + _SRC
        + r" to "
        + _DST
        + r" duration (?P<duration>\S+) bytes (?P<bytes>\d+)(?P<reason>[^(]*)",
    )(_teardown)


@_asa(
    "113015",
    r"^AAA user authentication Rejected : reason = (?P<reason>.*?) : local database : "
    r"user = (?P<user>.*?) ?: user IP = (?P<src_ip>[0-9A-Fa-f.:]+)\s*$",
)
def _asa_113015(m):
    # Cisco's template prints `user = name: : user IP`, its examples `user = name : user IP`.
    return {"username": m["user"].removesuffix(":"), "src_ip": m["src_ip"], "reason": m["reason"],
            "extra": {"action": "deny"}}  # fmt: skip


@_asa(
    "113005",
    r"^AAA user authentication Rejected : reason = (?P<reason>.*?) : server = (?P<server>\S+) : "
    r"user = (?P<user>.*?) ?: user IP = (?P<src_ip>[0-9A-Fa-f.:]+)\s*$",
)
def _asa_113005(m):
    return {"username": m["user"], "src_ip": m["src_ip"], "reason": m["reason"],
            "extra": {"action": "deny", "server": m["server"]}}  # fmt: skip


@_asa(
    "605004",
    r"^Login denied from "
    + _ADDR_PORT.format(n="src")
    + r" to (?P<dst_if>[^\s:]+):(?P<dst_ip>[0-9A-Fa-f.:]+)/(?P<service>\S+) for user "
    r"(?P<quote>['\"])(?P<user>.*)(?P=quote)\s*$",
)
def _asa_605004(m):
    return {"username": m["user"], "src_ip": m["src_ip"], "dst_ip": m["dst_ip"],
            "protocol": m["service"].lower(),
            "extra": clean({"action": "deny", "src_port": m["src_port"],
                            "dst_interface": m["dst_if"]})}  # fmt: skip


@_asa(
    "710003",
    r"^(?P<proto>\w+) access denied by ACL from "
    + _ADDR_PORT.format(n="src")
    + r" to (?P<dst_if>[^\s:]+):(?P<dst_ip>[0-9A-Fa-f.:]+)/(?P<service>\S+)",
)
def _asa_710003(m):
    """A connection to the firewall itself (SSH, HTTPS management) refused by its own
    access list. The service is a port number or a name such as `https`."""
    fields = _ends(m, "deny", service=None if m["service"].isdigit() else m["service"])
    if m["service"].isdigit():
        fields["port"] = int(m["service"])
    return fields


def _apply_asa(event: Event, message_id: str) -> Event:
    event.source_type = SourceType.FIREWALL
    event.event_key = f"ASA-{message_id}"
    known = _ASA.get(message_id)
    if not known:
        return event  # an ASA message we do not read further: key and severity only
    for pattern, build in known:
        if match := pattern.search(event.message):
            _set(event, build(match))
            return event
    event.parse_status = ParseStatus.PARTIAL  # a message we know did not look as expected
    return event


# --- iptables ---------------------------------------------------------------------------------

# Optional kernel uptime `[12345.678901] `, then the prefix, then the fields.
_IPTABLES = re.compile(r"^(?:\[\s*\d+\.\d+\]\s*)?(?P<prefix>.*?)\s*(?P<fields>IN=\S* OUT=.*)$")
_FIELD = re.compile(r"(?P<name>[A-Z]+)=(?P<value>\S*)")
_DENY_WORDS = re.compile(r"BLOCK|DROP|DENY|DENIED|REJECT", re.IGNORECASE)
_ALLOW_WORDS = re.compile(r"ACCEPT|ALLOW|PERMIT", re.IGNORECASE)


def _apply_iptables(event: Event) -> Event:
    match = _IPTABLES.match(event.message)
    if not match:
        return event
    # An ICMP error quotes the packet that caused it in brackets, with its own SRC= and
    # DST=; only the fields before it describe the packet that was logged.
    own = match["fields"].split("[", 1)[0]
    fields: dict[str, str] = {}
    for found in _FIELD.finditer(own):
        fields.setdefault(found["name"], found["value"])
    if "SRC" not in fields or "DST" not in fields:
        return event
    prefix = match["prefix"].strip()
    if _DENY_WORDS.search(prefix):
        action = "deny"
    elif _ALLOW_WORDS.search(prefix):
        action = "allow"
    else:
        action = "log"
    event.source_type = SourceType.FIREWALL
    event.event_key = f"iptables.{action}"
    dst_port = fields.get("DPT")
    _set(
        event,
        {
            "protocol": (fields.get("PROTO") or "").lower() or None,
            "src_ip": fields["SRC"],
            "dst_ip": fields["DST"],
            "port": int(dst_port) if dst_port and dst_port.isdigit() else None,
            "interface": fields.get("IN") or None,
            "extra": clean(
                {
                    "action": action,
                    "prefix": prefix or None,
                    "src_port": fields.get("SPT"),
                    "out_interface": fields.get("OUT"),
                    "icmp_type": fields.get("TYPE"),
                    "icmp_code": fields.get("CODE"),
                }
            ),
        },
    )
    return event


# --- Shared ------------------------------------------------------------------------------------


def _set(event: Event, fields: dict) -> None:
    extra = {**event.entities.extra, **fields.pop("extra", {})}
    if fields.get("src_ip") and not is_ip(fields["src_ip"]):
        extra["src_host"], fields["src_ip"] = fields["src_ip"], None
    if fields.get("dst_ip") and not is_ip(fields["dst_ip"]):
        extra["dst_host"], fields["dst_ip"] = fields["dst_ip"], None
    try:
        event.entities = Entities(**fields, extra=extra)
    except ValidationError:
        event.entities = Entities(extra=extra)
        event.parse_status = ParseStatus.PARTIAL


def spans(event: Event) -> list[Span]:
    """Where a username sits in an ASA message, for masking in templates."""
    asa = re.fullmatch(r"ASA-(?P<id>\d{6})", event.event_key or "")
    for pattern, _ in _ASA.get(asa["id"], []) if asa else []:
        if match := pattern.search(event.message):
            return free_text_spans(match)
    return []


def known_event_keys() -> set[str]:
    """The message types this parser produces, for spotting typos in rule files."""
    return {f"ASA-{message_id}" for message_id in _ASA} | {
        "iptables.deny",
        "iptables.allow",
        "iptables.log",
    }


def apply(event: Event) -> Event:
    """Recognize an ASA message or an iptables packet log. Other events are untouched."""
    if event.parse_status is ParseStatus.UNPARSED:
        return event
    if event.event_key and (asa := _ASA_KEY.match(event.event_key)):
        return _apply_asa(event, asa["id"])
    if (event.app or "").lower() == "kernel" and "IN=" in event.message:
        return _apply_iptables(event)
    return event
