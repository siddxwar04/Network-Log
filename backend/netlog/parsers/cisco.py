"""Cisco IOS messages: `%FACILITY-SEVERITY-MNEMONIC: text`.

The syslog parser has already read the line's header. This parser recognizes a Cisco
message inside it, takes the event key and severity from the message code, decides
which timestamp to trust, and pulls out the interface, neighbor, user and so on.

To support another message, add one extractor function below and one golden test.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, tzinfo

from pydantic import ValidationError

from netlog.parsers.patterns import Span, free_text_spans
from netlog.parsers.syslog import MONTHS
from netlog.schema import (
    Entities,
    Event,
    ParseStatus,
    Severity,
    SourceType,
    normalize_interface,
)

# [counter: ][device timestamp: ]%FACILITY-SEVERITY-MNEMONIC: text
_BODY = re.compile(
    r"^(?:(?P<seq>\d+): )?"
    r"(?:(?P<stamp>[^%]+?): )?"
    r"%(?P<facility>[A-Z][A-Z0-9_]*)-(?P<severity>[0-7])-(?P<mnemonic>[A-Z0-9_]+): ?"
    r"(?P<text>.*)$"
)
_PRI = re.compile(r"^<(?P<pri>\d{1,3})>(?P<rest>.*)$")
# `*Mar  1 00:00:52.000`, `.Mar  3 02:14:07`, `Mar  3 2026 02:14:07.123 UTC`
_STAMP = re.compile(
    r"^(?P<flag>[*.])?(?P<month>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2})(?: (?P<year>\d{4}))? "
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?:\.(?P<ms>\d{1,3}))?"
    r"(?: (?P<zone>[A-Za-z]{2,5}))?$"
)
# A device whose clock disagrees with the collector by more than this is not believed.
_MAX_CLOCK_DIFFERENCE = timedelta(hours=24)

# BGP NOTIFICATION error codes (RFC 4271 section 4.5, RFC 4486), as "code/subcode".
_BGP_ERRORS = {
    "1": "Message header error",
    "2": "OPEN message error",
    "2/2": "Bad peer AS: the neighbor's AS number is not the one configured",
    "3": "UPDATE message error",
    "4": "Hold timer expired: no keepalive arrived in time",
    "5": "Finite state machine error",
    "6": "Cease: the session was closed on purpose",
    "6/1": "Cease: maximum number of prefixes reached",
    "6/2": "Cease: administrative shutdown",
    "6/3": "Cease: peer de-configured",
    "6/4": "Cease: administrative reset",
    "6/5": "Cease: connection rejected",
    "6/6": "Cease: other configuration change",
    "6/7": "Cease: connection collision resolution",
}

Extractor = Callable[[str], dict | None]
_EXTRACTORS: dict[str, Extractor] = {}
_PATTERNS: dict[str, re.Pattern[str]] = {}


def spans(event: Event) -> list[Span]:
    """Where the username sits in a Cisco event's message."""
    pattern = _PATTERNS.get(event.event_key or "")
    match = pattern.search(event.message) if pattern else None
    return free_text_spans(match) if match else []


def _extractor(*event_keys: str, pattern: str):
    """Register a function that turns a message's regex match into entity fields."""
    compiled = re.compile(pattern)

    def register(build: Callable[[re.Match[str]], dict]) -> Extractor:
        def extract(text: str) -> dict | None:
            match = compiled.search(text)
            return build(match) if match else None

        for key in event_keys:
            _EXTRACTORS[key] = extract
            _PATTERNS[key] = compiled
        return extract

    return register


def _clean(extra: dict[str, str | None]) -> dict[str, str]:
    return {key: value for key, value in extra.items() if value}


# --- Interfaces ---------------------------------------------------------------------------


@_extractor("LINK-3-UPDOWN", pattern=r"^Interface (\S+), changed state to (\w+)")
def _link(m):
    return {"interface": m[1], "state_to": m[2].lower()}


@_extractor(
    "LINEPROTO-5-UPDOWN", pattern=r"^Line protocol on Interface (\S+), changed state to (\w+)"
)
def _lineproto(m):
    return {"interface": m[1], "state_to": m[2].lower()}


@_extractor("LINK-5-CHANGED", pattern=r"^Interface (\S+), changed state to (.+?)\s*$")
def _link_changed(m):
    state = m[2].lower()
    # "administratively down" means a person shut the interface on purpose.
    admin = "true" if state.startswith("administratively") else None
    return {"interface": m[1], "state_to": state, "extra": _clean({"admin": admin})}


@_extractor(
    "SW_MATM-4-MACFLAP_NOTIF",
    pattern=r"^Host (\S+) in vlan (\d+) is flapping between port (\S+) and port (\S+)",
)
def _mac_flap(m):
    return {
        "mac": m[1],
        "vlan": int(m[2]),
        "interface": m[3],
        "extra": {"second_interface": normalize_interface(m[4])},
    }


# --- Routing ------------------------------------------------------------------------------


@_extractor(
    "BGP-5-ADJCHANGE",
    pattern=r"^neighbor \*?(\S+)(?: vpn vrf (\S+))? (Up|Down)\b\s*(.*?)\s*$",
)
def _bgp_adjacency(m):
    return {
        "protocol": "bgp",
        "neighbor_ip": m[1],
        "state_to": m[3].lower(),
        "reason": m[4] or None,
        "extra": _clean({"vrf": m[2]}),
    }


@_extractor(
    "BGP-3-NOTIFICATION",
    pattern=r"^(sent to|received from) neighbor \*?(\S+) (\d+)/(\d+) \(([^)]*)\)",
)
def _bgp_notification(m):
    code = f"{m[3]}/{m[4]}"
    return {
        "protocol": "bgp",
        "neighbor_ip": m[2],
        "reason": m[5],
        "extra": _clean(
            {
                "direction": "sent" if m[1].startswith("sent") else "received",
                "error_code": code,
                "error_meaning": _BGP_ERRORS.get(code) or _BGP_ERRORS.get(m[3]),
            }
        ),
    }


@_extractor(
    "OSPF-5-ADJCHG",
    pattern=r"^Process (\d+), Nbr (\S+) on (\S+) from (\S+) to (\S+?),\s*(.*?)\s*$",
)
def _ospf_adjacency(m):
    return {
        "protocol": "ospf",
        "neighbor_ip": m[2],
        "interface": m[3],
        "state_from": m[4],
        "state_to": m[5],
        "reason": m[6].removeprefix("Neighbor Down: ") or None,
        "extra": {"process": m[1]},
    }


# --- People -------------------------------------------------------------------------------
# Usernames are typed by whoever is logging in, so they can contain anything, including
# text that imitates the rest of the message. Every pattern here is anchored so that the
# fields the device itself appends (source address, port) are read from the end.


@_extractor(
    "SYS-5-CONFIG_I",
    pattern=r"^Configured from (\S+) by (?P<user>.+?)(?: on (\S+))?(?: \(([0-9A-Fa-f.:]+)\))?\s*$",
)
def _config_change(m):
    return {"username": m[2], "src_ip": m[4], "extra": _clean({"source": m[1], "line": m[3]})}


@_extractor(
    "SEC_LOGIN-4-LOGIN_FAILED",
    "SEC_LOGIN-5-LOGIN_SUCCESS",
    pattern=(
        r"^Login (?:failed|Success) \[user: (?P<user>.*)\] \[Source: (\S+)\] \[localport: (\d+)\]"
        r"(?: \[Reason: (.*?)\])?(?: at .*)?$"
    ),
)
def _login(m):
    port = int(m[3])
    return {
        "username": m[1],
        "src_ip": m[2],
        "port": port,
        "reason": m[4],
        "protocol": {22: "ssh", 23: "telnet"}.get(port),
    }


@_extractor(
    "SYS-5-RELOAD",
    pattern=(
        r"^Reload requested(?: by (?P<user>\S+?))?(?: on (\S+))?(?: \(([0-9A-Fa-f.:]+)\))?\.?"
        r"(?: Reload [Rr]eason: (.*?)\.?)?\s*$"
    ),
)
def _reload(m):
    return {"username": m[1], "src_ip": m[3], "reason": m[4], "extra": _clean({"line": m[2]})}


# --- System -------------------------------------------------------------------------------


@_extractor("SYS-5-RESTART", pattern=r"^System restarted(?: --\s*(.*?))?\s*$")
def _restart(m):
    return {"extra": _clean({"software": m[1]})}


@_extractor(
    "SYS-3-CPUHOG",
    pattern=r"^Task is running for \((\d+)\)msecs.*?process = (.+?)\.?\s*$",
)
def _cpu_hog(m):
    return {"extra": {"duration_ms": m[1], "process": m[2]}}


@_extractor("SYS-2-MALLOCFAIL", pattern=r"^Memory allocation of (\d+) bytes failed")
def _malloc_fail(m):
    process = re.search(r'-Process= "([^"]+)"', m.string)
    return {"extra": _clean({"bytes": m[1], "process": process[1] if process else None})}


# --- The parser ---------------------------------------------------------------------------


@dataclass
class _Time:
    timestamp: datetime | None
    from_device: bool = False
    year_assumed: bool = True
    tz_assumed: bool = True
    clock: str | None = None  # why the device's clock was not used, if it was not


class CiscoParser:
    """Recognizes Cisco IOS messages in events the syslog parser has produced.

    Which timestamp is used: a Cisco line stored by a collector carries two, the
    collector's and the device's own. The device's is used, because it records when the
    event happened and has millisecond precision. The collector's is used instead when
    the device's cannot be trusted: it is marked unsynchronized (`*`), it is an uptime
    counter, or it differs from the collector's by more than 24 hours. The reason is
    then recorded in `entities.extra["clock"]`.
    """

    def __init__(self, year: int | None = None, tz: tzinfo = UTC) -> None:
        self._year = year if year is not None else datetime.now(UTC).year
        self._tz = tz

    def apply(self, event: Event) -> Event:
        if event.parse_status is ParseStatus.UNPARSED:
            return self._parse_headerless(event)
        if event.app is not None:
            return event
        body = _BODY.match(event.message)
        if not body:
            return event
        time = self._resolve_time(body["stamp"], reference=event.timestamp)
        self._fill(event, body, time)
        return event

    def _parse_headerless(self, event: Event) -> Event:
        """A line straight from a device, with no collector header: `<189>42: *Mar  1 ...: %...`."""
        text, facility = event.raw, None
        if pri := _PRI.match(text):
            if int(pri["pri"]) > 191:
                return event
            facility, text = int(pri["pri"]) // 8, pri["rest"]
        body = _BODY.match(text)
        if not body or not body["stamp"]:
            return event
        time = self._resolve_time(body["stamp"], reference=None)
        if time.timestamp is None:
            return event

        parsed = Event(
            line_no=event.line_no,
            raw=event.raw,
            timestamp=time.timestamp,
            facility=facility,
        )
        self._fill(parsed, body, time)
        return parsed

    def _fill(self, event: Event, body: re.Match[str], time: _Time) -> None:
        key = f"{body['facility']}-{body['severity']}-{body['mnemonic']}"
        event.source_type = SourceType.CISCO_IOS
        event.event_key = key
        # The digit in the message code is the severity. It wins over <PRI>.
        event.severity = Severity(int(body["severity"]))
        event.message = body["text"]

        if time.from_device:
            event.timestamp = time.timestamp
            event.year_assumed = time.year_assumed
            event.tz_assumed = time.tz_assumed

        extra = _clean({"seq": body["seq"], "clock": time.clock})
        if time.clock:
            extra["device_time"] = body["stamp"]

        fields: dict = {}
        if extractor := _EXTRACTORS.get(key):
            extracted = extractor(body["text"])
            if extracted is None:
                # A message we claim to understand did not look as expected.
                event.parse_status = ParseStatus.PARTIAL
            else:
                fields = extracted
        extra.update(fields.pop("extra", {}))
        try:
            event.entities = Entities(**fields, extra=extra)
        except ValidationError:  # for example a neighbor that is not an IP address
            event.entities = Entities(extra=extra)
            event.parse_status = ParseStatus.PARTIAL

    def _resolve_time(self, stamp: str | None, reference: datetime | None) -> _Time:
        """Decide between the device's own timestamp and the collector's (`reference`)."""
        if stamp is None:
            return _Time(reference)
        match = _STAMP.match(stamp)
        if not match or match["month"] not in MONTHS:
            return _Time(reference, clock="uptime")

        zone = (match["zone"] or "").upper()
        known_zone = zone in ("UTC", "GMT")
        tz = UTC if known_zone else self._tz
        month, day = MONTHS[match["month"]], int(match["day"])
        clock_fields = (
            int(match["hour"]),
            int(match["minute"]),
            int(match["second"]),
            int((match["ms"] or "0").ljust(3, "0")) * 1000,
        )

        def at(year: int) -> datetime | None:
            try:
                return datetime(year, month, day, *clock_fields, tzinfo=tz).astimezone(UTC)
            except ValueError:
                return None

        if match["year"]:
            device = at(int(match["year"]))
        elif reference is not None:
            # No year on the line: take the one that puts the device closest to the
            # collector, which gets the turn of the year right.
            candidates = [t for y in (-1, 0, 1) if (t := at(reference.year + y))]
            device = min(candidates, key=lambda t: abs(t - reference), default=None)
        else:
            device = at(self._year)
        if device is None:
            return _Time(reference, clock="invalid")

        unsynced = match["flag"] == "*"
        if reference is not None:
            if unsynced:
                return _Time(reference, clock="unsynced")
            if abs(device - reference) > _MAX_CLOCK_DIFFERENCE:
                return _Time(reference, clock="suspect")
        return _Time(
            device,
            from_device=True,
            year_assumed=not match["year"],
            tz_assumed=not known_zone,
            clock="unsynced" if unsynced else None,
        )
