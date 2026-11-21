"""The two generic syslog formats: RFC 3164 (the classic BSD format) and RFC 5424.

These parsers understand the header of a line: when, which device, which program.
Vendor parsers build on the result to understand what the message itself says.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from enum import StrEnum

from netlog.ingestion.reader import RawLine
from netlog.schema import Entities, Event, ParseStatus, SourceType

MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}
_MAX_PRI = 191  # facility 23, severity 7


class LineFormat(StrEnum):
    RFC5424 = "rfc5424"
    RFC3164_PRI = "rfc3164_pri"  # as sent on the wire: starts with <PRI>
    RFC3164 = "rfc3164"  # as rsyslog writes it to a file: starts with the timestamp
    ISO = "iso"  # a file with ISO 8601 times: `2026-03-03T02:14:07.123456+00:00 host app: text`
    UNKNOWN = "unknown"


_DETECT_5424 = re.compile(r"^<\d{1,3}>\d{1,2} ")
_DETECT_3164_PRI = re.compile(r"^<\d{1,3}>[A-Z][a-z]{2} ")
# Cisco ASAs and some collectors put the year after the day: `Oct 10 2018 12:34:56`.
_DETECT_3164 = re.compile(r"^[A-Z][a-z]{2} {1,2}\d{1,2} (?:\d{4} )?\d{2}:\d{2}:\d{2}")
# rsyslog's high-precision file format, the default in recent Debian and Ubuntu releases.
_DETECT_ISO = re.compile(r"^(?:<\d{1,3}>)?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


def detect_format(text: str) -> LineFormat:
    """Decide which syslog format one line is in. One file can mix formats."""
    if _DETECT_5424.match(text):
        return LineFormat.RFC5424
    if _DETECT_3164_PRI.match(text):
        return LineFormat.RFC3164_PRI
    if _DETECT_3164.match(text):
        return LineFormat.RFC3164
    if _DETECT_ISO.match(text):
        return LineFormat.ISO
    return LineFormat.UNKNOWN


def parse_timezone(text: str) -> tzinfo:
    """Turn `UTC`, an offset such as `+05:30`, or a zone name such as `Asia/Kolkata` into a tzinfo.

    Zone names need the system's timezone database, which Windows does not ship; use an
    offset there, or install the `tzdata` package.
    """
    text = text.strip()
    if text.upper() in ("UTC", "Z"):
        return UTC
    if match := re.fullmatch(r"([+-])(\d{1,2}):?(\d{2})", text):
        sign = -1 if match[1] == "-" else 1
        offset = timedelta(hours=int(match[2]), minutes=int(match[3]))
        if offset > timedelta(hours=14):
            raise ValueError(f"timezone offset out of range: {text}")
        return timezone(sign * offset)
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(text)
    except Exception as error:
        raise ValueError(
            f"unknown timezone {text!r}; use UTC, an offset such as +05:30, or a zone name"
        ) from error


def _split_pri(pri: str | None) -> tuple[int | None, int | None] | None:
    """<PRI> packs two numbers into one: facility * 8 + severity. Returns None if invalid."""
    if pri is None:
        return None, None
    value = int(pri)
    if value > _MAX_PRI:
        return None
    return value // 8, value % 8


_RFC3164 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<month>[A-Z][a-z]{2}) {1,2}(?P<day>\d{1,2}) (?:(?P<year>\d{4}) )?"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?:\.(?P<fraction>\d{1,6}))?"
    r" (?P<host>\S+) ?(?P<rest>.*)$"
)
# `sshd[2417]: text` or `sudo: text`. The tag must start with a letter, which keeps the
# message counter Cisco devices send (`1042: ...`) from being mistaken for a program.
# Older Red Hat systems name the PAM module too: `sshd(pam_unix)[4101]: text`.
_TAG = re.compile(
    r"^(?P<app>[A-Za-z_][\w./-]*)(?:\((?P<module>[\w-]+)\))?(?:\[(?P<pid>\d+)\])?: ?"
    r"(?P<message>.*)$"
)
# Infoblox appliances write their address after their name: `ib.example.com 10.0.0.1 dhcpd[7]:`.
_HOST_ADDRESS = re.compile(r"^(?P<address>\d{1,3}(?:\.\d{1,3}){3}) (?=[A-Za-z_])")
_ISO = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<stamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(?P<fraction>\d{1,9}))?"
    r"(?P<zone>Z|[+-]\d{2}:?\d{2})? (?P<host>\S+) ?(?P<rest>.*)$"
)

_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d{1,2}) (?P<timestamp>\S+) (?P<host>\S+) "
    r"(?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) (?P<rest>.*)$"
)
_SD_PARAM = re.compile(r'(\S+?)="((?:[^"\\]|\\.)*)"')
_NIL = "-"


class SyslogParser:
    """Parses syslog headers. Keeps state between lines to track the year.

    RFC 3164 timestamps have no year and no timezone, so both are assumed:
      - year: the `year` given (default: the current year) is the year of the first line.
        When the month jumps backwards by six months or more (December to January), the
        log has crossed into a new year and the year is advanced.
      - timezone: `tz` (default UTC) is the timezone the devices' clocks were set to.
    Events record both assumptions in `year_assumed` and `tz_assumed`.
    """

    def __init__(self, year: int | None = None, tz: tzinfo = UTC) -> None:
        self._year = year if year is not None else datetime.now(UTC).year
        self._tz = tz
        self._last_month: int | None = None

    def parse(self, raw: RawLine) -> Event:
        fmt = detect_format(raw.text)
        event = None
        if fmt is LineFormat.RFC5424:
            event = self._parse_5424(raw)
        elif fmt in (LineFormat.RFC3164, LineFormat.RFC3164_PRI):
            event = self._parse_3164(raw)
        elif fmt is LineFormat.ISO:
            event = self._parse_iso(raw)

        if event is None:
            return Event(line_no=raw.line_no, raw=raw.text, parse_status=ParseStatus.UNPARSED)
        if raw.truncated:
            event.parse_status = ParseStatus.PARTIAL
        return event

    def _parse_3164(self, raw: RawLine) -> Event | None:
        match = _RFC3164.match(raw.text)
        if not match or match["month"] not in MONTHS:
            return None
        priority = _split_pri(match["pri"])
        if priority is None:
            return None

        month = MONTHS[match["month"]]
        year = self._year
        if match["year"]:
            year = int(match["year"])
        elif self._last_month is not None and self._last_month - month >= 6:
            year += 1
        try:
            local = datetime(
                year,
                month,
                int(match["day"]),
                int(match["hour"]),
                int(match["minute"]),
                int(match["second"]),
                int((match["fraction"] or "0").ljust(6, "0")),
                tzinfo=self._tz,
            )
        except ValueError:  # for example Feb 31 or 25:00:00
            return None
        self._year, self._last_month = year, month
        event = _generic(raw, local, match["host"], match["rest"], priority)
        event.year_assumed = not match["year"]
        return event

    def _parse_iso(self, raw: RawLine) -> Event | None:
        match = _ISO.match(raw.text)
        if not match:
            return None
        priority = _split_pri(match["pri"])
        if priority is None:
            return None
        fraction = (match["fraction"] or "")[:6]  # Python keeps microseconds, not nanoseconds
        zone = match["zone"] or ""
        try:
            when = datetime.fromisoformat(
                match["stamp"] + (f".{fraction}" if fraction else "") + zone.replace("Z", "+00:00")
            )
        except ValueError:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=self._tz)
        event = _generic(raw, when, match["host"], match["rest"], priority)
        event.year_assumed = False
        event.tz_assumed = not zone
        return event

    def _parse_5424(self, raw: RawLine) -> Event | None:
        match = _RFC5424.match(raw.text)
        if not match:
            return None
        priority = _split_pri(match["pri"])
        if priority is None:
            return None
        split = _split_structured_data(match["rest"])
        if split is None:
            return None
        extra, message = split

        if match["procid"] != _NIL:
            extra["pid"] = match["procid"]
        if match["msgid"] != _NIL:
            extra["msgid"] = match["msgid"]

        timestamp = None
        if match["timestamp"] != _NIL:
            try:
                timestamp = datetime.fromisoformat(match["timestamp"])
            except ValueError:
                return None
            if timestamp.tzinfo is None:
                return None

        return Event(
            line_no=raw.line_no,
            raw=raw.text,
            timestamp=timestamp,
            host=None if match["host"] == _NIL else match["host"],
            source_type=SourceType.SYSLOG_GENERIC,
            app=None if match["app"] == _NIL else match["app"],
            facility=priority[0],
            severity=priority[1],
            message=message.removeprefix("﻿"),
            entities=Entities(extra=extra),
            # The format allows a missing timestamp, but an event without one cannot be
            # placed in time, so it is kept as unparsed with whatever else was understood.
            parse_status=ParseStatus.PARSED if timestamp else ParseStatus.UNPARSED,
        )


def _generic(
    raw: RawLine, when: datetime, host: str, rest: str, priority: tuple[int | None, int | None]
) -> Event:
    """An event from a header already read: the time, the host and what follows them."""
    extra: dict[str, str] = {}
    # A Cisco ASA writes `host : %ASA-...`, with a space before the colon.
    message = rest[2:] if rest.startswith(": ") else rest
    if address := _HOST_ADDRESS.match(message):
        if _TAG.match(message[address.end() :]):
            extra["host_ip"], message = address["address"], message[address.end() :]
    app = None
    if tag := _TAG.match(message):
        app, message = tag["app"], tag["message"].lstrip()
        extra.update({"pid": tag["pid"], "module": tag["module"]})
    return Event(
        line_no=raw.line_no,
        raw=raw.text,
        timestamp=when,
        year_assumed=True,
        tz_assumed=True,
        host=host,
        source_type=SourceType.SYSLOG_GENERIC,
        app=app,
        facility=priority[0],
        severity=priority[1],
        message=message,
        entities=Entities(extra={key: value for key, value in extra.items() if value}),
    )


def _split_structured_data(rest: str) -> tuple[dict[str, str], str] | None:
    """Split the tail of an RFC 5424 line into its structured data and its message.

    Structured data looks like `[id key="value" key2="value2"][id2 ...]`, or `-` for none.
    Values are returned as `id.key`.
    """
    if rest == _NIL or rest.startswith(_NIL + " "):
        return {}, rest[2:]
    if not rest.startswith("["):
        return None

    data: dict[str, str] = {}
    position = 0
    while position < len(rest) and rest[position] == "[":
        end = _closing_bracket(rest, position)
        if end is None:
            return None
        sd_id, _, params = rest[position + 1 : end].partition(" ")
        for name, value in _SD_PARAM.findall(params):
            data[f"{sd_id}.{name}"] = re.sub(r"\\(.)", r"\1", value)
        position = end + 1
    return data, rest[position:].lstrip(" ")


def _closing_bracket(text: str, start: int) -> int | None:
    """Find the `]` that closes the element starting at `start`, skipping quoted values."""
    in_quotes = False
    position = start + 1
    while position < len(text):
        char = text[position]
        if char == "\\" and in_quotes:
            position += 1
        elif char == '"':
            in_quotes = not in_quotes
        elif char == "]" and not in_quotes:
            return position
        position += 1
    return None
