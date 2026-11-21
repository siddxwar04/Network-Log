"""Turns a log file into a stream of events and measures how much of it was understood."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, tzinfo
from pathlib import Path

from netlog.ingestion.reader import DEFAULT_MAX_LINE_LENGTH, RawLine, read_lines
from netlog.parsers import cisco, dhcp, dns, firewall, linux_auth
from netlog.parsers.cisco import CiscoParser
from netlog.parsers.patterns import Span
from netlog.parsers.syslog import SyslogParser
from netlog.schema import Event, ParseStatus, SourceType


def free_text_spans(event: Event) -> list[Span]:
    """Where an event's message holds text chosen by a person or a client: a username or
    a DHCP hostname. Returned as (start, end, placeholder), for masking in templates."""
    if event.source_type is SourceType.CISCO_IOS:
        return cisco.spans(event)
    if event.source_type is SourceType.LINUX_AUTH:
        return linux_auth.spans(event)
    if event.source_type is SourceType.DHCP:
        return dhcp.spans(event)
    if event.source_type is SourceType.FIREWALL:
        return firewall.spans(event)
    if event.source_type is SourceType.DNS:
        return dns.spans(event)
    return []


def line_shape(text: str) -> str:
    """Reduce a line to its shape so that similar unparsed lines can be counted together."""
    return re.sub(r"\d+", "N", text)[:80]


@dataclass
class Coverage:
    """How many lines of a file were understood."""

    parsed: int = 0
    partial: int = 0
    unparsed: int = 0
    blank: int = 0
    # Parsed lines whose message was also recognized: they have an event key.
    classified: int = 0
    _unparsed_shapes: Counter[str] = field(default_factory=Counter, repr=False)

    @property
    def total(self) -> int:
        """Lines with content. Blank lines are not counted against coverage."""
        return self.parsed + self.partial + self.unparsed

    @property
    def percent_parsed(self) -> float:
        return 100.0 * self.parsed / self.total if self.total else 0.0

    @property
    def percent_classified(self) -> float:
        return 100.0 * self.classified / self.total if self.total else 0.0

    def record(self, event: Event) -> None:
        if event.parse_status is ParseStatus.PARSED:
            self.parsed += 1
            self.classified += event.event_key is not None
        elif event.parse_status is ParseStatus.PARTIAL:
            self.partial += 1
        else:
            self.unparsed += 1
            self._unparsed_shapes[line_shape(event.raw)] += 1

    def top_unparsed(self, count: int = 10) -> list[tuple[str, int]]:
        """The most common shapes among lines no parser understood."""
        return self._unparsed_shapes.most_common(count)


class LineParser:
    """Runs one line through every parser: the syslog header first, then vendor messages."""

    def __init__(self, year: int | None = None, tz: tzinfo = UTC) -> None:
        self._syslog = SyslogParser(year=year, tz=tz)
        self._cisco = CiscoParser(year=year, tz=tz)
        self._tz = tz

    def parse(self, raw: RawLine) -> Event:
        event = self._cisco.apply(self._syslog.parse(raw))
        if event.parse_status is ParseStatus.UNPARSED:
            # BIND's own log file has a header of its own, not a syslog one.
            event = dns.parse_bind_file_line(raw, self._tz) or event
        event = dhcp.apply(linux_auth.apply(event))
        event = dns.apply(firewall.apply(event))
        if raw.truncated and event.parse_status is ParseStatus.PARSED:
            event.parse_status = ParseStatus.PARTIAL
        return event


def parse_file(
    path: str | Path,
    *,
    year: int | None = None,
    tz: tzinfo = UTC,
    max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
    coverage: Coverage | None = None,
) -> Iterator[Event]:
    """Yield one event per non-blank line of the file, in file order.

    Every non-blank line produces an event: a line no parser understands becomes an
    event with status `unparsed`, so nothing is dropped silently. Pass a `Coverage`
    to collect the counts.
    """
    parser = LineParser(year=year, tz=tz)
    for raw in read_lines(path, max_line_length):
        if not raw.text.strip():
            if coverage is not None:
                coverage.blank += 1
            continue
        event = parser.parse(raw)
        if coverage is not None:
            coverage.record(event)
        yield event
