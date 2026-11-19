"""Turns a log file into a stream of events and measures how much of it was understood."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, tzinfo
from pathlib import Path

from netlog.ingestion.reader import DEFAULT_MAX_LINE_LENGTH, RawLine, read_lines
from netlog.parsers.cisco import CiscoParser
from netlog.parsers.syslog import SyslogParser
from netlog.schema import Event, ParseStatus


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
    _unparsed_shapes: Counter[str] = field(default_factory=Counter, repr=False)

    @property
    def total(self) -> int:
        """Lines with content. Blank lines are not counted against coverage."""
        return self.parsed + self.partial + self.unparsed

    @property
    def percent_parsed(self) -> float:
        return 100.0 * self.parsed / self.total if self.total else 0.0

    def record(self, event: Event) -> None:
        if event.parse_status is ParseStatus.PARSED:
            self.parsed += 1
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

    def parse(self, raw: RawLine) -> Event:
        event = self._cisco.apply(self._syslog.parse(raw))
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
