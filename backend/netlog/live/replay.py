"""Replaying a log file to the live listener, as if the devices were sending it now.

Every timestamp in a line (the syslog header, and a Cisco device's own clock after the
sequence number) is moved so the first line happens now, and the gaps between lines are
divided by `speed`: at speed 60, an hour of log arrives in a minute. Lines are sent at
those moments, over UDP by default.

    netlog replay data\\scenarios\\02_cascade.log --speed 60
"""

from __future__ import annotations

import re
import socket
import time
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime, timedelta

MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
# "Mar  3 02:46:12" at the start of a line, and "Mar  3 02:46:11.699" (often after a
# sequence number, sometimes with a * or . marking an unsynchronized clock) inside it.
_HEADER = re.compile(r"^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d\d:\d\d:\d\d)")
_DEVICE = re.compile(
    r"(?<=: )(?P<mark>[*.]?)(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) "
    r"(?P<time>\d\d:\d\d:\d\d)(?P<frac>\.\d+)?(?=:)"
)


def _moment(match: re.Match, year: int) -> datetime | None:
    if match["mon"] not in MONTHS:
        return None
    hour, minute, second = (int(part) for part in match["time"].split(":"))
    try:
        return datetime(year, MONTHS.index(match["mon"]) + 1, int(match["day"]), hour, minute,
                        second, tzinfo=UTC)  # fmt: skip
    except ValueError:
        return None


def _stamp(moment: datetime, frac: str | None = None) -> str:
    text = f"{MONTHS[moment.month - 1]} {moment.day:>2} {moment:%H:%M:%S}"
    if frac:
        digits = len(frac) - 1
        text += f".{moment.microsecond // 10 ** (6 - digits):0{digits}d}"
    return text


def _moved(
    match: re.Match, first: datetime, start: datetime, speed: float, year: int, device: bool = False
) -> str:
    """One timestamp of a line, moved: as far after `start` as it was after `first`,
    divided by `speed`."""
    then = _moment(match, year)
    if then is None:
        return match[0]
    moment = start + timedelta(seconds=(then - first).total_seconds() / speed)
    if not device:
        return _stamp(moment)
    fraction = int((match["frac"] or ".0")[1:].ljust(6, "0")[:6])
    moment += timedelta(microseconds=fraction / speed)
    return match["mark"] + _stamp(moment, match["frac"])


def rewrite(lines: Iterable[str], start: datetime, speed: float) -> Iterator[tuple[float, str]]:
    """(seconds from now to send it, the line with its times moved) for each line. A line
    with no time of its own is sent with the one before."""
    first: datetime | None = None
    offset = 0.0
    year = start.year
    for line in lines:
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        header = _HEADER.match(line)
        original = _moment(header, year) if header else None
        if original is not None:
            if first is None:
                first = original
            offset = max(0.0, (original - first).total_seconds() / speed)

        if first is not None:
            base = (first, start, speed, year)
            if header:
                line = _HEADER.sub(lambda m, b=base: _moved(m, *b), line, count=1)
            line = _DEVICE.sub(lambda m, b=base: _moved(m, *b, True), line, count=1)
        yield offset, line


def replay(
    lines: Iterable[str],
    send: Callable[[bytes], None],
    *,
    speed: float = 1.0,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Send every line at its moment. Returns how many were sent."""
    if speed <= 0:
        raise ValueError("speed must be greater than zero")
    began = monotonic()
    sent = 0
    for offset, line in rewrite(lines, now(), speed):
        wait = offset - (monotonic() - began)
        if wait > 0:
            sleep(wait)
        send(line.encode("utf-8"))
        sent += 1
    return sent


def sender(
    host: str, port: int, tcp: bool = False
) -> tuple[Callable[[bytes], None], Callable[[], None]]:
    """A function that sends one message to the listener, and one that closes the socket."""
    if tcp:
        connection = socket.create_connection((host, port), timeout=10)
        return (lambda data: connection.sendall(data + b"\n")), connection.close
    udp = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM)
    return (lambda data: udp.sendto(data, (host, port))), udp.close
