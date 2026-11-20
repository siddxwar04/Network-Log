"""The front door of the live listener: every message that arrives passes through here.

Anyone who can reach the port can send anything, so nothing is trusted. A message is
counted and thrown away when it comes from an address not on the allow-list, when its
sender is over its rate limit, when it is too long, or when it is not text. What is left
waits in a bounded queue for the writer; when a burst overflows the queue, the oldest
messages are dropped and counted, so memory never grows without limit.

This module never raises on bad input: whatever arrives is either queued or counted.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

# Why messages were not kept. The API and the live page show these counts.
REASONS = ("refused", "rate_limited", "oversized", "not_text", "malformed", "dropped")


@dataclass
class Message:
    arrived: datetime
    sender: str
    text: str


@dataclass
class Counters:
    received: int = 0
    accepted: int = 0
    stored: int = 0
    refused: int = 0
    rate_limited: int = 0
    oversized: int = 0
    not_text: int = 0
    malformed: int = 0
    dropped: int = 0

    def as_dict(self) -> dict[str, int]:
        return dict(self.__dict__)


@dataclass
class Sender:
    messages: int = 0
    discarded: int = 0
    last_seen: datetime | None = None
    tokens: float = 0.0
    refilled: float = 0.0


@dataclass
class IntakeSettings:
    max_message_bytes: int = 8192
    queue_size: int = 10_000
    rate_per_sender: float = 200.0  # messages per second, on average
    burst_per_sender: float = 400.0  # how many may come at once
    allowed_senders: tuple[str, ...] = ()  # empty: any address
    max_senders_tracked: int = 1000

    @classmethod
    def from_config(cls, live: dict) -> IntakeSettings:
        return cls(
            max_message_bytes=int(live["max_message_bytes"]),
            queue_size=int(live["queue_size"]),
            rate_per_sender=float(live["rate_per_sender"]),
            burst_per_sender=float(live["burst_per_sender"]),
            allowed_senders=tuple(live["allowed_senders"]),
            max_senders_tracked=int(live["max_senders_tracked"]),
        )


@dataclass
class Intake:
    settings: IntakeSettings
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    monotonic: Callable[[], float] = time.monotonic
    counters: Counters = field(default_factory=Counters)
    warnings: deque = field(default_factory=lambda: deque(maxlen=20))

    def __post_init__(self) -> None:
        self.queue: deque[Message] = deque()
        self.senders: OrderedDict[str, Sender] = OrderedDict()
        self.recent: deque[float] = deque()  # when accepted messages arrived, for the rate
        self._lock = threading.Lock()
        self._overflowing = False

    # --- Arrival --------------------------------------------------------------------------

    def accept(self, data: bytes, sender: str) -> None:
        """One UDP datagram, or one framed TCP message. A datagram may hold several lines."""
        if len(data) > self.settings.max_message_bytes:
            self._count(sender, "oversized")
            return
        parts = [part for part in data.replace(b"\r\n", b"\n").split(b"\n") if part.strip()]
        if not parts:
            self._count(sender, "malformed")
            return
        for part in parts:
            self._one(part, sender)

    def oversized(self, sender: str) -> None:
        """A TCP message that grew past the limit before it ended."""
        self._count(sender, "oversized")

    def _one(self, data: bytes, sender: str) -> None:
        if self.settings.allowed_senders and sender not in self.settings.allowed_senders:
            self._count(sender, "refused")
            return
        if not self._within_rate(sender):
            self._count(sender, "rate_limited")
            return
        if b"\x00" in data:
            self._count(sender, "not_text")
            return
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            self._count(sender, "not_text")
            return
        text = text.strip()
        if not text or any(ord(c) < 32 and c != "\t" for c in text):
            self._count(sender, "not_text" if text else "malformed")
            return
        now = self.clock()
        with self._lock:
            self.counters.received += 1
            self.counters.accepted += 1
            entry = self._sender(sender)
            entry.messages += 1
            entry.last_seen = now
            if len(self.queue) >= self.settings.queue_size:
                self.queue.popleft()  # the oldest goes, so the newest can be kept
                self.counters.dropped += 1
                if not self._overflowing:
                    self._overflowing = True
                    self.warnings.append(
                        f"{now.isoformat(timespec='seconds')}: the queue of "
                        f"{self.settings.queue_size} messages overflowed; the oldest are "
                        "being dropped"
                    )
            elif len(self.queue) < self.settings.queue_size // 2:
                self._overflowing = False
            self.queue.append(Message(now, sender, text))
            self.recent.append(self.monotonic())

    def _count(self, sender: str, reason: str) -> None:
        with self._lock:
            self.counters.received += 1
            setattr(self.counters, reason, getattr(self.counters, reason) + 1)
            entry = self._sender(sender)
            entry.discarded += 1
            entry.last_seen = self.clock()

    def _sender(self, address: str) -> Sender:
        """The record of one sender. Only so many are kept: a flood of forged addresses
        cannot grow it without limit."""
        entry = self.senders.get(address)
        if entry is None:
            entry = Sender(tokens=self.settings.burst_per_sender, refilled=self.monotonic())
            self.senders[address] = entry
            while len(self.senders) > self.settings.max_senders_tracked:
                self.senders.popitem(last=False)
        else:
            self.senders.move_to_end(address)
        return entry

    def _within_rate(self, address: str) -> bool:
        """A token bucket per sender: one misbehaving device cannot starve the others."""
        with self._lock:
            entry = self._sender(address)
            now = self.monotonic()
            entry.tokens = min(
                self.settings.burst_per_sender,
                entry.tokens + (now - entry.refilled) * self.settings.rate_per_sender,
            )
            entry.refilled = now
            if entry.tokens < 1:
                return False
            entry.tokens -= 1
            return True

    # --- Leaving --------------------------------------------------------------------------

    def take(self, limit: int = 5000) -> list[Message]:
        """The waiting messages, oldest first, up to `limit`."""
        taken = []
        with self._lock:
            while self.queue and len(taken) < limit:
                taken.append(self.queue.popleft())
        return taken

    def per_minute(self) -> int:
        """How many messages were accepted in the last 60 seconds."""
        cutoff = self.monotonic() - 60
        with self._lock:
            while self.recent and self.recent[0] < cutoff:
                self.recent.popleft()
            return len(self.recent)

    def senders_seen(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "address": address,
                    "messages": entry.messages,
                    "discarded": entry.discarded,
                    "last_seen": entry.last_seen.isoformat() if entry.last_seen else None,
                }
                for address, entry in reversed(self.senders.items())
            ]


class TcpFramer:
    """Splits a TCP stream into messages. Two framings are in use (RFC 6587): a newline
    after each message, or each message preceded by its length and a space. A message
    longer than the limit is reported as None and skipped; a length that is not believable
    breaks the connection, since the stream can no longer be followed."""

    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max_bytes
        self.buffer = b""
        self.skipping = False  # inside a message that is too long, until its newline
        self.broken = False

    def feed(self, data: bytes) -> list[bytes | None]:
        out: list[bytes | None] = []
        self.buffer += data
        while self.buffer and not self.broken:
            if self.skipping:
                end = self.buffer.find(b"\n")
                if end < 0:
                    self.buffer = b""
                    break
                self.buffer = self.buffer[end + 1 :]
                self.skipping = False
                continue
            head = self.buffer[:12]
            space = head.find(b" ")
            if space > 0 and head[:space].isdigit() and not self.buffer.startswith(b"<"):
                length = int(head[:space])
                if length <= 0 or length > self.max_bytes:
                    out.append(None)
                    self.broken = True
                    break
                if len(self.buffer) < space + 1 + length:
                    break
                out.append(self.buffer[space + 1 : space + 1 + length])
                self.buffer = self.buffer[space + 1 + length :]
                continue
            end = self.buffer.find(b"\n")
            if end < 0:
                if len(self.buffer) > self.max_bytes:
                    out.append(None)
                    self.buffer = b""
                    self.skipping = True
                break
            message, self.buffer = self.buffer[:end], self.buffer[end + 1 :]
            if len(message) > self.max_bytes:
                out.append(None)
            elif message.strip():
                out.append(message)
        return out
