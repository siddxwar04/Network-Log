"""A small registry of message patterns, shared by the parsers that work per program.

Each program (sshd, sudo, dhcpd) gets an ordered list of patterns. The first one that
matches a message decides its event key and its entities. To support another message,
add one decorated function to the program's parser and one golden test.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable

from pydantic import ValidationError

from netlog.schema import Entities, Event, ParseStatus


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def clean(extra: dict[str, str | None]) -> dict[str, str]:
    """Drop empty values, so `extra` only holds what the message really contained."""
    return {key: value for key, value in extra.items() if value}


# Named groups that hold text chosen by a person or a client, and the placeholder that
# stands for them. Such text can be anything at all, so template mining masks it by its
# exact position in the message.
FREE_TEXT_GROUPS = {"user": "<USER>", "hostname": "<HOST>"}

Span = tuple[int, int, str]  # start, end, placeholder


def free_text_spans(match: re.Match[str]) -> list[Span]:
    """Where the person-chosen values sit in a matched message."""
    spans = []
    for group, placeholder in FREE_TEXT_GROUPS.items():
        if group in match.re.groupindex and match.group(group):
            spans.append((*match.span(group), placeholder))
    return spans


class PatternSet:
    def __init__(self) -> None:
        self._rules: list[tuple[str, re.Pattern[str], Callable[[re.Match[str]], dict]]] = []

    def rule(self, event_key: str, pattern: str):
        """Register a builder that turns a regex match into entity fields.

        A builder may return `"event_key"` among its fields to override the default key,
        for messages that share a shape but mean different things.
        """

        def register(build: Callable[[re.Match[str]], dict]):
            self._rules.append((event_key, re.compile(pattern), build))
            return build

        return register

    def spans(self, message: str) -> list[Span] | None:
        """The free-text positions in `message`, or None if no pattern matches it."""
        for _, pattern, _ in self._rules:
            if match := pattern.search(message):
                return free_text_spans(match)
        return None

    def apply(self, event: Event) -> None:
        """Set the event key and entities of `event` from the first matching pattern."""
        for event_key, pattern, build in self._rules:
            match = pattern.search(event.message)
            if not match:
                continue
            fields = build(match)
            event.event_key = fields.pop("event_key", event_key)
            extra = {**event.entities.extra, **fields.pop("extra", {})}
            try:
                event.entities = Entities(**fields, extra=extra)
            except ValidationError:  # for example a client id that is not a MAC address
                event.entities = Entities(extra=extra)
                event.parse_status = ParseStatus.PARTIAL
            return
