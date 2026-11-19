"""Rule definitions: loading them from TOML and checking they make sense.

Rules are data. The engine knows how to run three kinds of rule; everything specific to
one kind of problem (which messages, which thresholds, what to call it, how serious it
is) lives in `config/rules.toml`.
"""

from __future__ import annotations

import os
import string
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from netlog.schema import Event
from netlog.storage.database import ENTITY_COLUMNS

_TOP_FIELDS = ("host", "app", "source_type", "severity", "event_key")
KINDS = ("threshold", "sequence", "absence")
# From least to most serious.
LEVELS = ("info", "low", "medium", "high", "critical")

_MATCHER_KEYS = {"event_keys", "where", "where_not"}
_COMMON_KEYS = {
    "name",
    "incident_type",
    "description",
    "kind",
    "title",
    "enabled",
    "strong_at",
    "severity",
    "severity_because",
    "severity_when",
}
_PAIR_KEYS = _COMMON_KEYS | {"first", "then", "same", "within_seconds"}
_KEYS_BY_KIND = {
    "threshold": _COMMON_KEYS
    | _MATCHER_KEYS
    | {
        "group_by",
        "window_seconds",
        "threshold",
        "distinct",
        "capture",
        "tags",
        "followed_by",
        "related",
    },
    "sequence": _PAIR_KEYS,
    "absence": _PAIR_KEYS,
}
_FOLLOWED_BY_KEYS = _MATCHER_KEYS | {"flag", "same", "within_seconds", "after"}
_RELATED_KEYS = _MATCHER_KEYS | {"same", "margin_seconds", "capture"}
_ESCALATION_KEYS = {"flag", "strength_at_least", "level", "because"}


class RuleError(ValueError):
    """A rule file has a mistake. The message names the rule, the field and the problem."""


def field_value(event: Event, name: str):
    """Read a field of an event by the name used in rule files."""
    if name.startswith("extra."):
        return event.entities.extra.get(name[6:])
    if name in ENTITY_COLUMNS:
        return getattr(event.entities, name)
    value = getattr(event, name)
    if name == "source_type":
        return str(value)
    if name == "severity" and value is not None:
        return int(value)
    return value


def metric_name(field_name: str) -> str:
    """The name a captured field gets among a finding's metrics: `extra.process` -> `process`."""
    return field_name.removeprefix("extra.")


def _is_field(name: object) -> bool:
    if not isinstance(name, str):
        return False
    if name.startswith("extra."):
        return len(name) > 6
    return name in _TOP_FIELDS or name in ENTITY_COLUMNS


@dataclass(frozen=True)
class Matcher:
    """Which events a rule looks at."""

    event_keys: tuple[str, ...]
    where: dict[str, tuple] = field(default_factory=dict)
    where_not: dict[str, tuple] = field(default_factory=dict)

    def matches(self, event: Event) -> bool:
        if event.event_key not in self.event_keys:
            return False
        if any(field_value(event, name) not in allowed for name, allowed in self.where.items()):
            return False
        return not any(
            field_value(event, name) in banned for name, banned in self.where_not.items()
        )


@dataclass(frozen=True)
class Tag:
    name: str
    metric: str
    at_least: float


@dataclass(frozen=True)
class FollowedBy:
    flag: str
    matcher: Matcher
    same: tuple[str, ...]
    within_seconds: float
    # Which moment the later event must come after: the moment the "threshold" was
    # reached (a login succeeding once guessing is established), or the "last" matching
    # event (a session that is up again after its final drop).
    after: str = "threshold"


@dataclass(frozen=True)
class Related:
    """Other events about the same thing, added to a finding's evidence."""

    matcher: Matcher
    same: tuple[str, ...]
    margin_seconds: float
    capture: tuple[str, ...]


@dataclass(frozen=True)
class Escalation:
    """A condition under which a finding is more serious than the rule's base level."""

    level: str
    because: str
    flag: str | None = None
    strength_at_least: float | None = None


@dataclass(frozen=True)
class Rule:
    name: str
    incident_type: str
    kind: str
    title: str
    description: str = ""
    enabled: bool = True
    strong_at: float = 4.0
    severity: str = "medium"
    severity_because: str = ""
    severity_when: tuple[Escalation, ...] = ()
    # threshold
    matcher: Matcher | None = None
    group_by: tuple[str, ...] = ()
    window_seconds: float = 0
    threshold: int = 0
    distinct: tuple[str, ...] = ()
    capture: tuple[str, ...] = ()
    tags: tuple[Tag, ...] = ()
    followed_by: FollowedBy | None = None
    related: Related | None = None
    # sequence and absence
    first: Matcher | None = None
    then: Matcher | None = None
    same: tuple[str, ...] = ()
    within_seconds: float = 0


# --- Parsing ---------------------------------------------------------------------------------


class _Reader:
    """Reads one rule's table, turning every problem into a RuleError that names the rule."""

    def __init__(self, rule_name: str, table: dict, where: str = "") -> None:
        self.rule_name = rule_name
        self.table = table
        self.where = where

    def fail(self, key: str, problem: str) -> RuleError:
        return RuleError(f"rule {self.rule_name!r}: {self.where}{key} {problem}")

    def check_keys(self, allowed: set[str]) -> None:
        for key in self.table:
            if key not in allowed:
                known = ", ".join(sorted(allowed))
                raise self.fail(key, f"is not a known setting (known: {known})")

    def text(self, key: str, default: str | None = None) -> str:
        value = self.table.get(key, default)
        if not isinstance(value, str) or not value.strip():
            raise self.fail(key, "must be a non-empty text value")
        return value

    def number(self, key: str, default: float | None = None, *, whole: bool = False):
        value = self.table.get(key, default)
        if isinstance(value, bool) or not isinstance(value, int | float) or value <= 0:
            raise self.fail(key, "must be a number greater than zero")
        if whole and not float(value).is_integer():
            raise self.fail(key, "must be a whole number")
        return int(value) if whole else float(value)

    def level(self, key: str, default: str | None = None) -> str:
        value = self.table.get(key, default)
        if value not in LEVELS:
            raise self.fail(key, f"is {value!r}; it must be one of: {', '.join(LEVELS)}")
        return value

    def fields(self, key: str, *, required: bool = True) -> tuple[str, ...]:
        value = self.table.get(key, [])
        if not isinstance(value, list) or (required and not value):
            need = " with at least one" if required else ""
            raise self.fail(key, f"must be a list of field names{need}")
        for name in value:
            if not _is_field(name):
                raise self.fail(key, f"names {name!r}, which is not a field of an event")
        return tuple(value)

    def conditions(self, key: str) -> dict[str, tuple]:
        value = self.table.get(key, {})
        if not isinstance(value, dict):
            raise self.fail(key, "must be a table of field = value")
        out = {}
        for name, allowed in value.items():
            if not _is_field(name):
                raise self.fail(key, f"names {name!r}, which is not a field of an event")
            out[name] = tuple(allowed) if isinstance(allowed, list) else (allowed,)
        return out

    def matcher(self) -> Matcher:
        keys = self.table.get("event_keys")
        if not isinstance(keys, list) or not keys or not all(isinstance(k, str) for k in keys):
            raise self.fail("event_keys", "must be a list with at least one message type")
        return Matcher(tuple(keys), self.conditions("where"), self.conditions("where_not"))

    def sub(self, key: str) -> _Reader:
        value = self.table.get(key)
        if not isinstance(value, dict):
            raise self.fail(key, "is required and must be a table")
        return _Reader(self.rule_name, value, f"{key}.")

    def entries(self, key: str) -> list[_Reader]:
        value = self.table.get(key, [])
        if not isinstance(value, list) or not all(isinstance(entry, dict) for entry in value):
            raise self.fail(key, "must be a list of tables")
        return [_Reader(self.rule_name, entry, f"{key}.") for entry in value]


def _check_title(reader: _Reader, title: str, known: set[str]) -> None:
    try:
        names = {name for _, name, _, _ in string.Formatter().parse(title) if name}
    except ValueError as error:
        raise reader.fail("title", f"is not a valid template: {error}") from None
    for name in names - known:
        raise reader.fail("title", f"uses {{{name}}}, which this rule does not provide")


def _escalations(reader: _Reader, flags: set[str] | None) -> tuple[Escalation, ...]:
    out = []
    for entry in reader.entries("severity_when"):
        entry.check_keys(_ESCALATION_KEYS)
        flag = entry.table.get("flag")
        strength = entry.table.get("strength_at_least")
        if (flag is None) == (strength is None):
            raise entry.fail("flag", "or strength_at_least must be given, and only one of them")
        if flag is not None and flags is not None and flag not in flags:
            raise entry.fail("flag", f"is {flag!r}, which this rule never sets")
        if strength is not None:
            strength = entry.number("strength_at_least")
        out.append(Escalation(entry.level("level"), entry.text("because"), flag, strength))
    return tuple(out)


def _parse_rule(table: dict) -> Rule:
    name = table.get("name")
    if not isinstance(name, str) or not name.strip():
        raise RuleError('a rule has no name; every [[rule]] needs name = "..."')
    reader = _Reader(name, table)
    kind = reader.text("kind")
    if kind not in KINDS:
        raise reader.fail("kind", f"is {kind!r}; it must be one of: {', '.join(KINDS)}")
    reader.check_keys(_KEYS_BY_KIND[kind])
    enabled = table.get("enabled", True)
    if not isinstance(enabled, bool):
        raise reader.fail("enabled", "must be true or false")
    common = {
        "name": name,
        "incident_type": reader.text("incident_type"),
        "kind": kind,
        "title": reader.text("title"),
        "description": table.get("description", ""),
        "enabled": enabled,
        "strong_at": reader.number("strong_at", 4.0),
        "severity": reader.level("severity", "medium"),
        "severity_because": table.get("severity_because", ""),
    }
    title_fields = {"host", "count", "duration"}

    if kind == "threshold":
        group_by = reader.fields("group_by")
        distinct = reader.fields("distinct", required=False)
        capture = reader.fields("capture", required=False)
        metrics = {"peak_count", "threshold", "window_seconds", "rate_per_minute"}
        metrics |= {f"distinct_{metric_name(name)}" for name in distinct}
        flags: set[str] = set()
        tags = []
        for entry in reader.entries("tags"):
            entry.check_keys({"name", "metric", "at_least"})
            metric = entry.text("metric")
            if metric not in metrics | {"count"}:
                raise entry.fail("metric", f"is {metric!r}, which this rule does not measure")
            tags.append(Tag(entry.text("name"), metric, entry.number("at_least")))
            flags.add(tags[-1].name)
        followed_by = None
        if "followed_by" in table:
            sub = reader.sub("followed_by")
            sub.check_keys(_FOLLOWED_BY_KEYS)
            followed_by = FollowedBy(
                flag=sub.text("flag"),
                matcher=sub.matcher(),
                same=sub.fields("same"),
                within_seconds=sub.number("within_seconds"),
                after=sub.table.get("after", "threshold"),
            )
            if followed_by.after not in ("threshold", "last"):
                raise sub.fail("after", 'must be "threshold" or "last"')
            flags.add(followed_by.flag)
            for shared in followed_by.same:
                if shared not in group_by:
                    raise sub.fail("same", f"names {shared!r}, which is not in group_by")
        related = None
        if "related" in table:
            sub = reader.sub("related")
            sub.check_keys(_RELATED_KEYS)
            related = Related(
                matcher=sub.matcher(),
                same=sub.fields("same"),
                margin_seconds=sub.number("margin_seconds"),
                capture=sub.fields("capture", required=False),
            )
            for shared in related.same:
                if shared not in group_by:
                    raise sub.fail("same", f"names {shared!r}, which is not in group_by")
        group_names = {metric_name(name) for name in group_by}
        _check_title(reader, common["title"], title_fields | group_names | metrics)
        return Rule(
            **common,
            severity_when=_escalations(reader, flags),
            matcher=reader.matcher(),
            group_by=group_by,
            window_seconds=reader.number("window_seconds"),
            threshold=reader.number("threshold", whole=True),
            distinct=distinct,
            capture=capture,
            tags=tuple(tags),
            followed_by=followed_by,
            related=related,
        )

    same = reader.fields("same")
    first, then = reader.sub("first"), reader.sub("then")
    first.check_keys(_MATCHER_KEYS)
    then.check_keys(_MATCHER_KEYS)
    extra_fields = {"delay"} if kind == "sequence" else set()
    same_names = {metric_name(name) for name in same}
    _check_title(reader, common["title"], title_fields | same_names | extra_fields)
    return Rule(
        **common,
        severity_when=_escalations(reader, None if kind == "sequence" else {"not_recovered"}),
        first=first.matcher(),
        then=then.matcher(),
        same=same,
        within_seconds=reader.number("within_seconds"),
    )


def parse_rules(text: str, source: str = "rules") -> list[Rule]:
    """Parse rule definitions from TOML text."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise RuleError(f"{source} is not valid TOML: {error}") from None
    tables = data.get("rule", [])
    if not isinstance(tables, list):
        raise RuleError(f"{source}: rules must be written as [[rule]] tables")
    rules = [_parse_rule(table) for table in tables]
    seen: set[str] = set()
    for rule in rules:
        if rule.name in seen:
            raise RuleError(f"rule {rule.name!r} is defined twice in {source}")
        seen.add(rule.name)
    return rules


def load_rules(path: str | Path | None = None) -> list[Rule]:
    """The built-in rules, with a user file's rules replacing or adding to them.

    A user rule with the name of a built-in rule replaces it completely. The user file is
    `path`, or the file named by the NETLOG_RULES environment variable.
    """
    built_in = resources.files("netlog.config").joinpath("rules.toml").read_text(encoding="utf-8")
    rules = {rule.name: rule for rule in parse_rules(built_in, "the built-in rules")}

    path = path or os.environ.get("NETLOG_RULES")
    if path:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except FileNotFoundError:
            raise RuleError(f"rule file not found: {path}") from None
        rules.update({rule.name: rule for rule in parse_rules(text, str(path))})
    return list(rules.values())
