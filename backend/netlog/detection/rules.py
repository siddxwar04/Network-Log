"""Rule definitions: loading them from TOML and checking they make sense.

Rules are data. The engine knows how to run four kinds of rule; everything specific to
one kind of problem (which messages, which thresholds, what to call it, how serious it
is) lives in `config/rules.toml`.
"""

from __future__ import annotations

import json
import os
import string
import tomllib
from dataclasses import dataclass, field, replace
from importlib import resources
from pathlib import Path

from netlog.schema import Event
from netlog.storage.database import ENTITY_COLUMNS

_TOP_FIELDS = ("host", "app", "source_type", "severity", "event_key")
KINDS = ("threshold", "sequence", "absence", "share")
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
        "count_distinct",
        "distinct",
        "capture",
        "tags",
        "followed_by",
        "related",
    },
    "sequence": _PAIR_KEYS,
    "absence": _PAIR_KEYS,
    "share": _COMMON_KEYS
    | _MATCHER_KEYS
    | {"of", "group_by", "window_seconds", "threshold", "share", "distinct", "capture"},
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
    # Count how many different values of this field a window holds, instead of how many
    # events: one address reaching 500 different ports, not one port 500 times.
    count_distinct: str | None = None
    distinct: tuple[str, ...] = ()
    capture: tuple[str, ...] = ()
    tags: tuple[Tag, ...] = ()
    followed_by: FollowedBy | None = None
    related: Related | None = None
    # share: the events matched above, as a share of the events `of` matches
    of: Matcher | None = None
    share: float = 0.0
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
            raise self.fail(key, f"must be a number greater than zero, not {value!r}")
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
        parts = list(string.Formatter().parse(title))
    except ValueError as error:
        raise reader.fail("title", f"is not a valid template: {error}") from None
    # A title only names values. Formatting such as {count:>99999999} or {host!r} could
    # make a huge string or reach into Python, so it is refused.
    for _, name, spec, conversion in parts:
        if name is not None and (spec or conversion):
            raise reader.fail("title", f"formats {{{name}}}; write the name alone, as {{{name}}}")
    names = {name for _, name, _, _ in parts if name}
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

    if kind == "share":
        group_by = reader.fields("group_by")
        distinct = reader.fields("distinct", required=False)
        of = reader.sub("of")
        of.check_keys(_MATCHER_KEYS)
        metrics = {"total", "percent", "peak_percent", "threshold", "window_seconds"}
        metrics |= {f"distinct_{metric_name(name)}" for name in distinct}
        group_names = {metric_name(name) for name in group_by}
        _check_title(reader, common["title"], title_fields | group_names | metrics)
        share = reader.number("share")
        if share > 1:
            raise reader.fail("share", f"is a fraction from 0 to 1, such as 0.25, not {share!r}")
        return Rule(
            **common,
            severity_when=_escalations(reader, set()),
            matcher=reader.matcher(),
            of=of.matcher(),
            group_by=group_by,
            window_seconds=reader.number("window_seconds"),
            threshold=reader.number("threshold", whole=True),
            share=share,
            distinct=distinct,
            capture=reader.fields("capture", required=False),
        )

    if kind == "threshold":
        group_by = reader.fields("group_by")
        distinct = reader.fields("distinct", required=False)
        count_distinct = table.get("count_distinct")
        if count_distinct is not None:
            if not _is_field(count_distinct):
                raise reader.fail(
                    "count_distinct", f"names {count_distinct!r}, which is not a field of an event"
                )
            if count_distinct in group_by:
                raise reader.fail(
                    "count_distinct", "names a group_by field, which has one value per group"
                )
            if count_distinct not in distinct:
                distinct = (*distinct, count_distinct)
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
            count_distinct=count_distinct,
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


# --- A user's own rule file ------------------------------------------------------------------
#
# Besides [[rule]] tables, which add a rule or replace a built-in one of the same name, a
# user file may hold:
#
#   [[override]]   change some settings of an existing rule and keep the rest
#   [critical]     devices and interfaces whose findings are one level more serious

# The settings an override may change, and the kinds of rule each applies to.
OVERRIDABLE = {
    "enabled": KINDS,
    "severity": KINDS,
    "severity_because": KINDS,
    "strong_at": KINDS,
    "threshold": ("threshold", "share"),
    "window_seconds": ("threshold", "share"),
    "share": ("share",),
    "within_seconds": ("sequence", "absence"),
}
_CRITICAL_KEYS = {"devices", "interfaces"}
USER_FILE_SECTIONS = {"rule", "override", "critical"}


@dataclass
class RuleSet:
    """The rules in force: the built-in ones, changed and added to by a user file."""

    rules: list[Rule]
    # Not mistakes, but worth a look: a message type no parser produces may be a typo.
    warnings: list[str] = field(default_factory=list)
    critical_devices: list[str] = field(default_factory=list)
    critical_interfaces: list[dict] = field(default_factory=list)
    # Where each rule comes from: "built-in", "built-in, changed" or "your file".
    origin: dict[str, str] = field(default_factory=dict)
    overrides: dict[str, dict] = field(default_factory=dict)
    user_file: Path | None = None

    def by_name(self, name: str) -> Rule | None:
        return next((rule for rule in self.rules if rule.name == name), None)

    def severity_settings(self, config: dict) -> dict:
        """The settings with the user file's critical devices and interfaces added, for
        the severity rules to use."""
        severity = dict(config.get("severity", {}))
        devices = severity.get("critical_devices", [])
        interfaces = severity.get("critical_interfaces", [])
        severity["critical_devices"] = list(dict.fromkeys([*devices, *self.critical_devices]))
        severity["critical_interfaces"] = [
            *interfaces,
            *(entry for entry in self.critical_interfaces if entry not in interfaces),
        ]
        return {**config, "severity": severity}


def apply_override(rule: Rule, settings: dict) -> Rule:
    """The rule with some of its settings changed. Every value is checked the way it is
    checked in a [[rule]] table, and a setting that does not fit the rule is refused."""
    reader = _Reader(rule.name, settings, "override ")
    changes: dict = {}
    for key, value in settings.items():
        if key == "name":
            continue
        if key not in OVERRIDABLE:
            known = ", ".join(sorted(OVERRIDABLE))
            raise reader.fail(key, f"is not a setting an override can change (known: {known})")
        if rule.kind not in OVERRIDABLE[key]:
            raise reader.fail(key, f"does not apply to a {rule.kind} rule")
        if key == "enabled":
            if not isinstance(value, bool):
                raise reader.fail(key, "must be true or false")
            changes[key] = value
        elif key == "severity":
            changes[key] = reader.level(key)
        elif key == "severity_because":
            changes[key] = reader.text(key)
        elif key == "threshold":
            changes[key] = reader.number(key, whole=True)
        elif key == "share":
            changes[key] = reader.number(key)
            if changes[key] > 1:
                raise reader.fail(key, f"is a fraction from 0 to 1, such as 0.25, not {value!r}")
        else:
            changes[key] = reader.number(key)
    return replace(rule, **changes)


def _known_event_keys() -> set[str]:
    """The message types the parsers produce, for spotting a typo in a rule file."""
    from netlog.parsers import cisco, dhcp, dns, firewall, linux_auth

    known = set(cisco._EXTRACTORS) | firewall.known_event_keys() | dns.known_event_keys()
    for patterns in (linux_auth._SSHD, dhcp._DHCPD):
        known |= {key for key, _, _ in patterns._rules}
    known |= {"sudo.auth_failure", "sudo.not_in_sudoers", "dhcp.no_free_leases"}
    for service in ("sshd", "sudo", "cron", "login", "su"):
        known |= {f"{service}.session_opened", f"{service}.session_closed"}
    return known


def event_keys_of(rule: Rule) -> list[str]:
    """Every message type a rule looks at."""
    matchers = [rule.matcher, rule.of, rule.first, rule.then]
    if rule.followed_by:
        matchers.append(rule.followed_by.matcher)
    if rule.related:
        matchers.append(rule.related.matcher)
    return [key for matcher in matchers if matcher for key in matcher.event_keys]


def _critical(table: object, source: str) -> tuple[list[str], list[dict]]:
    if not isinstance(table, dict):
        raise RuleError(f"{source}: [critical] must be a table with devices and interfaces")
    for key in table:
        if key not in _CRITICAL_KEYS:
            raise RuleError(
                f"{source}: [critical] {key} is not a known setting (known: devices, interfaces)"
            )
    devices = table.get("devices", [])
    if not isinstance(devices, list) or not all(isinstance(d, str) and d for d in devices):
        raise RuleError(f"{source}: [critical] devices must be a list of device names")
    interfaces = table.get("interfaces", [])
    if not isinstance(interfaces, list):
        raise RuleError(f"{source}: [critical] interfaces must be a list of tables")
    for entry in interfaces:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"host", "interface"}
            or not all(isinstance(value, str) and value for value in entry.values())
        ):
            raise RuleError(
                f"{source}: [critical] each entry of interfaces must name a host and an "
                'interface, such as { host = "R1", interface = "GigabitEthernet0/1" }'
            )
    return devices, interfaces


# Names the user's rule file in place of `[rules] user_file`; the tests point it at a file
# that does not exist, so a developer's own rules never change what the tests find.
USER_FILE_ENV = "NETLOG_USER_RULES"


def user_rules_path(config: dict | None = None, path: str | Path | None = None) -> Path | None:
    """The user's rule file: the one given, else NETLOG_RULES, else NETLOG_USER_RULES,
    else `[rules] user_file` in the settings."""
    if path:
        return Path(path)
    if os.environ.get("NETLOG_RULES"):
        return Path(os.environ["NETLOG_RULES"])
    if USER_FILE_ENV in os.environ:
        return Path(os.environ[USER_FILE_ENV]) if os.environ[USER_FILE_ENV] else None
    configured = (config or {}).get("rules", {}).get("user_file")
    return Path(configured) if configured else None


def _read_user_file(result: RuleSet, rules: dict[str, Rule], known_keys: set[str]) -> None:
    user = result.user_file
    source = str(user)
    try:
        text = user.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise RuleError(f"rule file not found: {user}") from None
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise RuleError(f"{source} is not valid TOML: {error}") from None
    for key in data:
        if key not in USER_FILE_SECTIONS:
            raise RuleError(
                f"{source}: {key!r} is not a known section "
                "(known: [[rule]], [[override]], [critical])"
            )
    for rule in parse_rules(text, source):
        result.origin[rule.name] = "your file"
        for key in event_keys_of(rule):
            if key not in known_keys:
                result.warnings.append(
                    f"rule {rule.name!r}: event key {key!r} is not a message type netlog "
                    "knows; check the spelling (it is fine if your devices send it)"
                )
        rules[rule.name] = rule
    tables = data.get("override", [])
    if not isinstance(tables, list) or not all(isinstance(table, dict) for table in tables):
        raise RuleError(f"{source}: overrides must be written as [[override]] tables")
    for table in tables:
        name = table.get("name")
        if not isinstance(name, str) or not name:
            raise RuleError(f'{source}: an [[override]] has no name; it needs name = "..."')
        if name in result.overrides:
            raise RuleError(f"{source}: rule {name!r} is overridden twice")
        if name not in rules:
            raise RuleError(f"{source}: [[override]] names rule {name!r}, which does not exist")
        rules[name] = apply_override(rules[name], table)
        result.overrides[name] = {key: value for key, value in table.items() if key != "name"}
        if result.origin[name] == "built-in":
            result.origin[name] = "built-in, changed"
    if "critical" in data:
        result.critical_devices, result.critical_interfaces = _critical(data["critical"], source)


def load_rule_set(path: str | Path | None = None, config: dict | None = None) -> RuleSet:
    """The built-in rules with a user file applied.

    The user file is `path`, or the file named by NETLOG_RULES, or `[rules] user_file` in
    the settings when that file exists. A [[rule]] with the name of a built-in rule
    replaces it completely; an [[override]] changes some of its settings. Any mistake
    raises a RuleError naming the rule, the setting and the problem: a rule is never
    ignored without a word.
    """
    built_in = resources.files("netlog.config").joinpath("rules.toml").read_text(encoding="utf-8")
    rules = {rule.name: rule for rule in parse_rules(built_in, "the built-in rules")}
    result = RuleSet(rules=[], origin=dict.fromkeys(rules, "built-in"))
    known_keys = _known_event_keys() | {
        key for rule in rules.values() for key in event_keys_of(rule)
    }
    explicit = path or os.environ.get("NETLOG_RULES")
    user = user_rules_path(config, path)
    if user is not None and (explicit or user.is_file()):
        result.user_file = user
        _read_user_file(result, rules, known_keys)
    result.rules = list(rules.values())
    return result


def load_rules(path: str | Path | None = None) -> list[Rule]:
    """The built-in rules, with a user file's rules replacing or adding to them and its
    overrides applied. The user file is `path`, or the file named by NETLOG_RULES."""
    return load_rule_set(path).rules


# --- Changing the user file from the API -------------------------------------------------------


def _toml_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)  # a TOML basic string
    raise TypeError(f"cannot write {value!r} to a rule file")


def _override_name(block: list[str]) -> str | None:
    try:
        tables = tomllib.loads("\n".join(block)).get("override", [])
    except tomllib.TOMLDecodeError:
        return None
    return tables[0].get("name") if tables else None


def with_override(text: str, name: str, settings: dict) -> str:
    """The text of a user rule file with the [[override]] of one rule replaced by
    `settings`, or removed when `settings` is empty. Everything else in the file, comments
    included, is kept as it is."""
    lines = text.splitlines()
    kept: list[str] = []
    i = 0
    while i < len(lines):
        if lines[i].strip() == "[[override]]":
            end = i + 1
            while end < len(lines) and not lines[end].startswith("["):
                end += 1
            # Comments and blank lines after the last setting introduce what follows.
            last = end - 1
            while last > i and (not lines[last].strip() or lines[last].lstrip().startswith("#")):
                last -= 1
            block = lines[i : last + 1]
            if _override_name(block) != name:
                kept += block
            kept += lines[last + 1 : end]
            i = end
            continue
        kept.append(lines[i])
        i += 1
    while kept and not kept[-1].strip():
        kept.pop()
    if settings:
        if kept:
            kept.append("")
        kept += ["[[override]]", f"name = {_toml_value(name)}"]
        kept += [f"{key} = {_toml_value(value)}" for key, value in settings.items()]
    return "\n".join(kept) + "\n" if kept else ""
