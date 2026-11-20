"""The validator: checks an explanation against the evidence pack it was written from.

An LLM can write a fluent explanation that cites a log line which does not exist, names
an interface nobody mentioned, or does what a username in the logs told it to do. None
of that may reach the reader. Every explanation is put through seven checks, and each
one that fails gives a specific reason:

    1. citations_exist         every cited id is in the pack
    2. citations_present       every timeline step and every hypothesis cites something
    3. entities_in_pack        every address, token, interface and time mentioned in the
                               text is in the pack
    4. facts_not_contradicted  no other severity, no other root cause, no higher
                               confidence, and no claim that nothing happened
    5. no_links_or_html        no web links, no HTML, no script
    6. length_limits           no field longer than allowed
    7. changes_flagged         a step that changes a device is marked "review before
                               running", and verification commands change nothing

The checks are plain code and read nothing but the explanation and the pack, so the same
answer always gets the same verdict.

What check 3 can and cannot see: with redaction on (the default), device names and
usernames are tokens such as HOST_2 and USER_3, and a token that is not in the pack is
caught. With redaction switched off, a made-up device name or username is an ordinary
word and cannot be told from any other word; addresses, interfaces and times are still
checked.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from netlog.config import load_config
from netlog.llm.evidence import EvidencePack
from netlog.llm.explanation import Explanation
from netlog.redaction.redactor import find_values
from netlog.schema import normalize_interface

CHECKS = (
    "citations_exist",
    "citations_present",
    "entities_in_pack",
    "facts_not_contradicted",
    "no_links_or_html",
    "length_limits",
    "changes_flagged",
)
SEVERITIES = ("info", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")
# A value quoted in a reason is cut to this length. Reasons are sent back to the LLM on
# the retry, and they should carry as little of its own text as possible.
_QUOTE_CHARS = 60

_LEVEL = r"(?P<level>informational|info|low|medium|moderate|high|critical)"
_SEVERITY_STATED = (
    re.compile(
        r"\bseverity(?:\s+level)?"
        r"(?:\s+(?:is|was|of|to|as|at|remains|stays|rated|set|should|be|now|only|just))*"
        rf"\s*[:=]?\s*[\"']?{_LEVEL}\b",
        re.IGNORECASE,
    ),
    re.compile(rf"\b{_LEVEL}[- ]severity\b", re.IGNORECASE),
)
_CONFIDENCE_STATED = (
    re.compile(
        r"\bconfidence(?:\s+level)?"
        r"(?:\s+(?:is|was|of|to|as|at|remains|stays|rated|set|should|be|now))*"
        rf"\s*[:=]?\s*[\"']?{_LEVEL}\b",
        re.IGNORECASE,
    ),
    re.compile(rf"\b{_LEVEL}(?:er)?[- ]confidence\b", re.IGNORECASE),
)
_LEVEL_NAMES = {"informational": "info", "moderate": "medium"}

_ISO_TIME = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?")
_ISO_DATE = re.compile(r"(?<![\d-])(\d{4})-(\d{2})-(\d{2})(?![\d-])")
_CLOCK = re.compile(
    r"(?<![\d:.])(\d{1,2}):(\d{2})(?::(\d{2})(\.\d+)?)?(?![\d:])(?:\s*([AaPp])\.?[Mm]\b)?"
)
_MONTHS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
_MONTH = r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*"
_MONTH_DAY = re.compile(rf"\b{_MONTH}\.?\s+(\d{{1,2}})\b(?![:/.]\d)")
_DAY_MONTH = re.compile(rf"\b(\d{{1,2}})(?:st|nd|rd|th)?\s+(?:of\s+)?{_MONTH}\b")

_LINK = re.compile(
    r"(?:https?|ftp|file)://|\bwww\.\w|\]\s*\(|\bjavascript\s*:|\bdata\s*:\s*text/", re.IGNORECASE
)
_TAG = re.compile(r"<\s*[/!?]?\s*[A-Za-z*][^<>]*>")
_ENTITY = re.compile(r"&(?:#\d+|#x[0-9a-f]+|[a-z]{2,8});", re.IGNORECASE)
# Placeholders the tool itself writes into message patterns (`<IP>`, `<*>`), besides the
# names of the mining masks.
_OWN_PLACEHOLDERS = {"*", "USER", "HOST"}


@dataclass(frozen=True)
class Problem:
    """One failed check: which check, where in the explanation, and why."""

    check: str
    where: str
    reason: str

    def __str__(self) -> str:
        return f"{self.where}: {self.reason}"


@dataclass(frozen=True)
class _Text:
    where: str  # "summary", "timeline step 2" ...
    kind: str  # summary, timeline, hypothesis, impact, fix, command, purpose, unknown
    text: str


def _quote(value: str) -> str:
    value = " ".join(value.split())
    if len(value) > _QUOTE_CHARS:
        value = value[: _QUOTE_CHARS - 3] + "..."
    return '"' + value.replace("<", "(").replace(">", ")") + '"'


def _texts(explanation: Explanation) -> Iterator[_Text]:
    yield _Text("summary", "summary", explanation.summary)
    for n, step in enumerate(explanation.timeline, 1):
        yield _Text(f"timeline step {n}", "timeline", step.text)
    for n, hypothesis in enumerate(explanation.hypotheses, 1):
        yield _Text(f"hypothesis {n}", "hypothesis", hypothesis.text)
    for n, impact in enumerate(explanation.impact, 1):
        yield _Text(f"impact {n}", "impact", impact.text)
    for n, fix in enumerate(explanation.fix_steps, 1):
        yield _Text(f"fix step {n}", "fix", fix.text)
    for n, command in enumerate(explanation.verification_commands, 1):
        yield _Text(f"verification command {n}", "command", command.command)
        yield _Text(f"verification command {n} (purpose)", "purpose", command.purpose)
    for n, unknown in enumerate(explanation.unknowns, 1):
        yield _Text(f"unknown {n}", "unknown", unknown)


def _citations(explanation: Explanation) -> Iterator[tuple[str, list[str]]]:
    for n, step in enumerate(explanation.timeline, 1):
        yield f"timeline step {n}", step.evidence
    for n, hypothesis in enumerate(explanation.hypotheses, 1):
        yield f"hypothesis {n}", hypothesis.supporting
        yield f"hypothesis {n} (contradicting)", hypothesis.contradicting
    for n, impact in enumerate(explanation.impact, 1):
        yield f"impact {n}", impact.evidence


def citation_counts(explanation: Explanation, pack: EvidencePack) -> tuple[int, int]:
    """How many of the explanation's citations name an id that is in the pack, and how
    many citations there are."""
    ids = pack.ids
    cited = [cid for _, group in _citations(explanation) for cid in group]
    return sum(1 for cid in cited if cid in ids), len(cited)


# --- Checks 1 and 2: citations -----------------------------------------------------------


def _check_citations_exist(explanation: Explanation, pack: EvidencePack) -> Iterator[Problem]:
    ids = pack.ids
    for where, cited in _citations(explanation):
        missing = [cid for cid in cited if cid not in ids]
        if missing:
            listed = ", ".join(_quote(cid) for cid in missing[:5])
            yield Problem(
                "citations_exist", where, f"cites {listed}, which is not an id in the evidence pack"
            )


def _check_citations_present(explanation: Explanation) -> Iterator[Problem]:
    for n, step in enumerate(explanation.timeline, 1):
        if not step.evidence:
            yield Problem("citations_present", f"timeline step {n}", "cites no evidence id")
    for n, hypothesis in enumerate(explanation.hypotheses, 1):
        if not hypothesis.supporting:
            yield Problem(
                "citations_present", f"hypothesis {n}", "cites no supporting evidence id"
            )


# --- Check 3: nothing mentioned that is not in the pack ----------------------------------


def _clock_times(text: str) -> list[tuple[float, float, str]]:
    """Times of day in a text, as (seconds since midnight, how exact, as written)."""
    found = []
    for match in _CLOCK.finditer(text):
        hour, minute, second, fraction, half = match.groups()
        hour = int(hour)
        if half and half.lower() == "p" and hour < 12:
            hour += 12
        elif half and half.lower() == "a" and hour == 12:
            hour = 0
        if hour > 23 or int(minute) > 59 or int(second or 0) > 59:
            continue
        moment = hour * 3600 + int(minute) * 60 + int(second or 0) + float(fraction or 0)
        if second is None:
            exact = 60.0  # written to the minute
        elif fraction is None:
            exact = 1.0
        else:
            exact = 10.0 ** -(len(fraction) - 1)
        found.append((moment, exact, match.group(0).strip()))
    return found


class _PackFacts:
    """What an explanation is allowed to mention, read from the pack once."""

    def __init__(self, pack: EvidencePack, interface: re.Pattern[str] | None) -> None:
        text = pack.to_json()
        self.values = {value for _, value in find_values(text)}
        self.interface = interface
        self.interfaces = self._interfaces(text)
        self.times = [moment for moment, _, _ in _clock_times(text)]
        self.dates = set()
        for match in _ISO_TIME.finditer(text):
            year, month, day = (int(part) for part in match.groups()[:3])
            self.dates.add((year, month, day))

    def _interfaces(self, text: str) -> set[str]:
        if self.interface is None:
            return set()
        return {normalize_interface(match.group(0)) for match in self.interface.finditer(text)}

    def has_time(self, moment: float, exact: float) -> bool:
        # A time may be cut short or rounded: 02:46:11.719 written as 02:46:11 or 02:46:12.
        return any(abs(known - moment) <= exact for known in self.times)

    def has_month_day(self, month: int, day: int) -> bool:
        return any((m, d) == (month, day) for _, m, d in self.dates)


def _check_entities(explanation: Explanation, facts: _PackFacts) -> Iterator[Problem]:
    for item in _texts(explanation):
        text = item.text
        for kind, value in find_values(text):
            if value not in facts.values:
                what = {"token": "the token", "mac": "the MAC address", "ip": "the address"}[kind]
                yield Problem(
                    "entities_in_pack",
                    item.where,
                    f"mentions {what} {_quote(value)}, which is not in the evidence pack",
                )
        if facts.interface is not None:
            for match in facts.interface.finditer(text):
                if normalize_interface(match.group(0)) not in facts.interfaces:
                    yield Problem(
                        "entities_in_pack",
                        item.where,
                        f"mentions the interface {_quote(match.group(0))}, which is not in "
                        "the evidence pack",
                    )
        for moment, exact, written in _clock_times(text):
            if not facts.has_time(moment, exact):
                yield Problem(
                    "entities_in_pack",
                    item.where,
                    f"mentions the time {_quote(written)}, which is not in the evidence pack",
                )
        for match in _ISO_DATE.finditer(text):
            if tuple(int(part) for part in match.groups()) not in facts.dates:
                yield Problem(
                    "entities_in_pack",
                    item.where,
                    f"mentions the date {_quote(match.group(0))}, which is not in the "
                    "evidence pack",
                )
        named = [(m.group(1), m.group(2), m.group(0)) for m in _MONTH_DAY.finditer(text)]
        named += [(m.group(2), m.group(1), m.group(0)) for m in _DAY_MONTH.finditer(text)]
        for month, day, written in named:
            if not facts.has_month_day(_MONTHS.index(month.lower()) + 1, int(day)):
                yield Problem(
                    "entities_in_pack",
                    item.where,
                    f"mentions the date {_quote(written)}, which is not in the evidence pack",
                )


# --- Check 4: the facts the tool decided -------------------------------------------------


def _levels(patterns, text: str) -> Iterator[str]:
    for pattern in patterns:
        for match in pattern.finditer(text):
            level = match.group("level").lower()
            yield _LEVEL_NAMES.get(level, level)


def _check_facts(explanation: Explanation, pack: EvidencePack, rules: dict) -> Iterator[Problem]:
    incident = pack.data["incident"]
    severity, confidence = incident["severity"], incident["confidence"]
    # A finding inside the incident has a severity of its own, which may be repeated.
    allowed = {severity} | {finding["severity"] for finding in pack.data["findings"]}

    for item in _texts(explanation):
        for level in _levels(_SEVERITY_STATED, item.text):
            if level not in allowed:
                yield Problem(
                    "facts_not_contradicted",
                    item.where,
                    f"states the severity as {level}; the tool decided {severity}",
                )
        for level in _levels(_CONFIDENCE_STATED, item.text):
            if level in CONFIDENCES and confidence in CONFIDENCES:
                if CONFIDENCES.index(level) > CONFIDENCES.index(confidence):
                    yield Problem(
                        "facts_not_contradicted",
                        item.where,
                        f"states a {level} confidence; the tool decided {confidence}",
                    )
        for pattern in rules["denials"]:
            match = pattern.search(item.text)
            if match:
                yield Problem(
                    "facts_not_contradicted",
                    item.where,
                    f"says {_quote(match.group(0))}; the tool found an incident of "
                    f"severity {severity}, and the explanation may not deny it",
                )
        if item.kind in ("summary", "timeline", "hypothesis", "impact"):
            for pattern in rules["overclaims"]:
                match = pattern.search(item.text)
                if match:
                    yield Problem(
                        "facts_not_contradicted",
                        item.where,
                        f"says {_quote(match.group(0))}, which claims more certainty than "
                        f'the tool\'s {confidence} confidence; write "likely cause"',
                    )

    # The first hypothesis must be the root cause the tool chose. Free text cannot be
    # compared with it, but its citations can: it has to rest on the root-cause findings.
    root = pack.data.get("root_cause") or {}
    root_ids = set(root.get("findings", []))
    if root_ids and explanation.hypotheses:
        lines = {
            line
            for finding in pack.data["findings"]
            if finding["id"] in root_ids
            for line in finding["evidence"]
        }
        first = explanation.hypotheses[0]
        listed = ", ".join(sorted(root_ids))
        if not (root_ids | lines) & set(first.supporting):
            yield Problem(
                "facts_not_contradicted",
                "hypothesis 1",
                f"does not cite the root cause the tool chose ({listed}); the first "
                "hypothesis must be that root cause",
            )
        if root_ids & set(first.contradicting):
            yield Problem(
                "facts_not_contradicted",
                "hypothesis 1",
                f"lists the tool's root cause ({listed}) as evidence against itself",
            )


# --- Checks 5 and 6: links, HTML and length ----------------------------------------------


def _check_links_and_html(explanation: Explanation, placeholders: set[str]) -> Iterator[Problem]:
    for item in _texts(explanation):
        match = _LINK.search(item.text)
        if match:
            yield Problem("no_links_or_html", item.where, "contains a web link")
        for match in _TAG.finditer(item.text):
            if match.group(0)[1:-1].strip() in placeholders:
                continue  # `<IP>` or `<*>`, copied from a message pattern in the pack
            yield Problem(
                "no_links_or_html", item.where, f"contains HTML or script: {_quote(match.group(0))}"
            )
            break
        if _ENTITY.search(item.text):
            yield Problem("no_links_or_html", item.where, "contains an HTML character entity")


def _check_lengths(explanation: Explanation, rules: dict) -> Iterator[Problem]:
    for item in _texts(explanation):
        limit = rules[
            {"summary": "max_summary_chars", "command": "max_command_chars"}.get(
                item.kind, "max_text_chars"
            )
        ]
        if len(item.text) > limit:
            yield Problem(
                "length_limits",
                item.where,
                f"is {len(item.text):,} characters long; the limit is {limit:,}",
            )
    lists = {
        "timeline": explanation.timeline,
        "hypotheses": explanation.hypotheses,
        "impact": explanation.impact,
        "fix steps": explanation.fix_steps,
        "verification commands": explanation.verification_commands,
        "unknowns": explanation.unknowns,
    }
    for name, items in lists.items():
        if len(items) > rules["max_items"]:
            yield Problem(
                "length_limits",
                name,
                f"has {len(items)} items; the limit is {rules['max_items']}",
            )
    for where, cited in _citations(explanation):
        if len(cited) > rules["max_citations"]:
            yield Problem(
                "length_limits",
                where,
                f"cites {len(cited)} ids; the limit is {rules['max_citations']}",
            )


# --- Check 7: commands that change a device ----------------------------------------------


def changes_something(text: str, rules: dict) -> str | None:
    """The part of a step or command that would change a device's configuration or
    state, or None when nothing in it would."""
    for pattern in (*rules["change_commands"], rules["change_verbs"]):
        match = pattern.search(text)
        if match:
            return match.group(0).strip(" .;!?")
    return None


def _check_changes(explanation: Explanation, rules: dict) -> Iterator[Problem]:
    for n, fix in enumerate(explanation.fix_steps, 1):
        change = None if fix.changes_configuration else changes_something(fix.text, rules)
        if change:
            yield Problem(
                "changes_flagged",
                f"fix step {n}",
                f"would change a device ({_quote(change)}) but is not marked: set "
                "changes_configuration to true so that it is reviewed before running",
            )
    for n, command in enumerate(explanation.verification_commands, 1):
        change = changes_something(command.command, rules)
        if change:
            yield Problem(
                "changes_flagged",
                f"verification command {n}",
                f"would change a device ({_quote(change)}); verification commands must be "
                "read-only, so move it to the fix steps and mark it",
            )


# --- Putting it together -----------------------------------------------------------------


def _compile(patterns, name: str) -> list[re.Pattern[str]]:
    compiled = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(pattern, re.IGNORECASE))
        except re.error as error:
            raise ValueError(
                f"validation.{name}: {pattern!r} is not a valid pattern: {error}"
            ) from None
    return compiled


def validation_rules(config: dict | None = None) -> dict:
    """The validator's settings, with every pattern compiled."""
    config = config or load_config()
    settings = config["validation"]
    rules: dict = {}
    for name in (
        "max_summary_chars", "max_text_chars", "max_command_chars", "max_items", "max_citations"
    ):
        if settings[name] <= 0:
            raise ValueError(f"validation.{name} must be greater than zero")
        rules[name] = int(settings[name])
    for name in ("denials", "overclaims", "change_commands"):
        rules[name] = _compile(settings[name], name)

    verbs = sorted((re.escape(verb).replace(r"\ ", r"\s+") for verb in settings["change_verbs"]),
                   key=len, reverse=True)
    verb = f"(?:{'|'.join(verbs) or '(?!)'})"
    # At the start of the step or of a sentence in it, or after "then". After "and" or
    # "or" only when an object follows ("and reset the port"), because many of these
    # words are also nouns ("any maintenance or change").
    start = r"(?:^\s*|[.;:!?]\s+|\b(?:then|otherwise|please)\s+)"
    article = r"(?:the|it|its|that|this|these|those|them|all|any|a|an|each|every)"
    rules["change_verbs"] = re.compile(
        rf"{start}{verb}\b|\b(?:and|or)\s+{verb}\s+{article}\b", re.IGNORECASE
    )

    masks = config["mining"]["masks"]
    rules["placeholders"] = {mask["name"] for mask in masks} | _OWN_PLACEHOLDERS
    interfaces = [mask["pattern"] for mask in masks if mask["name"] == "IF"]
    rules["interface"] = re.compile("|".join(interfaces)) if interfaces else None
    return rules


def validate_explanation(
    explanation: Explanation, pack: EvidencePack, config: dict | None = None
) -> list[Problem]:
    """Check an explanation against the pack it was written from.

    `pack` must be the pack the writer was given: the redacted one, when redaction is
    on. Returns every problem found; an empty list means the explanation may be shown.
    """
    rules = validation_rules(config)
    facts = _PackFacts(pack, rules["interface"])
    problems = [
        *_check_citations_exist(explanation, pack),
        *_check_citations_present(explanation),
        *_check_entities(explanation, facts),
        *_check_facts(explanation, pack, rules),
        *_check_links_and_html(explanation, rules["placeholders"]),
        *_check_lengths(explanation, rules),
        *_check_changes(explanation, rules),
    ]
    return list(dict.fromkeys(problems))  # the same problem is reported once


def describe_problems(problems: list[Problem], limit: int = 12) -> str:
    """The problems as a list to read, or to send back to the LLM."""
    lines = [f"- {problem}" for problem in problems[:limit]]
    if len(problems) > limit:
        lines.append(f"- and {len(problems) - limit} more")
    return "\n".join(lines)

