"""The built-in explanation: written by code from the incident's facts, with no LLM.

It is used when no provider is configured, when the provider cannot be reached, and when
the LLM's answer fails validation twice. It is less fluent than an LLM's explanation and
always accurate, because every sentence in it is either a fact the tool decided or a
fixed text from `config/fallback.toml`.

It has the same structure as an LLM's explanation and cites the same evidence ids, so the
rest of the tool does not care which of the two it is given. It is built from the
evidence pack, like the LLM's: from the redacted pack it comes out with the same tokens
(HOST_1, IP_3) and is restored for the reader the same way.

Nothing from a raw log line is copied into it. It cites log lines by id and quotes only
texts the tool wrote itself, so text an attacker put into a log cannot end up in it as a
statement.

There are two wordings, like the LLM's. The senior one is terse and leads with the root
cause. The junior one adds what this kind of problem means, the terms a newcomer needs,
the mechanism behind each step of cause and effect, and why each check is worth doing.
The facts, the steps and the citations are the same in both.
"""

from __future__ import annotations

import tomllib
from functools import cache
from importlib import resources

from netlog.config import load_config
from netlog.llm.evidence import EvidencePack
from netlog.redaction.redactor import is_safe_in_command
from netlog.llm.explanation import (
    MODES,
    Explanation,
    FixStep,
    Hypothesis,
    Impact,
    TimelineStep,
    VerificationCommand,
)

DEFAULT = "default"
_CUT = "..."


@cache
def load_templates() -> dict:
    """The templates of `config/fallback.toml`, checked for the parts each must have."""
    text = resources.files("netlog.config").joinpath("fallback.toml").read_text(encoding="utf-8")
    data = tomllib.loads(text)
    templates, aliases = data.get("template", {}), data.get("aliases", {})
    if DEFAULT not in templates:
        raise ValueError("fallback.toml lacks [template.default]")
    for name, template in templates.items():
        for part in ("meaning", "terms", "impact", "checks", "commands", "unknowns"):
            if not template.get(part):
                raise ValueError(f"fallback.toml: [template.{name}] lacks `{part}`")
        for check in template["checks"]:
            if not check.get("text") or not check.get("why") or "changes" not in check:
                raise ValueError(
                    f"fallback.toml: a check of [template.{name}] lacks `text`, `why` or `changes`"
                )
    for alias, target in aliases.items():
        if target not in templates:
            raise ValueError(f"fallback.toml: alias {alias} names a missing template {target}")
    return {"templates": templates, "aliases": aliases}


def template_name(pack: EvidencePack) -> str:
    """Which template fits the incident: by its root cause, then by its kinds of problem."""
    loaded = load_templates()
    root = pack.data.get("root_cause") or {}
    for name in [root.get("kind"), *pack.data["incident"]["types"]]:
        name = loaded["aliases"].get(name, name)
        if name in loaded["templates"]:
            return name
    return DEFAULT


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: max(limit - len(_CUT), 0)].rstrip() + _CUT


def _sentence(text: str) -> str:
    text = text.strip()
    return text if text.endswith((".", "!", "?")) else text + "."


def _clock(moment: str) -> str:
    """`2026-03-03T02:46:11.719Z` -> `02:46:11 UTC`. Pack times are always UTC."""
    return f"{moment[11:19]} UTC"


def _fill(text: str, values: dict[str, str | None]) -> str | None:
    """A template text with its placeholders filled in, or None when one has no value."""
    for name, value in values.items():
        if "{" + name + "}" in text:
            if not value:
                return None
            text = text.replace("{" + name + "}", value)
    return text


def _delays(links: list[dict]) -> str:
    """How long after its cause a group of effects began: `at once`, `20.3s to 24.1s later`."""
    delays = sorted(link["delay_seconds"] for link in links)
    if delays[-1] < 1:
        return "at once"
    if delays[-1] - delays[0] < 1:
        return f"{delays[-1]:g}s later"
    return f"{max(delays[0], 0):g}s to {delays[-1]:g}s later"


def fallback_explanation(
    pack: EvidencePack, mode: str = "senior", config: dict | None = None
) -> Explanation:
    """The built-in explanation of the incident in `pack`, worded for a junior or a senior
    reader. The same pack and mode always give the same explanation."""
    if mode not in MODES:
        raise ValueError(f"unknown audience mode {mode!r}; choose from {', '.join(MODES)}")
    junior = mode == "junior"
    limits = (config or load_config())["validation"]
    text_limit, list_limit = int(limits["max_text_chars"]), int(limits["max_items"])
    cite_limit = int(limits["max_citations"])
    template = load_templates()["templates"][template_name(pack)]

    data = pack.data
    incident, root = data["incident"], data.get("root_cause")
    findings = data["findings"]
    problems = [f["id"] for f in findings if f["role"] != "context"] or [
        f["id"] for f in findings
    ]
    chain_ids = [step["id"] for step in data["chain"]]

    # --- Summary: what was seen, how serious, the likely cause, what it means -------------
    reason = incident["severity_reason"]
    level, _, rest = reason.partition(": ")
    if level.lower() == incident["severity"] and rest:
        reason = rest
    # A single finding is its own root cause; saying its title twice adds nothing.
    same = bool(root) and root["summary"].rstrip(".") == incident["title"].rstrip(".")
    if junior:
        sentences = [
            _sentence(incident["title"]),
            _sentence(f"Severity is {incident['severity']}: {reason}"),
        ]
        if root:
            cause = "That finding is itself the likely root cause" if same else (
                f"The likely root cause: {root['summary']}"
            )
            sentences.append(
                _sentence(
                    f"{cause} (the tool's confidence is {incident['confidence']}: "
                    f"{incident['confidence_reason']})"
                )
            )
        else:
            sentences.append("The logs do not point to one root cause.")
        sentences.append(_sentence(template["meaning"]))
        # The terms of this kind of problem, then of every other kind in the incident.
        loaded = load_templates()
        named = [template_name(pack), *incident["types"]]
        named = [loaded["aliases"].get(name, name) for name in named]
        for name in dict.fromkeys(name for name in named if name in loaded["templates"]):
            sentences.append(_sentence(loaded["templates"][name]["terms"]))
    else:
        # Terse, and the root cause first.
        if root:
            sentences = [
                _sentence(
                    f"Likely root cause: {root['summary']} (confidence {incident['confidence']})"
                )
            ]
        else:
            sentences = ["No single root cause in these logs."]
        sentences.append(f"Severity {incident['severity']}.")
        if not same:
            sentences.append(_sentence(incident["title"]))
    summary = ""
    for sentence in sentences:
        if len(summary) + len(sentence) + 1 > int(limits["max_summary_chars"]):
            break
        summary = f"{summary} {sentence}".strip()
    summary = summary or _clip(sentences[0], int(limits["max_summary_chars"]))

    # --- Timeline: the findings, in the order they started --------------------------------
    shown = findings[:list_limit]
    if len(findings) > list_limit:
        shown = findings[: list_limit - 1]
    timeline = [
        TimelineStep(
            text=_clip(f"{_clock(finding['start'])}: {_sentence(finding['title'])}", text_limit),
            evidence=[finding["id"], *finding["evidence"]][:cite_limit],
        )
        for finding in shown
    ]
    if len(findings) > len(shown):
        rest_ids = [finding["id"] for finding in findings[len(shown) :]]
        timeline.append(
            TimelineStep(
                text=f"{len(rest_ids)} more findings followed, from "
                f"{_clock(findings[len(shown)]['start'])} on.",
                evidence=rest_ids[:cite_limit],
            )
        )

    # --- Hypotheses: the root cause the tool chose, then its alternatives -----------------
    def supporting(cause: dict | None) -> list[str]:
        ids = list(cause["findings"]) if cause else []
        return (ids + chain_ids if ids else problems)[:cite_limit]

    hypotheses = []
    if root and junior:
        text = (
            f"The likely root cause: {_sentence(root['summary'])} It accounts for "
            f"{root['explains']} of the incident's {root['of']} findings. The tool's "
            f"confidence is {incident['confidence']}: {_sentence(incident['confidence_reason'])}"
        )
    elif root:
        text = (
            f"Likely root cause: {_sentence(root['summary'])} Accounts for {root['explains']} "
            f"of {root['of']} findings; confidence {incident['confidence']}."
        )
    elif junior:
        text = (
            "The logs do not point to one root cause. The findings in the timeline are what "
            "is known."
        )
    else:
        text = "No single root cause in these logs; see the timeline."
    hypotheses.append(
        Hypothesis(text=_clip(text, text_limit), supporting=supporting(root), contradicting=[])
    )
    for other in data["alternatives"][: max(list_limit - 1, 0)]:
        if junior:
            text = (
                f"A less likely alternative: {_sentence(other['summary'])} It would account "
                f"for {other['explains']} of the {other['of']} findings."
            )
        else:
            text = (
                f"Alternative: {_sentence(other['summary'])} Would account for "
                f"{other['explains']} of {other['of']} findings."
            )
        hypotheses.append(
            Hypothesis(
                text=_clip(text, text_limit), supporting=supporting(other), contradicting=[]
            )
        )

    # --- Impact: what this kind of problem affects, then each step of cause and effect ---
    impact = [Impact(text=_sentence(template["impact"]), evidence=problems[:cite_limit])]
    for step in data["chain"][: max(list_limit - 1, 0)]:
        effects = list(dict.fromkeys(link["effect"] for link in step["links"]))
        if junior:  # the mechanism, spelled out
            text = _sentence(step["explanation"])
        else:
            count = f"{len(effects)} finding{'' if len(effects) == 1 else 's'}"
            text = f"{step['certainty'].capitalize()} effect: {count}, {_delays(step['links'])}."
        impact.append(
            Impact(text=_clip(text, text_limit), evidence=[step["id"], *effects][:cite_limit])
        )

    # --- What to check, and how to confirm ------------------------------------------------
    devices = (root["devices"] if root else None) or incident["devices"]
    values = {"device": ", ".join(devices), "entity": root["entity"] if root else None}
    fix_steps = []
    for check in template["checks"][:list_limit]:
        text = _fill(check["text"], values)
        if text is not None and junior:
            text = f"{text} {_fill(check['why'], values) or ''}".strip()
        if text is not None:
            fix_steps.append(
                FixStep(text=_clip(text, text_limit), changes_configuration=bool(check["changes"]))
            )
    commands = []
    for item in template["commands"][:list_limit]:
        # A command is shown with a Copy button, so a value from a log goes into one only
        # when it is plainly a name or an address.
        command = _fill(
            item["command"],
            {key: value if is_safe_in_command(value) else None for key, value in values.items()},
        )
        if command is not None and len(command) <= int(limits["max_command_chars"]):
            commands.append(
                VerificationCommand(
                    command=command, purpose=_clip(_sentence(item["purpose"]), text_limit)
                )
            )

    unknowns = [_clip(text, text_limit) for text in data["unknowns"][:list_limit]]
    if not unknowns:
        unknowns = [_clip(text, text_limit) for text in template["unknowns"][:list_limit]]

    return Explanation(
        summary=summary,
        timeline=timeline,
        hypotheses=hypotheses,
        impact=impact,
        fix_steps=fix_steps,
        verification_commands=commands,
        unknowns=unknowns,
    )
