"""The fixed structure of an explanation.

Free text from an LLM cannot be checked. An answer in this structure can: every step of
the timeline and every hypothesis names the evidence ids it rests on, and those ids can
be looked up in the evidence pack that was sent.

The same structure is used by the built-in fallback explanation, so the rest of the
tool does not care which of the two wrote it.
"""

from __future__ import annotations

import json

from pydantic import BaseModel, ConfigDict, ValidationError

MODES = ("junior", "senior")


class ExplanationError(ValueError):
    """The provider's answer is not an explanation in the agreed structure."""


class _Part(BaseModel):
    # Unknown fields are an error: an answer with extra fields is not the agreed structure.
    model_config = ConfigDict(extra="forbid")


class TimelineStep(_Part):
    """One thing that happened, in order."""

    text: str
    evidence: list[str]  # ids from the pack: E3, F1, C2 ...


class Hypothesis(_Part):
    """A likely root cause, with what speaks for it and what speaks against it."""

    text: str
    supporting: list[str]
    contradicting: list[str]


class Impact(_Part):
    """Something that was affected."""

    text: str
    evidence: list[str]


class FixStep(_Part):
    """Something to check or do. A step that changes a device's configuration is marked,
    so the reader reviews it before running it."""

    text: str
    changes_configuration: bool


class VerificationCommand(_Part):
    """A read-only command that confirms the diagnosis, such as a show command."""

    command: str
    purpose: str


class Explanation(_Part):
    summary: str
    timeline: list[TimelineStep]
    hypotheses: list[Hypothesis]
    impact: list[Impact]
    fix_steps: list[FixStep]
    verification_commands: list[VerificationCommand]
    unknowns: list[str]


def explanation_schema() -> dict:
    """The structure as a JSON schema, for a provider's structured-output feature."""
    return Explanation.model_json_schema()


def parse_explanation(text: str) -> Explanation:
    """Read a provider's answer. Anything that is not the agreed structure is rejected.

    Only the shape is checked here. Whether the cited ids exist and whether the text
    invents anything is the validator's job.
    """
    try:
        data = json.loads(text)
    except (TypeError, ValueError) as error:
        raise ExplanationError(f"the answer is not JSON: {error}") from None
    try:
        explanation = Explanation.model_validate(data)
    except ValidationError as error:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in issue['loc']) or 'answer'}: {issue['msg']}"
            for issue in error.errors()[:5]
        )
        raise ExplanationError(
            f"the answer does not have the agreed structure: {problems}"
        ) from None
    if not explanation.summary.strip():
        raise ExplanationError("the answer has an empty summary")
    if not explanation.timeline:
        raise ExplanationError("the answer has an empty timeline")
    if not explanation.hypotheses:
        raise ExplanationError("the answer has no root-cause hypothesis")
    return explanation
