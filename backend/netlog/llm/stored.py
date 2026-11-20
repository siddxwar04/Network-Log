"""Explanations stored with the demo scenarios, so the demo works with no API key.

A real LLM explains each built-in scenario once, for each audience, and the answers are
kept in a data file in the repository (`[demo] explanations` in the settings). When the
same incident is explained later, its evidence pack is the same byte for byte, so its
hash finds the stored answer and no request is made.

What is stored is exactly what the LLM answered: redacted, with stand-ins such as HOST_1
and evidence ids such as E3. It is checked by the validator every time it is read, like
any answer from an LLM, and a stored answer that no longer passes is not used.

The file is data only. It is read as JSON and never executed.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from netlog.llm.evidence import EvidencePack
from netlog.llm.explanation import Explanation, ExplanationError, parse_explanation
from netlog.llm.validate import validate_explanation

FORMAT = 1


@dataclass(frozen=True)
class StoredAnswer:
    scenario: str
    pack_hash: str
    mode: str
    provider: str
    model: str
    prompt_version: str
    content: str  # the LLM's answer as JSON, redacted
    created_at: str


# Names another file of stored answers. The tests point it at a file that does not
# exist, so the answers kept in the repository never stand in for a test's fake LLM.
ENV_FILE = "NETLOG_DEMO_EXPLANATIONS"


def stored_path(config: dict) -> Path:
    if os.environ.get(ENV_FILE):
        return Path(os.environ[ENV_FILE])
    return Path(config.get("demo", {}).get("explanations", "data/scenarios/explanations.json"))


def load_stored(path: Path) -> dict[tuple[str, str], StoredAnswer]:
    """The stored answers by (pack hash, audience). A missing or unreadable file gives
    none: the demo then uses the built-in explanations."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        return {}
    found: dict[tuple[str, str], StoredAnswer] = {}
    for item in data.get("answers", []):
        try:
            answer = StoredAnswer(
                **{name: str(item[name]) for name in StoredAnswer.__annotations__}
            )
        except (KeyError, TypeError):
            continue
        found[(answer.pack_hash, answer.mode)] = answer
    return found


def find_stored(
    pack: EvidencePack, mode: str, config: dict, path: Path | None = None
) -> tuple[Explanation, StoredAnswer] | None:
    """The stored answer for this pack and audience, if there is one and it still passes
    every check against the pack."""
    answer = load_stored(path or stored_path(config)).get((pack.hash, mode))
    if answer is None:
        return None
    try:
        explanation = parse_explanation(answer.content)
    except ExplanationError:
        return None
    if validate_explanation(explanation, pack, config):
        return None
    return explanation, answer


def write_stored(path: Path, answers: list[StoredAnswer]) -> None:
    """Write the stored answers, sorted so that regenerating gives a small diff."""
    ordered = sorted(answers, key=lambda a: (a.scenario, a.mode, a.pack_hash))
    data = {
        "format": FORMAT,
        "about": (
            "Explanations of the built-in demo scenarios, written once by a real LLM and "
            "checked against the evidence. Regenerate with: netlog demo-explanations"
        ),
        "written": datetime.now(UTC).strftime("%Y-%m-%d"),
        "answers": [answer.__dict__ for answer in ordered],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
