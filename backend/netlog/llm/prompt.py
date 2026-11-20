"""Loads the prompt from its own file and fills it in.

The wording lives in `prompts/explain_v1.md`, not in code, so it can be read, reviewed
and changed like any other document. The prompt version is the file's name plus a
fingerprint of its content: edit a word and the version changes, so an answer cached
under the old wording is never mistaken for an answer to the new one.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from functools import cache
from importlib import resources

from netlog.llm.evidence import EvidencePack
from netlog.llm.explanation import MODES

_PART = re.compile(r"(?m)^=== (.+?) ===[ \t]*\n")


@dataclass(frozen=True)
class Prompt:
    version: str
    system: str
    user: str  # with {mode} and {pack} still to be filled in
    modes: dict[str, str]

    def render(self, pack: EvidencePack, mode: str) -> tuple[str, str]:
        """The system text and the user message for one pack."""
        if mode not in self.modes:
            raise ValueError(f"unknown audience mode {mode!r}; choose from {', '.join(MODES)}")
        # The pack is JSON. Writing "<" as its JSON escape keeps it the same data while
        # making it impossible for log text to close the <evidence_pack> block early
        # and continue as if it were our instructions.
        data = pack.to_json().replace("<", "\\u003c")
        user = self.user.replace("{mode}", self.modes[mode]).replace("{pack}", data)
        return self.system, user


@cache
def load_prompt(name: str = "explain_v1") -> Prompt:
    if not re.fullmatch(r"[A-Za-z0-9_]+", name):
        raise ValueError(f"not a prompt name: {name!r}")
    try:
        text = resources.files(__package__).joinpath("prompts", f"{name}.md").read_text("utf-8")
    except FileNotFoundError:
        raise ValueError(f"prompt file not found: prompts/{name}.md") from None
    text = text.replace("\r\n", "\n")

    pieces = _PART.split(text)[1:]  # what comes before the first part is a note
    parts = {pieces[i].strip(): pieces[i + 1].strip() for i in range(0, len(pieces), 2)}
    modes = {key.split(":", 1)[1].strip(): value for key, value in parts.items() if ":" in key}
    missing = [part for part in ("system", "user") if part not in parts]
    missing += [f"mode: {mode}" for mode in MODES if mode not in modes]
    if missing:
        raise ValueError(f"prompt {name} lacks the part(s): {', '.join(missing)}")
    for placeholder in ("{mode}", "{pack}"):
        if placeholder not in parts["user"]:
            raise ValueError(f"prompt {name}: the user part must contain {placeholder}")

    fingerprint = hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]
    return Prompt(
        version=f"{name}-{fingerprint}",
        system=parts["system"],
        user=parts["user"],
        modes=modes,
    )
