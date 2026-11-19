"""Loading the causal priors: the table of what can cause what."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

RELATIONS = ("same_interface", "same_host", "neighbor_is_cause", "link_peer")
# From strongest to weakest.
CERTAINTIES = ("direct", "plausible", "suspect")

_KEYS = {
    "name",
    "cause",
    "effect",
    "relation",
    "max_delay_seconds",
    "during",
    "effect_before_seconds",
    "certainty",
    "priority",
    "explanation",
}


class PriorError(ValueError):
    """The causal priors file has a mistake."""


@dataclass(frozen=True)
class Prior:
    name: str
    cause: tuple[str, ...]
    effect: tuple[str, ...]
    relation: str
    max_delay_seconds: float
    certainty: str
    priority: int
    explanation: str
    during: bool = False
    effect_before_seconds: float = 0.0


def _rules(table: dict, key: str, name: str) -> tuple[str, ...]:
    value = table.get(key)
    if not isinstance(value, list) or not value or not all(isinstance(v, str) for v in value):
        raise PriorError(f"prior {name!r}: {key} must be a list of rule names")
    return tuple(value)


def _number(table: dict, key: str, name: str, default: float | None = None) -> float:
    value = table.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        raise PriorError(f"prior {name!r}: {key} must be a number, zero or more")
    return float(value)


def parse_priors(text: str, source: str = "causal priors") -> list[Prior]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise PriorError(f"{source} is not valid TOML: {error}") from None

    priors, seen = [], set()
    for table in data.get("prior", []):
        name = table.get("name") if isinstance(table, dict) else None
        if not isinstance(name, str) or not name:
            raise PriorError(f"{source}: a prior has no name")
        if name in seen:
            raise PriorError(f"prior {name!r} is defined twice in {source}")
        seen.add(name)
        for key in table:
            if key not in _KEYS:
                raise PriorError(f"prior {name!r}: {key} is not a known setting")
        if table.get("relation") not in RELATIONS:
            raise PriorError(f"prior {name!r}: relation must be one of: {', '.join(RELATIONS)}")
        if table.get("certainty") not in CERTAINTIES:
            raise PriorError(
                f"prior {name!r}: certainty must be one of: {', '.join(CERTAINTIES)}"
            )
        explanation = table.get("explanation")
        if not isinstance(explanation, str) or not explanation.strip():
            raise PriorError(f"prior {name!r}: explanation must say what the mechanism is")
        priority = table.get("priority", 0)
        if isinstance(priority, bool) or not isinstance(priority, int):
            raise PriorError(f"prior {name!r}: priority must be a whole number")
        during = table.get("during", False)
        if not isinstance(during, bool):
            raise PriorError(f"prior {name!r}: during must be true or false")
        priors.append(
            Prior(
                name=name,
                cause=_rules(table, "cause", name),
                effect=_rules(table, "effect", name),
                relation=table["relation"],
                max_delay_seconds=_number(table, "max_delay_seconds", name),
                certainty=table["certainty"],
                priority=priority,
                explanation=explanation.strip(),
                during=during,
                effect_before_seconds=_number(table, "effect_before_seconds", name, 0.0),
            )
        )
    return priors


def load_priors(path: str | Path | None = None) -> list[Prior]:
    """The built-in priors, with a user file's priors replacing or adding to them by name.

    The user file is `path`, or the one named by the NETLOG_PRIORS environment variable.
    """
    built_in = resources.files("netlog.config").joinpath("causal_priors.toml")
    priors = {p.name: p for p in parse_priors(built_in.read_text(encoding="utf-8"))}
    path = path or os.environ.get("NETLOG_PRIORS")
    if path:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except FileNotFoundError:
            raise PriorError(f"causal priors file not found: {path}") from None
        priors.update({p.name: p for p in parse_priors(text, str(path))})
    return list(priors.values())
