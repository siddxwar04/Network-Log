"""Which LLM to use, read from the settings file and the environment.

The provider and the model can be set in either place; the environment wins. The API
key comes from the environment only. It is never written to a settings file, never
stored in the database and never printed: it is even left out of this object's repr.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass, field
from pathlib import Path

from netlog.config import load_config

ENV_PROVIDER = "NETLOG_LLM_PROVIDER"
ENV_MODEL = "NETLOG_LLM_MODEL"
ENV_KEY = "NETLOG_LLM_API_KEY"


def load_env_file(
    path: str | Path = ".env", environ: MutableMapping[str, str] | None = None
) -> list[str]:
    """Read `NAME=value` lines from a .env file into the environment.

    A variable that is already set keeps its value, so the shell can override the file.
    Returns the names that were set. A missing file is not an error.
    """
    environ = os.environ if environ is None else environ
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return []
    added = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.removeprefix("export ").strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if name and value and name not in environ:
            environ[name] = value
            added.append(name)
    return added


@dataclass(frozen=True)
class LLMSettings:
    provider: str  # empty when none is configured
    model: str  # empty means the provider's default
    api_key: str = field(repr=False, default="")
    timeout_seconds: float = 60.0
    max_retries: int = 3
    backoff_seconds: float = 2.0
    max_output_tokens: int = 4000
    reasoning_effort: str = ""
    prompt: str = "explain_v1"
    default_models: Mapping[str, str] = field(default_factory=dict)

    @property
    def configured(self) -> bool:
        return bool(self.provider)

    def model_for(self, provider_name: str) -> str:
        return self.model or self.default_models.get(provider_name, "") or provider_name


def llm_settings(
    config: dict | None = None, environ: Mapping[str, str] | None = None
) -> LLMSettings:
    settings = (config or load_config())["llm"]
    environ = os.environ if environ is None else environ
    for name in ("timeout_seconds", "max_output_tokens"):
        if settings[name] <= 0:
            raise ValueError(f"llm.{name} must be greater than zero")
    if settings["max_retries"] < 0 or settings["backoff_seconds"] < 0:
        raise ValueError("llm.max_retries and llm.backoff_seconds cannot be negative")
    if "api_key" in settings:
        raise ValueError(
            f"the API key does not belong in a settings file; set {ENV_KEY} in .env instead"
        )
    return LLMSettings(
        provider=(environ.get(ENV_PROVIDER) or settings["provider"] or "").strip().lower(),
        model=(environ.get(ENV_MODEL) or settings["model"] or "").strip(),
        api_key=(environ.get(ENV_KEY) or "").strip(),
        timeout_seconds=float(settings["timeout_seconds"]),
        max_retries=int(settings["max_retries"]),
        backoff_seconds=float(settings["backoff_seconds"]),
        max_output_tokens=int(settings["max_output_tokens"]),
        reasoning_effort=str(settings["reasoning_effort"]).strip(),
        prompt=str(settings["prompt"]),
        default_models=dict(settings.get("default_models", {})),
    )
