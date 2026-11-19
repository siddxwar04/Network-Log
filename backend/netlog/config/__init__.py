"""Settings: the defaults shipped with the package, overridden by an optional user file.

Thresholds, windows and other tunables live here and in `defaults.toml`, not in code.
"""

from __future__ import annotations

import os
import tomllib
from importlib import resources
from pathlib import Path


def _merge(base: dict, override: dict) -> dict:
    """Overlay `override` on `base`. Tables are merged; any other value is replaced."""
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(path: str | Path | None = None) -> dict:
    """Return the settings as nested dictionaries.

    `path` is a user file whose values replace the defaults. When it is not given, the
    file named by the NETLOG_CONFIG environment variable is used, if there is one.
    """
    defaults = resources.files(__package__).joinpath("defaults.toml").read_text(encoding="utf-8")
    config = tomllib.loads(defaults)

    path = path or os.environ.get("NETLOG_CONFIG")
    if path:
        try:
            with open(path, "rb") as handle:
                config = _merge(config, tomllib.load(handle))
        except FileNotFoundError:
            raise ValueError(f"config file not found: {path}") from None
        except tomllib.TOMLDecodeError as error:
            raise ValueError(f"config file {path} is not valid TOML: {error}") from None
    return config
