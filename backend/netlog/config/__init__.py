"""Settings: the defaults shipped with the package, overridden by an optional user file
and then by environment variables.

Thresholds, windows and other tunables live here and in `defaults.toml`, not in code.

Any setting can also be given as an environment variable named after its section and key,
joined by double underscores: `NETLOG__LIVE__PORT=5514` sets `port` in `[live]`. This is
how the Docker install keeps every setting in one environment file. The value is read as
a TOML value (`5514`, `true`, `["10.0.0.1"]`, `"text"`); a bare word that is not valid
TOML, such as `UTC`, is taken as text. An empty value changes nothing.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from importlib import resources
from pathlib import Path

ENV_PREFIX = "NETLOG__"


def _merge(base: dict, override: dict) -> dict:
    """Overlay `override` on `base`. Tables are merged; any other value is replaced."""
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _env_value(name: str, raw: str):
    """A variable's text read as a TOML value, or as plain text when it is not one."""
    try:
        return tomllib.loads(f"value = {raw}")["value"]
    except tomllib.TOMLDecodeError:
        if raw.lstrip().startswith(("[", "{", '"', "'")):
            raise ValueError(f"{name} is not a valid value: {raw}") from None
        return raw


def _same_kind(default, value) -> bool:
    """Whether `value` may replace `default`: same type, except that a whole number may
    stand where a decimal is expected."""
    if isinstance(default, bool) or isinstance(value, bool):
        return isinstance(default, bool) and isinstance(value, bool)
    if isinstance(default, float):
        return isinstance(value, int | float)
    return isinstance(value, type(default))


def _apply_environment(config: dict, environ: Mapping[str, str]) -> dict:
    """Apply every NETLOG__SECTION__KEY variable to the settings. A variable naming a
    setting that does not exist, or giving a value of the wrong kind, is an error, so a
    typing mistake is reported instead of silently ignored."""
    overrides: dict = {}
    for name in sorted(environ):
        if not name.upper().startswith(ENV_PREFIX):
            continue
        raw = environ[name].strip()
        if not raw:
            continue
        path = [part.lower() for part in name[len(ENV_PREFIX) :].split("__")]
        if len(path) < 2 or not all(path):
            raise ValueError(f"{name} must name a section and a setting, as NETLOG__LIVE__PORT")
        node = config
        for depth, part in enumerate(path):
            if not isinstance(node, dict) or part not in node:
                where = ".".join(path[: depth + 1])
                raise ValueError(f"{name} names a setting that does not exist: {where}")
            if depth < len(path) - 1:
                node = node[part]
        default = node[path[-1]]
        if isinstance(default, dict):
            raise ValueError(f"{name} names a whole section; name one setting inside it")
        value = _env_value(name, raw)
        if isinstance(default, str) and not isinstance(value, str):
            value = raw  # a text setting keeps the text as written: a model named 4 is "4"
        if not _same_kind(default, value):
            raise ValueError(
                f"{name} must be {type(default).__name__}, like the default {default!r}"
            )
        target = overrides
        for part in path[:-1]:
            target = target.setdefault(part, {})
        target[path[-1]] = value
    return _merge(config, overrides)


def load_config(path: str | Path | None = None, environ: Mapping[str, str] | None = None) -> dict:
    """Return the settings as nested dictionaries.

    `path` is a user file whose values replace the defaults. When it is not given, the
    file named by the NETLOG_CONFIG environment variable is used, if there is one.
    NETLOG__SECTION__KEY environment variables are applied last, over both.
    """
    environ = os.environ if environ is None else environ
    defaults = resources.files(__package__).joinpath("defaults.toml").read_text(encoding="utf-8")
    config = tomllib.loads(defaults)

    path = path or environ.get("NETLOG_CONFIG")
    if path:
        try:
            with open(path, "rb") as handle:
                config = _merge(config, tomllib.load(handle))
        except FileNotFoundError:
            raise ValueError(f"config file not found: {path}") from None
        except tomllib.TOMLDecodeError as error:
            raise ValueError(f"config file {path} is not valid TOML: {error}") from None
    return _apply_environment(config, environ)
