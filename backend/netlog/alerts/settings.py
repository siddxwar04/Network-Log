"""Alert settings, read from the `[alerts]` section and the environment.

A webhook address is a secret: whoever has it can post to the channel. So addresses come
from the environment (or the .env file) only, never from a settings file, and they are
kept out of this object's repr, out of every log line and out of every API answer.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from netlog.config import load_config
from netlog.detection.rules import LEVELS

ENV_SLACK = "NETLOG_ALERT_SLACK_URL"
ENV_WEBHOOK = "NETLOG_ALERT_WEBHOOK_URL"
# The two kinds of target, by the environment variable that names each.
TARGETS = {"slack": ENV_SLACK, "webhook": ENV_WEBHOOK}


@dataclass(frozen=True)
class Target:
    name: str  # "slack" or "webhook": what is shown and logged instead of the address
    url: str = field(repr=False)


@dataclass(frozen=True)
class AlertSettings:
    targets: tuple[Target, ...] = ()
    min_severity: str = "high"
    first_alert_wait_seconds: float = 30.0
    on_close: bool = False
    max_alerts: int = 5
    period_seconds: float = 600.0
    redact: bool = False
    link_base: str = "http://localhost:5173"
    summary_chars: int = 200
    timeout_seconds: float = 10.0
    max_retries: int = 3
    backoff_seconds: float = 2.0
    max_silence_hours: float = 168.0

    @property
    def enabled(self) -> bool:
        return bool(self.targets)

    def public(self) -> dict:
        """The settings as the API shows them: which targets are set, never where."""
        return {
            "targets": {name: any(t.name == name for t in self.targets) for name in TARGETS},
            "min_severity": self.min_severity,
            "first_alert_wait_seconds": self.first_alert_wait_seconds,
            "on_close": self.on_close,
            "max_alerts": self.max_alerts,
            "period_seconds": self.period_seconds,
            "redact": self.redact,
            "link_base": self.link_base,
        }


def _check_url(name: str, url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        # The value itself is not repeated: it may be a real webhook with a typo.
        raise ValueError(f"{TARGETS[name]} must be an http:// or https:// address")
    return url


def alert_settings(
    config: dict | None = None, environ: Mapping[str, str] | None = None
) -> AlertSettings:
    settings = (config or load_config())["alerts"]
    environ = os.environ if environ is None else environ
    for key in settings:
        if "url" in key.lower() or "webhook" in key.lower():
            raise ValueError(
                f"alerts.{key}: webhook addresses do not belong in a settings file; set "
                f"{ENV_SLACK} or {ENV_WEBHOOK} in .env instead"
            )
    if settings["min_severity"] not in LEVELS:
        raise ValueError(f"alerts.min_severity must be one of: {', '.join(LEVELS)}")
    if int(settings["max_alerts"]) < 1 or float(settings["period_seconds"]) <= 0:
        raise ValueError("alerts.max_alerts and alerts.period_seconds must be greater than zero")
    if float(settings["first_alert_wait_seconds"]) < 0:
        raise ValueError("alerts.first_alert_wait_seconds cannot be negative")
    if float(settings["timeout_seconds"]) <= 0:
        raise ValueError("alerts.timeout_seconds must be greater than zero")
    if int(settings["max_retries"]) < 0 or float(settings["backoff_seconds"]) < 0:
        raise ValueError("alerts.max_retries and alerts.backoff_seconds cannot be negative")
    targets = tuple(
        Target(name, _check_url(name, environ[variable].strip()))
        for name, variable in TARGETS.items()
        if (environ.get(variable) or "").strip()
    )
    return AlertSettings(
        targets=targets,
        min_severity=settings["min_severity"],
        first_alert_wait_seconds=float(settings["first_alert_wait_seconds"]),
        on_close=bool(settings["on_close"]),
        max_alerts=int(settings["max_alerts"]),
        period_seconds=float(settings["period_seconds"]),
        redact=bool(settings["redact"]),
        link_base=str(settings["link_base"]).rstrip("/"),
        summary_chars=int(settings["summary_chars"]),
        timeout_seconds=float(settings["timeout_seconds"]),
        max_retries=int(settings["max_retries"]),
        backoff_seconds=float(settings["backoff_seconds"]),
        max_silence_hours=float(settings["max_silence_hours"]),
    )
