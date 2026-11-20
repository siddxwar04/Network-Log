"""Posting an alert to a webhook, with retries.

A failure that may pass (no connection, a timeout, a server error, "too many requests") is
tried again after a pause that doubles each time. A refusal that will not pass (the
address is wrong, the webhook was revoked) is not. Either way the result is returned, to
be recorded; nothing here raises.

The address is never part of what is returned or logged. Errors are described in our own
words ("HTTP 500", "timed out"), not with the library's message, which can contain it.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

from netlog.alerts.message import FORMATS
from netlog.alerts.settings import AlertSettings, Target

USER_AGENT = "netlog-alerts"


class _Failed(Exception):
    def __init__(self, reason: str, retry: bool) -> None:
        super().__init__(reason)
        self.reason = reason
        self.retry = retry


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A webhook that redirects is refused rather than followed: a redirected POST loses
    its body, and the alert would silently not arrive."""

    def redirect_request(self, *_args, **_kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def post_json(url: str, payload: dict, timeout: float) -> None:
    """POST `payload` as JSON. Raises _Failed with a description safe to show."""
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            response.read(4096)
    except urllib.error.HTTPError as error:
        code = error.code
        error.close()
        retry = code == 429 or code >= 500
        raise _Failed(f"HTTP {code}", retry) from None
    except TimeoutError:
        raise _Failed("timed out", True) from None
    except urllib.error.URLError as error:
        reason = error.reason
        if isinstance(reason, TimeoutError):
            raise _Failed("timed out", True) from None
        if isinstance(reason, OSError) and reason.strerror:
            raise _Failed(f"could not connect: {reason.strerror}", True) from None
        raise _Failed("could not connect", True) from None
    except OSError as error:
        reason = error.strerror or type(error).__name__
        raise _Failed(f"could not connect: {reason}", True) from None


@dataclass
class Delivery:
    target: str
    ok: bool
    attempts: int
    error: str | None = None

    def as_dict(self) -> dict:
        return {"target": self.target, "ok": self.ok, "attempts": self.attempts,
                "error": self.error}  # fmt: skip


def deliver(
    target: Target,
    facts: dict,
    settings: AlertSettings,
    *,
    sleep: Callable[[float], None] = time.sleep,
    post: Callable[[str, dict, float], None] = post_json,
) -> Delivery:
    """Send one alert to one target, trying again on a failure that may pass."""
    payload = FORMATS[target.name](facts)
    wait = settings.backoff_seconds
    attempts = 0
    while True:
        attempts += 1
        try:
            post(target.url, payload, settings.timeout_seconds)
            return Delivery(target.name, True, attempts)
        except _Failed as failure:
            if not failure.retry or attempts > settings.max_retries:
                return Delivery(target.name, False, attempts, failure.reason)
        except Exception as error:  # a fault of ours: recorded, never raised
            return Delivery(target.name, False, attempts, f"internal error: {type(error).__name__}")
        sleep(wait)
        wait *= 2
