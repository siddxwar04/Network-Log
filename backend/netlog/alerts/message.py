"""What an alert says, and how it is written for each kind of webhook.

An alert is first gathered as plain facts (severity, title, likely cause, devices, start,
link, the explanation's one-line summary when it is ready). Those facts are what is
stored, and what both formats are written from:

  - Slack's format: one short block of text, readable on a phone's lock screen.
  - Plain JSON for anything else: the same facts as fields, and the same text.

Titles, causes and summaries are made from log content, which anyone who can reach the
listener can write. So every value is put on one line, cut to length, and, for Slack,
escaped so it cannot become a link or a mention that pings the whole channel.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime

from netlog.correlation.incident import Incident
from netlog.detection.rules import LEVELS
from netlog.redaction.redactor import find_values

MAX_TITLE = 140
MAX_CAUSE = 200
MAX_DEVICES = 5
MAX_DIGEST_ITEMS = 8
REDACTED_IP = "[IP]"
REDACTED_USER = "[user]"

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]+")
_MENTION = re.compile(r"@(everyone|here|channel)\b", re.IGNORECASE)


def one_line(text: str | None, limit: int) -> str:
    """Text on one line, without control characters, cut to `limit` characters."""
    text = " ".join(_CONTROL.sub(" ", text or "").split())
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def first_sentence(text: str | None, limit: int) -> str:
    text = one_line(text, 10_000)
    match = re.search(r"(?<=[.!?])\s", text)
    return one_line(text[: match.start()] if match else text, limit)


def duration_text(seconds: float) -> str:
    seconds = max(0, round(seconds))
    if seconds < 60:
        return f"{seconds} s"
    minutes = round(seconds / 60)
    if minutes < 60:
        return f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes} min" if minutes else f"{hours} h"


def _time(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def incident_link(link_base: str, upload_id: int, incident_id: str) -> str:
    return f"{link_base}/uploads/{upload_id}/incidents/{incident_id}"


def incident_facts(
    kind: str,
    incident: Incident,
    *,
    upload_id: int,
    link_base: str,
    summary: str | None = None,
    summary_chars: int = 200,
    previous_severity: str | None = None,
) -> dict:
    """The facts of one alert about an incident. `kind` is opened, raised or closed."""
    root = incident.root_cause
    return {
        "kind": kind,
        "test": False,
        "incident_id": incident.id,
        "severity": incident.severity,
        "previous_severity": previous_severity,
        "title": one_line(incident.title, MAX_TITLE),
        "likely_cause": one_line(root.summary, MAX_CAUSE) if root else None,
        "confidence": incident.confidence if root else None,
        "devices": [one_line(device, 60) for device in incident.devices],
        "start": incident.start.isoformat(),
        "end": incident.end.isoformat(),
        "duration_seconds": incident.duration_seconds,
        "summary": first_sentence(summary, summary_chars) or None,
        "link": incident_link(link_base, upload_id, incident.id),
    }


def digest_facts(held: list[dict], link_base: str) -> dict:
    """One message standing for every alert the rate limit held back."""
    latest: dict[str, dict] = {}
    for alert in sorted(held, key=lambda a: a["id"]):
        message = alert["message"]
        latest[message.get("incident_id") or f"#{alert['id']}"] = message
    items = sorted(
        latest.values(), key=lambda m: (-LEVELS.index(m["severity"]), m.get("start") or "")
    )
    return {
        "kind": "digest",
        "test": False,
        "severity": items[0]["severity"] if items else "info",
        "count": len(held),
        "incidents": len(items),
        "items": [
            {
                key: message.get(key)
                for key in ("incident_id", "kind", "severity", "title", "devices", "link")
            }
            for message in items
        ],
        "link": f"{link_base}/live",
    }


def test_facts(now: datetime, link_base: str) -> dict:
    return {
        "kind": "test",
        "test": True,
        "severity": "info",
        "title": "Test alert from netlog",
        "sent": now.isoformat(),
        "link": f"{link_base}/live",
    }


def redact(facts: dict, usernames: Iterable[str] = ()) -> dict:
    """The facts with IP addresses and the given usernames replaced in every piece of
    text taken from the logs. The link and the ids are kept."""
    names = sorted({name for name in usernames if name}, key=len, reverse=True)
    user = (
        re.compile(rf"(?<![\w.-])(?:{'|'.join(map(re.escape, names))})(?![\w.-])")
        if names
        else None
    )

    def clean(text):
        if not isinstance(text, str):
            return text
        for kind, value in sorted(find_values(text), key=lambda kv: -len(kv[1])):
            if kind == "ip":
                text = text.replace(value, REDACTED_IP)
        return user.sub(REDACTED_USER, text) if user else text

    out = dict(facts)
    for key in ("title", "likely_cause", "summary"):
        out[key] = clean(out.get(key))
    if "devices" in out:
        out["devices"] = [clean(device) for device in out["devices"]]
    if "items" in out:
        out["items"] = [
            {**item, "title": clean(item["title"]),
             "devices": [clean(d) for d in item.get("devices") or []]}
            for item in out["items"]
        ]  # fmt: skip
    return out


# --- Writing it out -----------------------------------------------------------------------


def _devices(devices: list[str]) -> str:
    shown = ", ".join(devices[:MAX_DEVICES])
    more = len(devices) - MAX_DEVICES
    return shown + (f" and {more} more" if more > 0 else "")


def _lines(facts: dict, value) -> list[str]:
    """The alert as lines of text. `value` prepares each piece of text from the logs."""
    kind = facts["kind"]
    level = facts["severity"].upper()
    if kind == "test":
        return [
            "TEST ALERT from netlog. Nothing is wrong.",
            "If you can read this, alerts reach this channel.",
            f"Sent {_time(datetime.fromisoformat(facts['sent']))}",
        ]
    if kind == "digest":
        lines = [
            f"{level}: {facts['count']} more alert(s) about {facts['incidents']} incident(s), "
            "held back by the rate limit"
        ]
        for item in facts["items"][:MAX_DIGEST_ITEMS]:
            where = f" ({value(_devices(item['devices']))})" if item.get("devices") else ""
            lines.append(f"- {item['severity'].upper()}: {value(item['title'])}{where}")
        more = len(facts["items"]) - MAX_DIGEST_ITEMS
        if more > 0:
            lines.append(f"- and {more} more")
        return lines

    if kind == "raised":
        head = f"{level} (was {facts['previous_severity'].upper()}): {value(facts['title'])}"
    elif kind == "closed":
        lasted = duration_text(facts["duration_seconds"])
        head = f"RESOLVED after {lasted}: {value(facts['title'])}"
    else:
        head = f"{level}: {value(facts['title'])}"
    lines = [head]
    if facts.get("likely_cause"):
        lines.append(
            f"Likely cause: {value(facts['likely_cause'])} ({facts['confidence']} confidence)"
        )
    else:
        lines.append("Likely cause: not clear from the logs")
    start = _time(datetime.fromisoformat(facts["start"]))
    lines.append(f"Devices: {value(_devices(facts['devices']))} | started {start}")
    if facts.get("summary"):
        lines.append(f"Summary: {value(facts['summary'])}")
    return lines


def _link_label(facts: dict) -> str:
    return "Open the live page" if facts["kind"] in ("digest", "test") else "Open the incident"


def plain_text(facts: dict) -> str:
    return "\n".join([*_lines(facts, str), f"{_link_label(facts)}: {facts['link']}"])


def _slack_value(text: str) -> str:
    # Slack reads <...> as links and mentions, and &, < and > must be escaped. Discord's
    # Slack-compatible address reads @everyone and @here: a zero-width space breaks them.
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _MENTION.sub(lambda m: "@​" + m.group(1), text)


def slack_payload(facts: dict) -> dict:
    link = facts["link"].replace(">", "%3E").replace("|", "%7C")
    return {"text": "\n".join([*_lines(facts, _slack_value), f"<{link}|{_link_label(facts)}>"])}


def json_payload(facts: dict) -> dict:
    return {"source": "netlog", **facts, "text": plain_text(facts)}


FORMATS = {"slack": slack_payload, "webhook": json_payload}
