"""Deciding when to alert, and sending alerts without holding up detection.

After every detection pass the live listener hands its incidents to `review`, which
decides, from what has already been alerted (kept in the database, so a restart changes
nothing):

  - an open incident at or above the minimum severity that has had no alert: one alert,
    once it has been open for `first_alert_wait_seconds`. An incident often grows in its
    first seconds (an interface goes down, then OSPF, then BGP); waiting a little sends
    one alert with the severity and likely cause it settles on, not one per step;
  - an open incident whose severity rose above every level it was alerted at: one more;
  - with `on_close`, an incident that raised an alert and has closed: one more, saying
    how long it lasted;
  - anything else, including more evidence at the same severity: nothing.

Each alert decided on is recorded first, and then:

  - silenced, if a silence covers the incident: recorded, never sent;
  - held, if the rate limit is reached: sent later inside one digest message, as soon as
    there is room again;
  - otherwise queued, and sent by a background thread. Retries and their pauses happen
    there, so a webhook that is down never slows a detection pass.

Which incidents a silence covers:
  - a device silence: every incident that involves that device;
  - a type silence: incidents whose likely cause is of that kind (a rule name such as
    link_flap, or link_failure); an incident with no likely cause, when any of its
    findings comes from that rule;
  - "all": everything.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections import deque
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path

from netlog.alerts.delivery import Delivery, deliver
from netlog.alerts.message import digest_facts, incident_facts, redact, test_facts
from netlog.alerts.settings import AlertSettings, alert_settings
from netlog.correlation.incident import Incident
from netlog.detection.rules import LEVELS
from netlog.storage.database import Database

log = logging.getLogger("netlog.alerts")

SCOPES = ("device", "type", "all")
# Kinds of alert that are about an incident, and the statuses that mean "dealt with":
# the incident will not be alerted again at that severity.
INCIDENT_KINDS = ("opened", "raised", "closed")
DECIDED = ("pending", "sent", "failed", "held", "digested", "silenced")
# Statuses of messages that went, or are going, to the channel: what the rate limit counts.
COUNTED = ("pending", "sent", "failed")
COUNTED_KINDS = ("opened", "raised", "closed", "digest")
_STOP = object()


def _level(severity: str | None) -> int:
    return LEVELS.index(severity) if severity in LEVELS else -1


class Alerter:
    def __init__(
        self,
        db_path: str | Path,
        settings: AlertSettings,
        *,
        sleep: Callable[[float], None] = time.sleep,
        post=None,
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.settings = settings
        self.sleep = sleep
        self.post = post  # replaces the HTTP request in tests
        self.on_error = on_error
        self.errors: deque[str] = deque(maxlen=20)
        self._queue: queue.Queue = queue.Queue()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()  # one decision pass at a time

    @property
    def enabled(self) -> bool:
        return self.settings.enabled

    # --- Deciding -------------------------------------------------------------------------

    def review(self, db: Database, upload_id: int, items: list[dict], now: datetime) -> list[int]:
        """Decide on alerts for the live incidents `items`, after a detection pass.
        Returns the ids of the alerts recorded."""
        if not self.enabled:
            return []
        with self._lock:
            made = []
            history = self._history(db, [item["id"] for item in items])
            silences = db.silences(active_at=now)
            for item in sorted(items, key=lambda i: (i["opened_at"], i["id"])):
                decision = self._decide(item, history.get(item["id"]), now)
                if decision is None:
                    continue
                incident = db.get_incident(upload_id, item["id"])
                if incident is None:
                    continue
                kind, previous = decision
                facts = incident_facts(
                    kind, incident, upload_id=upload_id, link_base=self.settings.link_base,
                    summary=item.get("summary"), summary_chars=self.settings.summary_chars,
                    previous_severity=previous,
                )  # fmt: skip
                if self.settings.redact:
                    facts = redact(facts, _usernames(db, incident))
                made.append(self._record(db, kind, facts, incident, silences, now))
            made += self._digest(db, now)
            return made

    def _history(self, db: Database, incident_ids: list[str]) -> dict[str, dict]:
        """What each incident has been alerted for: the highest severity, and whether its
        close has been."""
        history: dict[str, dict] = {}
        for alert in db.alerts(statuses=DECIDED, incident_ids=incident_ids):
            if alert["kind"] not in INCIDENT_KINDS:
                continue
            seen = history.setdefault(
                alert["incident_id"], {"severity": None, "closed": False, "spoke": False}
            )
            if alert["kind"] == "closed":
                seen["closed"] = True
                continue
            if _level(alert["severity"]) > _level(seen["severity"]):
                seen["severity"] = alert["severity"]
            if alert["status"] != "silenced":
                seen["spoke"] = True
        return history

    def _decide(
        self, item: dict, seen: dict | None, now: datetime
    ) -> tuple[str, str | None] | None:
        incident = item["snapshot"].get("incident") or {}
        severity = incident.get("severity")
        if item["state"] == "open":
            if _level(severity) < _level(self.settings.min_severity):
                return None
            if seen is None or seen["severity"] is None:
                settling = timedelta(seconds=self.settings.first_alert_wait_seconds)
                return ("opened", None) if now - item["opened_at"] >= settling else None
            if _level(severity) > _level(seen["severity"]):
                return "raised", seen["severity"]
            return None
        # Closed: said only of an incident the channel has heard about.
        if self.settings.on_close and seen and seen["spoke"] and not seen["closed"]:
            return "closed", None
        return None

    def _record(
        self, db: Database, kind: str, facts: dict, incident: Incident, silences, now: datetime
    ) -> int:
        silence = next((s for s in silences if _covers(s, incident, db)), None)
        if silence is not None:
            status = "silenced"
        elif self._sent_in_period(db, now) >= self.settings.max_alerts:
            status = "held"
        else:
            status = "pending"
        alert_id = db.add_alert(
            kind, status, now, facts, incident_id=incident.id, severity=incident.severity,
            silence_id=silence["id"] if silence else None,
        )  # fmt: skip
        if status == "pending":
            self._queue.put(alert_id)
        return alert_id

    def _sent_in_period(self, db: Database, now: datetime) -> int:
        since = now - timedelta(seconds=self.settings.period_seconds)
        recent = db.alerts(statuses=COUNTED, since=since)
        # "since" includes the edge; an alert exactly one period ago has left the window.
        return sum(1 for a in recent if a["kind"] in COUNTED_KINDS and a["created_at"] > since)

    def _digest(self, db: Database, now: datetime) -> list[int]:
        """Send every held alert in one message, once the rate limit has room for it."""
        held = db.alerts(statuses=("held",))
        if not held or self._sent_in_period(db, now) >= self.settings.max_alerts:
            return []
        facts = digest_facts(held, self.settings.link_base)
        digest_id = db.add_alert("digest", "pending", now, facts, severity=facts["severity"])
        db.mark_digested([alert["id"] for alert in held], digest_id)
        self._queue.put(digest_id)
        return [digest_id]

    # --- Sending --------------------------------------------------------------------------

    def _send(self, db: Database, alert_id: int, now: Callable[[], datetime]) -> list[Delivery]:
        alert = db.get_alert(alert_id)
        if alert is None or alert["status"] != "pending":
            return []
        options = {"sleep": self.sleep}
        if self.post is not None:
            options["post"] = self.post
        results = [deliver(t, alert["message"], self.settings, **options)
                   for t in self.settings.targets]  # fmt: skip
        ok = all(result.ok for result in results)
        db.finish_alert(
            alert_id, "sent" if ok else "failed", [r.as_dict() for r in results],
            now() if any(r.ok for r in results) else None,
        )  # fmt: skip
        for result in results:
            if not result.ok:
                what = alert["kind"] + (f" {alert['incident_id']}" if alert["incident_id"] else "")
                text = (
                    f"alert #{alert_id} ({what}) to {result.target} failed after "
                    f"{result.attempts} tries: {result.error}"
                )
                log.warning("%s", text)
                self.errors.append(text)
                if self.on_error:
                    self.on_error(text)
        return results

    def send_test(self, now: datetime) -> dict:
        """Send a clearly labelled test alert straight away, to every target. Not counted
        by the rate limit and not affected by silences."""
        with Database(self.db_path) as db:
            facts = test_facts(now, self.settings.link_base)
            alert_id = db.add_alert("test", "pending", now, facts)
            results = self._send(db, alert_id, lambda: now)
        return {
            "id": alert_id,
            "sent": bool(results) and all(r.ok for r in results),
            "deliveries": [r.as_dict() for r in results],
        }

    def flush(self, now: Callable[[], datetime]) -> int:
        """Send what is queued, here and now. The background thread does this when it
        runs; tests call it directly. Returns how many alerts were sent or failed."""
        done = 0
        with Database(self.db_path) as db:
            while True:
                try:
                    alert_id = self._queue.get_nowait()
                except queue.Empty:
                    return done
                try:
                    if alert_id is not _STOP:
                        self._send(db, alert_id, now)
                        done += 1
                finally:
                    self._queue.task_done()

    def start(self, now: Callable[[], datetime]) -> None:
        """Start the sending thread. Alerts left waiting by a previous run go first."""
        if not self.enabled or self._thread is not None:
            return
        with Database(self.db_path) as db:
            for alert in reversed(db.alerts(statuses=("pending",))):
                if alert["kind"] != "test":
                    self._queue.put(alert["id"])
        self._thread = threading.Thread(
            target=self._worker, args=(now,), name="netlog-alerts", daemon=True
        )
        self._thread.start()

    def _worker(self, now: Callable[[], datetime]) -> None:
        with Database(self.db_path) as db:
            while True:
                alert_id = self._queue.get()
                try:
                    if alert_id is _STOP:
                        return
                    self._send(db, alert_id, now)
                except Exception:  # never let one alert stop the others
                    log.exception("sending an alert")
                finally:
                    self._queue.task_done()

    def wait(self, timeout: float = 10.0) -> bool:
        """Wait until everything queued has been sent or has failed. For tests and for
        stopping cleanly."""
        deadline = time.monotonic() + timeout
        while self._queue.unfinished_tasks:
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.01)
        return True

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the thread after what is queued, waiting at most `timeout` seconds. An
        alert not sent by then stays pending and goes out at the next start."""
        if self._thread is None:
            return
        self._queue.put(_STOP)
        self._thread.join(timeout)
        self._thread = None

    # --- Silences -------------------------------------------------------------------------

    def silence(
        self,
        scope: str,
        value: str | None,
        minutes: float,
        reason: str,
        now: datetime,
    ) -> dict:
        """Silence a device, an incident type, or everything, for `minutes`."""
        return add_silence(self.db_path, self.settings, scope, value, minutes, reason, now)


def add_silence(
    db_path: str | Path,
    settings: AlertSettings,
    scope: str,
    value: str | None,
    minutes: float,
    reason: str,
    now: datetime,
) -> dict:
    if scope not in SCOPES:
        raise ValueError(f"a silence is for one of: {', '.join(SCOPES)}")
    value = (value or "").strip() or None
    if (scope == "all") != (value is None):
        raise ValueError(
            "say which device or incident type to silence" if scope != "all"
            else "a silence of everything takes no device or type"
        )  # fmt: skip
    if not minutes > 0 or minutes > settings.max_silence_hours * 60:
        raise ValueError(
            f"a silence lasts more than 0 minutes and at most {settings.max_silence_hours:g} "
            "hours (alerts.max_silence_hours)"
        )
    ends = now + timedelta(minutes=minutes)
    reason = " ".join(reason.split())[:200]
    with Database(db_path) as db:
        silence_id = db.add_silence(scope, value, now, ends, reason)
        return next(s for s in db.silences() if s["id"] == silence_id)


def _covers(silence: dict, incident: Incident, db: Database) -> bool:
    scope, value = silence["scope"], silence["value"]
    if scope == "all":
        return True
    if scope == "device":
        return value.lower() in {device.lower() for device in incident.devices}
    if incident.root_cause is not None:
        return incident.root_cause.kind == value
    rules = {f.rule for f in db.findings(incident.upload_id) if f.id in incident.finding_ids}
    return value in rules


def _usernames(db: Database, incident: Incident) -> set[str]:
    """Every username in the messages behind an incident, to be left out of its alert."""
    wanted = set(incident.finding_ids) | set(incident.context_ids)
    evidence = [e for f in db.findings(incident.upload_id) if f.id in wanted for e in f.evidence]
    names = {event.entities.username for event in db.events_by_id(evidence[:2000])}
    return {name for name in names if name}


def alerter_from_config(db_path: str | Path, config: dict, **options) -> Alerter:
    """The alerter the settings and the environment describe. It sends nothing when no
    webhook address is set."""
    return Alerter(db_path, alert_settings(config), **options)
