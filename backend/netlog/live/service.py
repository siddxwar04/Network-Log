"""The live syslog listener: devices send their messages straight to netlog, and incidents
open, grow and close while things are happening.

    UDP and TCP sockets -> intake (checks, rate limits, bounded queue)
                        -> writer: parse each message, store it under the "live" upload
                        -> detector: every few seconds, run the rules and correlation over
                           the recent window and update the live incidents
                        -> pruner: now and then, delete old messages

Every message goes through the same parsers as a file. The sender's address is recorded,
and used as the device name when a message carries none. A device clock that is far off
is not trusted: the message keeps its device time for reference, and the time it arrived
is used instead.

Plain syslog has no authentication: anyone who can reach the port can send messages that
look like they come from a router. The listener binds to one address (127.0.0.1 unless
set otherwise), can be limited to a list of senders, and counts and drops whatever does
not look like a log message.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import threading
import time
from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from netlog.correlation.grouping import correlate
from netlog.detection.engine import detect
from netlog.detection.rules import RuleError, load_rule_set
from netlog.ingestion.reader import RawLine
from netlog.live.intake import Intake, IntakeSettings, Message, TcpFramer
from netlog.live.tracker import (
    finding_from_dict,
    finding_key,
    finding_to_dict,
    group_key,
    incident_from_dict,
    incident_to_dict,
    merge_findings,
    merge_incident,
    new_id,
    translate,
)
from netlog.llm.provider import Provider
from netlog.llm.settings import LLMSettings
from netlog.parsers.pipeline import LineParser
from netlog.parsers.syslog import parse_timezone
from netlog.report.explain import explain_one
from netlog.schema import Event, ParseStatus
from netlog.storage.database import Database, EventFilter

log = logging.getLogger("netlog.live")

ENV_SWITCH = "NETLOG_LIVE"
CLOCK_NOTE = "the device clock was off by more than the allowed skew; arrival time used"


def live_enabled(config: dict) -> bool:
    """Whether the API should start the listener: `[live] enabled`, or NETLOG_LIVE=1."""
    switch = os.environ.get(ENV_SWITCH)
    if switch is not None:
        return switch.strip().lower() in ("1", "true", "yes", "on")
    return bool(config.get("live", {}).get("enabled"))


class _Udp(asyncio.DatagramProtocol):
    def __init__(self, intake: Intake) -> None:
        self.intake = intake

    def datagram_received(self, data: bytes, addr) -> None:
        self.intake.accept(data, addr[0])


class LiveService:
    def __init__(
        self,
        db_path: str | Path,
        config: dict,
        *,
        llm: LLMSettings | None = None,
        provider: Provider | None = None,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.db_path = Path(db_path)
        self.config = config
        self.live = config["live"]
        self.llm = llm
        self.provider = provider
        self.clock = clock or (lambda: datetime.now(UTC))
        self.monotonic = monotonic
        self.intake = Intake(
            IntakeSettings.from_config(self.live), clock=self.clock, monotonic=monotonic
        )
        self.tz = parse_timezone(self.live["timezone"])
        self.skew = timedelta(seconds=float(self.live["max_clock_skew_seconds"]))
        self.lookback = timedelta(seconds=float(self.live["lookback_seconds"]))
        self.quiet = timedelta(seconds=float(self.live["quiet_seconds"]))
        self.explain_after = timedelta(seconds=float(self.live["explain_after_seconds"]))
        self.upload_id: int | None = None
        self.listening: dict[str, str] = {}
        self.errors: deque[str] = deque(maxlen=20)
        self.last_detection: datetime | None = None
        self._parsers: dict[int, LineParser] = {}
        self._next_line = 1
        self._lock = threading.Lock()
        self._dirty = True
        self._transports: list = []
        self._task: asyncio.Task | None = None
        self._clients: set[asyncio.StreamWriter] = set()

    # --- Storage --------------------------------------------------------------------------

    def open(self) -> int:
        """Find or create the live upload. Messages and incidents from before a restart are
        still there, and numbering carries on where it stopped."""
        with Database(self.db_path) as db:
            self.upload_id = db.live_upload()
            self._next_line = db.next_line_no(self.upload_id)
        return self.upload_id

    def _parser(self, year: int) -> LineParser:
        if year not in self._parsers:
            self._parsers[year] = LineParser(year=year, tz=self.tz)
        return self._parsers[year]

    def _event(self, message: Message, line_no: int) -> Event | None:
        event = self._parser(message.arrived.year).parse(RawLine(line_no, message.text))
        if event.parse_status is ParseStatus.UNPARSED:
            return None  # not a syslog message: counted as malformed, not stored
        extra = event.entities.extra
        extra["sender"] = message.sender
        extra["arrival"] = message.arrived.isoformat()
        if not event.host:
            event.host = message.sender
        if event.timestamp is None or abs(event.timestamp - message.arrived) > self.skew:
            if event.timestamp is not None:
                extra["device_time"] = event.timestamp.isoformat()
                extra["clock"] = CLOCK_NOTE
            event.timestamp = message.arrived
        return event

    def drain(self) -> int:
        """Parse and store the waiting messages. Returns how many were stored."""
        messages = self.intake.take()
        if not messages:
            return 0
        with self._lock:
            events = []
            for message in messages:
                event = self._event(message, self._next_line)
                if event is None:
                    with self.intake._lock:
                        self.intake.counters.malformed += 1
                    continue
                events.append(event)
                self._next_line += 1
            if events:
                with Database(self.db_path) as db:
                    db.add_events(self.upload_id, events)
                with self.intake._lock:
                    self.intake.counters.stored += len(events)
                self._dirty = True
        return len(events)

    # --- Detection ------------------------------------------------------------------------

    def _analyze(self, events: list[Event]) -> list[tuple[dict, dict[str, dict]]]:
        """The ordinary rules and correlation over a window of events, in a scratch
        database. Returns each incident as plain data with its findings, by key."""
        ruleset = load_rule_set(config=self.config)
        with Database(":memory:") as scratch:
            window = scratch.create_upload("live window", 0, source="live")
            scratch.add_events(window, events)
            main_id = {event.line_no: event.id for event in events}
            moved = {e.id: main_id[e.line_no] for e in scratch.iter_events(window)}
            detect(
                scratch, window, ruleset.rules, ruleset.severity_settings(self.config),
                until=self.clock(),
            )  # fmt: skip
            incidents = correlate(scratch, window, self.config)
            findings = scratch.findings(window)
        key_of = {finding.id: finding_key(finding) for finding in findings}
        as_data = {}
        for finding in findings:
            data = finding_to_dict(finding)
            data["evidence"] = [moved[e] for e in finding.evidence if e in moved]
            as_data[key_of[finding.id]] = data
        found = []
        for incident in incidents:
            members = [*incident.finding_ids, *incident.context_ids]
            found.append(
                (
                    incident_to_dict(incident, key_of),
                    {key_of[i]: as_data[key_of[i]] for i in members},
                )
            )
        found.sort(key=lambda item: item[0]["start"])
        return found

    def tick(self) -> None:
        """One detection pass over the recent window."""
        with self._lock, Database(self.db_path) as db:
            now = self.clock()
            events = list(db.iter_events(self.upload_id, EventFilter(start=now - self.lookback)))
            try:
                found = self._analyze(events) if events else []
            except RuleError as error:
                self.errors.append(f"{now.isoformat(timespec='seconds')}: rules: {error}")
                return
            state = {item["id"]: item for item in db.live_incidents(self.upload_id)}
            before = json.dumps(
                {key: item["snapshot"] for key, item in state.items()}, sort_keys=True
            )
            changed = self._update(state, found, now)
            for item in state.values():
                # Quiet means no new messages, and nothing in it still down: an interface
                # that has not come back keeps its incident open however quiet it is.
                still_down = any(
                    "not_recovered" in finding["flags"]
                    for finding in item["snapshot"]["findings"].values()
                )
                if (
                    item["state"] == "open"
                    and not still_down
                    and now - item["changed_at"] >= self.quiet
                ):
                    item["state"], item["closed_at"] = "closed", now
                    changed = True
            # Written whenever anything differs, even only the end of an outage that is
            # still going on, so the pages show it as it is now.
            after = json.dumps(
                {key: item["snapshot"] for key, item in state.items()}, sort_keys=True
            )
            if changed or self._dirty or after != before:
                self._persist(db, state)
                self._dirty = False
            self._explain(db, state, now)
            self.last_detection = now

    def _update(self, state: dict[str, dict], found, now: datetime) -> bool:
        changed = False
        for incident, findings in found:
            groups = {group_key(f) for f in findings.values()}
            open_matches = [
                item
                for item in state.values()
                if item["state"] == "open"
                and groups & {group_key(f) for f in item["snapshot"]["findings"].values()}
            ]
            matches = open_matches or [
                item for item in state.values() if set(findings) & set(item["snapshot"]["findings"])
            ]
            if matches:
                target = min(matches, key=lambda item: (item["opened_at"], item["id"]))
                for other in matches:
                    if other is target:
                        continue
                    # One incident seen as two until now: the older id stays.
                    merged, _, _ = merge_findings(
                        target["snapshot"]["findings"], other["snapshot"]["findings"]
                    )
                    target["snapshot"]["findings"] = merged
                    del state[other["id"]]
                    changed = True
                grew = False
            else:
                first = min(findings, key=lambda key: (findings[key]["start"], key))
                target = {
                    "id": new_id(first, set(state)),
                    "state": "open",
                    "opened_at": now,
                    "changed_at": now,
                    "closed_at": None,
                    "snapshot": {"findings": {}, "incident": None},
                    "explained_hash": None,
                    "explanations": 0,
                }
                state[target["id"]] = target
                grew = True
            merged, more, alias = merge_findings(target["snapshot"]["findings"], findings)
            target["snapshot"] = {
                "findings": merged,
                "incident": merge_incident(
                    target["snapshot"]["incident"], translate(incident, alias), merged
                ),
            }
            if grew or more:
                target["changed_at"] = now
                if target["state"] == "closed":
                    target["state"], target["closed_at"] = "open", None
                changed = True
        return changed

    def _persist(self, db: Database, state: dict[str, dict]) -> None:
        """Write every live incident and its findings as the live upload's own, so the
        ordinary pages and endpoints can show them."""
        items = sorted(state.values(), key=lambda item: (item["opened_at"], item["id"]))
        findings = [
            finding_from_dict(data)
            for item in items
            for data in item["snapshot"]["findings"].values()
        ]
        db.save_findings(self.upload_id, findings)
        id_of: dict[str, int] = {}
        for finding in db.findings(self.upload_id):
            id_of.setdefault(finding_key(finding), finding.id)
        incidents = [
            incident_from_dict(item["id"], item["snapshot"]["incident"], id_of)
            for item in items
            if item["snapshot"]["incident"]
        ]
        db.save_incidents(self.upload_id, incidents)
        db.save_live_incidents(self.upload_id, items)
        db.refresh_counts(self.upload_id)

    @staticmethod
    def _fingerprint(item: dict) -> str:
        incident = item["snapshot"]["incident"] or {}
        basis = json.dumps([sorted(item["snapshot"]["findings"]), incident.get("severity")])
        return hashlib.sha256(basis.encode()).hexdigest()[:16]

    def _explain(self, db: Database, state: dict[str, dict], now: datetime) -> None:
        """Explain an incident once it has been stable for a while, and at most once more
        when it closes, if it changed since. This keeps the number of LLM requests small."""
        explained = False
        for item in state.values():
            fingerprint = self._fingerprint(item)
            if item["state"] == "open":
                due = item["explanations"] == 0 and now - item["changed_at"] >= self.explain_after
            else:
                due = item["explanations"] < 2 and item["explained_hash"] != fingerprint
            if not due:
                continue
            incident = db.get_incident(self.upload_id, item["id"])
            if incident is None:
                continue
            try:
                explain_one(
                    db, self.upload_id, incident, db, "senior",
                    provider=self.provider, settings=self.llm, config=self.config,
                )  # fmt: skip
            except Exception as error:  # an explanation never stops detection
                self.errors.append(
                    f"{now.isoformat(timespec='seconds')}: explaining {item['id']}: {error}"
                )
            item["explained_hash"] = fingerprint
            item["explanations"] += 1
            explained = True
        if explained:
            db.save_live_incidents(
                self.upload_id, sorted(state.values(), key=lambda i: (i["opened_at"], i["id"]))
            )

    # --- Retention ------------------------------------------------------------------------

    def prune(self) -> int:
        """Delete messages older than the retention period, keeping the evidence of every
        incident that is kept, and forget incidents closed longer ago than theirs."""
        with self._lock, Database(self.db_path) as db:
            now = self.clock()
            events_before = now - timedelta(days=float(self.live["retention_events_days"]))
            incidents_before = now - timedelta(days=float(self.live["retention_incidents_days"]))
            items = db.live_incidents(self.upload_id)
            kept = [
                item
                for item in items
                if item["state"] == "open" or (item["closed_at"] or now) >= incidents_before
            ]
            if len(kept) != len(items):
                self._persist(db, {item["id"]: item for item in kept})
            evidence = {
                event_id
                for item in kept
                for finding in item["snapshot"]["findings"].values()
                for event_id in finding["evidence"]
            }
            deleted = db.prune_events(self.upload_id, events_before, evidence)
            db.refresh_counts(self.upload_id)
        return deleted

    # --- Running --------------------------------------------------------------------------

    async def start(self) -> None:
        """Open the sockets and start the background loop."""
        self.open()
        loop = asyncio.get_running_loop()
        host, port = self.live["bind"], int(self.live["port"])
        if self.live["udp"]:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _Udp(self.intake), local_addr=(host, port)
            )
            self._transports.append(transport)
            self.listening["udp"] = f"{host}:{transport.get_extra_info('sockname')[1]}"
        if self.live["tcp"]:
            server = await asyncio.start_server(self._tcp_client, host, port)
            self._transports.append(server)
            self.listening["tcp"] = f"{host}:{server.sockets[0].getsockname()[1]}"
        log.info(
            "live syslog listener on %s", ", ".join(f"{k} {v}" for k, v in self.listening.items())
        )
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        for writer in list(self._clients):
            writer.close()
        for transport in self._transports:
            transport.close()
        self._transports.clear()
        await asyncio.to_thread(self.drain)  # what already arrived is kept

    async def _tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sender = (writer.get_extra_info("peername") or ("unknown",))[0]
        if len(self._clients) >= int(self.live["max_tcp_clients"]):
            self.intake._count(sender, "refused")
            writer.close()
            return
        self._clients.add(writer)
        framer = TcpFramer(self.intake.settings.max_message_bytes)
        try:
            while data := await reader.read(65536):
                for message in framer.feed(data):
                    if message is None:
                        self.intake.oversized(sender)
                    else:
                        self.intake.accept(message, sender)
                if framer.broken:
                    break
        except (ConnectionError, OSError):
            pass
        finally:
            self._clients.discard(writer)
            writer.close()

    async def _run(self) -> None:
        detect_every = float(self.live["detect_every_seconds"])
        prune_every = float(self.live["prune_every_seconds"])
        next_tick = self.monotonic() + detect_every
        next_prune = self.monotonic() + prune_every
        while True:
            await asyncio.sleep(0.5)
            try:
                await asyncio.to_thread(self.drain)
                if self.monotonic() >= next_tick:
                    next_tick = self.monotonic() + detect_every
                    await asyncio.to_thread(self.tick)
                if self.monotonic() >= next_prune:
                    next_prune = self.monotonic() + prune_every
                    await asyncio.to_thread(self.prune)
            except asyncio.CancelledError:
                raise
            except Exception as error:  # never let one bad pass stop the listener
                log.exception("live listener")
                self.errors.append(f"{self.clock().isoformat(timespec='seconds')}: {error}")

    def status(self) -> dict:
        intake = self.intake
        return {
            "listening": dict(self.listening),
            "upload_id": self.upload_id,
            "counters": intake.counters.as_dict(),
            "per_minute": intake.per_minute(),
            "queued": len(intake.queue),
            "senders": intake.senders_seen()[:50],
            "warnings": [*intake.warnings, *self.errors],
            "last_detection": self.last_detection.isoformat() if self.last_detection else None,
        }
