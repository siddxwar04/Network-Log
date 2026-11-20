"""The live syslog listener: intake checks, the incident lifecycle, restarts, retention,
the replay tool and the API."""

import asyncio
import re
import socket
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_api import build

from netlog.config import load_config
from netlog.live.intake import Intake, IntakeSettings, TcpFramer
from netlog.live.replay import replay, rewrite
from netlog.live.service import CLOCK_NOTE, LiveService
from netlog.storage.database import Database

CASCADE = Path("data/scenarios/02_cascade.log")
STAMP = re.compile(r"^(\w{3}) +(\d+) (\d\d):(\d\d):(\d\d)")
MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
ROUTER = "198.51.100.1"
CONFIG = "%SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.10.10.5)"
LINK = "%LINK-3-UPDOWN: Interface Gi0/1, changed state to"


def when(line: str) -> datetime:
    m = STAMP.match(line)
    return datetime(
        2026, MONTHS.index(m[1]) + 1, int(m[2]), int(m[3]), int(m[4]), int(m[5]), tzinfo=UTC
    )


def cascade_lines(start: str = "02:40", end: str = "03:00") -> list[str]:
    lines = CASCADE.read_text(encoding="utf-8").splitlines()
    return [line for line in lines if start <= line[7:12] <= end]


def live_config(**changes) -> dict:
    config = load_config()
    config["live"] = {**config["live"], **changes}
    return config


class Clock:
    def __init__(self, start: datetime) -> None:
        self.now = start
        self.ticks = 0.0

    def __call__(self) -> datetime:
        return self.now

    def monotonic(self) -> float:
        return self.ticks


def service(db_path: Path, clock: Clock, **changes) -> LiveService:
    live = LiveService(db_path, live_config(**changes), clock=clock, monotonic=clock.monotonic)
    live.open()
    return live


def feed(live: LiveService, clock: Clock, lines: list[str], tick_every: float = 10.0):
    """Send lines as a device would, at their own times, with a detection pass every
    `tick_every` seconds. Yields the time of each pass."""
    last = None
    for line in lines:
        clock.now = when(line) + timedelta(milliseconds=300)
        live.intake.accept(line.encode(), ROUTER)
        if last is None or (clock.now - last).total_seconds() >= tick_every:
            live.drain()
            live.tick()
            last = clock.now
            yield clock.now
    live.drain()
    live.tick()
    yield clock.now


def live_incidents(db_path: Path, live: LiveService) -> list[dict]:
    with Database(db_path) as db:
        return db.live_incidents(live.upload_id)


# --- The incident lifecycle ---------------------------------------------------------------


def test_replaying_the_cascade_opens_one_incident_that_grows_and_then_closes(tmp_path):
    db_path = tmp_path / "live.db"
    clock = Clock(when(cascade_lines()[0]))
    live = service(db_path, clock)

    sizes, ids = [], set()
    for _ in feed(live, clock, cascade_lines()):
        items = live_incidents(db_path, live)
        if items:
            (item,) = items
            ids.add(item["id"])
            sizes.append(len(item["snapshot"]["findings"]))
            assert item["state"] == "open"
    assert len(ids) == 1  # the same id from the first finding to the last
    assert sizes[0] < sizes[-1] == 13  # it grew as the OSPF and BGP findings arrived
    assert sizes == sorted(sizes)

    # The incident is an ordinary incident of the live upload, under its live id.
    with Database(db_path) as db:
        (incident,) = db.incidents(live.upload_id)
    assert incident.id == ids.pop() and incident.severity == "critical"
    assert incident.root_cause.summary.startswith("Interface GigabitEthernet0/1 on R1 was down")

    # Quiet for longer than the quiet period: it closes, keeping its id.
    clock.now += timedelta(seconds=301)
    live.tick()
    (item,) = live_incidents(db_path, live)
    assert item["state"] == "closed" and item["id"] == incident.id
    assert item["closed_at"] == clock.now
    # Explained once when it settled; at most once more when it closed.
    assert 1 <= item["explanations"] <= 2


def test_an_incident_is_explained_once_stable_and_not_on_every_message(tmp_path):
    db_path = tmp_path / "live.db"
    clock = Clock(when(cascade_lines()[0]))
    live = service(db_path, clock, explain_after_seconds=30)
    counts = []
    for _ in feed(live, clock, cascade_lines("02:40", "02:56"), tick_every=5):
        counts.extend(item["explanations"] for item in live_incidents(db_path, live))
    assert max(counts) <= 1
    for _ in range(4):  # the incident settles, then closes
        clock.now += timedelta(seconds=100)
        live.tick()
    (item,) = live_incidents(db_path, live)
    assert item["state"] == "closed" and item["explanations"] <= 2


def test_after_a_restart_the_incident_continues_with_the_same_id(tmp_path):
    db_path = tmp_path / "live.db"
    lines = cascade_lines()
    half = next(i for i, line in enumerate(lines) if line[7:15] >= "02:46:35")
    clock = Clock(when(lines[0]))
    first = service(db_path, clock)
    for _ in feed(first, clock, lines[:half]):
        pass
    (before,) = live_incidents(db_path, first)

    second = service(db_path, clock)  # a new process, the same database
    assert second.upload_id == first.upload_id
    for _ in feed(second, clock, lines[half:]):
        pass
    (after,) = live_incidents(db_path, second)
    assert after["id"] == before["id"]
    assert len(after["snapshot"]["findings"]) > len(before["snapshot"]["findings"])
    with Database(db_path) as db:
        numbers = [e.line_no for e in db.iter_events(second.upload_id)]
    assert sorted(numbers) == list(range(1, len(lines) + 1))  # numbering carried on


# --- What arrives -------------------------------------------------------------------------


def test_garbage_oversized_and_non_text_messages_are_counted_and_never_crash(tmp_path):
    db_path = tmp_path / "live.db"
    clock = Clock(datetime(2026, 3, 3, 2, 46, tzinfo=UTC))
    live = service(db_path, clock, max_message_bytes=200)
    good = f"Mar  3 02:46:12 R1 89085: Mar  3 02:46:11.699: {LINK} down".encode()
    for data in [
        b"\x00\x01\x02\xff\xfe binary",
        b"\xc3\x28 not utf-8",
        b"x" * 5000,
        b"",
        b"   \n  \n",
        b"just some words, no syslog header",
        b"Mar  3 02:46:12 R1 bell \x07 in the middle",
        good,
    ]:
        live.intake.accept(data, "203.0.113.9")
    stored = live.drain()
    live.tick()

    counts = live.intake.counters
    assert stored == 1 and counts.stored == 1
    assert counts.not_text == 3 and counts.oversized == 1 and counts.malformed == 3
    assert counts.received == 8


def test_a_burst_beyond_the_queue_drops_the_oldest_and_says_so(tmp_path):
    clock = Clock(datetime(2026, 3, 3, tzinfo=UTC))
    intake = Intake(
        IntakeSettings(queue_size=100, rate_per_sender=1e6, burst_per_sender=1e6),
        clock=clock,
        monotonic=clock.monotonic,
    )
    for n in range(250):
        intake.accept(f"Mar  3 00:00:00 R1 message {n}".encode(), ROUTER)
    assert len(intake.queue) == 100
    assert intake.counters.dropped == 150 and intake.counters.accepted == 250
    assert intake.queue[0].text.endswith("message 150")  # the newest were kept
    assert len(intake.warnings) == 1
    assert (
        "the queue of 100 messages overflowed; the oldest are being dropped" in intake.warnings[0]
    )


def test_one_noisy_sender_is_rate_limited_without_starving_the_others():
    clock = Clock(datetime(2026, 3, 3, tzinfo=UTC))
    intake = Intake(
        IntakeSettings(rate_per_sender=1, burst_per_sender=10),
        clock=clock,
        monotonic=clock.monotonic,
    )
    for _ in range(50):
        intake.accept(b"Mar  3 00:00:00 SW9 storm", "192.0.2.50")
    intake.accept(b"Mar  3 00:00:00 R1 normal", ROUTER)
    assert intake.counters.rate_limited == 40
    assert [m.sender for m in intake.queue].count(ROUTER) == 1
    clock.ticks += 5  # five seconds later, five more are allowed
    for _ in range(10):
        intake.accept(b"Mar  3 00:00:05 SW9 storm", "192.0.2.50")
    assert intake.counters.rate_limited == 45


def test_only_listed_senders_are_accepted_when_there_is_a_list():
    intake = Intake(IntakeSettings(allowed_senders=(ROUTER,)))
    intake.accept(b"Mar  3 00:00:00 R1 from the router", ROUTER)
    intake.accept(b"Mar  3 00:00:00 R1 pretending to be the router", "203.0.113.66")
    assert intake.counters.refused == 1 and len(intake.queue) == 1
    seen = {s["address"]: s for s in intake.senders_seen()}
    assert seen["203.0.113.66"]["discarded"] == 1 and seen[ROUTER]["messages"] == 1


def test_a_wrong_device_clock_is_replaced_by_the_arrival_time(tmp_path):
    db_path = tmp_path / "live.db"
    clock = Clock(datetime(2026, 11, 21, 10, 0, 5, tzinfo=UTC))
    live = service(db_path, clock)
    live.intake.accept(
        f"Jan  1 00:00:07 R1 5: {CONFIG}".encode(),
        ROUTER,
    )
    live.intake.accept(
        f"Nov 21 10:00:02 R2 6: {CONFIG}".encode(),
        ROUTER,
    )
    live.intake.accept(
        b"<34>1 2026-11-21T10:00:04Z - netlog-test - - - a message with no host", "192.0.2.77"
    )
    live.drain()
    with Database(db_path) as db:
        wrong, right, nameless = sorted(db.iter_events(live.upload_id), key=lambda e: e.line_no)
    assert wrong.timestamp == clock.now
    assert wrong.entities.extra["device_time"].startswith("2026-01-01T00:00:07")
    assert wrong.entities.extra["clock"] == CLOCK_NOTE
    assert right.timestamp == datetime(2026, 11, 21, 10, 0, 2, tzinfo=UTC)
    assert "device_time" not in right.entities.extra
    assert right.entities.extra["sender"] == ROUTER and right.entities.extra["arrival"]
    assert nameless.host == "192.0.2.77"  # the sender's address stands in for the name


def test_the_tcp_framer_reads_both_framings_and_skips_what_is_too_long():
    framer = TcpFramer(max_bytes=50)
    assert framer.feed(b"first line\nsecond ") == [b"first line"]
    assert framer.feed(b"line\n") == [b"second line"]
    assert framer.feed(b"11 hello world5 again") == [b"hello world", b"again"]
    assert framer.feed(b"x" * 80) == [None]  # too long: reported once, skipped to its end
    assert framer.feed(b"y" * 30 + b"\nafter\n") == [b"after"]
    broken = TcpFramer(max_bytes=50)
    assert broken.feed(b"99999 x") == [None] and broken.broken


# --- Retention ----------------------------------------------------------------------------


def test_pruning_removes_old_messages_and_keeps_the_evidence_of_incidents(tmp_path):
    db_path = tmp_path / "live.db"
    lines = cascade_lines()
    clock = Clock(when(lines[0]))
    live = service(db_path, clock)
    for _ in feed(live, clock, lines, tick_every=30):
        pass
    (item,) = live_incidents(db_path, live)
    evidence = {e for f in item["snapshot"]["findings"].values() for e in f["evidence"]}
    with Database(db_path) as db:
        before = db.count_events(live.upload_id)

    clock.now += timedelta(days=8)
    live.tick()  # long quiet: the incident closes
    deleted = live.prune()
    with Database(db_path) as db:
        left = {e.id for e in db.iter_events(live.upload_id)}
        upload = db.get_upload(live.upload_id)
        assert db.get_incident(live.upload_id, item["id"]) is not None
    assert deleted == before - len(evidence)
    assert left == evidence  # every evidence line of the incident is still there
    assert upload.line_count == len(evidence)

    clock.now += timedelta(days=91)  # past the retention of incidents
    live.prune()
    assert live_incidents(db_path, live) == []
    with Database(db_path) as db:
        assert db.count_events(live.upload_id) == 0


# --- The replay tool ----------------------------------------------------------------------


def test_replay_moves_every_timestamp_to_now_and_divides_the_gaps_by_the_speed():
    lines = [
        f"Mar  3 02:46:12 R1 89085: Mar  3 02:46:11.699: {LINK} down",
        f"Mar  3 02:47:12 R1 89086: Mar  3 02:47:11.699: {LINK} up",
    ]
    now = datetime(2026, 11, 21, 10, 0, 0, tzinfo=UTC)
    (o1, l1), (o2, l2) = rewrite(lines, now, speed=60)
    assert (o1, o2) == (0.0, 1.0)  # a minute apart, sent a second apart
    assert l1.startswith("Nov 21 10:00:00 R1 89085: Nov 21 09:59:59.994: %LINK-3-UPDOWN")
    assert l2.startswith("Nov 21 10:00:01 R1 89086: Nov 21 10:00:00.994: %LINK-3-UPDOWN")

    sent, waits = [], []
    clock = [0.0]
    count = replay(lines, sent.append, speed=60, now=lambda: now, monotonic=lambda: clock[0],
                   sleep=waits.append)  # fmt: skip
    assert count == 2 and waits == [1.0]
    assert sent[1].decode().startswith("Nov 21 10:00:01 R1")
    with pytest.raises(ValueError):
        replay(lines, sent.append, speed=0)


# --- Sockets and the API ------------------------------------------------------------------


def test_the_listener_receives_over_udp_and_tcp(tmp_path):
    async def run():
        live = LiveService(tmp_path / "live.db", live_config(port=0))
        await live.start()
        udp_port = int(live.listening["udp"].rsplit(":", 1)[1])
        tcp_port = int(live.listening["tcp"].rsplit(":", 1)[1])
        now = datetime.now(UTC)
        line = f"{now:%b} {now.day:>2} {now:%H:%M:%S} R1 1: {CONFIG}"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.sendto(line.encode(), ("127.0.0.1", udp_port))
            udp.sendto(b"\x00garbage", ("127.0.0.1", udp_port))
        reader, writer = await asyncio.open_connection("127.0.0.1", tcp_port)
        writer.write((line + "\n").encode() + b"9 truncated" + b"\n")
        await writer.drain()
        writer.close()
        await asyncio.sleep(0.5)
        await live.stop()
        return live

    live = asyncio.run(run())
    counts = live.intake.counters
    assert counts.stored == 2  # one over UDP, one over TCP
    assert counts.not_text == 1


def test_the_api_shows_live_incidents_and_opens_them_like_any_other(tmp_path, monkeypatch):
    monkeypatch.setenv("NETLOG_LIVE", "1")
    app = build(tmp_path)
    app.state.live.live.update(port=0, detect_every_seconds=0.2, quiet_seconds=600)
    with TestClient(app) as client:
        status = client.get("/api/live").json()
        assert status["enabled"] is True and status["listening"]["udp"].startswith("127.0.0.1:")
        port = int(status["listening"]["udp"].rsplit(":", 1)[1])

        lines = cascade_lines("02:45", "02:47")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            replay(lines, lambda data: udp.sendto(data, ("127.0.0.1", port)), speed=1000)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            status = client.get("/api/live").json()
            if status["open_incidents"]:
                break
            time.sleep(0.3)
        (incident,) = status["open_incidents"]
        assert incident["id"].startswith("live-") and incident["state"] == "open"
        assert incident["severity"] == "critical"
        assert status["counters"]["stored"] == len(lines)
        assert status["senders"][0]["address"] == "127.0.0.1"

        upload_id = status["upload_id"]
        page = client.get(f"/api/uploads/{upload_id}/incidents/{incident['id']}")
        assert page.status_code == 200 and page.json()["evidence"]
        explanation = client.get(f"/api/uploads/{upload_id}/incidents/{incident['id']}/explanation")
        assert explanation.status_code == 200
        refused = client.delete(f"/api/uploads/{upload_id}")
        assert refused.status_code == 409 and refused.json()["error"]["code"] == "live_running"


def test_the_api_says_when_the_listener_is_off(tmp_path):
    with TestClient(build(tmp_path)) as client:
        assert client.get("/api/live").json() == {"enabled": False}


def test_an_incident_with_something_still_down_stays_open_however_quiet(tmp_path):
    db_path = tmp_path / "live.db"
    lines = cascade_lines("02:40", "02:47")
    clock = Clock(when(lines[0]))
    live = service(db_path, clock)
    for _ in feed(live, clock, lines):
        pass
    for _ in range(6):  # an hour with no messages at all
        clock.now += timedelta(minutes=10)
        live.tick()
    (item,) = live_incidents(db_path, live)
    assert item["state"] == "open"
    down = [f for f in item["snapshot"]["findings"].values() if f["rule"] == "interface_down"]
    assert down and down[0]["flags"] == ["not_recovered"]
    assert down[0]["end"] == clock.now.isoformat()  # down until now, not until the last message
