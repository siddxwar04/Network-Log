"""Alerts: when they are sent, what they say, rate limits and digests, silences, failing
webhooks, and keeping the webhook address secret. Every alert goes to a fake webhook
receiver: a small HTTP server on this machine that records what it is sent."""

import json
import logging
import socket
import threading
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient
from test_api import build
from test_live import Clock, cascade_lines, feed, live_config, when

from netlog.alerts.alerter import Alerter, add_silence
from netlog.alerts.message import (
    digest_facts,
    duration_text,
    incident_facts,
    plain_text,
    redact,
    slack_payload,
)
from netlog.alerts.settings import AlertSettings, Target, alert_settings
from netlog.alerts_cli import minutes_of
from netlog.cli import main as cli_main
from netlog.config import load_config
from netlog.correlation.incident import Incident, RootCause
from netlog.live.replay import replay
from netlog.live.service import LiveService
from netlog.storage.database import Database

# What a real Slack webhook looks like: the path is the secret.
SECRET = "T0000/B0000/xS3cr3tW3bh00kT0k3n"
T0 = datetime(2026, 3, 3, 2, 0, tzinfo=UTC)


class Receiver:
    """A fake webhook: records every POST, and answers with `status`."""

    def __init__(self, status: int = 200, delay: float = 0.0) -> None:
        self.status = status
        self.delay = delay
        self.received: list[tuple[str, dict]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.received.append((self.path, json.loads(body)))
                time.sleep(outer.delay)
                self.send_response(outer.status)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def url(self, path: str = f"/services/{SECRET}") -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}{path}"

    def texts(self) -> list[str]:
        return [body.get("text", "") for _, body in self.received]

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def receiver():
    made = Receiver()
    yield made
    made.close()


def settings_for(*targets: Target, **changes) -> AlertSettings:
    base = alert_settings(load_config(), environ={})
    return replace(base, targets=targets, backoff_seconds=0.0, **changes)


def slack(receiver: Receiver) -> Target:
    return Target("slack", receiver.url())


def live_with(db_path, clock: Clock, alerter: Alerter, **changes) -> LiveService:
    live = LiveService(
        db_path, live_config(**changes), alerts=alerter, clock=clock, monotonic=clock.monotonic
    )
    live.open()
    return live


def run_cascade(live: LiveService, clock: Clock, lines=None) -> None:
    for _ in feed(live, clock, lines or cascade_lines()):
        live.alerts.flush(clock)


# --- Made-up incidents, for the rules about when to alert ---------------------------------


class Board:
    """A live upload whose incidents a test sets by hand, then asks the alerter about."""

    def __init__(self, db_path, alerter: Alerter) -> None:
        self.db_path = db_path
        self.alerter = alerter
        with Database(db_path) as db:
            self.upload = db.live_upload()
        self.items: dict[str, dict] = {}
        self.incidents: dict[str, Incident] = {}

    def put(self, incident_id, severity, now, devices=("R1",), state="open", cause="link_flap"):
        incident = Incident(
            id=incident_id, title=f"Problem {incident_id} on {devices[0]}", severity=severity,
            severity_reason="test", start=now, end=now + timedelta(seconds=90),
            devices=list(devices), finding_ids=[],
            root_cause=RootCause(cause, f"Gi0/1 on {devices[0]} flapped", list(devices),
                                 "GigabitEthernet0/1", [], 1),
            confidence="high",
        )  # fmt: skip
        self.incidents[incident_id] = incident
        old = self.items.get(incident_id)
        self.items[incident_id] = {
            "id": incident_id,
            "state": state,
            "opened_at": old["opened_at"] if old else now,
            "closed_at": now if state == "closed" else None,
            "summary": None,
            "snapshot": {"incident": {"severity": severity}, "findings": {}},
        }

    def review(self, now) -> None:
        with Database(self.db_path) as db:
            db.save_incidents(self.upload, list(self.incidents.values()))
            self.alerter.review(db, self.upload, list(self.items.values()), now)
        self.alerter.flush(lambda: now)

    def alerts(self) -> list[dict]:
        with Database(self.db_path) as db:
            return list(reversed(db.alerts()))


# --- One alert per incident, one more per rise --------------------------------------------


def test_one_incident_gives_exactly_one_alert_with_what_matters(tmp_path, receiver):
    db_path = tmp_path / "live.db"
    lines = cascade_lines()
    clock = Clock(when(lines[0]))
    live = live_with(db_path, clock, Alerter(db_path, settings_for(slack(receiver))))
    run_cascade(live, clock, lines)

    assert len(receiver.received) == 1
    path, body = receiver.received[0]
    assert path == f"/services/{SECRET}"
    first, cause, devices, link = body["text"].splitlines()
    # Readable on a lock screen: severity and what broke first, then the likely cause.
    assert first.startswith("CRITICAL: BGP session from R1")
    assert cause == ("Likely cause: Interface GigabitEthernet0/1 on R1 was down for 1m 5s "
                     "(high confidence)")  # fmt: skip
    assert devices == "Devices: R1, R2, R3, R4 | started 2026-03-03 02:46:11 UTC"
    (incident,) = Database(db_path).incidents(live.upload_id)
    assert link == (
        f"<http://localhost:5173/uploads/{live.upload_id}/incidents/{incident.id}"
        "|Open the incident>"
    )

    # More evidence, the close, and a restart on the same database: nothing more.
    clock.now += timedelta(seconds=301)
    live.tick()
    restarted = live_with(db_path, clock, Alerter(db_path, settings_for(slack(receiver))))
    restarted.tick()
    restarted.alerts.flush(clock)
    assert len(receiver.received) == 1


def test_the_first_alert_waits_for_the_incident_to_settle(tmp_path):
    board = Board(tmp_path / "a.db", Alerter(tmp_path / "a.db", settings_for(
        Target("slack", "http://127.0.0.1:9/x"))))  # fmt: skip
    board.alerter.post = lambda *_: None
    board.put("i1", "high", T0)
    board.review(T0 + timedelta(seconds=29))
    assert board.alerts() == []
    board.review(T0 + timedelta(seconds=30))
    assert [a["kind"] for a in board.alerts()] == ["opened"]


def test_a_severity_rise_gives_one_more_and_more_evidence_at_the_same_level_none(tmp_path):
    db_path = tmp_path / "a.db"
    posted = []
    alerter = Alerter(db_path, settings_for(Target("webhook", "http://example.invalid/x"),
                                            first_alert_wait_seconds=0),
                      post=lambda url, payload, timeout: posted.append(payload))  # fmt: skip
    board = Board(db_path, alerter)

    board.put("i1", "medium", T0)  # below the minimum: nothing yet
    board.review(T0)
    board.put("i1", "high", T0)
    board.review(T0 + timedelta(seconds=10))
    board.put("i1", "high", T0)  # more evidence, same severity
    board.review(T0 + timedelta(seconds=20))
    board.put("i1", "critical", T0)
    board.review(T0 + timedelta(seconds=30))
    board.review(T0 + timedelta(seconds=40))
    board.put("i1", "critical", T0, state="closed")  # on_close is off by default
    board.review(T0 + timedelta(seconds=50))

    assert [(p["kind"], p["severity"]) for p in posted] == [
        ("opened", "high"), ("raised", "critical")
    ]  # fmt: skip
    assert posted[1]["text"].startswith("CRITICAL (was HIGH): Problem i1 on R1")
    assert posted[1]["source"] == "netlog" and posted[1]["incident_id"] == "i1"


def test_with_on_close_an_alerted_incident_says_when_it_ends_and_how_long_it_lasted(tmp_path):
    db_path = tmp_path / "a.db"
    posted = []
    alerter = Alerter(db_path, settings_for(Target("slack", "http://example.invalid/x"),
                                            first_alert_wait_seconds=0, on_close=True),
                      post=lambda url, payload, timeout: posted.append(payload))  # fmt: skip
    board = Board(db_path, alerter)
    board.put("loud", "high", T0)
    board.put("quiet", "low", T0, devices=("R2",))  # never alerted, so its close is not news
    board.review(T0)
    board.put("loud", "high", T0, state="closed")
    board.put("quiet", "low", T0, devices=("R2",), state="closed")
    board.review(T0 + timedelta(minutes=10))
    board.review(T0 + timedelta(minutes=11))
    assert len(posted) == 2
    assert posted[1]["text"].startswith("RESOLVED after 2 min: Problem loud on R1")


# --- Floods -------------------------------------------------------------------------------


def test_twenty_incidents_in_a_minute_give_the_limit_plus_one_digest(tmp_path, receiver):
    db_path = tmp_path / "a.db"
    alerter = Alerter(db_path, settings_for(slack(receiver), first_alert_wait_seconds=0,
                                            max_alerts=5, period_seconds=600))  # fmt: skip
    board = Board(db_path, alerter)
    for n in range(20):
        now = T0 + timedelta(seconds=3 * n)
        board.put(f"i{n:02}", "critical" if n == 7 else "high", now, devices=(f"SW{n}",))
        board.review(now)
    assert len(receiver.received) == 5
    statuses = [a["status"] for a in board.alerts()]
    assert statuses == ["sent"] * 5 + ["held"] * 15

    board.review(T0 + timedelta(seconds=599))  # the first alert is still within the period
    assert len(receiver.received) == 5
    board.review(T0 + timedelta(seconds=601))
    board.review(T0 + timedelta(seconds=700))
    assert len(receiver.received) == 6
    digest = receiver.texts()[5].splitlines()
    assert digest[0] == ("CRITICAL: 15 more alert(s) about 15 incident(s), held back by the "
                         "rate limit")  # fmt: skip
    assert digest[1] == "- CRITICAL: Problem i07 on SW7 (SW7)"  # the worst first
    assert digest[-2] == "- and 7 more" and digest[-1].endswith("/live|Open the live page>")
    assert {a["status"] for a in board.alerts()[5:20]} == {"digested"}


# --- Silences -----------------------------------------------------------------------------


def test_a_silenced_device_gives_no_alert_and_the_incident_is_still_stored(tmp_path, receiver):
    db_path = tmp_path / "live.db"
    lines = cascade_lines()
    clock = Clock(when(lines[0]))
    settings = settings_for(slack(receiver))
    live = live_with(db_path, clock, Alerter(db_path, settings))
    add_silence(db_path, settings, "device", "r1", 120, "planned maintenance", clock.now)
    run_cascade(live, clock, lines)

    assert receiver.received == []
    with Database(db_path) as db:
        (incident,) = db.incidents(live.upload_id)
        (alert,) = db.alerts()
    assert incident.severity == "critical"
    assert alert["status"] == "silenced" and alert["incident_id"] == incident.id
    assert alert["silence_id"] is not None


def test_silences_by_type_and_of_everything_and_their_end(tmp_path):
    db_path = tmp_path / "a.db"
    posted = []
    settings = settings_for(Target("webhook", "http://example.invalid/x"),
                            first_alert_wait_seconds=0)  # fmt: skip
    board = Board(db_path, Alerter(db_path, settings, post=lambda u, p, t: posted.append(p)))
    add_silence(db_path, settings, "type", "link_flap", 60, "", T0)
    board.put("flap", "high", T0)
    board.put("bgp", "high", T0, cause="bgp_down")
    board.review(T0)
    assert [p["incident_id"] for p in posted] == ["bgp"]

    everything = add_silence(db_path, settings, "all", None, 60, "", T0)
    board.put("other", "high", T0, devices=("R9",))
    board.review(T0 + timedelta(seconds=1))
    with Database(db_path) as db:
        db.end_silence(everything["id"], T0 + timedelta(seconds=2))
    board.put("after", "high", T0, devices=("R8",), cause="bgp_down")
    board.review(T0 + timedelta(seconds=3))
    assert [p["incident_id"] for p in posted] == ["bgp", "after"]

    with pytest.raises(ValueError, match="at most 168 hours"):
        add_silence(db_path, settings, "all", None, 169 * 60, "", T0)
    with pytest.raises(ValueError, match="which device"):
        add_silence(db_path, settings, "device", " ", 10, "", T0)


# --- Failing webhooks ---------------------------------------------------------------------


def test_a_failing_webhook_retries_records_the_failure_and_detection_goes_on(tmp_path):
    failing = Receiver(status=500)
    try:
        db_path = tmp_path / "live.db"
        waits = []
        settings = replace(settings_for(slack(failing)), max_retries=3, backoff_seconds=2.0)
        alerter = Alerter(db_path, settings, sleep=waits.append)
        lines = cascade_lines()
        clock = Clock(when(lines[0]))
        live = live_with(db_path, clock, alerter)
        run_cascade(live, clock, lines)

        assert len(failing.received) == 4  # the first try and three more
        assert waits == [2.0, 4.0, 8.0]
        with Database(db_path) as db:
            (alert,) = db.alerts()
            assert db.incidents(live.upload_id)  # detection carried on
        assert alert["status"] == "failed" and alert["sent_at"] is None
        assert alert["deliveries"] == [
            {"target": "slack", "ok": False, "attempts": 4, "error": "HTTP 500"}
        ]
        assert any("to slack failed after 4 tries: HTTP 500" in w
                   for w in live.status()["warnings"])  # fmt: skip
    finally:
        failing.close()


def test_a_refusal_that_will_not_pass_is_not_retried(tmp_path):
    gone = Receiver(status=404)  # a revoked webhook
    try:
        alerter = Alerter(tmp_path / "a.db", settings_for(slack(gone)))
        result = alerter.send_test(T0)
        assert result["sent"] is False
        assert result["deliveries"] == [
            {"target": "slack", "ok": False, "attempts": 1, "error": "HTTP 404"}
        ]
    finally:
        gone.close()


def test_sending_happens_in_the_background_and_never_slows_detection(tmp_path):
    slow = Receiver(delay=0.6)
    try:
        db_path = tmp_path / "live.db"
        lines = cascade_lines()
        clock = Clock(when(lines[0]))
        alerter = Alerter(db_path, settings_for(slack(slow)))
        live = live_with(db_path, clock, alerter)
        alerter.start(clock)
        passes, tick = [], live.tick

        def timed():
            began = time.monotonic()
            tick()
            passes.append(time.monotonic() - began)

        live.tick = timed
        for _ in feed(live, clock, lines):
            pass
        assert alerter.wait(10)
        alerter.stop()
        assert len(slow.received) == 1
        assert max(passes) < 0.6  # no pass waited for the webhook
    finally:
        slow.close()


def test_an_unreachable_webhook_is_recorded_too(tmp_path):
    with socket.socket() as probe:  # a port nothing listens on
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    alerter = Alerter(
        tmp_path / "a.db",
        settings_for(Target("webhook", f"http://127.0.0.1:{port}/{SECRET}"), max_retries=1),
    )
    result = alerter.send_test(T0)
    (delivery,) = result["deliveries"]
    assert delivery["ok"] is False and delivery["attempts"] == 2
    assert delivery["error"].startswith("could not connect")


# --- Keeping the address secret -----------------------------------------------------------


def test_the_webhook_address_never_appears_in_logs_or_api_responses(
    tmp_path, monkeypatch, caplog
):
    failing = Receiver(status=500)
    try:
        url = failing.url()
        monkeypatch.setenv("NETLOG_ALERT_SLACK_URL", url)
        monkeypatch.setenv("NETLOG_LIVE", "1")
        caplog.set_level(logging.DEBUG)
        config = load_config()
        config["alerts"] = {**config["alerts"], "max_retries": 1, "backoff_seconds": 0}
        settings = alert_settings(config)
        assert SECRET not in repr(settings) and SECRET not in repr(settings.targets)

        app = build(tmp_path)
        app.state.live.live.update(port=0)
        app.state.alerts.settings = settings
        with TestClient(app) as client:
            answers = [
                client.post("/api/alerts/test"),
                client.get("/api/alerts"),
                client.get("/api/live"),
                client.get("/api/health"),
                client.post("/api/alerts/silences", json={"all": True, "minutes": 5}),
            ]
        assert answers[0].json()["deliveries"][0]["error"] == "HTTP 500"
        assert answers[1].json()["targets"] == {"slack": True, "webhook": False}
        for answer in answers:
            assert answer.status_code < 300, answer.text
            assert SECRET not in answer.text and url not in answer.text
        assert "failed after 2 tries" in caplog.text
        assert SECRET not in caplog.text
        with Database(tmp_path / "api.db") as db:
            assert SECRET not in json.dumps([a["deliveries"] for a in db.alerts()])
    finally:
        failing.close()


def test_webhook_addresses_are_refused_in_a_settings_file():
    config = load_config()
    config["alerts"] = {**config["alerts"], "slack_url": "https://hooks.example/x"}
    with pytest.raises(ValueError, match="do not belong in a settings file"):
        alert_settings(config, environ={})
    with pytest.raises(ValueError, match="must be an http"):
        alert_settings(load_config(), environ={"NETLOG_ALERT_WEBHOOK_URL": "file:///etc/passwd"})
    assert alert_settings(load_config(), environ={}).enabled is False


# --- What an alert says --------------------------------------------------------------------


def incident(**changes) -> Incident:
    values = dict(
        id="live-1", title="Failed SSH logins for alice from 192.0.2.77", severity="high",
        severity_reason="", start=T0, end=T0 + timedelta(minutes=3), devices=["srv1"],
        finding_ids=[], confidence="medium",
        root_cause=RootCause("brute_force", "Password guessing against alice from 192.0.2.77",
                             ["srv1"], "192.0.2.77", [], 1),
    )  # fmt: skip
    return Incident(**{**values, **changes})


def test_log_content_cannot_ping_the_channel_or_add_lines():
    facts = incident_facts(
        "opened",
        incident(title="Bad <!channel> @everyone <http://evil|click>\nCRITICAL: fake line"),
        upload_id=3, link_base="http://localhost:5173",
    )  # fmt: skip
    text = slack_payload(facts)["text"]
    assert "<!channel>" not in text and "@everyone" not in text and "<http://evil" not in text
    assert "&lt;!channel&gt;" in text and "@​everyone" in text
    assert text.splitlines()[0].endswith("click&gt; CRITICAL: fake line")  # one line still
    assert len(text.splitlines()) == 4


def test_redaction_replaces_addresses_and_usernames_but_keeps_the_link():
    facts = incident_facts(
        "opened", incident(devices=["srv1", "203.0.113.9"]), upload_id=3,
        link_base="http://192.168.1.20:5173", summary="Someone guessed alice's password. More.",
    )  # fmt: skip
    assert facts["summary"] == "Someone guessed alice's password."  # one sentence only
    hidden = redact(facts, {"alice"})
    text = plain_text(hidden)
    assert "alice" not in text and "192.0.2.77" not in text and "203.0.113.9" not in text
    assert "Failed SSH logins for [user] from [IP]" in text
    assert hidden["devices"] == ["srv1", "[IP]"]
    assert hidden["link"] == "http://192.168.1.20:5173/uploads/3/incidents/live-1"


def test_a_redacting_alerter_sends_no_address_or_username(tmp_path):
    db_path = tmp_path / "a.db"
    posted = []
    settings = settings_for(Target("webhook", "http://example.invalid/x"),
                            first_alert_wait_seconds=0, redact=True)  # fmt: skip
    board = Board(db_path, Alerter(db_path, settings, post=lambda u, p, t: posted.append(p)))
    board.put("i1", "high", T0, devices=("192.0.2.5",))
    board.review(T0)
    (payload,) = posted
    assert "192.0.2.5" not in json.dumps(payload) and payload["devices"] == ["[IP]"]


def test_small_helpers():
    assert duration_text(45) == "45 s" and duration_text(720) == "12 min"
    assert duration_text(7500) == "2 h 5 min"
    assert minutes_of("90") == 90 and minutes_of("2h") == 120 and minutes_of("1d") == 1440
    with pytest.raises(ValueError):
        minutes_of("soon")
    assert digest_facts([], "http://x")["items"] == []


# --- The test alert, from the command line and the API ------------------------------------


def test_the_command_sends_a_clearly_labelled_test_alert(receiver, monkeypatch, capsys):
    assert cli_main(["alerts", "test"]) == 2  # no webhook set
    assert "no webhook is set" in capsys.readouterr().err

    monkeypatch.setenv("NETLOG_ALERT_SLACK_URL", receiver.url())
    monkeypatch.setenv("NETLOG_ALERT_WEBHOOK_URL", receiver.url("/generic"))
    assert cli_main(["alerts", "test"]) == 0
    assert capsys.readouterr().out == "slack: delivered\nwebhook: delivered\n"
    (_, to_slack), (path, to_generic) = receiver.received
    assert to_slack["text"].startswith("TEST ALERT from netlog. Nothing is wrong.")
    assert path == "/generic" and to_generic["test"] is True and to_generic["kind"] == "test"


def test_the_command_silences_lists_and_ends_a_silence(monkeypatch, capsys):
    assert cli_main(["alerts", "silence", "--device", "R1", "--for", "2h",
                     "--reason", "IOS upgrade"]) == 0  # fmt: skip
    made = capsys.readouterr().out
    assert made.startswith("Silence 1: no alerts for device R1 until ")
    assert cli_main(["alerts", "list"]) == 0
    listed = capsys.readouterr().out
    assert "Silences in force: 1" in listed and "device R1 until" in listed
    assert "(IOS upgrade)" in listed
    assert cli_main(["alerts", "unsilence", "1"]) == 0
    assert cli_main(["alerts", "list"]) == 0
    assert "Silences in force: none" in capsys.readouterr().out
    assert cli_main(["alerts", "silence", "--all", "--for", "later"]) == 2


def test_the_api_test_alert_and_silences(tmp_path, receiver, monkeypatch):
    with TestClient(build(tmp_path)) as client:
        off = client.post("/api/alerts/test")
        assert off.status_code == 409 and off.json()["error"]["code"] == "alerts_off"
        assert client.get("/api/alerts").json()["enabled"] is False

    monkeypatch.setenv("NETLOG_ALERT_SLACK_URL", receiver.url())
    with TestClient(build(tmp_path)) as client:
        sent = client.post("/api/alerts/test").json()
        assert sent["sent"] is True and len(receiver.received) == 1

        made = client.post("/api/alerts/silences",
                           json={"type": "link_flap", "minutes": 30, "reason": "work"})  # fmt: skip
        assert made.status_code == 201
        silence = made.json()
        assert silence["scope"] == "type" and silence["active"] is True
        for wrong in ({"minutes": 5}, {"all": True, "device": "R1", "minutes": 5},
                      {"all": True, "minutes": 0}, {"all": True, "minutes": 99999}):  # fmt: skip
            assert client.post("/api/alerts/silences", json=wrong).status_code in (400, 422)

        status = client.get("/api/alerts").json()
        assert status["enabled"] is True and status["min_severity"] == "high"
        assert [s["id"] for s in status["silences"]] == [silence["id"]]
        (alert,) = status["alerts"]["items"]
        assert alert["kind"] == "test" and alert["status"] == "sent"

        ended = client.delete(f"/api/alerts/silences/{silence['id']}").json()
        assert ended["active"] is False
        assert client.delete("/api/alerts/silences/999").status_code == 404


# --- Done when: a replayed scenario gives one alert at the fake receiver -------------------


def test_a_replayed_scenario_gives_one_alert_at_the_receiver(tmp_path, receiver, monkeypatch):
    monkeypatch.setenv("NETLOG_LIVE", "1")
    monkeypatch.setenv("NETLOG_ALERT_SLACK_URL", receiver.url())
    app = build(tmp_path)
    app.state.live.live.update(port=0, detect_every_seconds=0.2, quiet_seconds=600)
    app.state.alerts.settings = replace(app.state.alerts.settings, first_alert_wait_seconds=1)
    with TestClient(app) as client:
        port = int(client.get("/api/live").json()["listening"]["udp"].rsplit(":", 1)[1])
        lines = cascade_lines("02:45", "02:48")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            replay(lines, lambda data: udp.sendto(data, ("127.0.0.1", port)), speed=1000)
        deadline = time.monotonic() + 30
        while not receiver.received and time.monotonic() < deadline:
            time.sleep(0.2)
        time.sleep(2)  # several more detection passes: still one alert
        (text,) = receiver.texts()
        assert text.startswith("CRITICAL: ")
        # Sent at a thousand times real speed, the timings, and so the wording of the cause,
        # differ from the file; it is still one alert about R1.
        assert text.splitlines()[1].startswith("Likely cause: ")
        assert "on R1, R2, R3, R4" in text
        assert client.get("/api/alerts").json()["alerts"]["items"][0]["status"] == "sent"


def test_an_alert_carries_the_explanation_summary_when_it_is_ready(tmp_path):
    db_path = tmp_path / "a.db"
    posted = []
    settings = settings_for(Target("webhook", "http://example.invalid/x"),
                            first_alert_wait_seconds=0)  # fmt: skip
    board = Board(db_path, Alerter(db_path, settings, post=lambda u, p, t: posted.append(p)))
    board.put("i1", "high", T0)
    board.review(T0)  # not explained yet: the alert does not wait for it
    board.put("i1", "critical", T0)
    board.items["i1"]["summary"] = "Gi0/1 on R1 kept flapping.\nThe rest is detail."
    board.review(T0 + timedelta(seconds=40))
    assert posted[0]["summary"] is None and "Summary:" not in posted[0]["text"]
    assert posted[1]["summary"] == "Gi0/1 on R1 kept flapping."
    assert "\nSummary: Gi0/1 on R1 kept flapping.\n" in posted[1]["text"]


def test_the_listener_keeps_each_incident_explanation_summary_for_its_alerts(tmp_path):
    db_path = tmp_path / "live.db"
    lines = cascade_lines()
    clock = Clock(when(lines[0]))
    live = live_with(db_path, clock, Alerter(db_path, settings_for()))
    for _ in feed(live, clock, lines):
        pass
    with Database(db_path) as db:
        (item,) = db.live_incidents(live.upload_id)
    assert item["explanations"] >= 1 and item["summary"]
