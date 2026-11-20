import json
import re
import sqlite3
import time
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import netlog.api.app as api_module
from netlog.api import pipeline as pipeline_module
from netlog.api.app import KINDS, api_settings, create_app, kind_of, label_of
from netlog.api.pipeline import STAGES
from netlog.cli import main as cli_main
from netlog.config import load_config
from netlog.llm.evidence import EvidencePack
from netlog.llm.fallback import fallback_explanation
from netlog.llm.provider import FakeProvider
from netlog.llm.settings import llm_settings
from netlog.storage.database import _MIGRATIONS, SCHEMA_VERSION, Database

SCENARIOS = Path("data/scenarios")
TOKEN = re.compile(r"(?<![A-Za-z0-9_])(?:IP|USER|HOST|MAC|TEXT)_\d+(?![A-Za-z0-9_])")
FAILED = "Mar  3 02:00:{:02d} srv1 sshd[{}]: Failed password for {} from 192.0.2.77 port 4{} ssh2"


def small_log(user: str = "root", lines: int = 30) -> bytes:
    """A log small enough to analyze in a blink: one brute force on srv1."""
    rows = [FAILED.format(n, 1000 + n, user, 1000 + n) for n in range(lines)]
    rows.append("Mar  3 02:01:10 R1 15: Mar  3 02:01:10.000: %SYS-5-CONFIG_I: Configured from "
                "console by admin on vty0 (10.10.10.50)")  # fmt: skip
    return ("\n".join(rows) + "\n").encode()


def fitting(request) -> dict:
    """A valid answer for whatever evidence pack a request carries."""
    block = request.user.split("<evidence_pack>\n")[1].split("\n</evidence_pack>")[0]
    pack = EvidencePack(data=json.loads(block), redacted=True)
    mode = "junior" if "junior engineer" in request.user else "senior"
    return fallback_explanation(pack, mode).model_dump()


def build(folder: Path, provider=None, **api):
    """An app with a database and an upload folder of its own."""
    config = load_config()
    config["api"] = {**config["api"], "upload_dir": str(folder / "uploads"), **api}
    settings = api_settings(config, folder / "api.db")
    return create_app(
        config, settings=settings, llm=llm_settings(config, environ={}), provider=provider
    )


def upload(client, data: bytes, name: str = "test.log", **form):
    return client.post("/api/uploads", files={"file": (name, data)}, data=form)


def wait(client, upload_id: int, seconds: float = 60.0) -> dict:
    """Poll the status endpoint until the pipeline has finished, as a browser would."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        status = client.get(f"/api/uploads/{upload_id}/status").json()
        if status["finished"]:
            return status
        time.sleep(0.02)
    raise AssertionError(f"upload {upload_id} did not finish: {status}")


def assert_error(response, status: int, code: str) -> dict:
    assert response.status_code == status, response.text
    assert response.headers["content-type"] == "application/json"
    body = response.json()
    assert set(body) == {"error"} and body["error"]["code"] == code
    assert body["error"]["message"] and "Traceback" not in response.text
    return body["error"]


@pytest.fixture
def client(tmp_path):
    """A fresh API with no LLM configured."""
    with TestClient(build(tmp_path)) as test_client:
        test_client.folder = tmp_path
        yield test_client


@pytest.fixture(scope="module")
def loaded(tmp_path_factory):
    """One API for the read-only tests, with three sample logs analyzed once and a fake
    LLM provider writing the explanations."""
    folder = tmp_path_factory.mktemp("api")
    provider = FakeProvider([fitting])
    app = build(folder, provider)
    with TestClient(app) as test_client:
        ids = {}
        for name in ("02_cascade", "10_overlap", "09_prompt_injection"):
            data = (SCENARIOS / f"{name}.log").read_bytes()
            ids[name] = upload(test_client, data, f"{name}.log", year="2026").json()["id"]
        for upload_id in ids.values():
            assert wait(test_client, upload_id)["stage"] == "done"
        test_client.ids, test_client.provider, test_client.folder = ids, provider, folder
        yield test_client


@pytest.fixture(scope="module")
def cascade(loaded):
    """The cascade's upload id and its one incident's id."""
    upload_id = loaded.ids["02_cascade"]
    (incident,) = loaded.get(f"/api/uploads/{upload_id}/incidents").json()["items"]
    return upload_id, incident["id"]


# --- Upload, then poll until done ---------------------------------------------------------


def test_upload_returns_at_once_and_the_pipeline_runs_to_completion(tmp_path):
    provider = FakeProvider([fitting])
    with TestClient(build(tmp_path, provider)) as client:
        response = upload(client, small_log(), "edge.log", year="2026", timezone="+05:30")

        assert response.status_code == 202
        created = response.json()
        assert (created["status"], created["filename"]) == ("processing", "edge.log")
        assert created["stage"] in STAGES and created["lines"] == 0  # nothing waited for
        assert (created["year"], created["timezone"], created["source"]) == (2026, "+05:30", "file")

        seen = set()
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            status = client.get(f"/api/uploads/{created['id']}/status").json()
            seen.add(status["stage"])
            if status["finished"]:
                break
        assert status == {
            "id": created["id"],
            "status": "done",
            "stage": "done",
            "failed_stage": None,
            "error": None,
            "finished": True,
            "stages": list(STAGES),
            "counts": {"lines": 31, "templates": 2, "findings": 2, "incidents": 1},
        }
        assert seen <= set(STAGES)
        # The explanation stage asked the LLM once, and the answer is served from the cache.
        assert len(provider.requests) == 1
        (incident,) = client.get(f"/api/uploads/{created['id']}/incidents").json()["items"]
        explanation = client.get(
            f"/api/uploads/{created['id']}/incidents/{incident['id']}/explanation"
        ).json()
        assert explanation["source"] == "cache" and len(provider.requests) == 1

        done = client.get(f"/api/uploads/{created['id']}").json()
        assert (done["status"], done["lines"], done["percent_parsed"]) == ("done", 31, 100.0)
        assert done["counts"]["incidents"] == 1 and done["finished_at"]
        assert done["incidents_by_severity"]["medium"] == 1


def test_the_stored_file_gets_a_generated_name(client):
    created = upload(client, small_log(), "../../etc/passwd").json()
    wait(client, created["id"])

    assert created["filename"] == "passwd"  # a label, and only its last part
    (stored,) = (client.folder / "uploads").iterdir()
    assert re.fullmatch(r"[0-9a-f]{32}\.log", stored.name)
    assert stored.read_bytes() == small_log()
    assert not (client.folder / "etc").exists() and not (client.folder.parent / "etc").exists()
    assert "stored_name" not in created  # where it is kept is nobody's business


@pytest.mark.parametrize(
    ("given", "label"),
    [
        ("router.log", "router.log"),
        ("../../etc/passwd", "passwd"),
        ("C:\\Users\\me\\..\\..\\Windows\\system32\\evil.log", "evil.log"),
        ("/var/log/../../../root/.ssh/id_rsa", "id_rsa"),
        ("a\x00b\r\nc.log", "abc.log"),
        ("..", "upload.log"),
        ("", "upload.log"),
        (None, "upload.log"),
        ("x" * 500 + ".log", "x" * 200),
    ],
)
def test_an_uploaded_filename_is_only_ever_a_label(given, label):
    assert label_of(given) == label


# --- Files that are refused ---------------------------------------------------------------


def test_an_empty_file_is_refused(client):
    error = assert_error(upload(client, b""), 400, "empty_file")
    assert error["message"] == "The file is empty."
    assert client.get("/api/uploads").json()["total"] == 0
    assert list((client.folder / "uploads").iterdir()) == []  # nothing is left behind


def test_a_binary_file_is_refused(client):
    error = assert_error(upload(client, b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", "x.png"), 400,
                         "not_text")  # fmt: skip
    assert "not a text file" in error["message"]
    assert client.get("/api/uploads").json()["total"] == 0
    assert list((client.folder / "uploads").iterdir()) == []


def test_an_oversized_file_is_refused_politely(tmp_path):
    with TestClient(build(tmp_path, max_upload_mb=0.001)) as client:  # about one kilobyte
        # A little over: accepted for reading, then refused while it is copied.
        error = assert_error(upload(client, small_log(lines=40)), 413, "file_too_large")
        assert "larger than the 0.001 MB limit" in error["message"]
        # Far over: refused from its declared size, before any of it is read.
        assert_error(upload(client, b"x" * 300_000), 413, "file_too_large")
        assert client.get("/api/uploads").json()["total"] == 0
        assert list((tmp_path / "uploads").iterdir()) == []
        # A file within the limit is still welcome.
        assert upload(client, small_log(lines=5)).status_code == 202
        assert client.get("/api/health").json()["max_upload_bytes"] == 1048


def test_a_utf16_file_is_text_not_binary(client):
    text = small_log().decode().encode("utf-16")  # what Windows PowerShell redirection writes
    created = upload(client, text).json()
    assert wait(client, created["id"])["counts"]["incidents"] == 1


@pytest.mark.parametrize(
    ("form", "status", "code"),
    [
        ({"timezone": "Mars/Olympus"}, 400, "invalid_timezone"),
        ({"year": "12"}, 422, "invalid_request"),
        ({"year": "soon"}, 422, "invalid_request"),
    ],
)
def test_bad_upload_options_are_refused(client, form, status, code):
    assert_error(upload(client, small_log(), **form), status, code)
    assert client.get("/api/uploads").json()["total"] == 0


def test_an_upload_without_a_file_is_a_readable_error(client):
    error = assert_error(client.post("/api/uploads"), 422, "invalid_request")
    assert error["details"] == [{"field": "file", "problem": "Field required"}]


# --- A pipeline that fails ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"hello\nworld\nthis is not a log\n", "No recognizable log lines in the file."),
        (b"\n\n   \n\n", "The file contains only blank lines."),
    ],
)
def test_a_file_that_is_not_a_log_fails_with_the_stage_and_a_reason(client, data, reason):
    created = upload(client, data, "notes.txt")
    assert created.status_code == 202  # it is text, so it is accepted and then examined

    status = wait(client, created.json()["id"])
    assert (status["status"], status["stage"], status["failed_stage"]) == (
        "failed", "failed", "parsing",
    )  # fmt: skip
    assert status["error"].startswith(reason)
    one = client.get(f"/api/uploads/{created.json()['id']}").json()
    assert (one["status"], one["failed_stage"]) == ("failed", "parsing") and one["finished_at"]


def test_an_unexpected_failure_names_the_stage_and_leaks_nothing(client, monkeypatch, caplog):
    def broken(*args, **kwargs):
        raise RuntimeError("secret internal detail at C:\\server\\path.py line 42")

    monkeypatch.setattr(pipeline_module, "detect", broken)
    status = wait(client, upload(client, small_log()).json()["id"])

    assert (status["status"], status["failed_stage"]) == ("failed", "detection")
    assert status["error"] == (
        "An unexpected error occurred while running the detection rules. The details are in "
        "the server log."
    )
    assert "secret internal detail" not in json.dumps(status)
    assert "secret internal detail" in caplog.text  # the server log has it
    # What was done before the failure is still there to look at.
    assert status["counts"]["lines"] == 31 and status["counts"]["findings"] == 0


def test_uploads_left_unfinished_by_a_stopped_server_are_marked_failed(tmp_path):
    with Database(tmp_path / "api.db") as db:
        upload_id = db.create_upload("half.log", 10)
        db.set_stage(upload_id, "detection")

    with TestClient(build(tmp_path)) as client:
        status = client.get(f"/api/uploads/{upload_id}/status").json()
    assert (status["status"], status["failed_stage"]) == ("failed", "detection")
    assert status["error"].startswith("The server stopped while this upload was being processed")


def test_an_llm_that_fails_does_not_fail_the_pipeline(tmp_path):
    from netlog.llm.provider import ServerError

    provider = FakeProvider([ServerError("overloaded")])
    with TestClient(build(tmp_path, provider)) as client:
        created = upload(client, small_log()).json()
        assert wait(client, created["id"])["status"] == "done"
        (incident,) = client.get(f"/api/uploads/{created['id']}/incidents").json()["items"]
        explanation = client.get(
            f"/api/uploads/{created['id']}/incidents/{incident['id']}/explanation"
        ).json()
    assert explanation["source"] == "fallback" and "overloaded" in explanation["fallback_reason"]


# --- Unknown ids --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "code"),
    [
        ("get", "/api/uploads/999", "upload_not_found"),
        ("get", "/api/uploads/999/status", "upload_not_found"),
        ("get", "/api/uploads/999/events", "upload_not_found"),
        ("get", "/api/uploads/999/templates", "upload_not_found"),
        ("get", "/api/uploads/999/incidents", "upload_not_found"),
        ("get", "/api/uploads/999/summary", "upload_not_found"),
        ("delete", "/api/uploads/999", "upload_not_found"),
        ("get", "/api/uploads/999/incidents/inc-x", "upload_not_found"),
        ("get", "/api/uploads/999/incidents/inc-x/explanation", "upload_not_found"),
        ("get", "/api/uploads/999/incidents/inc-x/timeline", "upload_not_found"),
        ("post", "/api/uploads/999/incidents/inc-x/explanation/regenerate", "upload_not_found"),
        ("get", "/api/uploads/{id}/incidents/inc-nope", "incident_not_found"),
        ("get", "/api/uploads/{id}/incidents/inc-nope/explanation", "incident_not_found"),
        ("get", "/api/uploads/{id}/incidents/inc-nope/timeline", "incident_not_found"),
        ("post", "/api/uploads/{id}/incidents/inc-nope/explanation/regenerate",
         "incident_not_found"),
        ("post", "/api/demo/scenarios/no_such_scenario", "scenario_not_found"),
        ("get", "/api/no/such/place", "not_found"),
    ],
)
def test_unknown_ids_give_a_readable_404(loaded, method, path, code):
    path = path.replace("{id}", str(loaded.ids["02_cascade"]))
    error = assert_error(getattr(loaded, method)(path), 404, code)
    assert "999" in error["message"] or "no" in error["message"].lower()


def test_ids_of_the_wrong_kind_and_wrong_methods(loaded):
    assert_error(loaded.get("/api/uploads/abc"), 422, "invalid_request")
    assert_error(loaded.put("/api/uploads/1"), 405, "method_not_allowed")
    assert_error(loaded.get("/api/demo/scenarios/02_cascade"), 405, "method_not_allowed")


# --- Lists and pagination -----------------------------------------------------------------


def test_uploads_are_listed_newest_first_and_paged(loaded):
    everything = loaded.get("/api/uploads").json()
    assert (everything["total"], everything["limit"], everything["offset"]) == (3, 50, 0)
    assert [item["filename"] for item in everything["items"]] == [
        "09_prompt_injection.log", "10_overlap.log", "02_cascade.log",
    ]  # fmt: skip
    assert everything["items"][0]["incidents_by_severity"]["critical"] == 1
    assert everything["items"][1]["incidents_by_severity"] == {
        "critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0,
    }  # fmt: skip

    first = loaded.get("/api/uploads", params={"limit": 1}).json()
    last = loaded.get("/api/uploads", params={"limit": 1, "offset": 2}).json()
    beyond = loaded.get("/api/uploads", params={"limit": 5, "offset": 3}).json()
    assert [first["items"][0]["filename"], last["items"][0]["filename"]] == [
        "09_prompt_injection.log", "02_cascade.log",
    ]  # fmt: skip
    assert (beyond["items"], beyond["total"], beyond["offset"]) == ([], 3, 3)


@pytest.mark.parametrize(
    "path",
    [
        "/api/uploads",
        "/api/uploads/{id}/events",
        "/api/uploads/{id}/templates",
        "/api/uploads/{id}/incidents",
        "/api/demo/scenarios",
    ],
)
def test_every_list_has_the_same_paging_and_the_same_limits(loaded, path):
    path = path.replace("{id}", str(loaded.ids["02_cascade"]))

    page = loaded.get(path, params={"limit": 1, "offset": 0}).json()
    assert set(page) == {"items", "total", "limit", "offset"}
    assert len(page["items"]) == 1 and page["total"] >= 1
    assert loaded.get(path, params={"limit": 500}).status_code == 200  # the largest allowed
    far = loaded.get(path, params={"offset": 10_000_000}).json()
    assert far["items"] == [] and far["total"] == page["total"]
    for bad in ({"limit": 0}, {"limit": 501}, {"limit": -1}, {"offset": -1}, {"limit": "many"}):
        assert_error(loaded.get(path, params=bad), 422, "invalid_request")


def test_pages_of_events_join_up_without_gaps_or_repeats(loaded):
    path = f"/api/uploads/{loaded.ids['02_cascade']}/events"
    whole = loaded.get(path, params={"q": "OSPF", "limit": 500}).json()
    assert whole["total"] == 12 == len(whole["items"])

    lines = []
    for offset in range(0, 12, 5):
        page = loaded.get(path, params={"q": "OSPF", "limit": 5, "offset": offset}).json()
        lines += [event["line_no"] for event in page["items"]]
    assert lines == [event["line_no"] for event in whole["items"]] and len(set(lines)) == 12
    last = loaded.get(path, params={"q": "OSPF", "limit": 5, "offset": 10}).json()
    assert len(last["items"]) == 2


# --- Events -------------------------------------------------------------------------------


def test_events_can_be_filtered(loaded):
    path = f"/api/uploads/{loaded.ids['02_cascade']}/events"

    everything = loaded.get(path, params={"limit": 1}).json()
    assert everything["total"] == 5000
    event = everything["items"][0]
    assert {"line_no", "raw", "timestamp", "host", "severity", "event_key", "message",
            "entities"} <= set(event)  # fmt: skip

    r1 = loaded.get(path, params={"host": "R1", "limit": 500}).json()
    assert 0 < r1["total"] < 5000 and {e["host"] for e in r1["items"]} == {"R1"}

    serious = loaded.get(path, params={"severity": 3, "limit": 500}).json()
    assert serious["total"] > 0 and all(e["severity"] <= 3 for e in serious["items"])

    keys = loaded.get(
        path, params={"event_key": ["BGP-5-ADJCHANGE", "OSPF-5-ADJCHG"], "limit": 500}
    ).json()
    assert {e["event_key"] for e in keys["items"]} == {"BGP-5-ADJCHANGE", "OSPF-5-ADJCHG"}

    window = {"start": "2026-03-03T02:46:00Z", "end": "2026-03-03T02:47:00Z", "limit": 500}
    during = loaded.get(path, params=window).json()
    assert during["total"] > 20
    assert all("2026-03-03T02:46" in e["timestamp"] for e in during["items"])

    both = loaded.get(path, params={**window, "host": "R1", "q": "neighbor Down"}).json()
    # Three BGP sessions and three OSPF neighbors went down on R1 in that minute.
    assert both["total"] == 6 and all("Down" in e["message"] for e in both["items"])

    newest = loaded.get(path, params={"order": "desc", "limit": 2}).json()["items"]
    assert newest[0]["timestamp"] >= newest[1]["timestamp"] > event["timestamp"]
    assert loaded.get(path, params={"q": "zzzznothing"}).json()["total"] == 0


def test_bad_event_filters_are_refused(loaded):
    path = f"/api/uploads/{loaded.ids['02_cascade']}/events"
    error = assert_error(loaded.get(path, params={"start": "yesterday"}), 400, "invalid_time")
    assert "2026-03-03T02:46:00Z" in error["message"]
    assert_error(loaded.get(path, params={"severity": 9}), 422, "invalid_request")
    assert_error(loaded.get(path, params={"order": "sideways"}), 422, "invalid_request")
    # Search text is data: characters that mean something to the search engine are harmless.
    assert loaded.get(path, params={"q": '") OR 1=1 --'}).status_code == 200


# --- Templates and incidents --------------------------------------------------------------


def test_templates_are_sortable_by_count(loaded):
    path = f"/api/uploads/{loaded.ids['02_cascade']}/templates"

    most = loaded.get(path).json()
    rarest = loaded.get(path, params={"sort": "count_asc"}).json()
    counts = [t["count"] for t in most["items"]]
    assert most["total"] == rarest["total"] == 34 == len(counts)
    assert counts == sorted(counts, reverse=True) and counts[0] == 761
    assert [t["count"] for t in rarest["items"]] == sorted(counts)
    assert set(most["items"][0]) == {
        "id", "pattern", "event_key", "source_type", "count", "first_seen", "last_seen", "hosts",
    }  # fmt: skip
    assert most["items"][0]["pattern"] == "DHCPACK on <IP> to <MAC> (<HOST>) via <IF>"
    assert_error(loaded.get(path, params={"sort": "alphabetical"}), 422, "invalid_request")


def test_incidents_are_sortable_by_severity_and_time(loaded):
    path = f"/api/uploads/{loaded.ids['10_overlap']}/incidents"

    by_severity = loaded.get(path).json()
    assert by_severity["total"] == 2
    assert [i["severity"] for i in by_severity["items"]] == ["high", "medium"]
    mildest = loaded.get(path, params={"order": "asc"}).json()["items"]
    assert [i["severity"] for i in mildest] == ["medium", "high"]

    by_time = loaded.get(path, params={"sort": "time", "order": "asc"}).json()["items"]
    latest = loaded.get(path, params={"sort": "time", "order": "desc"}).json()["items"]
    assert by_time[0]["start"] < by_time[1]["start"]
    assert [i["id"] for i in latest] == [i["id"] for i in reversed(by_time)]

    flap = by_severity["items"][0]
    assert set(flap) == {
        "id", "headline", "title", "severity", "severity_reason", "start", "end",
        "duration_seconds", "devices", "root_cause", "confidence", "confidence_reason", "findings",
    }  # fmt: skip
    assert flap["headline"].startswith("Interface GigabitEthernet0/5 on SW2 went down 10 times")
    assert (flap["devices"], flap["confidence"], flap["findings"]) == (["SW2"], "medium", 1)
    assert len(loaded.get(path, params={"limit": 1, "offset": 1}).json()["items"]) == 1


# --- One incident -------------------------------------------------------------------------


def test_one_incident_in_full_matches_the_command_line_report(loaded, cascade, capsys):
    upload_id, incident_id = cascade
    incident = loaded.get(f"/api/uploads/{upload_id}/incidents/{incident_id}").json()

    cli_main(["analyze", str(SCENARIOS / "02_cascade.log"), "--year", "2026", "--format", "json",
              "--quiet"])  # fmt: skip
    (reported,) = json.loads(capsys.readouterr().out)["incidents"]
    for field in ("id", "headline", "title", "severity", "severity_reason", "start", "end",
                  "devices", "confidence", "confidence_reason", "unknowns"):  # fmt: skip
        assert incident[field] == reported[field], field
    assert incident["root_cause"]["summary"] == reported["root_cause"]["summary"]
    labels = [row["label"] for row in incident["story"]]
    assert labels == [row["label"] for row in reported["story"]]
    assert len(incident["chain"]) == len(reported["chain"]) == 12

    assert incident["upload_id"] == upload_id and "explanation" not in incident
    # The findings inside, and the log lines it rests on.
    details = incident["finding_details"]
    assert len(details) == 13 and {f["role"] for f in details} == {"problem", "context"}
    assert {f["id"] for f in details} == set(incident["findings"]) | set(incident["context"])
    evidence = incident["evidence"]
    assert [e["line"] for e in evidence] == sorted(e["line"] for e in evidence)
    first = evidence[0]
    assert set(first) == {"line", "time", "host", "event_key", "kind", "text", "findings"}
    assert (first["line"], first["host"], first["kind"]) == (2260, "R1", "link")
    assert "%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down" in first["text"]
    assert set(first["findings"]) <= {f["id"] for f in details}
    assert {e["host"] for e in evidence} == {"R1", "R2", "R3", "R4"}


@pytest.mark.parametrize("mode", ["senior", "junior"])
def test_the_explanation_of_an_incident_for_each_audience(loaded, cascade, mode):
    upload_id, incident_id = cascade
    path = f"/api/uploads/{upload_id}/incidents/{incident_id}/explanation"
    before = len(loaded.provider.requests)
    explanation = loaded.get(path, params={"mode": mode}).json()
    again = loaded.get(path, params={"mode": mode}).json()

    assert (explanation["upload_id"], explanation["incident_id"]) == (upload_id, incident_id)
    assert (explanation["audience"], explanation["provider"]) == (mode, "fake")
    # Senior was written by the pipeline; junior is written on the first request for it.
    assert explanation["source"] == ("cache" if mode == "senior" else "llm")
    assert again["source"] == "cache" and again["summary"] == explanation["summary"]
    assert len(loaded.provider.requests) == before + (0 if mode == "senior" else 1)

    assert explanation["fallback_reason"] is None
    assert "GigabitEthernet0/1 on R1" in explanation["summary"]
    assert not TOKEN.search(json.dumps(explanation))  # real names, no stand-ins
    assert explanation["timeline"][0]["lines"] == [2260, 2400]
    assert explanation["fix_steps"][-1]["review_before_running"] is True
    # Every line a statement points to comes with its text, for the page to show.
    cited = {
        line
        for part in ("timeline", "hypotheses", "impact")
        for item in explanation[part]
        for line in item["lines"]
    }
    assert {item["line"] for item in explanation["cited_lines"]} == cited
    assert explanation["cited_lines"][0]["line"] == 2260
    assert "%LINK-3-UPDOWN" in explanation["cited_lines"][0]["text"]


def test_the_two_audiences_agree_on_the_facts(loaded, cascade):
    upload_id, incident_id = cascade
    path = f"/api/uploads/{upload_id}/incidents/{incident_id}/explanation"
    senior = loaded.get(path).json()
    junior = loaded.get(path, params={"mode": "junior"}).json()

    assert senior["audience"] == "senior"  # the default
    assert senior["summary"] != junior["summary"]
    assert [s["lines"] for s in senior["timeline"]] == [s["lines"] for s in junior["timeline"]]
    assert [s["review_before_running"] for s in senior["fix_steps"]] == [
        s["review_before_running"] for s in junior["fix_steps"]
    ]
    assert_error(loaded.get(path, params={"mode": "expert"}), 422, "invalid_request")


def test_regenerating_asks_the_llm_again(tmp_path):
    provider = FakeProvider([fitting])
    with TestClient(build(tmp_path, provider)) as client:
        created = upload(client, small_log()).json()
        wait(client, created["id"])
        (incident,) = client.get(f"/api/uploads/{created['id']}/incidents").json()["items"]
        path = f"/api/uploads/{created['id']}/incidents/{incident['id']}/explanation"

        assert client.get(path).json()["source"] == "cache" and len(provider.requests) == 1
        fresh = client.post(f"{path}/regenerate")
        assert fresh.status_code == 200 and fresh.json()["source"] == "llm"
        assert fresh.json()["usage"]["requests"] == 1 and len(provider.requests) == 2
        # The new answer replaced the stored one, and reading it costs nothing.
        assert client.get(path).json()["source"] == "cache" and len(provider.requests) == 2
        junior = client.post(f"{path}/regenerate", params={"mode": "junior"}).json()
        assert (junior["audience"], junior["source"]) == ("junior", "llm")
        bad = client.post(f"{path}/regenerate", params={"mode": "x"})
        assert_error(bad, 422, "invalid_request")


def test_without_an_llm_explanations_come_from_the_templates(client):
    created = upload(client, small_log()).json()
    wait(client, created["id"])
    (incident,) = client.get(f"/api/uploads/{created['id']}/incidents").json()["items"]
    path = f"/api/uploads/{created['id']}/incidents/{incident['id']}/explanation"

    explanation = client.get(path).json()
    regenerated = client.post(f"{path}/regenerate").json()
    assert explanation["source"] == "fallback"
    assert explanation["fallback_reason"] == "no LLM provider is configured"
    assert explanation["usage"]["requests"] == 0
    assert "30 failed logins from 192.0.2.77" in explanation["summary"]
    assert regenerated == explanation  # the same every time
    assert client.get("/api/health").json()["llm"] == {"configured": False, "provider": ""}


def test_the_timeline_is_ready_for_a_chart(loaded, cascade):
    upload_id, incident_id = cascade
    timeline = loaded.get(f"/api/uploads/{upload_id}/incidents/{incident_id}/timeline").json()

    assert timeline["lanes"] == ["R1", "R4", "R2", "R3"]  # the root-cause device first
    assert timeline["kinds"] == list(KINDS)
    events = timeline["events"]
    assert (timeline["total_events"], timeline["truncated"]) == (len(events), False)
    assert len(events) == 32
    times = [event["time"] for event in events]
    assert times == sorted(times) and (timeline["start"], timeline["end"]) == (times[0], times[-1])
    first = events[0]
    assert set(first) == {
        "id", "line", "time", "host", "event_key", "kind", "text", "findings", "root_cause",
    }  # fmt: skip
    assert (first["line"], first["host"], first["kind"], first["root_cause"]) == (
        2260, "R1", "link", True,
    )  # fmt: skip
    assert {event["kind"] for event in events} == {"link", "ospf", "bgp"}
    assert sum(event["root_cause"] for event in events) == 2  # down, and up again
    assert {event["host"] for event in events} == set(timeline["lanes"])


def test_a_long_timeline_is_cut_and_says_so(tmp_path):
    with TestClient(build(tmp_path, timeline_max_events=10)) as client:
        created = upload(client, small_log()).json()
        wait(client, created["id"])
        (incident,) = client.get(f"/api/uploads/{created['id']}/incidents").json()["items"]
        timeline = client.get(
            f"/api/uploads/{created['id']}/incidents/{incident['id']}/timeline"
        ).json()
    assert (len(timeline["events"]), timeline["total_events"], timeline["truncated"]) == (
        10, 30, True,
    )  # fmt: skip
    assert timeline["events"][0]["kind"] == "login" and timeline["lanes"] == ["srv1"]


def test_event_kinds():
    assert [kind_of(key) for key in (
        "LINK-3-UPDOWN", "LINEPROTO-5-UPDOWN", "OSPF-5-ADJCHG", "BGP-3-NOTIFICATION",
        "SYS-5-CONFIG_I", "sshd.failed_password", "SEC_LOGIN-4-LOGIN_FAILED", "dhcp.ack",
        "SYS-5-RESTART", None,
    )] == ["link", "link", "ospf", "bgp", "config", "login", "login", "dhcp", "system",
           "system"]  # fmt: skip


# --- File-level summary -------------------------------------------------------------------


def test_the_summary_of_an_upload(loaded, cascade):
    upload_id, incident_id = cascade
    summary = loaded.get(f"/api/uploads/{upload_id}/summary").json()

    assert set(summary) == {
        "upload", "file", "summary", "top_templates", "events_over_time", "incident_periods",
        "assumptions", "warnings",
    }  # fmt: skip
    assert summary["upload"]["id"] == upload_id
    assert (summary["file"]["lines"], summary["file"]["percent_parsed"]) == (5000, 100.0)
    assert [d["host"] for d in summary["file"]["devices"]] == [
        "R1", "R2", "R3", "R4", "SW1", "SW2", "dhcp1", "srv1",
    ]  # fmt: skip
    assert summary["summary"]["incidents_by_severity"]["critical"] == 1
    assert len(summary["top_templates"]) == 10 and summary["top_templates"][0]["count"] == 761

    # Events over time are counted on the server, in round buckets, never sent one by one.
    chart = summary["events_over_time"]
    assert chart["bucket_seconds"] == 300 and 60 <= len(chart["buckets"]) <= 120
    assert sum(bucket["count"] for bucket in chart["buckets"]) == 5000
    starts = [bucket["start"] for bucket in chart["buckets"]]
    assert starts == sorted(starts) and starts[0] == "2026-03-03T00:00:00Z"

    (period,) = summary["incident_periods"]
    assert (period["id"], period["severity"]) == (incident_id, "critical")
    assert period["start"].startswith("2026-03-03T02:46:11")
    assert summary["warnings"] == []
    assert summary["assumptions"] == [
        "The log lines carry no year; 2026 was used, as given.",
        "The log lines carry no timezone, so UTC was assumed.",  # no command-line advice
    ]


def test_a_quiet_log_has_a_summary_and_no_incidents(client):
    quiet = "\n".join(
        f"Mar  3 02:00:{n:02d} srv1 sshd[{n}]: Accepted publickey for alice from 10.0.0.5 "
        f"port 5{n:04d} ssh2" for n in range(20)
    )  # fmt: skip
    created = upload(client, quiet.encode()).json()
    assert wait(client, created["id"])["status"] == "done"

    assert client.get(f"/api/uploads/{created['id']}/incidents").json() == {
        "items": [], "total": 0, "limit": 50, "offset": 0,
    }  # fmt: skip
    summary = client.get(f"/api/uploads/{created['id']}/summary").json()
    assert summary["incident_periods"] == [] and summary["summary"]["incidents"] == 0
    assert summary["events_over_time"]["bucket_seconds"] == 1
    assert "(the current year) was assumed." in summary["assumptions"][0]


# --- Demo scenarios -----------------------------------------------------------------------


def test_the_demo_scenarios_are_listed_with_what_happens_in_each(loaded):
    listing = loaded.get("/api/demo/scenarios").json()

    assert listing["total"] == 10
    names = [item["name"] for item in listing["items"]]
    assert names == sorted(names) and "02_cascade" in names and "08_noise_50k" in names
    cascade_item = next(item for item in listing["items"] if item["name"] == "02_cascade")
    assert set(cascade_item) == {"name", "description", "lines", "year", "incidents"}
    assert cascade_item["description"].startswith("R1 lost its transit link")
    assert cascade_item["incidents"] == [
        {
            "type": "link_failure",
            "title": cascade_item["description"],
            "expected_severity": "critical",
        }
    ]
    noise = next(item for item in listing["items"] if item["name"] == "08_noise")
    assert (noise["description"], noise["incidents"]) == ("A normal day. No incident.", [])
    assert "path" not in json.dumps(listing).lower().replace("password", "")


def test_a_demo_scenario_loads_like_an_upload(client):
    response = client.post("/api/demo/scenarios/01_link_flap")
    assert response.status_code == 202
    created = response.json()
    assert (created["filename"], created["source"], created["year"]) == (
        "01_link_flap.log", "demo", 2026,
    )  # fmt: skip

    status = wait(client, created["id"])
    assert (status["status"], status["counts"]["lines"], status["counts"]["incidents"]) == (
        "done", 5000, 1,
    )  # fmt: skip
    (incident,) = client.get(f"/api/uploads/{created['id']}/incidents").json()["items"]
    assert incident["severity"] == "high" and incident["start"].startswith("2026-03-03T02:35")

    # Deleting it removes the upload, never the scenario's own file.
    assert client.delete(f"/api/uploads/{created['id']}").status_code == 204
    assert (SCENARIOS / "01_link_flap.log").is_file()
    assert not (client.folder / "uploads").exists()  # nothing was copied either


@pytest.mark.parametrize(
    "name",
    ["..%2F..%2Fpyproject", "02_cascade.log", "topology", "%2e%2e", "02_cascade%00", "C:%5Cx"],
)
def test_a_demo_name_is_looked_up_never_used_as_a_path(client, name):
    response = client.post(f"/api/demo/scenarios/{name}")
    assert response.status_code == 404
    assert client.get("/api/uploads").json()["total"] == 0


# --- Delete -------------------------------------------------------------------------------


def test_deleting_an_upload_removes_everything_that_belongs_to_it(client):
    keep = upload(client, small_log("alice")).json()["id"]
    gone = upload(client, small_log("bob")).json()["id"]
    wait(client, keep)
    wait(client, gone)
    assert len(list((client.folder / "uploads").iterdir())) == 2

    response = client.delete(f"/api/uploads/{gone}")
    assert (response.status_code, response.content) == (204, b"")
    assert_error(client.get(f"/api/uploads/{gone}"), 404, "upload_not_found")
    assert_error(client.delete(f"/api/uploads/{gone}"), 404, "upload_not_found")
    assert len(list((client.folder / "uploads").iterdir())) == 1  # its file went with it

    with Database(client.folder / "api.db") as db:
        assert db.progress(gone) == {"lines": 0, "templates": 0, "findings": 0, "incidents": 0}
        assert db.count_events(gone) == 0 and db.redaction_map(gone) == []
        assert db.progress(keep)["lines"] == 31  # the other upload is untouched
    assert client.get("/api/uploads").json()["total"] == 1


def test_an_upload_still_being_processed_cannot_be_deleted(client):
    with Database(client.folder / "api.db") as db:
        upload_id = db.create_upload("busy.log", 10)
    error = assert_error(client.delete(f"/api/uploads/{upload_id}"), 409, "still_processing")
    assert "still being processed" in error["message"]
    assert client.get(f"/api/uploads/{upload_id}").status_code == 200


# --- Safety -------------------------------------------------------------------------------


def test_log_content_is_returned_as_plain_data_never_html(client):
    hostile = "<script>alert(1)</script><img src=x onerror=alert(2)>"
    created = upload(client, small_log(hostile), f"{hostile}.log").json()
    wait(client, created["id"])
    (incident,) = client.get(f"/api/uploads/{created['id']}/incidents").json()["items"]
    base = f"/api/uploads/{created['id']}"

    for path in ("", "/events", "/templates", "/incidents", "/summary",
                 f"/incidents/{incident['id']}", f"/incidents/{incident['id']}/timeline",
                 f"/incidents/{incident['id']}/explanation"):  # fmt: skip
        response = client.get(base + path)
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json", path
    # The text comes back exactly as it was logged, as a string inside JSON.
    events = client.get(f"{base}/events", params={"limit": 1}).json()["items"]
    assert hostile in events[0]["raw"] and events[0]["entities"]["username"] == hostile
    assert hostile in client.get(f"{base}/incidents/{incident['id']}").json()["evidence"][0]["text"]


def test_scenario_9_is_reported_as_critical_whatever_its_usernames_say(loaded):
    upload_id = loaded.ids["09_prompt_injection"]
    (incident,) = loaded.get(f"/api/uploads/{upload_id}/incidents").json()["items"]
    explanation = loaded.get(
        f"/api/uploads/{upload_id}/incidents/{incident['id']}/explanation"
    ).json()

    assert incident["severity"] == "critical"
    assert incident["headline"].startswith("400 failed logins from 192.0.2.77")
    assert "ignore previous instructions" not in json.dumps(explanation["summary"])
    # The injected text reached the LLM only as stand-ins.
    for sent in loaded.provider.requests:
        assert "ignore previous instructions" not in sent.user


def test_only_configured_origins_may_call_from_a_browser(client):
    allowed = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
    other = client.get("/api/health", headers={"Origin": "https://evil.example"})
    preflight = client.options(
        "/api/uploads",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )

    assert allowed.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-origin" not in other.headers
    assert preflight.status_code == 400 and "access-control-allow-origin" not in preflight.headers


def test_api_settings_are_checked():
    config = load_config()
    assert api_settings(config).allowed_origins == (
        "http://localhost:5173", "http://127.0.0.1:5173",
    )  # fmt: skip
    for name, value, message in (
        ("allowed_origins", ["*"], "may not contain"),
        ("max_upload_mb", 0, "api.max_upload_mb must be greater than zero"),
        ("max_page_size", 10, "cannot be larger than"),
        ("workers", 0, "api.workers"),
    ):
        changed = load_config()
        changed["api"] = {**changed["api"], name: value}
        with pytest.raises(ValueError, match=message):
            api_settings(changed)


def test_an_unexpected_error_in_a_request_is_a_plain_500(tmp_path, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("secret internal detail")

    with TestClient(build(tmp_path), raise_server_exceptions=False) as client:
        created = upload(client, small_log()).json()
        wait(client, created["id"])
        monkeypatch.setattr(api_module, "build_report", broken)
        error = assert_error(client.get(f"/api/uploads/{created['id']}/summary"), 500,
                             "internal_error")  # fmt: skip
    assert error["message"].startswith("Something went wrong on the server.")
    assert "secret" not in json.dumps(error)


# --- Health and documentation -------------------------------------------------------------


def test_health(loaded):
    health = loaded.get("/api/health").json()
    assert health == {
        "status": "ok",
        "version": "0.1.0",
        "database_schema": SCHEMA_VERSION,
        "llm": {"configured": True, "provider": ""},  # the tests' stand-in provider
        "max_upload_bytes": 50 * 1024 * 1024,
        "stages": list(STAGES),
    }
    assert "key" not in json.dumps(health).lower()


def test_the_documentation_lists_every_endpoint_with_a_description(loaded):
    assert loaded.get("/docs").status_code == 200
    spec = loaded.get("/openapi.json").json()
    endpoints = {
        (method.upper(), path): details
        for path, methods in spec["paths"].items()
        for method, details in methods.items()
    }
    base = "/api/uploads/{upload_id}"
    incident = base + "/incidents/{incident_id}"
    assert set(endpoints) == {
        ("GET", "/api/health"),
        ("POST", "/api/uploads"),
        ("GET", "/api/uploads"),
        ("GET", base),
        ("DELETE", base),
        ("GET", base + "/status"),
        ("GET", base + "/events"),
        ("GET", base + "/templates"),
        ("GET", base + "/incidents"),
        ("GET", base + "/summary"),
        ("GET", incident),
        ("GET", incident + "/explanation"),
        ("POST", incident + "/explanation/regenerate"),
        ("GET", incident + "/timeline"),
        ("GET", "/api/demo/scenarios"),
        ("POST", "/api/demo/scenarios/{name}"),
    }
    for (method, path), details in endpoints.items():
        assert details.get("summary"), (method, path)
        assert len(details.get("description", "")) > 60, (method, path)
        assert details.get("tags"), (method, path)
    assert "single-user tool" in spec["info"]["description"]


def test_the_module_builds_its_app_only_when_asked(monkeypatch, tmp_path):
    monkeypatch.delitem(api_module.__dict__, "app", raising=False)
    assert "app" not in api_module.__dict__  # importing the module built nothing
    built = api_module.app
    assert built is api_module.app and built.title == "netlog API"
    assert built.state.settings.db_path == tmp_path / "netlog-cache.db"
    with pytest.raises(AttributeError):
        _ = api_module.no_such_thing
    monkeypatch.delitem(api_module.__dict__, "app", raising=False)


# --- Storage ------------------------------------------------------------------------------


def test_an_older_database_gains_the_stage_columns(tmp_path):
    path = tmp_path / "old.db"
    raw = sqlite3.connect(path)
    raw.executescript("".join(f"BEGIN; {step} COMMIT;" for step in _MIGRATIONS[:8]))
    raw.execute("INSERT INTO uploads (filename, status, created_at) VALUES ('a.log', 'done', 0)")
    raw.execute("INSERT INTO uploads (filename, status, created_at) VALUES ('b.log', 'failed', 0)")
    raw.execute("PRAGMA user_version = 8")
    raw.commit()
    raw.close()

    with Database(path) as db:
        assert db.schema_version == SCHEMA_VERSION >= 9
        done, failed = db.get_upload(1), db.get_upload(2)
        assert (done.stage, done.source) == ("done", "file")
        assert (done.stored_name, done.year) == (None, None)
        assert failed.stage == "failed" and db.count_uploads() == 2


def test_stages_are_recorded_on_the_upload(tmp_path):
    with Database(tmp_path / "x.db") as db:
        upload_id = db.create_upload(
            "a.log", 5, stored_name="abc.log", year=2024, timezone="+01:00", source="demo"
        )
        created = db.get_upload(upload_id)
        assert (created.status, created.stage) == ("processing", "queued")
        assert created.failed_stage is None
        assert (created.stored_name, created.year, created.timezone, created.source) == (
            "abc.log", 2024, "+01:00", "demo",
        )  # fmt: skip

        db.set_stage(upload_id, "correlation")
        db.fail_upload(upload_id, "it broke")
        failed = db.get_upload(upload_id)
        assert (failed.status, failed.stage, failed.failed_stage, failed.error) == (
            "failed", "failed", "correlation", "it broke",
        )  # fmt: skip
        db.fail_upload(upload_id, "a clearer reason")  # the stage it failed in is kept
        assert db.get_upload(upload_id).failed_stage == "correlation"

        other = db.create_upload("b.log")
        db.set_stage(other, "explanation")
        db.complete_upload(other)
        finished = db.get_upload(other)
        assert (finished.status, finished.stage) == ("done", "done") and finished.finished_at
        assert db.fail_interrupted("stopped") == 0  # nothing is still being processed
        assert db.progress(other) == {"lines": 0, "templates": 0, "findings": 0, "incidents": 0}


def test_events_by_line_and_rarest_templates(analyzed):
    db, upload, _ = analyzed("02_cascade")

    events = db.events_by_line(upload, [2400, 2260, 2260, 999_999])
    assert [event.line_no for event in events] == [2260, 2400]
    assert db.events_by_line(upload, []) == []
    rare = db.templates(upload, limit=3, rarest_first=True)
    common = db.templates(upload, limit=3)
    assert rare[0].count <= rare[-1].count < common[-1].count <= common[0].count


def test_asking_again_bypasses_the_cache(analyzed, tmp_path):
    from netlog.llm.evidence import outgoing_packs
    from netlog.llm.explain import explain_incident

    db, upload, _ = analyzed("02_cascade")
    ((_, pack),), _ = outgoing_packs(db, upload)
    provider = FakeProvider([fitting])
    settings = replace(llm_settings(environ={}), backoff_seconds=0.0)
    with Database(tmp_path / "cache.db") as cache:
        kwargs = dict(provider=provider, settings=settings)
        assert explain_incident(cache, pack, **kwargs).source == "llm"
        assert explain_incident(cache, pack, **kwargs).source == "cache"
        assert explain_incident(cache, pack, refresh=True, **kwargs).source == "llm"
        assert len(provider.requests) == 2
        assert explain_incident(cache, pack, **kwargs).source == "cache"


def test_events_can_be_limited_to_lines_that_were_not_understood(client):
    mixed = small_log().decode() + "unknown record 17\nunknown record 99\n"
    created = upload(client, mixed.encode()).json()
    wait(client, created["id"])
    path = f"/api/uploads/{created['id']}/events"

    unparsed = client.get(path, params={"parse_status": "unparsed"}).json()
    assert unparsed["total"] == 2
    assert [e["raw"] for e in unparsed["items"]] == ["unknown record 17", "unknown record 99"]
    assert {e["parse_status"] for e in unparsed["items"]} == {"unparsed"}
    assert client.get(path, params={"parse_status": "parsed"}).json()["total"] == 31
    assert_error(client.get(path, params={"parse_status": "maybe"}), 422, "invalid_request")
