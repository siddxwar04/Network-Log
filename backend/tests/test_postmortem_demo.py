"""The post-mortem export, and demo mode: the demo scenarios explained with answers stored
in the repository, with no API key and no request."""

import os
import re
import socket
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_api import build, fitting, wait
from test_report_explanation import check_golden

from netlog.cli import EXIT_CLEAN, EXIT_ERROR, main
from netlog.config import load_config
from netlog.demo import write_demo_explanations
from netlog.llm.provider import FakeProvider
from netlog.llm.stored import ENV_FILE, load_stored

SCENARIOS = Path("data/scenarios")
CASCADE = str(SCENARIOS / "02_cascade.log")
INJECTION = str(SCENARIOS / "09_prompt_injection.log")
SECTIONS = [
    "## Summary",
    "## Impact",
    "## Timeline",
    "## Likely root cause",
    "## Contributing factors",
    "## What was done, and what should be done",
    "## What cannot be determined from these logs",
    "## Follow-up actions",
    "## Appendix: evidence",
]


def postmortem(capsys, *args, provider=None):
    code = main(["postmortem", *args, "--quiet"], provider=provider)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# --- The post-mortem ----------------------------------------------------------------------


def test_the_cascade_post_mortem_matches_the_stored_document(capsys):
    code, out, err = postmortem(capsys, CASCADE, "--year", "2026", "--no-llm")

    assert code == EXIT_CLEAN and err == ""
    check_golden("postmortem_cascade.md", out)


def test_a_post_mortem_has_every_section_in_order_and_says_it_needs_review(capsys):
    _, out, _ = postmortem(capsys, CASCADE, "--year", "2026", "--no-llm")

    assert out.startswith("# Post-mortem: Interface GigabitEthernet0/1 on R1 was down for 8m 36s")
    assert "Drafted automatically by netlog. Review every statement before filing it." in out
    positions = [out.index(section) for section in SECTIONS]
    assert positions == sorted(positions)
    # The timeline in time order, starting with the uplink, with recoveries.
    timeline = out.split("## Timeline")[1].split("## ")[0]
    rows = [line for line in timeline.splitlines() if re.match(r"\| \d\d:\d\d:\d\d", line)]
    assert rows[0].startswith("| 02:46:11 | R1 | Interface GigabitEthernet0/1 on R1 was down")
    assert [row[2:10] for row in rows] == sorted(row[2:10] for row in rows)
    assert any("Recovered:" in row for row in rows)
    # Follow-up actions are a checklist for the team.
    assert out.count("- [ ] ") == 4
    assert "**REVIEW BEFORE RUNNING:** Shut and no shut the interface" in out
    # The appendix holds the log lines with their line numbers, as they are in the file.
    appendix = out.split("## Appendix: evidence")[1]
    assert "2260  Mar  3 02:46:12 R1 89085: Mar  3 02:46:11.699: %LINK-3-UPDOWN" in appendix


def test_a_post_mortem_for_a_chosen_incident_and_a_clear_error_for_an_unknown_one(capsys, tmp_path):
    out_file = tmp_path / "pm.md"
    code, out, _ = postmortem(
        capsys,
        CASCADE,
        "--year",
        "2026",
        "--no-llm",
        "--incident",
        "inc-6f861a94c9",
        "-o",
        str(out_file),
    )
    assert code == EXIT_CLEAN
    assert "Post-mortem written to" in out
    assert out_file.read_text(encoding="utf-8").startswith("# Post-mortem: ")

    code, _, err = postmortem(
        capsys, CASCADE, "--year", "2026", "--no-llm", "--incident", "inc-nope"
    )
    assert code == EXIT_ERROR
    assert "has no incident 'inc-nope'; it has: inc-6f861a94c9" in err

    code, _, err = postmortem(capsys, str(SCENARIOS / "08_noise.log"), "--no-llm")
    assert code == EXIT_ERROR and "no incidents found" in err


def test_text_from_the_logs_cannot_format_the_post_mortem(capsys):
    _, out, _ = postmortem(capsys, INJECTION, "--year", "2026", "--no-llm")

    prose = out.split("## Appendix: evidence")[0]
    # Nothing from a log line becomes a link, an image or HTML outside a code block.
    assert "](" not in prose and "<" not in prose.replace("\\<", "")
    appendix = out.split("## Appendix: evidence")[1]
    assert "Failed password for" in appendix
    fences = re.findall(r"^`{3,}", appendix, re.M)
    assert len(fences) == 2


def test_the_api_downloads_a_post_mortem_for_every_demo_incident(tmp_path):
    with TestClient(build(tmp_path)) as client:
        names = [s["name"] for s in client.get("/api/demo/scenarios").json()["items"]]
        downloaded = 0
        for name in [n for n in names if not n.endswith("_50k")]:
            upload_id = client.post(f"/api/demo/scenarios/{name}").json()["id"]
            wait(client, upload_id)
            for item in client.get(f"/api/uploads/{upload_id}/incidents").json()["items"]:
                response = client.get(f"/api/uploads/{upload_id}/incidents/{item['id']}/postmortem")
                assert response.status_code == 200
                assert response.headers["content-type"].startswith("text/markdown")
                disposition = response.headers["content-disposition"]
                assert disposition == f'attachment; filename="postmortem-{name}-{item["id"]}.md"'
                assert response.text.startswith("# Post-mortem: ")
                assert all(section in response.text for section in SECTIONS)
                downloaded += 1
        assert downloaded >= 8
        missing = client.get(f"/api/uploads/{upload_id}/incidents/inc-nope/postmortem")
        assert missing.status_code == 404


# --- Demo mode ----------------------------------------------------------------------------


@pytest.fixture(scope="module")
def stored_file(tmp_path_factory):
    """Answers for every demo scenario, written by the command with a stand-in LLM."""
    path = tmp_path_factory.mktemp("stored") / "explanations.json"
    stored, failed = write_demo_explanations(
        load_config(), FakeProvider([fitting]), path, say=lambda _: None
    )
    assert stored >= 16 and failed == 0
    return path


@pytest.fixture
def no_network(monkeypatch):
    """Any attempt to open a network connection fails the test."""

    connect = socket.socket.connect

    def local_only(self, address):
        # The event loop talks to itself over 127.0.0.1; that is not leaving the machine.
        host = address[0] if isinstance(address, tuple) else address
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise AssertionError(f"a network connection was attempted: {address}")
        return connect(self, address)

    def refuse(address, *args, **kwargs):
        raise AssertionError(f"a network connection was attempted: {address}")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", local_only)


def test_the_stored_file_holds_both_audiences_of_every_demo_incident(stored_file):
    answers = load_stored(stored_file)
    assert {mode for _, mode in answers} == {"junior", "senior"}
    assert len(answers) % 2 == 0
    text = stored_file.read_text(encoding="utf-8")
    # Stored as the LLM answered: redacted, with stand-ins, never the real names.
    assert "HOST_1" in text and "GigabitEthernet0/1 on R1" not in text


def test_with_no_key_every_demo_scenario_opens_with_a_stored_explanation_and_no_call(
    tmp_path, monkeypatch, stored_file, no_network
):
    monkeypatch.setenv(ENV_FILE, str(stored_file))
    with TestClient(build(tmp_path)) as client:
        health = client.get("/api/health").json()
        assert health["llm"]["configured"] is False
        assert health["demo"] == {
            "active": True,
            "stored_explanations": len(load_stored(stored_file)),
        }
        names = [s["name"] for s in client.get("/api/demo/scenarios").json()["items"]]
        seen = 0
        for name in [n for n in names if not n.endswith("_50k")]:
            upload_id = client.post(f"/api/demo/scenarios/{name}").json()["id"]
            assert wait(client, upload_id)["stage"] == "done"
            for item in client.get(f"/api/uploads/{upload_id}/incidents").json()["items"]:
                for mode in ("junior", "senior"):
                    explanation = client.get(
                        f"/api/uploads/{upload_id}/incidents/{item['id']}/explanation?mode={mode}"
                    ).json()
                    assert explanation["source"] == "stored", (name, mode)
                    assert explanation["audience"] == mode
                    assert "stored with the demo scenarios" in explanation["written_by"]
                    assert explanation["usage"]["requests"] == 0
                    # Real names back in place of the stand-ins.
                    assert not re.search(r"\b(?:HOST|IP|USER)_\d+\b", explanation["summary"])
                    seen += 1
        assert seen >= 16


def test_a_users_own_file_still_gets_the_built_in_explanation_in_demo_mode(
    tmp_path, monkeypatch, stored_file
):
    monkeypatch.setenv(ENV_FILE, str(stored_file))
    data = (SCENARIOS / "02_cascade.log").read_bytes().replace(b"R1 ", b"CORE1 ")
    with TestClient(build(tmp_path)) as client:
        upload_id = client.post(
            "/api/uploads", files={"file": ("mine.log", data)}, data={"year": "2026"}
        ).json()["id"]
        wait(client, upload_id)
        (item,) = client.get(f"/api/uploads/{upload_id}/incidents").json()["items"]
        explanation = client.get(
            f"/api/uploads/{upload_id}/incidents/{item['id']}/explanation"
        ).json()
        assert explanation["source"] == "fallback"


def test_a_stored_answer_that_no_longer_fits_its_pack_is_not_used(
    tmp_path, monkeypatch, stored_file
):
    broken = tmp_path / "broken.json"
    broken.write_text(
        stored_file.read_text(encoding="utf-8").replace('\\"F1\\"', '\\"F999\\"'), encoding="utf-8"
    )
    monkeypatch.setenv(ENV_FILE, str(broken))
    with TestClient(build(tmp_path)) as client:
        upload_id = client.post("/api/demo/scenarios/02_cascade").json()["id"]
        wait(client, upload_id)
        (item,) = client.get(f"/api/uploads/{upload_id}/incidents").json()["items"]
        explanation = client.get(
            f"/api/uploads/{upload_id}/incidents/{item['id']}/explanation"
        ).json()
        assert explanation["source"] == "fallback"


def test_the_command_refuses_without_an_llm_and_asks_for_yes_before_spending(capsys, tmp_path):
    out_file = tmp_path / "stored.json"
    assert main(["demo-explanations", "-o", str(out_file)]) == EXIT_ERROR
    assert "no LLM is configured" in capsys.readouterr().out

    assert main(["demo-explanations", "-o", str(out_file)], provider=FakeProvider([fitting])) == 0
    assert "Run it again with --yes" in capsys.readouterr().out
    assert not out_file.exists()

    assert (
        main(["demo-explanations", "--yes", "-o", str(out_file)], provider=FakeProvider([fitting]))
        == 0
    )
    assert "Stored " in capsys.readouterr().out
    assert len(load_stored(out_file)) >= 16


def test_the_tests_never_read_the_stored_file_of_the_repository():
    assert os.environ[ENV_FILE].endswith("netlog-tests-no-stored-explanations.json")
