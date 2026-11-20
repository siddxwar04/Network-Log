import copy
import json
import os
import re
from pathlib import Path

import pytest

from netlog.cli import EXIT_FINDINGS, main
from netlog.llm.evidence import outgoing_packs
from netlog.llm.explain import SWITCHED_OFF, explain_incident
from netlog.llm.fallback import fallback_explanation, load_templates
from netlog.llm.provider import FakeProvider, ServerError
from netlog.llm.settings import load_env_file
from netlog.llm.validate import validate_explanation
from netlog.report.build import build_report, to_json
from netlog.report.explain import explain_incidents
from netlog.report.render import render_markdown, render_text
from netlog.storage.database import Database

SCENARIOS = Path("data/scenarios")
GOLDEN = Path(__file__).parent / "golden"
CASCADE = str(SCENARIOS / "02_cascade.log")
WITH_INCIDENTS = [
    "01_link_flap",
    "02_cascade",
    "03_config_bgp",
    "04_brute_force",
    "05_dhcp_exhaustion",
    "07_device_reload",
    "09_prompt_injection",
    "10_overlap",
]
TOKEN = re.compile(r"(?<![A-Za-z0-9_])(?:IP|USER|HOST|MAC|TEXT)_\d+(?![A-Za-z0-9_])")

# The cascade explained twice by an LLM, as it would write from the redacted pack: the
# same facts and the same citations, in two wordings.
SENIOR = {
    "summary": (
        "Likely cause: GigabitEthernet0/1 on HOST_1 went down at 02:46:11 and stayed down. "
        "OSPF and BGP to HOST_1 dropped on HOST_2, HOST_3 and HOST_4 within 41 seconds."
    ),
    "timeline": [
        {"text": "GigabitEthernet0/1 on HOST_1 down.", "evidence": ["E1", "F1"]},
        {"text": "HOST_1 dropped three OSPF adjacencies at once.", "evidence": ["C1"]},
        {"text": "BGP hold timers expired on HOST_2, HOST_3 and HOST_4.", "evidence": ["C3"]},
        {"text": "OSPF dead timers expired on the peers.", "evidence": ["C4"]},
    ],
    "hypotheses": [
        {
            "text": "Most likely cause: failure of GigabitEthernet0/1 on HOST_1 (cable, optic "
            "or far end).",
            "supporting": ["F1", "C1", "C3", "C4"],
            "contradicting": [],
        }
    ],
    "impact": [{"text": "iBGP and OSPF to HOST_1 lost on three peers.", "evidence": ["C3", "C4"]}],
    "fix_steps": [
        {"text": "Check cable and optic on GigabitEthernet0/1.", "changes_configuration": False},
        {"text": "Shut and no shut the port if it stays down.", "changes_configuration": True},
    ],
    "verification_commands": [
        {"command": "show interfaces GigabitEthernet0/1", "purpose": "Up/up, no input errors."}
    ],
    "unknowns": ["Why the interface went down."],
}
JUNIOR = {
    "summary": (
        "The interface GigabitEthernet0/1 on HOST_1 went down at 02:46:11 and stayed down. "
        "That interface carried OSPF, the protocol the routers use to learn routes inside the "
        "network, so HOST_1 lost its OSPF neighbors at once. BGP, which exchanges routes "
        "between routers over long-lived sessions, then timed out on HOST_2, HOST_3 and "
        "HOST_4. The likely cause of all of it is that one interface."
    ),
    "timeline": [
        {
            "text": "The interface GigabitEthernet0/1 on HOST_1 changed state to down.",
            "evidence": ["E1", "F1"],
        },
        {
            "text": "HOST_1 knew its own interface was down, so it dropped its three OSPF "
            "neighbors on it immediately.",
            "evidence": ["C1"],
        },
        {
            "text": "HOST_2, HOST_3 and HOST_4 stopped receiving BGP keepalives from HOST_1 "
            "and closed their sessions when the hold timer ran out.",
            "evidence": ["C3"],
        },
        {
            "text": "The same three routers stopped hearing OSPF hellos and gave up after the "
            "40-second dead timer.",
            "evidence": ["C4"],
        },
    ],
    "hypotheses": [
        {
            "text": "The most likely cause is that GigabitEthernet0/1 on HOST_1 failed: a "
            "cable, an optic (the plug-in fiber module) or the device at the other end.",
            "supporting": ["F1", "C1", "C3", "C4"],
            "contradicting": [],
        }
    ],
    "impact": [
        {
            "text": "Three routers lost both their OSPF adjacency and their BGP session to "
            "HOST_1, so routes through HOST_1 were withdrawn.",
            "evidence": ["C3", "C4"],
        }
    ],
    "fix_steps": [
        {
            "text": "Look at the cable and the optic on GigabitEthernet0/1. A healthy port "
            "shows error counters that are not rising.",
            "changes_configuration": False,
        },
        {
            "text": "If it stays down, shut and no shut the port, which restarts it.",
            "changes_configuration": True,
        },
    ],
    "verification_commands": [
        {
            "command": "show interfaces GigabitEthernet0/1",
            "purpose": "Both the interface and the line protocol show up, and the input "
            "error counter stays still.",
        }
    ],
    "unknowns": ["Why the interface went down. The logs show that it did, not what broke."],
}


def run(capsys, *args, provider=None):
    code = main(["analyze", *args, "--quiet"], provider=provider)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def check_golden(name: str, text: str) -> None:
    path = GOLDEN / name
    if os.environ.get("UPDATE_GOLDEN"):
        path.write_text(text, encoding="utf-8", newline="\n")
    assert text == path.read_text(encoding="utf-8")


def section(out: str) -> str:
    """The explanation of the first incident in a text report."""
    return out.split("      Explanation\n")[1].split("\n\n")[0]


# --- Both audiences, written by an LLM ----------------------------------------------------


@pytest.mark.parametrize(("mode", "answer"), [("senior", SENIOR), ("junior", JUNIOR)])
def test_the_cascade_explained_by_an_llm_for_each_audience(capsys, mode, answer):
    provider = FakeProvider([answer])
    code, out, err = run(capsys, CASCADE, "--year", "2026", "--audience", mode, provider=provider)

    assert code == EXIT_FINDINGS and err == ""
    check_golden(f"report_cascade_{mode}.txt", out)
    text = section(out)
    assert f"For a {mode} reader. Written by an LLM (fake fake), checked against the" in text
    # The real names are back, and the request was made for this audience.
    assert "GigabitEthernet0/1 on R1 went down at 02:46:11" in text
    (sent,) = provider.requests
    assert f"{mode} engineer" in sent.user and "R1" not in sent.user.split("<evidence_pack>")[1]
    assert not TOKEN.search(out) and out.isascii()
    assert max(len(line) for line in out.splitlines()) <= 180


def test_the_two_audiences_differ_in_wording_only(capsys):
    _, senior, _ = run(capsys, CASCADE, "--year", "2026", provider=FakeProvider([SENIOR]))
    _, junior, _ = run(
        capsys, CASCADE, "--year", "2026", "--audience", "junior", provider=FakeProvider([JUNIOR])
    )

    # Everything the tool decided is printed identically in both.
    assert senior.split("      Explanation\n")[0] == junior.split("      Explanation\n")[0]
    assert section(senior) != section(junior)
    assert len(section(junior)) > 1.5 * len(section(senior))
    # The same statements point at the same lines of the log.
    cited = re.compile(r"\[lines? [\d, ]+(?: and \d+ more)?\]")
    # A long citation may be wrapped over two lines of the report.
    flat_senior, flat_junior = (" ".join(section(t).split()) for t in (senior, junior))
    assert cited.findall(flat_senior) == cited.findall(flat_junior)
    assert len(cited.findall(flat_senior)) == 6
    for text in (senior, junior):
        assert "2. [REVIEW BEFORE RUNNING]" in section(text)
        assert "show interfaces GigabitEthernet0/1" in section(text)
    assert "the protocol the routers use to learn routes" in section(junior)
    assert "the protocol" not in section(senior)


def test_each_audience_is_cached_separately(capsys):
    provider = FakeProvider([SENIOR, JUNIOR])
    run(capsys, CASCADE, "--year", "2026", provider=provider)
    run(capsys, CASCADE, "--year", "2026", "--audience", "junior", provider=provider)
    _, again, _ = run(capsys, CASCADE, "--year", "2026", "--usage", provider=provider)

    assert len(provider.requests) == 2  # the third run was answered from the cache
    flat = " ".join(again.split())
    assert "checked against the evidence, read from the cache" in flat
    assert "LLM usage: no request made; the cached answer cost" in flat
    assert "Usage: no request was made for this report." in again


# --- Citations ----------------------------------------------------------------------------


def test_citations_are_line_numbers_in_the_original_file(capsys):
    _, out, _ = run(capsys, CASCADE, "--year", "2026", provider=FakeProvider([SENIOR]))
    text = section(out)
    log = Path(CASCADE).read_text(encoding="utf-8").splitlines()

    # E1 and F1: the line where the interface went down, and the one where it came back.
    assert "- GigabitEthernet0/1 on R1 down. [lines 2260, 2400]" in text
    assert "%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down" in log[2259]
    assert log[2259].split()[3] == "R1" and "changed state to up" in log[2399]
    # C1, a step of cause and effect, stands for the first line of each thing it caused.
    assert "- R1 dropped three OSPF adjacencies at once. [lines 2261, 2262, 2263]" in text
    for number in (2261, 2262, 2263):
        assert "%OSPF-5-ADJCHG" in log[number - 1] and " R1 " in log[number - 1]
    # No evidence id is left for the reader to decode.
    assert not re.search(r"\b[EFCT]\d+\b", text)


def test_a_long_list_of_cited_lines_is_cut(capsys):
    _, out, _ = run(capsys, CASCADE, "--year", "2026", "--audience", "junior")
    impact = section(out).split("        Impact\n")[1].split("\n        What to do")[0]

    first = " ".join(impact.split("          - ")[1].split())
    assert first.endswith("2273, 2275 and 8 more]")


# --- Without an LLM -----------------------------------------------------------------------


def test_no_llm_gives_the_built_in_explanation_and_says_so(capsys):
    provider = FakeProvider([SENIOR])
    code, out, _ = run(capsys, CASCADE, "--year", "2026", "--no-llm", "--usage", provider=provider)

    assert code == EXIT_FINDINGS and provider.requests == []
    text = " ".join(section(out).split())
    assert "Written by the built-in templates, not an LLM (the LLM was switched off)." in text
    assert "Likely root cause: Interface GigabitEthernet0/1 on R1 was down for 8m 36s" in text
    assert "LLM usage: no request made" in text
    assert SWITCHED_OFF == "the LLM was switched off"
    assert not Path(os.environ["NETLOG_DB_PATH"]).exists()  # no cache was opened


def test_with_nothing_configured_the_report_is_complete_and_says_who_wrote_it(capsys):
    code, out, _ = run(capsys, CASCADE, "--year", "2026", "--timezone", "UTC")

    text = " ".join(section(out).split())
    assert "For a senior reader. Written by the built-in templates, not an LLM (no LLM" in text
    for heading in ("Timeline", "Root-cause hypotheses", "Impact", "What to do",
                    "Commands to confirm (read-only)"):
        assert f"        {heading}\n" in out
    assert "Also not known" not in out  # the fallback knows nothing the incident does not list
    assert "LLM usage" not in out  # only with --usage
    assert not Path(os.environ["NETLOG_DB_PATH"]).exists()


def test_the_fallback_audiences_have_the_same_facts_and_citations(capsys):
    _, senior, _ = run(capsys, CASCADE, "--year", "2026")
    _, junior, _ = run(capsys, CASCADE, "--year", "2026", "--audience", "junior")

    cited = re.compile(r"\[lines? [\d, ]+(?: and \d+ more)?\]")
    # A long citation may be wrapped over two lines of the report.
    flat_senior, flat_junior = (" ".join(section(t).split()) for t in (senior, junior))
    assert cited.findall(flat_senior) == cited.findall(flat_junior)
    assert section(senior).count("[REVIEW BEFORE RUNNING]") == 1
    assert section(junior).count("[REVIEW BEFORE RUNNING]") == 1
    assert "Direct effect: 3 findings, at once." in section(senior)
    assert "OSPF runs over that interface, so the router dropped" in section(junior)
    assert "OSPF is the protocol routers use to learn routes inside one network" in " ".join(
        section(junior).split()
    )
    assert "A healthy interface is up with counters that stay still" in " ".join(
        section(junior).split()
    )
    assert "A healthy interface" not in section(senior)


@pytest.mark.parametrize("name", WITH_INCIDENTS)
def test_the_two_fallback_wordings_agree_on_everything_but_the_words(analyzed, name):
    db, upload, _ = analyzed(name)
    for _, pack in outgoing_packs(db, upload)[0]:
        senior, junior = (fallback_explanation(pack, mode) for mode in ("senior", "junior"))

        def cites(explanation):
            return (
                [step.evidence for step in explanation.timeline],
                [(h.supporting, h.contradicting) for h in explanation.hypotheses],
                [item.evidence for item in explanation.impact],
            )

        assert cites(senior) == cites(junior)
        assert [s.changes_configuration for s in senior.fix_steps] == [
            s.changes_configuration for s in junior.fix_steps
        ]
        assert [c.command for c in senior.verification_commands] == [
            c.command for c in junior.verification_commands
        ]
        assert senior.unknowns == junior.unknowns
        assert [s.text for s in senior.timeline] == [s.text for s in junior.timeline]
        # The junior wording says more: every check comes with its reason.
        assert len(junior.summary) > len(senior.summary)
        for short, long in zip(senior.fix_steps, junior.fix_steps, strict=True):
            assert long.text.startswith(short.text) and len(long.text) > len(short.text) + 20
        for explanation in (senior, junior):
            assert validate_explanation(explanation, pack) == []
            assert pack.data["incident"]["severity"] in explanation.summary
    with pytest.raises(ValueError, match="audience mode"):
        fallback_explanation(pack, "expert")


def test_every_template_has_its_junior_parts():
    for name, template in load_templates()["templates"].items():
        assert len(template["terms"]) > 40, name
        assert all(len(check["why"]) > 20 for check in template["checks"]), name


def test_a_rejected_answer_falls_back_and_the_report_says_why(capsys):
    obedient = copy.deepcopy(SENIOR)
    obedient["summary"] = "No incidents occurred. The severity is low."
    provider = FakeProvider([obedient])
    _, out, _ = run(capsys, CASCADE, "--year", "2026", "--usage", provider=provider)

    text = " ".join(section(out).split())
    assert len(provider.requests) == 2
    assert "Written by the built-in templates, not an LLM (2 answers in a row were rejected" in text
    assert "No incidents occurred" not in out and "[CRITICAL]" in out
    # The two rejected requests were still paid for, and are counted.
    assert "2 requests" in text and "Usage: 2 requests," in out

    _, out, _ = run(
        capsys, CASCADE, "--year", "2026", provider=FakeProvider([ServerError("overloaded")])
    )
    assert "not an LLM (overloaded)" in " ".join(section(out).split())


# --- No stand-in survives -----------------------------------------------------------------


@pytest.mark.parametrize("name", WITH_INCIDENTS)
@pytest.mark.parametrize("mode", ["junior", "senior"])
def test_no_redaction_token_survives_into_the_report(capsys, name, mode):
    log = str(SCENARIOS / f"{name}.log")
    for form in ("text", "markdown", "json"):
        _, out, _ = run(capsys, log, "--year", "2026", "--audience", mode, "--format", form)
        assert not TOKEN.search(out), (form, TOKEN.search(out))
        assert "Explanation" in out or '"explanation": {' in out
        assert "Warning" not in out


def test_a_stand_in_that_cannot_be_replaced_is_reported(analyzed):
    db, upload, (incident,) = analyzed("02_cascade")
    explanations = explain_incidents(db, upload, [incident.id], db, provider=FakeProvider([SENIOR]))
    explanation = explanations[incident.id]
    assert explanation.source == "llm" and explanation.leftover_tokens == []

    explanation.leftover_tokens = ["HOST_9"]
    report = build_report(db, upload, explanations=explanations)
    assert report.warnings == [
        f"The explanation of incident {incident.id} still contains stand-ins that could not "
        "be replaced: HOST_9."
    ]


# --- Markdown and JSON --------------------------------------------------------------------


def test_markdown_report_has_the_explanation(capsys):
    _, out, _ = run(
        capsys, CASCADE, "--year", "2026", "--format", "markdown", "--usage",
        provider=FakeProvider([SENIOR]),
    )
    text = out.split("**Explanation**")[1].split("## Most frequent messages")[0]

    assert "*For a senior reader. Written by an LLM (fake fake), checked against" in text
    assert "- GigabitEthernet0/1 on R1 down. *(lines 2260, 2400)*" in text
    assert "1. Most likely cause: failure of GigabitEthernet0/1 on R1" in text
    assert "2. **REVIEW BEFORE RUNNING:** Shut and no shut the port if it stays down." in text
    assert "```text\nshow interfaces GigabitEthernet0/1\n```" in text
    assert "Healthy: Up/up, no input errors." in text
    assert "Also not known:\n\n- Why the interface went down." in text
    assert "LLM usage: " in text and "1 request" in text
    assert "- **LLM usage:** 1 request," in out


def test_json_report_has_the_explanation(capsys):
    _, out, _ = run(
        capsys, CASCADE, "--year", "2026", "--format", "json", provider=FakeProvider([SENIOR])
    )
    data = json.loads(out)
    explanation = data["incidents"][0]["explanation"]

    assert data["version"] == 1  # fields were added, none renamed
    assert set(explanation) == {
        "source", "written_by", "audience", "provider", "model", "fallback_reason", "summary",
        "timeline", "hypotheses", "impact", "fix_steps", "verification_commands", "unknowns",
        "usage",
    }  # fmt: skip
    assert (explanation["source"], explanation["audience"]) == ("llm", "senior")
    assert (explanation["provider"], explanation["fallback_reason"]) == ("fake", None)
    assert explanation["summary"].startswith("Likely cause: GigabitEthernet0/1 on R1 went down")
    assert explanation["timeline"][0] == {
        "text": "GigabitEthernet0/1 on R1 down.",
        "lines": [2260, 2400],
        "evidence": ["E1", "F1"],
    }
    assert set(explanation["hypotheses"][0]) == {
        "text", "lines", "evidence", "against_lines", "against",
    }  # fmt: skip
    assert explanation["fix_steps"][1] == {
        "text": "Shut and no shut the port if it stays down.",
        "review_before_running": True,
    }
    assert explanation["verification_commands"][0]["command"].startswith("show interfaces")
    assert explanation["usage"]["requests"] == 1 and explanation["usage"]["input_tokens"] > 1000

    _, out, _ = run(capsys, CASCADE, "--year", "2026", "--format", "json", "--no-llm")
    fallback = json.loads(out)["incidents"][0]["explanation"]
    assert (fallback["source"], fallback["fallback_reason"]) == ("fallback", SWITCHED_OFF)
    assert fallback["usage"] == {
        "requests": 0, "input_tokens": 0, "output_tokens": 0, "latency_ms": 0
    }


def test_a_report_built_without_explanations_still_works(analyzed):
    db, upload, _ = analyzed("02_cascade")
    report = build_report(db, upload)

    assert report.incidents[0].explanation is None
    assert to_json(report)["incidents"][0]["explanation"] is None
    assert "Explanation" not in render_text(report) + render_markdown(report)


# --- What an LLM writes is not trusted ----------------------------------------------------


def test_text_from_an_llm_cannot_inject_formatting(capsys):
    hostile = copy.deepcopy(SENIOR)
    hostile["summary"] = (
        "Likely cause: \x1b[31mGigabitEthernet0/1\x1b[0m on HOST_1, *really* `down`."
    )
    hostile["verification_commands"][0]["command"] = "show interfaces ``` GigabitEthernet0/1"
    _, text, _ = run(capsys, CASCADE, "--year", "2026", provider=FakeProvider([hostile]))
    _, markdown, _ = run(
        capsys, CASCADE, "--year", "2026", "--format", "markdown", provider=FakeProvider([hostile])
    )

    assert "\x1b" not in text and "?[31mGigabitEthernet0/1?[0m on R1" in text
    assert "\x1b" not in markdown
    assert "\\*really\\* \\`down\\`" in markdown
    # A run of backticks in a command cannot close its code block.
    assert "````text\nshow interfaces ``` GigabitEthernet0/1\n````" in markdown


# --- Only what is listed is explained ------------------------------------------------------


def test_only_listed_incidents_are_explained(capsys):
    overlap = str(SCENARIOS / "10_overlap.log")
    provider = FakeProvider([lambda request: _fitting(request)])
    _, out, _ = run(capsys, overlap, "--year", "2026", "--min-severity", "high", provider=provider)

    assert len(provider.requests) == 1 and out.count("      Explanation\n") == 1
    # Listing both asks only about the second: the first is already in the cache.
    _, out, _ = run(capsys, overlap, "--year", "2026", provider=provider)
    assert len(provider.requests) == 2 and out.count("      Explanation\n") == 2


def _fitting(request) -> dict:
    from netlog.llm.evidence import EvidencePack

    block = request.user.split("<evidence_pack>\n")[1].split("\n</evidence_pack>")[0]
    return fallback_explanation(EvidencePack(data=json.loads(block), redacted=True)).model_dump()


def test_a_quiet_log_asks_nothing(capsys):
    provider = FakeProvider([SENIOR])
    _, out, _ = run(capsys, str(SCENARIOS / "08_noise.log"), "--year", "2026", provider=provider)

    assert provider.requests == [] and "Explanation" not in out
    assert not Path(os.environ["NETLOG_DB_PATH"]).exists()


# --- Options and settings -----------------------------------------------------------------


def test_bad_audience_and_bad_llm_settings_are_polite_errors(capsys, tmp_path):
    with pytest.raises(SystemExit):
        main(["analyze", CASCADE, "--audience", "expert"])
    capsys.readouterr()

    config = tmp_path / "config.toml"
    config.write_text("[llm]\ntimeout_seconds = 0\n", encoding="utf-8")
    code, _, err = run(capsys, CASCADE, "--config", str(config))
    assert code == 2 and "netlog: llm.timeout_seconds must be greater than zero" in err

    config.write_text("[evidence]\nmax_tokens = 5\n", encoding="utf-8")
    code, _, err = run(capsys, CASCADE, "--year", "2026", "--config", str(config))
    assert code == 2 and "evidence.max_tokens = 5 is too small" in err


def test_switching_the_llm_off_works_through_explain_incident(analyzed, tmp_path):
    db, upload, _ = analyzed("02_cascade")
    ((_, pack),), _ = outgoing_packs(db, upload)
    provider = FakeProvider([SENIOR])
    with Database(tmp_path / "cache.db") as cache:
        result = explain_incident(cache, pack, "junior", use_llm=False, provider=provider)
        assert (result.source, result.reason, result.mode) == ("fallback", SWITCHED_OFF, "junior")
        assert result.explanation == fallback_explanation(pack, "junior")
        assert provider.requests == [] and cache.llm_calls() == []
        with pytest.raises(ValueError, match="audience mode"):
            explain_incident(cache, pack, "expert", use_llm=False)


def test_the_env_file_can_be_named_by_a_variable(tmp_path):
    path = tmp_path / "my.env"
    path.write_text("NETLOG_LLM_PROVIDER=openai\n", encoding="utf-8")
    environ = {"NETLOG_ENV_FILE": str(path)}
    assert load_env_file(environ=environ) == ["NETLOG_LLM_PROVIDER"]
    assert environ["NETLOG_LLM_PROVIDER"] == "openai"
    # The tests themselves are pointed at a file that does not exist.
    assert os.environ["NETLOG_ENV_FILE"] == "no-such-file.env" and load_env_file() == []
