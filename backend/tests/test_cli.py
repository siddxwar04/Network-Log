import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from netlog.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main

SCENARIOS = Path("data/scenarios")
GOLDEN = Path(__file__).parent / "golden"
FLAP = str(SCENARIOS / "01_link_flap.log")
NOISE = str(SCENARIOS / "08_noise.log")


def run(capsys, *args):
    code = main(["analyze", *args, "--quiet"])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def check_golden(name: str, text: str) -> None:
    """Compare with a stored report. Set UPDATE_GOLDEN=1 to rewrite the stored copy
    after a deliberate change to the report's layout."""
    path = GOLDEN / name
    if os.environ.get("UPDATE_GOLDEN"):
        path.write_text(text, encoding="utf-8", newline="\n")
    assert text == path.read_text(encoding="utf-8")


# --- The three formats -------------------------------------------------------------------


def test_text_report_for_the_link_flap_scenario(capsys):
    code, out, err = run(capsys, FLAP, "--year", "2026", "--timezone", "UTC")

    assert code == EXIT_FINDINGS and err == ""
    check_golden("report_link_flap.txt", out)
    # The order a tired engineer needs: the file, the verdict, then the findings.
    sections = [out.index(s) for s in ("File", "Verdict", "Findings", "Most frequent", "Notes")]
    assert sections == sorted(sections)
    assert "[HIGH] Interface GigabitEthernet0/2 on R1 went down 12 times in 3m 21s" in out
    assert "\x1b[" not in out  # no color codes when the output is captured
    assert out.isascii()  # displays in any Windows console
    assert max(len(line) for line in out.splitlines()) <= 180


def test_markdown_report_for_the_link_flap_scenario(capsys):
    code, out, _ = run(capsys, FLAP, "--year", "2026", "--timezone", "UTC", "--format", "markdown")

    assert code == EXIT_FINDINGS
    check_golden("report_link_flap.md", out)
    assert out.startswith("# Log report: 01\\_link\\_flap.log")
    assert "### High: Interface GigabitEthernet0/2 on R1 went down 12 times" in out
    assert "| 767 | dhcp.ack |" in out


def test_json_report_for_the_link_flap_scenario(capsys):
    code, out, _ = run(capsys, FLAP, "--year", "2026", "--format", "json")
    data = json.loads(out)

    assert code == EXIT_FINDINGS
    assert set(data) == {"version", "file", "summary", "findings", "templates", "assumptions", "warnings"}  # noqa: E501
    assert data["version"] == 1
    assert data["file"]["name"] == "01_link_flap.log"
    assert (data["file"]["lines"], data["file"]["percent_parsed"]) == (5000, 100.0)
    assert [d["host"] for d in data["file"]["devices"]] == [
        "R1", "R2", "R3", "R4", "SW1", "SW2", "dhcp1", "srv1",
    ]  # fmt: skip
    assert data["summary"]["shown"] == 1 and data["summary"]["hidden"] > 100
    assert data["summary"]["by_severity"]["high"] == 1

    (finding,) = data["findings"]
    assert set(finding) == {
        "severity", "severity_reason", "rule", "incident_type", "title", "host", "group",
        "start", "end", "duration_seconds", "strength", "flags", "metrics",
        "evidence_count", "evidence",
    }  # fmt: skip
    assert (finding["severity"], finding["rule"], finding["host"]) == ("high", "link_flap", "R1")
    assert finding["start"].startswith("2026-03-03T02:35:21") and finding["start"].endswith("Z")
    assert finding["evidence_count"] == 12 and len(finding["evidence"]) == 5
    assert finding["evidence"][0]["line"] == 2083
    assert "%LINK-3-UPDOWN" in finding["evidence"][0]["text"]
    assert len(data["templates"]) == 10 and data["templates"][0]["count"] == 767
    assert len(data["assumptions"]) == 2


# --- What is reported --------------------------------------------------------------------


def test_most_severe_findings_come_first(capsys):
    _, out, _ = run(capsys, str(SCENARIOS / "02_cascade.log"), "--year", "2026")

    assert "12 findings: 6 critical, 6 high" in out
    levels = [line.split("]")[0].strip(" [") for line in out.splitlines() if line.startswith("  [")]
    assert levels == ["CRITICAL"] * 6 + ["HIGH"] * 6
    assert "Detail    cause: hold time expired" in out
    assert "Detail    reason: Dead timer expired" in out
    assert "Detail    noted: recovered" in out


def test_brute_force_report_shows_the_first_failures_and_the_login_that_succeeded(capsys):
    _, out, _ = run(capsys, str(SCENARIOS / "04_brute_force.log"), "--year", "2026")

    assert "[CRITICAL] 400 failed logins from 192.0.2.77 in 11m 55s" in out
    assert "Evidence  401 line(s) (showing 5)" in out
    assert "...  396 more ..." in out
    assert "Accepted password for deploy from 192.0.2.77" in out
    assert "Detail    logged in as: deploy" in out
    assert "Detail    noted: password spraying, succeeded" in out


def test_a_quiet_log_says_so_and_exits_zero(capsys):
    code, out, _ = run(capsys, NOISE, "--year", "2026")

    assert code == EXIT_CLEAN
    assert "No problems found at low severity or above." in out
    assert "lower-severity findings not shown" in out
    assert "Findings\n" not in out
    assert "Most frequent messages" in out  # the summary is still shown


def test_minimum_severity_decides_what_is_listed_and_the_exit_code(capsys):
    cascade = str(SCENARIOS / "02_cascade.log")

    code_critical, critical_only, _ = run(capsys, cascade, "--min-severity", "critical")
    code_info, everything, _ = run(capsys, NOISE, "--year", "2026", "--min-severity", "info")
    code_high, _, _ = run(capsys, str(SCENARIOS / "10_overlap.log"), "--min-severity", "critical")

    assert code_critical == EXIT_FINDINGS
    assert "6 findings: 6 critical" in critical_only and "[HIGH]" not in critical_only
    assert code_info == EXIT_FINDINGS and "[INFO] Configuration of" in everything
    assert "not shown" not in everything
    assert code_high == EXIT_CLEAN  # the overlap scenario has nothing at critical


def test_assumptions_are_stated(capsys):
    _, defaults, _ = run(capsys, FLAP)
    _, given, _ = run(capsys, FLAP, "--year", "2024", "--timezone", "+05:30")
    this_year = datetime.now(UTC).year
    defaults = " ".join(defaults.split())  # long notes are wrapped over several lines

    assert f"so {this_year} (the current year) was assumed. Use --year to set it." in defaults
    assert "so UTC was assumed. Use --timezone to set it." in defaults
    assert "2024 was used, as given." in given and "+05:30 was used, as given." in given
    # Local times five and a half hours ahead of UTC land on the previous evening.
    assert "Time span  2024-03-02 18:30:03 to" in given


def test_low_parse_coverage_is_called_out(capsys, tmp_path):
    log = tmp_path / "mixed.log"
    good = "Mar  3 02:00:00 srv1 sshd[1]: Accepted password for alice from 10.0.0.5 port 1 ssh2"
    log.write_text("\n".join([good] * 6 + ["unknown record 17", "unknown record 99"]) + "\n")

    code, out, _ = run(capsys, str(log), "--year", "2026")

    assert code == EXIT_CLEAN
    assert "Lines      8 (75.0% parsed, 75.0% classified)" in out
    assert "Warning: Only 75.0% of lines were understood" in out
    assert '"unknown record N" (2)' in out


def test_text_from_a_log_line_cannot_inject_formatting(capsys, tmp_path):
    log = tmp_path / "hostile.log"
    name = "ev\x1b[31mil*_`<b>|x"
    line = "Mar  3 02:00:{:02d} srv1 sshd[1]: Failed password for {} from 192.0.2.77 port 1 ssh2"
    log.write_text("\n".join(line.format(n, name) for n in range(30)) + "\n", encoding="utf-8")

    _, text, _ = run(capsys, str(log), "--year", "2026")
    _, markdown, _ = run(capsys, str(log), "--year", "2026", "--format", "markdown")

    assert "\x1b" not in text and "ev?[31mil" in text
    assert "\x1b" not in markdown
    # In Markdown the evidence sits in a code block, and nothing outside one is raw.
    assert "```text" in markdown
    outside = markdown.split("```text")[0]
    assert "<b>" not in outside


# --- Output file -------------------------------------------------------------------------


def test_report_can_be_written_to_a_file(capsys, tmp_path):
    target = tmp_path / "reports" / "flap.md"

    code, out, _ = run(capsys, FLAP, "--year", "2026", "--format", "markdown", "-o", str(target))

    assert code == EXIT_FINDINGS
    assert out.strip() == f"Report written to {target} (1 finding(s) at low or above)."
    assert target.read_text(encoding="utf-8").startswith("# Log report:")


# --- Errors ------------------------------------------------------------------------------


def make(tmp_path, name, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


@pytest.mark.parametrize(
    ("build", "message"),
    [
        (lambda tmp: str(tmp / "missing.log"), "file not found"),
        (lambda tmp: str(tmp), "is a folder; give a log file"),
        (lambda tmp: make(tmp, "empty.log", b""), "is empty"),
        (lambda tmp: make(tmp, "blank.log", b"\n\n   \n"), "contains only blank lines"),
        (lambda tmp: make(tmp, "photo.png", b"\x89PNG\r\n\x00\x00IHDR"), "is not a text file"),
        (lambda tmp: make(tmp, "notes.txt", b"hello\nworld\n"), "no recognizable log lines"),
    ],
)
def test_unusable_files_give_a_polite_error(capsys, tmp_path, build, message):
    code, out, err = run(capsys, build(tmp_path))

    assert code == EXIT_ERROR and out == ""
    assert err.startswith("netlog: ") and message in err
    assert "Traceback" not in err and len(err.splitlines()) == 1


@pytest.mark.parametrize(
    ("options", "message"),
    [
        (["--timezone", "Mars/Olympus"], "unknown timezone 'Mars/Olympus'"),
        (["--year", "12"], "--year 12 is not a plausible year"),
        (["--rules", "no-such-rules.toml"], "rule file not found: no-such-rules.toml"),
        (["--config", "no-such-config.toml"], "config file not found: no-such-config.toml"),
    ],
)
def test_bad_options_give_a_polite_error(capsys, options, message):
    code, _, err = run(capsys, FLAP, *options)

    assert code == EXIT_ERROR and message in err and "Traceback" not in err


def test_a_mistake_in_a_rule_file_is_reported(capsys, tmp_path):
    rules = tmp_path / "rules.toml"
    rules.write_text('[[rule]]\nname = "x"\nkind = "magic"\n', encoding="utf-8")

    code, _, err = run(capsys, FLAP, "--rules", str(rules))

    assert code == EXIT_ERROR
    assert "netlog: rule 'x': kind is 'magic'; it must be one of" in err


def test_a_user_rule_file_changes_what_is_found(capsys, tmp_path):
    rules = tmp_path / "rules.toml"
    rules.write_text(
        """
        # Replaces the built-in rule of the same name with a far higher threshold.
        [[rule]]
        name = "link_flap"
        incident_type = "link_flap"
        kind = "threshold"
        title = "{interface} on {host} went down {count} times"
        event_keys = ["LINK-3-UPDOWN"]
        where = { state_to = "down" }
        group_by = ["host", "interface"]
        window_seconds = 300
        threshold = 50
        """,
        encoding="utf-8",
    )

    code, out, _ = run(capsys, FLAP, "--year", "2026", "--rules", str(rules))

    assert code == EXIT_CLEAN and "No problems found" in out


def test_usage_errors_exit_with_two():
    with pytest.raises(SystemExit) as stopped:
        main(["analyze"])

    assert stopped.value.code == EXIT_ERROR


# --- As a real command -------------------------------------------------------------------


def test_piped_output_has_no_color_and_no_progress():
    result = subprocess.run(
        [sys.executable, "-m", "netlog", "analyze", FLAP, "--year", "2026"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    assert result.returncode == EXIT_FINDINGS
    assert "\x1b[" not in result.stdout and result.stderr == ""
    assert "[HIGH] Interface GigabitEthernet0/2 on R1" in result.stdout


def test_output_survives_a_console_that_cannot_show_every_character(tmp_path):
    log = tmp_path / "unicode.log"
    line = "Mar  3 02:00:{:02d} srv1 sshd[1]: Failed password for 用户 from 192.0.2.77 port 1 ssh2"
    log.write_text("\n".join(line.format(n) for n in range(30)) + "\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-m", "netlog", "analyze", str(log), "--year", "2026"],
        capture_output=True,
        env={**os.environ, "PYTHONIOENCODING": "cp1252"},
    )

    assert result.returncode == EXIT_FINDINGS
    assert b"30 failed logins from 192.0.2.77" in result.stdout
    assert b"Traceback" not in result.stderr
