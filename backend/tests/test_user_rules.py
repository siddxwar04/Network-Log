"""Rules the people who run the tool can change: overrides, rules of their own, critical
devices, the checks on a rule file, the `rules test` command, and the rules API."""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_api import build, upload, wait

from netlog.cli import main
from netlog.config import load_config
from netlog.detection.rules import (
    USER_FILE_ENV,
    RuleError,
    load_rule_set,
    with_override,
)

DOC = Path("docs/WRITING_RULES.md")
SCENARIOS = Path("data/scenarios")


def doc_blocks() -> dict[str, str]:
    """The fenced blocks of the rule-writing guide that follow an `<!-- example N part -->`
    marker, by marker."""
    text = DOC.read_text(encoding="utf-8")
    found = re.findall(r"<!-- (example \d (?:log|rule|result)) -->\n```\w*\n(.*?)\n```", text, re.S)
    return {name: body + "\n" for name, body in found}


def write(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def rules_test(capsys, rule_file: Path, log_file: Path) -> tuple[int, str, str]:
    code = main(["rules", "test", str(rule_file), str(log_file), "--year", "2026"])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def error_of(tmp_path: Path, text: str) -> str:
    with pytest.raises(RuleError) as caught:
        load_rule_set(write(tmp_path, "rules.toml", text))
    return str(caught.value)


STORM = """
[[rule]]
name = "config_storm"
incident_type = "config_storm"
kind = "threshold"
title = "{count} configuration changes on {host} in {duration}"
event_keys = ["SYS-5-CONFIG_I"]
group_by = ["host"]
window_seconds = 3600
threshold = 11
"""


# --- The guide's examples, exactly as written ----------------------------------------------


@pytest.mark.parametrize(
    ("number", "rule_name", "log_name"),
    [
        (1, "tuning.toml", "flaps.log"),
        (2, "storm.toml", "changes.log"),
        (3, "sequence.toml", "login.log"),
    ],
)
def test_each_example_in_the_rule_writing_guide_works_exactly_as_written(
    capsys, tmp_path, number, rule_name, log_name
):
    blocks = doc_blocks()
    rule_file = write(tmp_path, rule_name, blocks[f"example {number} rule"])
    log_file = write(tmp_path, log_name, blocks[f"example {number} log"])

    code, out, err = rules_test(capsys, rule_file, log_file)

    assert err == ""
    assert code == 1
    assert out == blocks[f"example {number} result"]
    # The command shown in the guide is the one that was run.
    assert f"netlog rules test {rule_name} {log_name} --year 2026" in DOC.read_text(
        encoding="utf-8"
    )


def test_without_the_override_the_three_flaps_of_example_1_find_nothing(capsys, tmp_path):
    log_file = write(tmp_path, "flaps.log", doc_blocks()["example 1 log"])
    code, out, _ = rules_test(capsys, write(tmp_path, "empty.toml", "# nothing\n"), log_file)
    assert code == 0 and out.endswith("No rule triggered.\n")


def test_the_mistakes_in_the_guide_give_the_messages_it_shows(tmp_path):
    text = DOC.read_text(encoding="utf-8")
    messages = [
        error_of(tmp_path, '[[override]]\nname = "link_flap"\nthreshhold = 3\n'),
        error_of(tmp_path, STORM.replace("window_seconds = 3600", "window_seconds = -60")),
        error_of(tmp_path, STORM.replace("threshold = 11", "threshold = 0")),
        error_of(tmp_path, STORM.replace("threshold = 11", 'threshold = "11"')),
        error_of(tmp_path, '[[override]]\nname = "link_flapp"\nenabled = false\n'),
        error_of(tmp_path, STORM.replace("{count} configuration", "{count:>5} configuration")),
    ]
    for message in messages:
        shown = message.replace(str(tmp_path / "rules.toml"), "my-rules.toml")
        shown = re.sub(
            r"\(known: enabled, severity, .*\)", "(known: enabled, severity, ...)", shown
        )
        assert f"`{shown}`" in text, shown


# --- Overrides ------------------------------------------------------------------------------


def test_an_override_changes_one_setting_and_keeps_the_rest(tmp_path):
    ruleset = load_rule_set(
        write(tmp_path, "r.toml", '[[override]]\nname = "link_flap"\nthreshold = 3\n')
    )
    rule = ruleset.by_name("link_flap")
    built_in = load_rule_set(write(tmp_path, "none.toml", "")).by_name("link_flap")
    assert rule.threshold == 3 and built_in.threshold == 5
    assert rule.window_seconds == built_in.window_seconds and rule.title == built_in.title
    assert ruleset.origin["link_flap"] == "built-in, changed"
    assert ruleset.overrides == {"link_flap": {"threshold": 3}}


def test_disabling_a_rule_removes_its_findings(capsys, tmp_path):
    flap = SCENARIOS / "01_link_flap.log"
    _, before, _ = rules_test(capsys, write(tmp_path, "none.toml", ""), flap)
    off = write(tmp_path, "off.toml", '[[override]]\nname = "link_flap"\nenabled = false\n')
    _, after, _ = rules_test(capsys, off, flap)

    assert "link_flap: triggered 1 time" in before
    assert "link_flap:" not in after
    assert "switched off: link_flap" in after


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (
            '[[override]]\nname = "link_flap"\nwithin_seconds = 60\n',
            "within_seconds does not apply to a threshold rule",
        ),
        ('[[override]]\nname = "link_flap"\nenabled = "no"\n', "enabled must be true or false"),
        (
            '[[override]]\nname = "link_flap"\nseverity = "urgent"\n',
            "severity is 'urgent'; it must be one of",
        ),
        ("[[override]]\nthreshold = 3\n", 'an [[override]] has no name; it needs name = "..."'),
        (
            '[[override]]\nname = "link_flap"\nthreshold = 3\n'
            '[[override]]\nname = "link_flap"\nthreshold = 4\n',
            "rule 'link_flap' is overridden twice",
        ),
        ('[rule]\nname = "x"\n', "rules must be written as [[rule]] tables"),
        ("[settings]\nx = 1\n", "'settings' is not a known section"),
        ("[[rule]\n", "is not valid TOML"),
        ('[critical]\ndevices = "R1"\n', "[critical] devices must be a list of device names"),
        (
            '[critical]\ninterfaces = [{ host = "R1" }]\n',
            "each entry of interfaces must name a host and an interface",
        ),
        ('[critical]\nrouters = ["R1"]\n', "[critical] routers is not a known setting"),
    ],
)
def test_every_mistake_is_refused_with_a_message_saying_what_is_wrong(tmp_path, text, message):
    assert message in error_of(tmp_path, text)


def test_a_rule_of_unknown_settings_or_wrong_types_is_refused(tmp_path):
    assert "threshhold is not a known setting" in error_of(
        tmp_path, STORM.replace("threshold = 11", "threshhold = 11")
    )
    assert "group_by must be a list of field names" in error_of(
        tmp_path, STORM.replace('group_by = ["host"]', 'group_by = "host"')
    )
    assert "names 'hostname', which is not a field" in error_of(
        tmp_path, STORM.replace('["host"]', '["hostname"]')
    )
    assert "defined twice" in error_of(tmp_path, STORM + STORM)


def test_an_unknown_event_key_is_only_a_warning(tmp_path):
    ruleset = load_rule_set(
        write(tmp_path, "r.toml", STORM.replace("SYS-5-CONFIG_I", "SYS-5-CONFIG_l"))
    )
    assert ruleset.by_name("config_storm") is not None
    assert ruleset.warnings == [
        "rule 'config_storm': event key 'SYS-5-CONFIG_l' is not a message type netlog knows; "
        "check the spelling (it is fine if your devices send it)"
    ]
    assert load_rule_set(write(tmp_path, "ok.toml", STORM)).warnings == []


def test_a_rule_file_is_data_and_cannot_reach_into_python(tmp_path):
    for title in ("{host.__class__}", "{host!r}", "{host[0]}", "{count:>999999999}"):
        message = error_of(
            tmp_path, STORM.replace("{count} configuration changes on {host}", title)
        )
        assert "title" in message
    # TOML has no way to include another file or run anything: such text is only a string.
    ruleset = load_rule_set(
        write(
            tmp_path, "r.toml", STORM.replace('"config_storm"\nkind', "\"__import__('os')\"\nkind")
        )
    )
    assert ruleset.by_name("config_storm").incident_type == "__import__('os')"


def test_critical_devices_from_the_rule_file_raise_severity(capsys, tmp_path):
    log_file = write(tmp_path, "flaps.log", doc_blocks()["example 1 log"])
    tuning = doc_blocks()["example 1 rule"]
    _, plain, _ = rules_test(capsys, write(tmp_path, "a.toml", tuning), log_file)
    critical = write(tmp_path, "b.toml", tuning + '\n[critical]\ndevices = ["R1"]\n')
    _, raised, _ = rules_test(capsys, critical, log_file)

    assert "  medium   Interface GigabitEthernet0/2" in plain
    assert "  high     Interface GigabitEthernet0/2" in raised


def test_a_new_rules_findings_flow_into_incidents_and_the_report(capsys, tmp_path):
    blocks = doc_blocks()
    rule_file = write(tmp_path, "sequence.toml", blocks["example 3 rule"])
    log_file = write(tmp_path, "login.log", blocks["example 3 log"])

    code = main(["analyze", str(log_file), "--year", "2026", "--rules", str(rule_file), "--quiet",
                 "--format", "json", "--no-llm"])  # fmt: skip
    out = capsys.readouterr().out

    assert code == 1
    import json

    report = json.loads(out)
    (incident,) = [
        i for i in report["incidents"] if i["root_cause"] and "198.51.100.23" in i["title"]
    ]
    assert incident["severity"] == "low"
    assert (
        incident["title"] == "Login to R2 from 198.51.100.23, then a configuration change 45s later"
    )


def test_the_command_refuses_a_broken_rule_file_with_its_message(capsys, tmp_path):
    bad = write(tmp_path, "bad.toml", STORM.replace("threshold = 11", "threshold = 0"))
    code, out, err = rules_test(capsys, bad, SCENARIOS / "01_link_flap.log")
    assert code == 2 and out == ""
    assert (
        err == "netlog: rule 'config_storm': threshold must be a number greater than zero, not 0\n"
    )


# --- Writing overrides into a file ------------------------------------------------------------


def test_writing_an_override_keeps_the_rest_of_the_file():
    text = (
        "# My rules\n\n"
        '[[override]]\nname = "link_flap"\nthreshold = 3\n\n'
        "# A burst of changes\n" + STORM.strip() + "\n\n"
        '[[override]]\nname = "brute_force_login"\nenabled = false\n'
    )
    changed = with_override(text, "link_flap", {"threshold": 4, "severity": "high"})

    assert changed.startswith("# My rules\n")
    assert "# A burst of changes\n" in changed and 'name = "config_storm"' in changed
    assert changed.count("[[override]]") == 2
    assert changed.endswith('[[override]]\nname = "link_flap"\nthreshold = 4\nseverity = "high"\n')
    removed = with_override(changed, "link_flap", {})
    assert '"link_flap"' not in removed and '"brute_force_login"' in removed
    assert with_override("", "link_flap", {"enabled": False}) == (
        '[[override]]\nname = "link_flap"\nenabled = false\n'
    )


# --- The API ---------------------------------------------------------------------------------


@pytest.fixture
def rules_file(tmp_path, monkeypatch):
    path = tmp_path / "rules" / "my-rules.toml"
    monkeypatch.setenv(USER_FILE_ENV, str(path))
    return path


def test_the_api_lists_the_rules_in_force(tmp_path, rules_file):
    rules_file.parent.mkdir()
    write(rules_file.parent, rules_file.name, STORM + '\n[critical]\ndevices = ["R1"]\n')
    with TestClient(build(tmp_path)) as client:
        body = client.get("/api/rules").json()
    by_name = {item["name"]: item for item in body["items"]}
    assert body["total"] == len(body["items"]) == 17
    assert body["user_file"] == str(rules_file)
    assert body["critical"] == {"devices": ["R1"], "interfaces": []}
    flap = by_name["link_flap"]
    assert flap["origin"] == "built-in" and flap["threshold"] == 5 and flap["window_seconds"] == 300
    assert flap["event_keys"] == ["LINK-3-UPDOWN"] and flap["group_by"] == ["host", "interface"]
    assert by_name["config_storm"]["origin"] == "your file"


def test_a_change_through_the_api_is_stored_and_applies_to_the_next_analysis(tmp_path, rules_file):
    flaps = doc_blocks()["example 1 log"].encode()
    with TestClient(build(tmp_path)) as client:
        first = upload(client, flaps, "flaps.log", year="2026").json()["id"]
        wait(client, first)
        assert client.get(f"/api/uploads/{first}/incidents").json()["total"] == 0

        response = client.patch("/api/rules/link_flap", json={"threshold": 3, "severity": "high"})
        assert response.status_code == 200, response.text
        changed = response.json()
        assert changed["threshold"] == 3 and changed["severity"] == "high"
        assert changed["origin"] == "built-in, changed"
        assert changed["override"] == {"severity": "high", "threshold": 3}
        assert rules_file.read_text(encoding="utf-8") == (
            '[[override]]\nname = "link_flap"\nseverity = "high"\nthreshold = 3\n'
        )

        second = upload(client, flaps, "flaps.log", year="2026").json()["id"]
        wait(client, second)
        (incident,) = client.get(f"/api/uploads/{second}/incidents").json()["items"]
        assert incident["severity"] == "high"
        # The earlier result stays as it was.
        assert client.get(f"/api/uploads/{first}/incidents").json()["total"] == 0

        # Switch it off again, keeping the other settings.
        off = client.patch("/api/rules/link_flap", json={"enabled": False}).json()
        assert off["enabled"] is False and off["threshold"] == 3


def test_a_change_that_does_not_fit_is_refused_and_the_file_is_kept(tmp_path, rules_file):
    with TestClient(build(tmp_path)) as client:
        client.patch("/api/rules/link_flap", json={"threshold": 3})
        before = rules_file.read_text(encoding="utf-8")

        bad = client.patch("/api/rules/link_flap", json={"within_seconds": 60})
        assert bad.status_code == 400
        assert bad.json()["error"]["message"] == (
            "rule 'link_flap': override within_seconds does not apply to a threshold rule"
        )
        assert client.patch("/api/rules/link_flap", json={"threshold": 0}).status_code == 400
        assert client.patch("/api/rules/link_flap", json={"colour": "red"}).status_code == 422
        missing = client.patch("/api/rules/no_such_rule", json={"enabled": False})
        assert missing.status_code == 404 and missing.json()["error"]["code"] == "rule_not_found"
        assert rules_file.read_text(encoding="utf-8") == before
        assert not list(rules_file.parent.glob("*.checking"))


def test_the_api_will_not_start_with_a_broken_rule_file(tmp_path, rules_file):
    rules_file.parent.mkdir()
    write(rules_file.parent, rules_file.name, STORM.replace("threshold = 11", "threshold = 0"))
    with pytest.raises(RuleError, match="threshold must be a number greater than zero, not 0"):
        build(tmp_path)


def test_the_rule_file_setting_is_used_when_the_file_exists(tmp_path, monkeypatch):
    monkeypatch.delenv(USER_FILE_ENV)
    config = load_config()
    config["rules"] = {"user_file": str(tmp_path / "absent.toml")}
    assert load_rule_set(config=config).user_file is None
    write(tmp_path, "present.toml", '[[override]]\nname = "link_flap"\nthreshold = 2\n')
    config["rules"] = {"user_file": str(tmp_path / "present.toml")}
    assert load_rule_set(config=config).by_name("link_flap").threshold == 2
