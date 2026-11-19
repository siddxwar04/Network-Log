import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from netlog.detection.engine import detect, hot_ranges
from netlog.detection.finding import format_duration
from netlog.detection.rules import RuleError, load_rules, parse_rules
from netlog.ingestion.ingest import ingest_file
from netlog.ingestion.reader import RawLine
from netlog.parsers.pipeline import LineParser
from netlog.storage.database import Database

SCENARIOS = Path("data/scenarios")
ATTACKER = "192.0.2.77"
START = datetime(2026, 3, 3, 2, 0, 0, tzinfo=UTC)


@pytest.fixture
def db(tmp_path):
    with Database(tmp_path / "test.db") as database:
        yield database


def stamp(moment):
    return f"{moment:%b} {moment.day:>2} {moment:%H:%M:%S}"


def cisco(offset, host, body):
    moment = START + timedelta(seconds=offset)
    return f"{stamp(moment)} {host} 1: {stamp(moment)}.000: {body}"


def link(offset, state="down", host="R1", interface="GigabitEthernet0/2"):
    return cisco(offset, host, f"%LINK-3-UPDOWN: Interface {interface}, changed state to {state}")


def ssh(offset, text, host="srv1"):
    return f"{stamp(START + timedelta(seconds=offset))} {host} sshd[77]: {text}"


def failed(offset, ip=ATTACKER, user="root", host="srv1"):
    return ssh(offset, f"Failed password for {user} from {ip} port 4000 ssh2", host)


def accepted(offset, ip=ATTACKER, user="deploy"):
    return ssh(offset, f"Accepted password for {user} from {ip} port 4001 ssh2")


def run(db, lines, rules=None):
    parser = LineParser(year=2026)
    upload = db.create_upload("test.log")
    db.add_events(upload, [parser.parse(RawLine(n, line)) for n, line in enumerate(lines, 1)])
    return detect(db, upload, rules)


def scenario(db, name):
    upload = ingest_file(db, SCENARIOS / f"{name}.log", year=2026)
    labels = json.loads((SCENARIOS / f"{name}.labels.json").read_text(encoding="utf-8"))
    return upload, detect(db, upload), labels["incidents"]


def label_time(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def evidence_lines(db, finding):
    return [e.line_no for e in db.events_by_id(finding.evidence)]


# --- Scenarios ---------------------------------------------------------------------------


def test_link_flap_scenario_gives_exactly_one_finding(db):
    _, findings, (incident,) = scenario(db, "01_link_flap")

    (finding,) = findings
    assert finding.rule == "link_flap" and finding.incident_type == "link_flap"
    assert finding.host == "R1"
    assert finding.group == {"host": "R1", "interface": "GigabitEthernet0/2"}
    assert finding.metrics["count"] == 12 == incident["facts"]["down_transitions"]
    assert finding.metrics["peak_count"] == 12
    assert finding.flags == []
    assert finding.title.startswith("Interface GigabitEthernet0/2 on R1 went down 12 times in ")
    # The finding starts at the first down. The label also covers the last recovery.
    assert abs(finding.start - label_time(incident["start"])) < timedelta(seconds=3)
    assert timedelta(0) <= label_time(incident["end"]) - finding.end < timedelta(seconds=15)
    assert set(evidence_lines(db, finding)) <= set(incident["lines"])
    assert len(finding.evidence) == 12


def test_brute_force_scenario_gives_one_finding_marked_succeeded(db):
    _, findings, (incident,) = scenario(db, "04_brute_force")

    (finding,) = findings
    assert finding.rule == "brute_force_login" and finding.incident_type == "brute_force"
    assert finding.group == {"src_ip": ATTACKER}
    assert finding.host == "srv1" and finding.metrics["hosts"] == ["srv1"]
    assert finding.metrics["count"] == 400 == incident["facts"]["failed_logins"]
    assert finding.metrics["distinct_username"] >= 5
    assert finding.metrics["succeeded_username"] == incident["facts"]["compromised_user"]
    assert set(finding.flags) == {"password_spraying", "succeeded"}
    assert finding.strength == 1.0
    # 400 failures plus the login that succeeded.
    assert len(finding.evidence) == 401
    assert set(evidence_lines(db, finding)) <= set(incident["lines"])
    assert abs(finding.start - label_time(incident["start"])) < timedelta(seconds=5)


def test_overlap_scenario_gives_two_separate_findings(db):
    _, findings, incidents = scenario(db, "10_overlap")

    by_type = {f.incident_type: f for f in findings}
    assert len(findings) == 2 and set(by_type) == {"link_flap", "brute_force"}
    flap, brute = by_type["link_flap"], by_type["brute_force"]
    assert flap.group == {"host": "SW2", "interface": "GigabitEthernet0/5"}
    assert flap.metrics["count"] == 10
    assert brute.metrics["count"] == 300 and "succeeded" not in brute.flags
    assert flap.start < brute.end and brute.start < flap.end


QUIET = ("02_cascade", "03_config_bgp", "05_dhcp_exhaustion", "07_device_reload", "08_noise")


@pytest.mark.parametrize("name", [*QUIET, "08_noise_50k"])
def test_other_scenarios_and_noise_give_no_findings(db, name):
    upload = ingest_file(db, SCENARIOS / f"{name}.log", year=2026)

    assert detect(db, upload) == []


# --- Link flap ---------------------------------------------------------------------------


def flaps(count, spacing=20, start=0, **kw):
    lines = []
    for n in range(count):
        at = start + n * spacing
        lines += [link(at, "down", **kw), link(at + 5, "up", **kw)]
    return lines


def test_four_flaps_do_not_trigger_and_five_do(db):
    assert run(db, flaps(4)) == []

    (finding,) = run(db, flaps(5))
    assert finding.metrics["count"] == 5
    assert finding.strength == 0.25  # exactly at the threshold


def test_five_flaps_spread_over_more_than_the_window_do_not_trigger(db):
    assert run(db, flaps(5, spacing=80)) == []  # 320 seconds from first to last
    assert len(run(db, flaps(5, spacing=75))) == 1  # exactly 300 seconds: inside


def test_a_single_down_and_up_is_not_a_flap(db):
    assert run(db, flaps(1)) == []


def test_administrative_shutdowns_do_not_count(db):
    lines = []
    body = "%LINK-5-CHANGED: Interface Gi0/2, changed state to administratively down"
    for n in range(12):
        lines += [cisco(n * 20, "R1", body), link(n * 20 + 5, "up")]

    assert run(db, lines) == []


def test_half_an_hour_of_flapping_is_one_finding(db):
    (finding,) = run(db, flaps(90, spacing=20))  # one flap every 20 seconds for 30 minutes

    assert finding.metrics["count"] == 90
    assert finding.duration_seconds == 89 * 20
    assert finding.metrics["peak_count"] == 16  # the most in any 5 minutes
    assert finding.strength == 0.8
    assert "in 29m 40s" in finding.title


def test_two_bursts_an_hour_apart_are_two_findings(db):
    findings = run(db, flaps(6) + flaps(7, start=3600))

    assert [f.metrics["count"] for f in findings] == [6, 7]
    assert findings[1].start - findings[0].end > timedelta(minutes=50)


def test_bursts_closer_than_one_window_are_joined(db):
    (finding,) = run(db, flaps(5) + flaps(5, start=300))

    assert finding.metrics["count"] == 10


def test_flaps_on_different_interfaces_or_devices_are_not_added_together(db):
    lines = (
        flaps(3)
        + flaps(3, start=7, interface="GigabitEthernet0/3")
        + flaps(3, start=11, host="R2")
    )

    assert run(db, lines) == []


def test_short_and_long_interface_names_are_the_same_interface(db):
    lines = flaps(3) + flaps(3, start=100, interface="Gi0/2")

    (finding,) = run(db, lines)
    assert finding.group["interface"] == "GigabitEthernet0/2"


# --- Brute force -------------------------------------------------------------------------


def attempts(count, spacing=10, start=0, **kw):
    return [failed(start + n * spacing, **kw) for n in range(count)]


def test_nineteen_failures_do_not_trigger_and_twenty_do(db):
    assert run(db, attempts(19)) == []

    (finding,) = run(db, attempts(20))
    assert finding.metrics["count"] == 20 and finding.flags == []


def test_failures_from_different_addresses_are_not_added_together(db):
    lines = attempts(15) + attempts(15, start=3, ip="198.51.100.9")

    assert run(db, lines) == []


def test_cisco_and_linux_failures_from_one_address_are_counted_together(db):
    body = (
        "%SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 192.0.2.77] "
        "[localport: 22] [Reason: Login Authentication Failed] at 02:00:00 UTC Tue Mar 3 2026"
    )
    lines = attempts(10) + [cisco(100 + n * 5, "R1", body) for n in range(10)]

    (finding,) = run(db, lines)
    assert finding.metrics["count"] == 20
    assert finding.host is None  # more than one device was targeted
    assert finding.metrics["hosts"] == ["R1", "srv1"]
    assert finding.title == f"20 failed logins from {ATTACKER} in 2m 25s"


def test_many_usernames_are_noted_as_password_spraying(db):
    same_user = run(db, attempts(25))
    many_users = run(db, [failed(n * 10, user=f"user{n % 6}") for n in range(25)])

    assert same_user[0].metrics["distinct_username"] == 1 and same_user[0].flags == []
    assert many_users[0].metrics["distinct_username"] == 6
    assert many_users[0].flags == ["password_spraying"]


def test_success_after_the_failures_escalates(db):
    (finding,) = run(db, attempts(25) + [accepted(260)])

    assert finding.flags == ["succeeded"]
    assert finding.metrics["succeeded_username"] == "deploy"
    assert len(finding.evidence) == 26


@pytest.mark.parametrize(
    "extra_line",
    [
        accepted(100),  # before the twentieth failure: no guessing had been established
        accepted(260, ip="10.10.10.50"),  # someone else logging in
        accepted(240 + 601),  # too long after the last failure
    ],
)
def test_logins_that_do_not_follow_the_failures_do_not_escalate(db, extra_line):
    (finding,) = run(db, attempts(25) + [extra_line])

    assert finding.flags == []
    assert len(finding.evidence) == 25


def test_a_source_logged_as_a_hostname_is_not_grouped(db):
    lines = [failed(n * 10, ip="scanner.example.net") for n in range(30)]

    assert run(db, lines) == []


# --- Rules as data -----------------------------------------------------------------------


def test_changing_a_threshold_in_a_rule_file_changes_the_result(db, tmp_path):
    built_in = Path("backend/netlog/config/rules.toml").read_text(encoding="utf-8")
    stricter = tmp_path / "rules.toml"
    stricter.write_text(built_in.replace("threshold = 5", "threshold = 3"), encoding="utf-8")
    lines = flaps(3)

    assert run(db, lines) == []
    (finding,) = run(db, lines, load_rules(stricter))
    assert finding.rule == "link_flap" and finding.metrics["threshold"] == 3


def test_a_user_rule_replaces_the_built_in_rule_of_the_same_name(db, tmp_path, monkeypatch):
    user_file = tmp_path / "mine.toml"
    user_file.write_text(
        """
        [[rule]]
        name = "link_flap"
        incident_type = "link_flap"
        kind = "threshold"
        enabled = false
        title = "off"
        event_keys = ["LINK-3-UPDOWN"]
        group_by = ["host"]
        window_seconds = 60
        threshold = 2
        """,
        encoding="utf-8",
    )
    monkeypatch.setenv("NETLOG_RULES", str(user_file))

    rules = {rule.name: rule for rule in load_rules()}

    assert rules["link_flap"].enabled is False
    assert rules["brute_force_login"].threshold == 20  # untouched
    assert run(db, flaps(12), load_rules()) == []  # disabled rules do not run


SEQUENCE_RULE = """
[[rule]]
name = "config_after_login"
incident_type = "suspicious_config_change"
kind = "sequence"
title = "Config changed on {host} {delay}s after a login from {src_ip}"
same = ["host", "src_ip"]
within_seconds = 120
first = { event_keys = ["SEC_LOGIN-5-LOGIN_SUCCESS"] }
then = { event_keys = ["SYS-5-CONFIG_I"], where_not = { username = ["console"] } }
"""


def login(offset, ip="10.10.10.53", host="R2"):
    body = (
        f"%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: jdoe] [Source: {ip}] "
        "[localport: 22] at 02:00:00 UTC Tue Mar 3 2026"
    )
    return cisco(offset, host, body)


def config(offset, ip="10.10.10.53", host="R2"):
    return cisco(offset, host, f"%SYS-5-CONFIG_I: Configured from console by jdoe on vty0 ({ip})")


def test_sequence_rule_finds_one_event_followed_by_another(db):
    rules = parse_rules(SEQUENCE_RULE)

    (finding,) = run(db, [login(0), config(30)], rules)

    assert finding.incident_type == "suspicious_config_change"
    assert finding.group == {"host": "R2", "src_ip": "10.10.10.53"}
    assert finding.metrics["delay"] == 30.0
    assert finding.title == "Config changed on R2 30.0s after a login from 10.10.10.53"
    assert finding.strength == 0.75
    assert len(finding.evidence) == 2


@pytest.mark.parametrize(
    "lines",
    [
        [login(0), config(121)],  # too late
        [config(0), login(30)],  # wrong order
        [login(0), config(30, ip="10.10.10.99")],  # a different address
        [login(0), config(30, host="R3")],  # a different device
        [login(0)],
        [config(30)],
    ],
)
def test_sequence_rule_ignores_pairs_that_do_not_fit(db, lines):
    assert run(db, lines, parse_rules(SEQUENCE_RULE)) == []


def test_sequence_rule_pairs_each_later_event_with_the_most_recent_earlier_one(db):
    findings = run(db, [login(0), login(50), config(60), config(100)], parse_rules(SEQUENCE_RULE))

    assert [f.metrics["delay"] for f in findings] == [10.0, 50.0]


def test_where_accepts_one_value_or_a_list(db):
    rule = """
    [[rule]]
    name = "any_change"
    incident_type = "link_flap"
    kind = "threshold"
    title = "{count} changes on {host}"
    event_keys = ["LINK-3-UPDOWN"]
    where = { state_to = ["down", "up"], host = "R1" }
    group_by = ["host"]
    window_seconds = 300
    threshold = 6
    """

    (finding,) = run(db, flaps(3) + flaps(3, host="R2"), parse_rules(rule))

    assert finding.title == "6 changes on R1"


GOOD_RULE = """
[[rule]]
name = "r"
incident_type = "t"
kind = "threshold"
title = "{count} on {host}"
event_keys = ["X-1-Y"]
group_by = ["host"]
window_seconds = 300
threshold = 5
"""


@pytest.mark.parametrize(
    ("good", "bad", "message"),
    [
        ('kind = "threshold"', 'kind = "magic"', "rule 'r': kind is 'magic'; it must be one of"),
        ("threshold = 5", "threshold = 0", "rule 'r': threshold must be a number greater than"),
        ("threshold = 5", "threshold = 2.5", "rule 'r': threshold must be a whole number"),
        ("threshold = 5", 'threshold = "5"', "rule 'r': threshold must be a number"),
        ("window_seconds = 300", "window_seconds = -1", "rule 'r': window_seconds must be a"),
        ('["host"]', '["colour"]', "rule 'r': group_by names 'colour', which is not a field"),
        ('["X-1-Y"]', "[]", "rule 'r': event_keys must be a list with at least one message type"),
        ("{host}", "{interface}", "rule 'r': title uses {interface}, which this rule does not"),
        ('name = "r"', "", "a rule has no name"),
        ("threshold = 5", "threshold = 5\nthreshhold = 9", "rule 'r': threshhold is not a known"),
        ("threshold = 5", "threshold = 5\nwhere = 3", "rule 'r': where must be a table"),
        ("threshold = 5", "threshold = 5\nenabled = 1", "rule 'r': enabled must be true or false"),
    ],
)
def test_mistakes_in_a_rule_file_are_reported_clearly(good, bad, message):
    parse_rules(GOOD_RULE)  # the starting point is valid

    with pytest.raises(RuleError) as error:
        parse_rules(GOOD_RULE.replace(good, bad))

    assert message in str(error.value)


def test_other_rule_file_problems():
    with pytest.raises(RuleError, match="not valid TOML"):
        parse_rules("[[rule]\n")
    with pytest.raises(RuleError, match="defined twice"):
        parse_rules(SEQUENCE_RULE + SEQUENCE_RULE)
    with pytest.raises(RuleError, match="rule file not found"):
        load_rules("does-not-exist.toml")
    with pytest.raises(RuleError, match="uses {host.__class__}, which this rule does not provide"):
        parse_rules(SEQUENCE_RULE.replace("{host}", "{host.__class__}"))


def test_built_in_rules_load():
    rules = {rule.name: rule for rule in load_rules()}

    assert set(rules) >= {"link_flap", "brute_force_login"}
    flap, brute = rules["link_flap"], rules["brute_force_login"]
    assert (flap.threshold, flap.window_seconds) == (5, 300)
    assert (brute.threshold, brute.window_seconds) == (20, 600)


# --- Engine internals --------------------------------------------------------------------


def seconds(*offsets):
    return [START + timedelta(seconds=o) for o in offsets]


def test_hot_ranges():
    window = timedelta(seconds=10)

    assert hot_ranges([], window, 3) == []
    assert hot_ranges(seconds(0, 5), window, 3) == []
    assert hot_ranges(seconds(0, 5, 10), window, 3) == [(0, 2, 3, 2)]
    assert hot_ranges(seconds(0, 5, 11), window, 3) == []
    # Two bursts far apart stay separate; the second number is the last index.
    assert hot_ranges(seconds(0, 1, 2, 100, 101, 102), window, 3) == [(0, 2, 3, 2), (3, 5, 3, 5)]
    # Two bursts within one window of each other are joined.
    assert hot_ranges(seconds(0, 1, 2, 12, 13, 14), window, 3) == [(0, 5, 3, 2)]
    # The peak is the largest count seen in any one window.
    assert hot_ranges(seconds(0, 1, 2, 3, 4, 50), window, 3) == [(0, 4, 5, 2)]


def test_format_duration():
    assert [format_duration(s) for s in (0, 59, 60, 272, 3600, 3900)] == [
        "0s",
        "59s",
        "1m",
        "4m 32s",
        "1h",
        "1h 5m",
    ]


# --- Storage -----------------------------------------------------------------------------


def test_findings_are_stored_and_replaced_on_a_second_run(db):
    upload, first, _ = scenario(db, "01_link_flap")

    again = detect(db, upload)
    stored = db.findings(upload)

    assert len(stored) == 1 and stored[0].upload_id == upload and stored[0].id is not None
    assert [(f.rule, f.start, f.end, f.metrics, f.evidence) for f in again] == [
        (f.rule, f.start, f.end, f.metrics, f.evidence) for f in first
    ]


def test_deleting_an_upload_removes_its_findings(db):
    upload, findings, _ = scenario(db, "01_link_flap")
    assert findings

    db.delete_upload(upload)

    assert db.findings(upload) == []
