"""Firewall and DNS logs: the two parsers (golden files), the rules that use them, the two
generic engine features they needed (counting different values, and a share of events),
and scenarios 6 (port scan) and 11 (DNS failure)."""

import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from netlog.correlation.grouping import correlate
from netlog.detection.engine import detect, hot_ranges
from netlog.detection.rules import RuleError, apply_override, load_rule_set, load_rules, parse_rules
from netlog.ingestion.ingest import ingest_file
from netlog.ingestion.reader import RawLine
from netlog.mining.templates import mine_templates
from netlog.parsers.pipeline import LineParser, free_text_spans
from netlog.storage.database import Database

GOLDEN_DIR = Path(__file__).parent / "golden"
SCENARIOS = Path("data/scenarios")
START = datetime(2026, 3, 3, 2, 0, 0, tzinfo=UTC)
SCANNER = "203.0.113.66"


@pytest.fixture
def db(tmp_path):
    with Database(tmp_path / "test.db") as database:
        yield database


def load(name: str) -> list[dict]:
    return json.loads((GOLDEN_DIR / name).read_text(encoding="utf-8"))


def assert_subset(expected, actual, path=""):
    if isinstance(expected, dict) and expected:
        for key, value in expected.items():
            assert_subset(value, actual[key], f"{path}.{key}")
    else:
        assert actual == expected, f"{path}: expected {expected!r}, got {actual!r}"


CASES = [(f, case) for f in ("firewall.json", "dns.json") for case in load(f)]


@pytest.mark.parametrize(
    "case", [c for _, c in CASES], ids=[f"{f.split('.')[0]}: {c['name']}" for f, c in CASES]
)
def test_golden(case):
    event = LineParser(year=2026).parse(RawLine(1, case["line"]))
    assert event.raw == case["line"]
    assert_subset(case["expect"], event.model_dump(mode="json"))


@pytest.mark.parametrize(
    ("golden", "keys"),
    [
        (
            "firewall.json",
            ["ASA-106023", "ASA-106001", "ASA-106100", "ASA-710003", "ASA-302013", "ASA-113015",
             "ASA-605004", "iptables.deny"],
        ),
        ("dns.json", ["dns.query", "dns.query_failed", "dns.reply", "dns.forwarded"]),
    ],
)  # fmt: skip
def test_each_main_message_type_has_at_least_two_golden_cases(golden, keys):
    seen = Counter(case["expect"].get("event_key") for case in load(golden))
    for key in keys:
        assert seen[key] >= 2, key


def test_names_and_usernames_are_masked_in_templates():
    parser = LineParser(year=2026)
    dns = parser.parse(RawLine(1, "Mar  3 02:14:07 dhcp1 dnsmasq[4]: reply wpad.lan is NXDOMAIN"))
    ((start, end, placeholder),) = free_text_spans(dns)
    assert dns.message[start:end] == "wpad.lan" and placeholder == "<HOST>"
    asa = parser.parse(
        RawLine(
            2,
            "Mar  3 02:14:07 FW1 %ASA-6-605004: Login denied from "
            "192.0.2.7/51000 to outside:198.51.100.10/ssh for user 'admin'",
        )
    )
    ((start, end, placeholder),) = free_text_spans(asa)
    assert asa.message[start:end] == "admin" and placeholder == "<USER>"


def test_new_scenarios_and_the_noise_parse_completely():
    for name in ("06_port_scan", "08_noise", "11_dns_failure"):
        parser = LineParser(year=2026)
        lines = (SCENARIOS / f"{name}.log").read_text(encoding="utf-8").splitlines()
        events = [parser.parse(RawLine(n, line)) for n, line in enumerate(lines, 1)]
        statuses = Counter(e.parse_status.value for e in events)
        assert statuses == {"parsed": len(lines)}, (name, statuses)
        edge = [e for e in events if e.source_type.value in ("firewall", "dns")]
        assert len(edge) >= 1000
        # Every firewall and DNS line is recognized.
        unknown = [e.raw for e in edge if not e.event_key]
        assert unknown == []


# --- Engine features ------------------------------------------------------------------------


def test_hot_ranges_can_count_different_values():
    times = [START + timedelta(seconds=s) for s in range(10)]
    same_port = [22] * 10
    assert hot_ranges(times, timedelta(seconds=60), 5, same_port) == []
    assert hot_ranges(times, timedelta(seconds=60), 5) == [(0, 9, 10, 4)]
    ports = list(range(10))
    assert hot_ranges(times, timedelta(seconds=60), 5, ports) == [(0, 9, 10, 4)]
    # Values leave the count when they leave the window.
    spread = [START + timedelta(seconds=s * 30) for s in range(10)]
    assert hot_ranges(spread, timedelta(seconds=60), 4, ports) == []


SHARE_RULE = """
[[rule]]
name = "failures"
incident_type = "dns_failure"
kind = "share"
title = "{percent}% failed on {host} ({count} of {total})"
event_keys = ["dns.query_failed"]
of = { event_keys = ["dns.query"] }
group_by = ["host"]
window_seconds = 300
threshold = 10
share = 0.5
"""


def bind(offset, text):
    stamp = START + timedelta(seconds=offset)
    header = f"{stamp:%b} {stamp.day:>2} {stamp:%H:%M:%S} ns1 named[8]"
    return f"{header}: client 10.10.10.21#5000 ({text}"


def query(offset, name="example.com"):
    return bind(offset, f"{name}): query: {name} IN A + (10.10.10.53)")


def fail(offset, name="example.com"):
    return bind(offset, f"{name}): query failed (SERVFAIL) for {name}/IN/A at query.c:1")


def run(db, lines, rules):
    parser = LineParser(year=2026)
    upload = db.create_upload("test.log")
    db.add_events(upload, [parser.parse(RawLine(n, line)) for n, line in enumerate(lines, 1)])
    return detect(db, upload, rules)


def test_share_rule_needs_both_the_share_and_the_count(db):
    rules = parse_rules(SHARE_RULE)
    # 3 of every 5 queries fail, 12 in all. The total counts the queries asked while the
    # failures lasted (from the first failure to the last), so it is close to, not exactly, 20.
    lines = [query(i * 5) for i in range(20)]
    lines += [fail(i * 5 + 1) for i in range(20) if i % 5 < 3]
    (finding,) = run(db, lines, rules)
    assert finding.metrics["count"] == 12 and 15 <= finding.metrics["total"] <= 20
    assert 60 <= finding.metrics["percent"] <= 80 and finding.strength > 0
    assert finding.title.startswith(f"{finding.metrics['percent']}% failed on ns1 (12 of ")

    # Every query in the stretch failed: 100%, though later queries succeeded.
    lines = [query(i * 5) for i in range(20)] + [fail(i * 5 + 1) for i in range(12)]
    (finding,) = run(db, lines, rules)
    assert finding.title == "100% failed on ns1 (12 of 12)"

    # 3 of every 10 queries fail: 30%, below the share.
    lines = [query(i * 5) for i in range(40)]
    lines += [fail(i * 5 + 1) for i in range(40) if i % 10 < 3]
    assert run(db, lines, rules) == []

    # 8 failures out of 8 queries: all of them, but fewer than the threshold.
    lines = [query(i * 5) for i in range(8)] + [fail(i * 5 + 1) for i in range(8)]
    assert run(db, lines, rules) == []


def test_share_rule_without_query_logging_takes_the_failures_as_the_whole(db):
    (finding,) = run(db, [fail(i * 5) for i in range(15)], parse_rules(SHARE_RULE))
    assert finding.metrics["total"] == 15 and finding.metrics["percent"] == 100


def test_share_rule_mistakes_are_refused():
    with pytest.raises(RuleError, match="share is a fraction"):
        parse_rules(SHARE_RULE.replace("share = 0.5", "share = 50"))
    with pytest.raises(RuleError, match="of is required"):
        parse_rules(SHARE_RULE.replace('of = { event_keys = ["dns.query"] }\n', ""))
    with pytest.raises(RuleError, match="uses {distinct_port}"):
        parse_rules(SHARE_RULE.replace("({count} of {total})", "{distinct_port}"))
    rule = parse_rules(SHARE_RULE)[0]
    assert apply_override(rule, {"share": 0.3}).share == 0.3
    with pytest.raises(RuleError, match="fraction"):
        apply_override(rule, {"share": 3})
    with pytest.raises(RuleError, match="does not apply"):
        apply_override(rule, {"within_seconds": 3})


def test_count_distinct_mistakes_are_refused():
    rule = """
[[rule]]
name = "x"
incident_type = "x"
kind = "threshold"
title = "x"
event_keys = ["iptables.deny"]
group_by = ["src_ip"]
window_seconds = 60
threshold = 5
count_distinct = "{field}"
"""
    with pytest.raises(RuleError, match="not a field"):
        parse_rules(rule.format(field="colour"))
    with pytest.raises(RuleError, match="group_by field"):
        parse_rules(rule.format(field="src_ip"))
    (parsed,) = parse_rules(rule.format(field="port"))
    assert parsed.count_distinct == "port" and "port" in parsed.distinct


# --- The rules ---------------------------------------------------------------------------------


def asa_deny(offset, src, port, dst="198.51.100.10"):
    stamp = START + timedelta(seconds=offset)
    return (
        f"{stamp:%b} {stamp.day:>2} {stamp:%H:%M:%S} FW1 %ASA-4-106023: Deny tcp src "
        f'outside:{src}/40000 dst outside:{dst}/{port} by access-group "OUTSIDE_IN" [0x0, 0x0]'
    )


def notable(findings):
    return [f for f in findings if f.severity != "info"]


def test_port_scan_counts_ports_not_attempts(db):
    # 100 refused attempts on the same three ports is not a scan.
    lines = [asa_deny(i * 0.5, SCANNER, (22, 23, 3389)[i % 3]) for i in range(100)]
    assert notable(run(db, lines, None)) == []
    # 30 different ports in 30 seconds is.
    lines = [asa_deny(i, SCANNER, 1000 + i) for i in range(30)]
    (finding,) = notable(run(db, lines, None))
    assert finding.rule == "port_scan" and finding.severity == "medium"
    assert finding.title == f"Port scan from {SCANNER}: 30 ports tried in 29s"
    assert finding.group == {"src_ip": SCANNER}


def test_port_scan_followed_by_an_allowed_connection_is_high(db):
    lines = [asa_deny(i, SCANNER, 1000 + i) for i in range(30)]
    lines.append(
        f"Mar  3 02:05:00 FW1 %ASA-6-302013: Built inbound TCP connection 7 for "
        f"outside:{SCANNER}/40001 ({SCANNER}/40001) to dmz:10.10.10.20/443 (198.51.100.10/443)"
    )
    (finding,) = notable(run(db, lines, None))
    assert finding.flags == ["let_through"] and finding.severity == "high"


def test_port_sweep_counts_machines_on_one_port(db):
    lines = [asa_deny(i, SCANNER, 445, dst=f"10.10.10.{i + 1}") for i in range(25)]
    (finding,) = notable(run(db, lines, None))
    assert finding.rule == "port_sweep"
    assert finding.title == f"Port sweep from {SCANNER}: port 445 tried on 25 addresses in 24s"


def dnsmasq(offset, text):
    stamp = START + timedelta(seconds=offset)
    return f"{stamp:%b} {stamp.day:>2} {stamp:%H:%M:%S} dhcp1 dnsmasq[4]: {text}"


def test_nxdomain_burst_counts_different_names_from_one_client(db):
    client = "10.20.0.66"
    burst = [
        dnsmasq(i * 3, f"{i} {client}/5000 reply q{i:03d}x7kd.example is NXDOMAIN")
        for i in range(60)
    ]
    (finding,) = notable(run(db, burst, None))
    assert finding.rule == "dns_nxdomain_burst" and finding.group == {"src_ip": client}
    assert finding.metrics["distinct_qname"] == 60

    # The same missing name asked 200 times, and 40 different ones, are both below it.
    same = [dnsmasq(i, f"{i} {client}/5000 reply wpad.lan is NXDOMAIN") for i in range(200)]
    fewer = [dnsmasq(i * 3, f"{i} {client}/5000 reply n{i}.example is NXDOMAIN") for i in range(40)]
    assert notable(run(db, same, None)) == [] and notable(run(db, fewer, None)) == []


def test_the_new_rules_are_valid_and_their_message_types_are_known():
    rules = {rule.name: rule for rule in load_rules()}
    assert {"port_scan", "port_sweep", "dns_failure_spike", "dns_nxdomain_burst"} <= set(rules)
    assert rules["dns_failure_spike"].kind == "share"
    assert load_rule_set().warnings == []  # no rule names a message type nothing produces


# --- Scenarios ----------------------------------------------------------------------------------


def scenario(db, name):
    upload = ingest_file(db, SCENARIOS / f"{name}.log", year=2026)
    mine_templates(db, upload)
    labels = json.loads((SCENARIOS / f"{name}.labels.json").read_text(encoding="utf-8"))
    return upload, notable(detect(db, upload)), labels


def label_time(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def test_port_scan_scenario_matches_its_label(db):
    upload, findings, labels = scenario(db, "06_port_scan")
    (label,) = labels["incidents"]
    (finding,) = findings
    assert finding.rule == label["root_cause"]["kind"] == "port_scan"
    assert finding.group["src_ip"] == label["root_cause"]["entity"] == SCANNER
    assert finding.host == "FW1" and finding.severity == label["expected_severity"] == "medium"
    assert finding.metrics["distinct_port"] == label["facts"]["ports_tried"] == 500
    assert abs(finding.start - label_time(label["start"])) < timedelta(seconds=10)
    # The evidence is the scan's own lines and nothing else.
    evidence = {e.line_no for e in db.events_by_id(finding.evidence)}
    assert evidence == set(label["lines"])

    (incident,) = correlate(db, upload)
    assert incident.root_cause.entity == SCANNER and incident.devices == ["FW1"]


def test_dns_failure_scenario_matches_its_label(db):
    upload, findings, labels = scenario(db, "11_dns_failure")
    (label,) = labels["incidents"]
    (finding,) = findings
    assert finding.rule == "dns_failure_spike" and finding.host == "ns1"
    assert finding.severity == label["expected_severity"] == "high"
    assert finding.metrics["count"] == label["facts"]["failed"]
    assert finding.metrics["percent"] >= 70
    assert abs(finding.start - label_time(label["start"])) < timedelta(seconds=10)
    # Ten minutes of failures, not cut short and not run on.
    lasted = (finding.end - finding.start).total_seconds()
    assert 9 * 60 <= lasted <= 11 * 60

    (incident,) = correlate(db, upload)
    assert incident.devices == ["ns1"] and incident.severity == "high"


def test_the_noise_holds_everyday_firewall_and_dns_look_alikes(db):
    upload, findings, labels = scenario(db, "08_noise")
    assert findings == [] and labels["incidents"] == []
    events = list(db.iter_events(upload))
    denied = [e for e in events if e.entities.extra.get("action") == "deny"]
    ports: dict[str, set] = {}
    for event in denied:
        ports.setdefault(event.entities.src_ip, set()).add(event.entities.port)
    nxdomain = [e for e in events if e.entities.extra.get("rcode") == "NXDOMAIN"]
    failures = [e for e in events if e.event_key == "dns.query_failed"]
    # Ordinary refused connections from many addresses, names that do not exist at a normal
    # rate, and the odd failure: all present, none enough to be an incident.
    assert len(ports) > 50 and max(len(tried) for tried in ports.values()) < 25
    assert 10 <= len(nxdomain) and failures
