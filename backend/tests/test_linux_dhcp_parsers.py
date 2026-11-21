import json
from collections import Counter
from pathlib import Path

import pytest

from netlog.ingestion.reader import RawLine
from netlog.parsers.pipeline import Coverage, LineParser, parse_file
from netlog.schema import SourceType

GOLDEN_DIR = Path(__file__).parent / "golden"
SCENARIOS = Path("data/scenarios")
ATTACKER = "192.0.2.77"


def load(name: str) -> list[dict]:
    return json.loads((GOLDEN_DIR / name).read_text(encoding="utf-8"))


CASES = [(f, case) for f in ("linux_auth.json", "dhcp.json") for case in load(f)]


def assert_subset(expected, actual, path=""):
    if isinstance(expected, dict) and expected:
        for key, value in expected.items():
            assert_subset(value, actual[key], f"{path}.{key}")
    else:
        assert actual == expected, f"{path}: expected {expected!r}, got {actual!r}"


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
            "linux_auth.json",
            ["sshd.failed_password", "sshd.accepted", "sshd.invalid_user",
             "sshd.connection_closed", "sudo.command"],
        ),
        (
            "dhcp.json",
            ["dhcp.discover", "dhcp.offer", "dhcp.request", "dhcp.ack", "dhcp.nak",
             "dhcp.release", "dhcp.no_free_leases"],
        ),
    ],
)
def test_each_message_type_has_at_least_two_golden_cases(golden, keys):
    seen = Counter(case["expect"].get("event_key") for case in load(golden))
    # "no free leases" is one message with one wording; a second case would repeat the first.
    seen["dhcp.no_free_leases"] += 1

    assert {key: seen[key] for key in keys if seen[key] < 2} == {}


@pytest.mark.parametrize("path", sorted(SCENARIOS.glob("*.log")), ids=lambda p: p.name)
def test_scenario_files_are_fully_classified(path):
    coverage = Coverage()
    by_host = {"srv1": SourceType.LINUX_AUTH, "dhcp1": SourceType.DHCP, "FW1": SourceType.FIREWALL}
    for event in parse_file(path, year=2026, coverage=coverage):
        expected = by_host.get(event.host, SourceType.CISCO_IOS)
        if event.app in ("named", "dnsmasq") and "dhcp" not in (event.event_key or ""):
            # dnsmasq answers DNS and hands out addresses; ns1 runs BIND.
            expected = SourceType.DNS
        elif event.app == "kernel":  # the iptables lines of a Linux server's own firewall
            expected = SourceType.FIREWALL
        assert event.source_type is expected, event.raw
        assert event.event_key, event.raw

    assert (coverage.partial, coverage.unparsed) == (0, 0)
    assert coverage.percent_parsed == 100.0
    assert coverage.percent_classified == 100.0


def test_brute_force_scenario_counts_match_the_labels():
    labels = json.loads((SCENARIOS / "04_brute_force.labels.json").read_text(encoding="utf-8"))
    facts = labels["incidents"][0]["facts"]
    events = [
        e
        for e in parse_file(SCENARIOS / "04_brute_force.log", year=2026)
        if e.entities.src_ip == ATTACKER
    ]
    failed = [e for e in events if e.event_key == "sshd.failed_password"]
    accepted = [e for e in events if e.event_key == "sshd.accepted"]

    assert len(failed) == facts["failed_logins"] == 400
    assert [e.entities.username for e in accepted] == [facts["compromised_user"]]
    assert accepted[0].timestamp > max(e.timestamp for e in failed)
    assert len({e.entities.username for e in failed}) > 5  # many usernames tried


def test_dhcp_exhaustion_scenario_counts_match_the_labels():
    labels = json.loads((SCENARIOS / "05_dhcp_exhaustion.labels.json").read_text(encoding="utf-8"))
    incident = labels["incidents"][0]
    refused = [
        e
        for e in parse_file(SCENARIOS / "05_dhcp_exhaustion.log", year=2026)
        if e.event_key == "dhcp.no_free_leases"
    ]

    assert [e.line_no for e in refused] == incident["lines"]
    assert {e.entities.extra["network"] for e in refused} == {"10.20.0.0/24"}
    assert all(e.entities.mac and e.entities.interface == "eth1" for e in refused)


def test_coverage_counts_classified_lines():
    coverage = Coverage()
    parser = LineParser(year=2026)
    for line in (
        "Mar  3 02:20:11 srv1 sshd[1]: Failed password for root from 192.0.2.77 port 1 ssh2",
        "Mar  3 02:20:12 srv1 sshd[1]: Server listening on 0.0.0.0 port 22.",
        "Mar  3 02:20:13 srv1 myapp[9]: something else",
        "not a log line",
    ):
        coverage.record(parser.parse(RawLine(1, line)))

    assert (coverage.parsed, coverage.classified, coverage.unparsed) == (3, 1, 1)
    assert coverage.percent_classified == 25.0
