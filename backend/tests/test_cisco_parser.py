import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from netlog.ingestion.reader import RawLine
from netlog.parsers.cisco import _EXTRACTORS
from netlog.parsers.pipeline import Coverage, LineParser, parse_file
from netlog.parsers.syslog import parse_timezone
from netlog.schema import ParseStatus, SourceType

GOLDEN = json.loads((Path(__file__).parent / "golden" / "cisco.json").read_text(encoding="utf-8"))
SCENARIOS = Path("data/scenarios")

REQUIRED_MESSAGES = {
    "LINK-3-UPDOWN",
    "LINEPROTO-5-UPDOWN",
    "LINK-5-CHANGED",
    "BGP-5-ADJCHANGE",
    "BGP-3-NOTIFICATION",
    "OSPF-5-ADJCHG",
    "SYS-5-CONFIG_I",
    "SEC_LOGIN-4-LOGIN_FAILED",
    "SEC_LOGIN-5-LOGIN_SUCCESS",
    "SYS-5-RESTART",
    "SYS-5-RELOAD",
    "SYS-3-CPUHOG",
    "SYS-2-MALLOCFAIL",
    "SW_MATM-4-MACFLAP_NOTIF",
}


def parse(line: str, **options):
    return LineParser(year=2026, **options).parse(RawLine(1, line))


def assert_subset(expected, actual, path=""):
    if isinstance(expected, dict) and expected:
        for key, value in expected.items():
            assert_subset(value, actual[key], f"{path}.{key}")
    else:
        assert actual == expected, f"{path}: expected {expected!r}, got {actual!r}"


@pytest.mark.parametrize("case", GOLDEN, ids=[case["name"] for case in GOLDEN])
def test_golden(case):
    event = parse(case["line"])

    assert event.raw == case["line"]
    assert_subset(case["expect"], event.model_dump(mode="json"))


def test_every_required_message_has_an_extractor_and_two_golden_cases():
    assert REQUIRED_MESSAGES <= set(_EXTRACTORS)
    seen = Counter(
        case["line"].split("%", 1)[1].split(":", 1)[0] for case in GOLDEN if "%" in case["line"]
    )
    # The two login messages share one pattern, so they are counted together.
    logins = seen["SEC_LOGIN-4-LOGIN_FAILED"] + seen["SEC_LOGIN-5-LOGIN_SUCCESS"]
    seen["SEC_LOGIN-4-LOGIN_FAILED"] = seen["SEC_LOGIN-5-LOGIN_SUCCESS"] = logins
    assert {key: seen[key] for key in REQUIRED_MESSAGES if seen[key] < 2} == {}


def test_device_time_is_read_in_the_assumed_timezone():
    line = "Mar  3 02:14:08 R1 5: Mar  3 07:44:07.500: %SYS-5-CONFIG_I: Configured from console by console"  # noqa: E501

    event = parse(line.replace("02:14:08", "07:44:08"), tz=parse_timezone("+05:30"))

    assert event.timestamp == datetime(2026, 3, 3, 2, 14, 7, 500000, tzinfo=UTC)
    assert event.tz_assumed is True


def test_truncated_cisco_line_is_partial():
    line = "Mar  3 02:46:12 R1 89085: Mar  3 02:46:11.699: %LINK-3-UPDOWN: Interface Gigabi"

    event = LineParser(year=2026).parse(RawLine(1, line, truncated=True))

    assert event.parse_status is ParseStatus.PARTIAL
    assert event.event_key == "LINK-3-UPDOWN"


# The 50,000-line file is covered once, by the classification test for all parsers.
SMALL_SCENARIOS = sorted(p for p in SCENARIOS.glob("*.log") if "50k" not in p.name)


@pytest.mark.parametrize("path", SMALL_SCENARIOS, ids=lambda p: p.name)
def test_scenario_cisco_lines_are_fully_understood(path):
    coverage = Coverage()
    for event in parse_file(path, year=2026, coverage=coverage):
        if event.host in ("R1", "R2", "R3", "R4", "SW1", "SW2"):
            assert event.source_type is SourceType.CISCO_IOS, event.raw
            assert event.event_key, event.raw
            assert event.entities.extra.get("seq"), event.raw
        else:
            assert event.source_type is not SourceType.CISCO_IOS, event.raw

    assert (coverage.partial, coverage.unparsed) == (0, 0)


@pytest.mark.parametrize(
    ("scenario", "key", "host", "entities"),
    [
        ("01_link_flap", "LINK-3-UPDOWN", "R1", {"interface": "GigabitEthernet0/2"}),
        ("02_cascade", "LINK-3-UPDOWN", "R1", {"interface": "GigabitEthernet0/1"}),
        ("02_cascade", "OSPF-5-ADJCHG", "R3", {"neighbor_ip": "10.255.0.1", "protocol": "ospf"}),
        ("02_cascade", "BGP-5-ADJCHANGE", "R4", {"neighbor_ip": "10.255.0.1", "protocol": "bgp"}),
        ("02_cascade", "BGP-3-NOTIFICATION", "R2", {"reason": "hold time expired"}),
        ("03_config_bgp", "SYS-5-CONFIG_I", "R2", {"username": "jdoe", "src_ip": "10.10.10.53"}),
        ("03_config_bgp", "BGP-5-ADJCHANGE", "R2", {"neighbor_ip": "203.0.113.1"}),
        ("07_device_reload", "SYS-5-RELOAD", "SW1", {"username": "netops"}),
        ("07_device_reload", "LINK-3-UPDOWN", "R3", {"interface": "GigabitEthernet0/3"}),
    ],
)
def test_scenario_incident_lines_have_their_entities(scenario, key, host, entities):
    labels = json.loads((SCENARIOS / f"{scenario}.labels.json").read_text(encoding="utf-8"))
    wanted = set(labels["incidents"][0]["lines"])
    events = [
        e
        for e in parse_file(SCENARIOS / f"{scenario}.log", year=2026)
        if e.line_no in wanted and e.event_key == key and e.host == host
    ]

    assert events
    for event in events:
        assert_subset(entities, event.entities.model_dump())


def test_cascade_shows_each_session_going_down_and_coming_back():
    labels = json.loads((SCENARIOS / "02_cascade.labels.json").read_text(encoding="utf-8"))
    wanted = set(labels["incidents"][0]["lines"])
    events = [e for e in parse_file(SCENARIOS / "02_cascade.log", year=2026) if e.line_no in wanted]

    for peer in ("R2", "R3", "R4"):
        ospf = [e.entities for e in events if e.host == peer and e.event_key == "OSPF-5-ADJCHG"]
        bgp = [e.entities for e in events if e.host == peer and e.event_key == "BGP-5-ADJCHANGE"]
        assert [(o.state_from, o.state_to, o.reason) for o in ospf] == [
            ("FULL", "DOWN", "Dead timer expired"),
            ("LOADING", "FULL", "Loading Done"),
        ]
        assert [(b.state_to, b.reason) for b in bgp] == [("down", "BGP Notification sent"), ("up", None)]  # noqa: E501


def test_rebooted_switch_lines_use_collector_time_until_the_clock_is_set():
    events = [
        e for e in parse_file(SCENARIOS / "07_device_reload.log", year=2026) if e.host == "SW1"
    ]
    restart = next(i for i, e in enumerate(events) if e.event_key == "SYS-5-RESTART")
    booting = [e for e in events[restart:] if e.entities.extra.get("clock") == "unsynced"]

    assert len(booting) >= 20
    assert all(e.timestamp.year == 2026 and e.timestamp.month == 3 for e in booting)
    # The reload was requested a few minutes before the first boot message.
    assert timedelta(minutes=2) < events[restart].timestamp - events[restart - 1].timestamp
