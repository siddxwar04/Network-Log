"""Each built-in rule at its boundaries, and severity scoring."""

from datetime import UTC, datetime, timedelta

import pytest

from netlog.config import load_config
from netlog.detection.engine import detect
from netlog.detection.rules import LEVELS, RuleError, load_rules, parse_rules
from netlog.ingestion.reader import RawLine
from netlog.parsers.pipeline import LineParser
from netlog.storage.database import Database

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


def link(offset, state, host="R1", interface="GigabitEthernet0/1"):
    return cisco(offset, host, f"%LINK-3-UPDOWN: Interface {interface}, changed state to {state}")


def bgp(offset, state, host="R2", neighbor="10.255.0.1", reason="BGP Notification sent"):
    tail = f"Down {reason}" if state == "down" else "Up"
    return cisco(offset, host, f"%BGP-5-ADJCHANGE: neighbor {neighbor} {tail}")


def ospf(offset, frm, to, detail, host="R2", neighbor="10.255.0.1"):
    body = f"%OSPF-5-ADJCHG: Process 1, Nbr {neighbor} on GigabitEthernet0/1 from {frm} to {to}, {detail}"  # noqa: E501
    return cisco(offset, host, body)


def run(db, lines, config=None, rules=None):
    parser = LineParser(year=2026)
    upload = db.create_upload("test.log")
    db.add_events(upload, [parser.parse(RawLine(n, line)) for n, line in enumerate(lines, 1)])
    return detect(db, upload, rules, config)


def only(findings, rule):
    return [f for f in findings if f.rule == rule]


# --- Interface down ----------------------------------------------------------------------


def test_interface_down_longer_than_the_limit_is_a_finding(db):
    assert only(run(db, [link(0, "down"), link(30, "up")]), "interface_down") == []

    (finding,) = only(run(db, [link(0, "down"), link(31, "up")]), "interface_down")
    assert finding.group == {"host": "R1", "interface": "GigabitEthernet0/1"}
    assert finding.metrics["outage_seconds"] == 31.0
    assert finding.title == "Interface GigabitEthernet0/1 on R1 was down for 31s"
    assert (finding.start, finding.end) == (START, START + timedelta(seconds=31))
    assert finding.flags == [] and len(finding.evidence) == 2


def test_interface_that_never_comes_back_lasts_until_the_end_of_the_log(db):
    (finding,) = only(run(db, [link(0, "down"), bgp(600, "up")]), "interface_down")

    assert finding.flags == ["not_recovered"]
    assert finding.end == START + timedelta(seconds=600)
    assert len(finding.evidence) == 1


def test_interface_shut_on_purpose_is_not_reported_as_down(db):
    body = "%LINK-5-CHANGED: Interface Gi0/1, changed state to administratively down"

    assert only(run(db, [cisco(0, "R1", body), link(900, "up")]), "interface_down") == []


def test_repeated_down_messages_are_one_outage_and_each_outage_is_separate(db):
    lines = [link(0, "down"), link(5, "down"), link(100, "up"), link(500, "down"), link(700, "up")]

    findings = only(run(db, lines), "interface_down")

    assert [f.metrics["outage_seconds"] for f in findings] == [100.0, 200.0]


def test_interface_down_is_tracked_per_interface_and_device(db):
    lines = [
        link(0, "down"),
        link(10, "up", interface="GigabitEthernet0/2"),  # another interface coming up
        link(20, "up", host="R2"),  # the same name on another device
        link(100, "up"),
    ]

    (finding,) = only(run(db, lines), "interface_down")
    assert finding.metrics["outage_seconds"] == 100.0


# --- BGP and OSPF ------------------------------------------------------------------------


def test_one_bgp_session_down_is_a_finding(db):
    notification = cisco(
        0, "R2", "%BGP-3-NOTIFICATION: sent to neighbor 10.255.0.1 4/0 (hold time expired) 0 bytes"
    )
    (finding,) = only(run(db, [bgp(0, "down"), notification]), "bgp_session_down")

    assert finding.group == {"host": "R2", "neighbor_ip": "10.255.0.1"}
    assert finding.title == "BGP session from R2 to 10.255.0.1 went down"
    assert finding.metrics["reason"] == "BGP Notification sent"
    assert finding.metrics["related_reason"] == "hold time expired"
    assert finding.metrics["related_error_meaning"].startswith("Hold timer expired")
    assert finding.flags == [] and finding.severity == "critical"
    assert len(finding.evidence) == 2


def test_bgp_recovery_is_noted_and_three_drops_are_flapping(db):
    drops = [bgp(0, "down"), bgp(30, "up"), bgp(60, "down"), bgp(90, "up"), bgp(120, "down")]
    once = run(db, [bgp(0, "down"), bgp(120, "up")])
    still_down = run(db, drops)
    up_again = run(db, [*drops, bgp(150, "up")])

    (finding,) = only(once, "bgp_session_down")
    assert finding.flags == ["recovered"] and finding.metrics["recovered_after_seconds"] == 120.0
    # Coming up between two drops is not a recovery; only being up after the last one is.
    (finding,) = only(still_down, "bgp_session_down")
    assert finding.metrics["count"] == 3 and finding.flags == ["flapping"]
    (finding,) = only(up_again, "bgp_session_down")
    assert finding.flags == ["flapping", "recovered"]


def test_bgp_sessions_are_tracked_per_device_and_neighbor(db):
    lines = [bgp(0, "down"), bgp(1, "down", neighbor="203.0.113.1"), bgp(2, "down", host="R3")]

    assert len(only(run(db, lines), "bgp_session_down")) == 3


def test_bgp_session_coming_up_alone_is_not_a_finding(db):
    assert run(db, [bgp(0, "up")]) == []


def test_ospf_neighbor_leaving_full_is_a_finding(db):
    lines = [
        ospf(0, "FULL", "DOWN", "Neighbor Down: Dead timer expired"),
        ospf(50, "LOADING", "FULL", "Loading Done"),
    ]

    (finding,) = only(run(db, lines), "ospf_adjacency_loss")

    assert finding.group == {"host": "R2", "neighbor_ip": "10.255.0.1"}
    assert finding.metrics["reason"] == "Dead timer expired"
    assert finding.metrics["interface"] == "GigabitEthernet0/1"
    assert finding.flags == ["recovered"] and finding.severity == "high"


@pytest.mark.parametrize(
    ("frm", "to", "expected"),
    [
        ("FULL", "DOWN", 1),
        ("FULL", "EXSTART", 1),  # dropped back to renegotiate
        ("FULL", "INIT", 1),
        ("LOADING", "FULL", 0),  # forming, not failing
        ("INIT", "DOWN", 0),  # never was established
        ("EXSTART", "DOWN", 0),
    ],
)
def test_only_leaving_full_counts_as_an_ospf_loss(db, frm, to, expected):
    findings = only(run(db, [ospf(0, frm, to, "detail")]), "ospf_adjacency_loss")

    assert len(findings) == expected


# --- DHCP --------------------------------------------------------------------------------


def no_lease(offset, mac_tail):
    moment = START + timedelta(seconds=offset)
    return (
        f"{stamp(moment)} dhcp1 dhcpd[811]: DHCPDISCOVER from 00:11:22:33:44:{mac_tail:02x} "
        "via eth1: network 10.20.0.0/24: no free leases"
    )


def test_dhcp_exhaustion_threshold(db):
    assert only(run(db, [no_lease(n * 10, n) for n in range(9)]), "dhcp_exhaustion") == []

    (finding,) = only(run(db, [no_lease(n * 10, n % 4) for n in range(10)]), "dhcp_exhaustion")
    assert finding.metrics["count"] == 10 and finding.metrics["distinct_mac"] == 4
    assert finding.severity == "high"


def test_a_few_refusals_spread_over_time_are_not_exhaustion(db):
    assert only(run(db, [no_lease(n * 60, n) for n in range(9)]), "dhcp_exhaustion") == []


# --- Config change -----------------------------------------------------------------------


def config(offset, user="jdoe", host="R2", ip="10.10.10.53"):
    return cisco(offset, host, f"%SYS-5-CONFIG_I: Configured from console by {user} on vty0 ({ip})")


def test_every_config_change_is_recorded_at_info(db):
    other_user, other_host = config(4001, user="netops"), config(4002, host="R3")
    lines = [config(0), config(60), config(4000), other_user, other_host]

    findings = only(run(db, lines), "config_change")

    # Two saves by one person a minute apart are one piece of work.
    assert [(f.host, f.group["username"], f.metrics["count"]) for f in findings] == [
        ("R2", "jdoe", 2),
        ("R2", "jdoe", 1),
        ("R2", "netops", 1),
        ("R3", "jdoe", 1),
    ]
    assert {f.severity for f in findings} == {"info"}
    assert findings[0].metrics["src_ip"] == "10.10.10.53"
    assert findings[0].title == "Configuration of R2 changed by jdoe"


# --- Device health -----------------------------------------------------------------------


def cpu(offset, process="BGP Router"):
    body = f"%SYS-3-CPUHOG: Task is running for (2004)msecs, more than (2000)msecs (1/0),process = {process}."  # noqa: E501
    return cisco(offset, "R1", body)


def test_cpu_hog_threshold(db):
    assert only(run(db, [cpu(0), cpu(60)]), "cpu_hog") == []
    assert only(run(db, [cpu(0), cpu(200), cpu(400)]), "cpu_hog") == []  # too spread out

    (finding,) = only(run(db, [cpu(0), cpu(60), cpu(120)]), "cpu_hog")
    assert finding.incident_type == "resource_exhaustion" and finding.severity == "high"
    assert finding.metrics["process"] == "BGP Router"


def test_one_memory_allocation_failure_is_a_finding(db):
    body = "%SYS-2-MALLOCFAIL: Memory allocation of 65536 bytes failed from 0x60103098, alignment 0"

    (finding,) = only(run(db, [cisco(0, "R1", body)]), "memory_allocation_failure")

    assert finding.incident_type == "resource_exhaustion" and finding.severity == "high"
    assert finding.metrics["bytes"] == "65536"


def test_reload_and_restart(db):
    reload = cisco(0, "SW1", "%SYS-5-RELOAD: Reload requested by netops on vty0 (10.10.10.50). Reload Reason: Reload Command.")  # noqa: E501
    restart = cisco(200, "SW1", "%SYS-5-RESTART: System restarted -- Cisco IOS Software")

    requested = run(db, [reload, restart])
    crashed = run(db, [restart])

    assert [(f.rule, f.severity) for f in requested] == [
        ("device_reload", "high"),
        ("device_restart", "critical"),
    ]
    assert requested[0].metrics["username"] == "netops"
    # A restart with no request before it is still found: the device crashed or lost power.
    assert [(f.rule, f.severity) for f in crashed] == [("device_restart", "critical")]
    assert {f.incident_type for f in requested} == {"device_reload"}


def mac_flap(offset, mac="0011.2233.4455", vlan=10):
    body = f"%SW_MATM-4-MACFLAP_NOTIF: Host {mac} in vlan {vlan} is flapping between port Gi0/1 and port Gi0/2"  # noqa: E501
    return cisco(offset, "SW1", body)


def test_mac_flapping_threshold(db):
    assert only(run(db, [mac_flap(0), mac_flap(10)]), "mac_flapping") == []
    assert only(run(db, [mac_flap(0), mac_flap(10), mac_flap(20, vlan=20)]), "mac_flapping") == []

    (finding,) = only(run(db, [mac_flap(0), mac_flap(10), mac_flap(20, mac="aabb.cc00.0100")]), "mac_flapping")  # noqa: E501
    assert finding.group == {"host": "SW1", "vlan": 10}
    assert finding.metrics["distinct_mac"] == 2
    assert finding.metrics["second_interface"] == "GigabitEthernet0/2"
    assert finding.title == "MAC addresses flapping between ports on SW1 in VLAN 10 (3 warnings)"
    assert finding.severity == "high"


# --- Severity ----------------------------------------------------------------------------


def flap_lines(count):
    lines = []
    for n in range(count):
        lines += [link(n * 20, "down"), link(n * 20 + 5, "up")]
    return lines


def test_every_built_in_rule_has_a_level_and_a_reason():
    for rule in load_rules():
        assert rule.severity in LEVELS, rule.name
        assert rule.severity_because, rule.name
        assert rule.description, rule.name


def test_base_levels():
    levels = {rule.name: rule.severity for rule in load_rules()}

    assert levels == {
        "link_flap": "medium",
        "interface_down": "info",
        "bgp_session_down": "critical",
        "ospf_adjacency_loss": "high",
        "dhcp_exhaustion": "high",
        "config_change": "info",
        "brute_force_login": "medium",
        "cpu_hog": "high",
        "memory_allocation_failure": "high",
        "device_reload": "high",
        "device_restart": "critical",
        "mac_flapping": "high",
    }


def test_strength_raises_a_link_flap_from_medium_to_high(db):
    (mild,) = only(run(db, flap_lines(5)), "link_flap")
    (strong,) = only(run(db, flap_lines(10)), "link_flap")

    assert (mild.strength, mild.severity) == (0.25, "medium")
    assert mild.severity_reason == (
        "Medium: a flapping interface repeatedly interrupts whatever is connected through it; "
        "no critical interfaces are configured, so its importance is not known."
    )
    assert (strong.strength, strong.severity) == (0.5, "high")
    assert "raised from medium because it went down at least twice" in strong.severity_reason


def failed_logins(count):
    return [
        f"{stamp(START + timedelta(seconds=n * 5))} srv1 sshd[7]: "
        f"Failed password for root from 192.0.2.77 port 4000 ssh2"
        for n in range(count)
    ]


def test_a_successful_login_raises_a_brute_force_to_critical(db):
    accepted = (
        f"{stamp(START + timedelta(seconds=300))} srv1 sshd[8]: "
        "Accepted password for deploy from 192.0.2.77 port 4001 ssh2"
    )

    (failed_only,) = only(run(db, failed_logins(40)), "brute_force_login")
    (succeeded,) = only(run(db, failed_logins(40) + [accepted]), "brute_force_login")

    # However many attempts there are, guessing that fails stays at medium.
    assert failed_only.severity == "medium"
    assert failed_only.severity_reason == "Medium: password guessing is common and usually fails."
    assert succeeded.severity == "critical"
    assert "a login from the same address succeeded afterwards" in succeeded.severity_reason


def test_a_critical_interface_raises_the_level_by_one(db):
    settings = load_config()
    settings["severity"]["critical_interfaces"] = [
        {"host": "R1", "interface": "GigabitEthernet0/1"}
    ]
    lines = [link(0, "down"), link(600, "up")]

    (unlisted,) = only(run(db, lines), "interface_down")
    (listed,) = only(run(db, lines, settings), "interface_down")

    assert unlisted.severity == "info"
    assert "no critical interfaces are configured" in unlisted.severity_reason
    assert listed.severity == "low"
    assert listed.severity_reason.endswith(
        "raised one level because GigabitEthernet0/1 on R1 is listed as a critical interface."
    )


def test_a_critical_device_raises_the_level_by_one_but_never_past_critical(db):
    settings = load_config()
    settings["severity"]["critical_devices"] = ["R2"]

    (ospf_loss,) = only(run(db, [ospf(0, "FULL", "DOWN", "x")], settings), "ospf_adjacency_loss")
    (bgp_drop,) = only(run(db, [bgp(0, "down")], settings), "bgp_session_down")

    assert ospf_loss.severity == "critical"
    assert "raised one level because R2 is listed as a critical device" in ospf_loss.severity_reason
    assert bgp_drop.severity == "critical"
    assert "raised" not in bgp_drop.severity_reason


def test_the_most_serious_condition_wins():
    rules = parse_rules(
        """
        [[rule]]
        name = "r"
        incident_type = "t"
        kind = "threshold"
        title = "{count}"
        event_keys = ["LINK-3-UPDOWN"]
        group_by = ["host"]
        window_seconds = 300
        threshold = 1
        severity = "low"
        severity_when = [
            { strength_at_least = 0.2, level = "medium", because = "first" },
            { strength_at_least = 0.2, level = "critical", because = "second" },
            { strength_at_least = 0.9, level = "high", because = "third" },
        ]
        """
    )
    assert rules[0].severity_when[1].level == "critical"


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ('severity = "urgent"', "severity is 'urgent'; it must be one of: info, low, medium"),
        (
            'severity_when = [{ level = "high", because = "x" }]',
            "severity_when.flag or strength_at_least must be given",
        ),
        (
            'severity_when = [{ flag = "nope", level = "high", because = "x" }]',
            "severity_when.flag is 'nope', which this rule never sets",
        ),
        (
            'severity_when = [{ strength_at_least = 0.5, level = "high" }]',
            "severity_when.because must be a non-empty text value",
        ),
        ('capture = ["colour"]', "capture names 'colour', which is not a field"),
    ],
)
def test_mistakes_in_severity_settings_are_reported(line, message):
    rule = f"""
    [[rule]]
    name = "r"
    incident_type = "t"
    kind = "threshold"
    title = "{{count}}"
    event_keys = ["X"]
    group_by = ["host"]
    window_seconds = 300
    threshold = 1
    {line}
    """

    with pytest.raises(RuleError) as error:
        parse_rules(rule)

    assert f"rule 'r': {message}" in str(error.value)
