import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from netlog.config import load_config
from netlog.correlation.grouping import correlate
from netlog.correlation.topology import (
    Topology,
    TopologyError,
    build_topology,
    infer_owners,
    load_topology,
)
from netlog.detection.engine import detect
from netlog.ingestion.ingest import ingest_file
from netlog.ingestion.reader import RawLine
from netlog.parsers.pipeline import LineParser
from netlog.storage.database import Database

SCENARIOS = Path("data/scenarios")
HINTS = SCENARIOS / "topology.toml"
START = datetime(2026, 3, 3, 2, 0, 0, tzinfo=UTC)
ATTACKER = "192.0.2.77"


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


def bgp(offset, state, host, neighbor):
    tail = "Down BGP Notification sent" if state == "down" else "Up"
    return cisco(offset, host, f"%BGP-5-ADJCHANGE: neighbor {neighbor} {tail}")


def ospf(offset, state, host, neighbor, interface="GigabitEthernet0/1"):
    change = (
        "from FULL to DOWN, Neighbor Down: Dead timer expired"
        if state == "down"
        else "from LOADING to FULL, Loading Done"
    )
    return cisco(offset, host, f"%OSPF-5-ADJCHG: Process 1, Nbr {neighbor} on {interface} {change}")


def config(offset, host="R2", user="jdoe", ip="10.10.10.53"):
    return cisco(offset, host, f"%SYS-5-CONFIG_I: Configured from console by {user} on vty0 ({ip})")


def failed(offset, ip=ATTACKER, host="srv1"):
    moment = START + timedelta(seconds=offset)
    return f"{stamp(moment)} {host} sshd[7]: Failed password for root from {ip} port 4000 ssh2"


def brute(start, ip=ATTACKER, host="srv1", count=25):
    return [failed(start + n * 2, ip, host) for n in range(count)]


def flap(start, host="SW2", interface="GigabitEthernet0/5", count=6):
    lines = []
    for n in range(count):
        lines += [link(start + n * 10, "down", host, interface), link(start + n * 10 + 4, "up", host, interface)]  # noqa: E501
    return lines


def run(db, lines, hints=None, config=None):
    parser = LineParser(year=2026)
    upload = db.create_upload("test.log")
    ordered = sorted(lines, key=lambda line: line[:15])
    db.add_events(upload, [parser.parse(RawLine(n, line)) for n, line in enumerate(ordered, 1)])
    detect(db, upload)
    return upload, correlate(db, upload, config, hints)


def scenario(db, name, hints=None):
    upload = ingest_file(db, SCENARIOS / f"{name}.log", year=2026)
    detect(db, upload)
    labels = json.loads((SCENARIOS / f"{name}.labels.json").read_text(encoding="utf-8"))
    return upload, correlate(db, upload, hints=hints), labels["incidents"]


def rules_in(db, upload, ids):
    by_id = {f.id: f for f in db.findings(upload)}
    return sorted(by_id[i].rule for i in ids)


def label_time(text):
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


# --- Scenarios ---------------------------------------------------------------------------


@pytest.mark.parametrize("hints", [None, HINTS], ids=["logs only", "with topology file"])
def test_cascade_becomes_exactly_one_incident(db, hints):
    upload, incidents, (label,) = scenario(db, "02_cascade", hints and load_topology(hints))

    (incident,) = incidents
    assert incident.devices == label["devices"] == ["R1", "R2", "R3", "R4"]
    assert incident.severity == label["expected_severity"] == "critical"
    assert rules_in(db, upload, incident.finding_ids) == ["bgp_session_down"] * 6 + [
        "ospf_adjacency_loss"
    ] * 6
    # The interface that failed is attached as context: it is the likely cause.
    assert rules_in(db, upload, incident.context_ids) == ["interface_down"]
    (cause,) = [f for f in db.findings(upload) if f.id in incident.context_ids]
    assert (cause.host, cause.group["interface"]) == ("R1", "GigabitEthernet0/1")
    # The incident covers the failure; recovery messages come later.
    assert abs(incident.start - label_time(label["start"])) < timedelta(seconds=3)
    assert incident.end < label_time(label["end"])
    assert "with 11 related findings on R1, R2, R3, R4" in incident.title


def test_cascade_connections_can_be_explained(db):
    upload, (incident,), _ = scenario(db, "02_cascade")

    reasons = {link.reason for link in incident.links}
    assert "both on R1" in reasons
    assert "both lost the neighbor 10.255.0.1" in reasons
    assert "R2's neighbor 10.255.0.1 is R1 (inferred from the logs)" in reasons
    assert "same device and interface as a finding on R1" in reasons
    # Every finding in the incident is reached by at least one connection.
    linked = {i for link in incident.links for i in (link.a, link.b)}
    assert set(incident.finding_ids) | set(incident.context_ids) <= linked
    # From the logs alone, R1's own neighbors cannot be told apart.
    assert incident.notes == [
        "Neighbor addresses not matched to a device in these logs: 10.255.0.2, 10.255.0.3, "
        "10.255.0.4. List them in a topology file to say which device each one is."
    ]


def test_a_topology_file_settles_what_the_logs_cannot(db):
    upload, (incident,), _ = scenario(db, "02_cascade", load_topology(HINTS))

    assert incident.notes == []
    assert "R1's neighbor 10.255.0.2 is R2 (known)" in {link.reason for link in incident.links}


def test_overlap_stays_two_incidents(db):
    upload, incidents, labels = scenario(db, "10_overlap")

    assert len(incidents) == len(labels) == 2
    by_device = {tuple(i.devices): i for i in incidents}
    flap_incident, brute_incident = by_device[("SW2",)], by_device[("srv1",)]
    assert rules_in(db, upload, flap_incident.finding_ids) == ["link_flap"]
    assert rules_in(db, upload, brute_incident.finding_ids) == ["brute_force_login"]
    assert (flap_incident.severity, brute_incident.severity) == ("high", "medium")
    # They overlap in time and are still separate.
    assert flap_incident.start < brute_incident.end and brute_incident.start < flap_incident.end


@pytest.mark.parametrize(
    ("name", "rules", "devices"),
    [
        ("01_link_flap", ["link_flap"], ["R1"]),
        ("04_brute_force", ["brute_force_login"], ["srv1"]),
        ("05_dhcp_exhaustion", ["dhcp_exhaustion"], ["dhcp1"]),
    ],
)
def test_single_problem_scenarios_give_one_incident(db, name, rules, devices):
    upload, incidents, (label,) = scenario(db, name)

    (incident,) = incidents
    assert rules_in(db, upload, incident.finding_ids) == rules
    assert incident.devices == devices == label["devices"]
    assert incident.severity == label["expected_severity"]
    assert incident.context_ids == [] and incident.notes == []
    assert incident.title == db.findings(upload)[0].title or len(incident.finding_ids) == 1


@pytest.mark.parametrize("name", ["08_noise", "08_noise_50k"])
def test_noise_gives_no_incidents(db, name):
    upload, incidents, labels = scenario(db, name)

    assert incidents == [] and labels == []
    assert db.findings(upload)  # the routine findings exist; none of them is an incident


def test_config_change_is_attached_to_the_bgp_drop_that_followed(db):
    upload, incidents, (label,) = scenario(db, "03_config_bgp")

    (incident,) = incidents
    assert rules_in(db, upload, incident.finding_ids) == ["bgp_session_down"]
    changes = [f for f in db.findings(upload) if f.id in incident.context_ids]
    assert changes and {f.rule for f in changes} == {"config_change"}
    assert label["facts"]["changed_by"] in {f.group["username"] for f in changes}
    assert incident.devices == ["R2"]
    assert incident.severity == "critical"
    reasons = {link.reason for link in incident.links}
    assert "configuration of R2 changed shortly before or during" in reasons
    # The ISP's router is outside the network, so nothing in the logs identifies it.
    assert "203.0.113.1" in incident.notes[0]


def test_reload_without_a_topology_file_does_not_guess_the_neighbor(db):
    upload, incidents, _ = scenario(db, "07_device_reload")

    (incident,) = incidents
    assert rules_in(db, upload, incident.finding_ids) == ["device_reload", "device_restart"]
    # R3's link to the switch went down at that moment, but nothing in the logs says the
    # two are connected, so it is left out.
    assert incident.devices == ["SW1"]
    assert incident.severity == "critical"


def test_reload_with_a_topology_file_includes_the_neighbor(db):
    upload, incidents, (label,) = scenario(db, "07_device_reload", load_topology(HINTS))

    (incident,) = incidents
    assert sorted(incident.devices) == sorted(label["devices"]) == ["R3", "SW1"]
    link_down = [f for f in db.findings(upload) if f.id in incident.context_ids and f.host == "R3"]
    assert [f.group["interface"] for f in link_down] == ["GigabitEthernet0/3"]
    assert "GigabitEthernet0/3 on R3 is connected to GigabitEthernet0/1 on SW1" in {
        link.reason for link in incident.links
    }


# --- Time and connection -----------------------------------------------------------------


def test_identical_failures_an_hour_apart_are_two_incidents(db):
    _, incidents = run(db, flap(0) + flap(3600))

    assert len(incidents) == 2
    assert incidents[1].start - incidents[0].end > timedelta(minutes=50)


def test_the_same_kind_of_problem_on_one_device_is_joined_across_a_longer_gap(db):
    reload = "%SYS-5-RELOAD: Reload requested by netops on vty0 (10.10.10.50). Reload Reason: Reload Command."  # noqa: E501
    restart = "%SYS-5-RESTART: System restarted -- Cisco IOS Software"

    def incidents_for(seconds_until_restart):
        lines = [cisco(0, "SW1", reload), cisco(seconds_until_restart, "SW1", restart)]
        return run(db, lines)[1]

    # A reload and the restart four minutes later are one event...
    assert len(incidents_for(240)) == 1
    # ...but a restart half an hour after a reload request is something else.
    assert len(incidents_for(1800)) == 2


def test_unrelated_failures_in_the_same_second_are_two_incidents(db):
    _, incidents = run(db, flap(0, host="SW1") + flap(0, host="SW2"))

    assert sorted(i.devices for i in incidents) == [["SW1"], ["SW2"]]


def test_two_problems_on_one_device_close_together_are_one_incident(db):
    lines = flap(0, host="R1", interface="GigabitEthernet0/2")
    lines.append(bgp(70, "down", "R1", "198.51.100.1"))

    upload, (incident,) = run(db, lines)

    assert rules_in(db, upload, incident.finding_ids) == ["bgp_session_down", "link_flap"]
    assert incident.links[0].reason == "both on R1"
    assert incident.severity == "critical"


def test_an_attack_and_a_fault_on_the_same_device_stay_apart(db):
    lines = brute(0, host="R1") + flap(0, host="R1", interface="GigabitEthernet0/2")

    upload, incidents = run(db, lines)

    assert sorted(rules_in(db, upload, i.finding_ids) for i in incidents) == [
        ["brute_force_login"],
        ["link_flap"],
    ]


def test_two_attackers_at_once_are_two_incidents(db):
    _, incidents = run(db, brute(0) + brute(1, ip="198.51.100.9"))

    assert len(incidents) == 2


def test_findings_chain_through_a_shared_neighbor(db):
    # R2 and R3 both lose 10.255.0.1, 40 seconds apart. Nothing else is known.
    lines = [ospf(0, "down", "R2", "10.255.0.1"), ospf(40, "down", "R3", "10.255.0.1")]

    upload, (incident,) = run(db, lines)

    assert incident.devices == ["R2", "R3"]
    assert incident.links[0].reason == "both lost the neighbor 10.255.0.1"


def test_different_neighbors_on_different_devices_are_not_connected_without_knowledge(db):
    lines = [ospf(0, "down", "R2", "10.255.0.1"), ospf(5, "down", "R3", "10.255.0.9")]

    _, incidents = run(db, lines)

    assert len(incidents) == 2
    assert "10.255.0.1" in incidents[0].notes[0] or "10.255.0.1" in incidents[1].notes[0]


def test_clocks_three_seconds_apart_still_correlate_and_five_minutes_apart_do_not(db):
    near = [ospf(0, "down", "R2", "10.255.0.1"), ospf(63, "down", "R3", "10.255.0.1")]
    far = [ospf(0, "down", "R2", "10.255.0.1"), ospf(300, "down", "R3", "10.255.0.1")]

    assert len(run(db, near)[1]) == 1  # 60 second gap plus 5 seconds for clock skew
    assert len(run(db, far)[1]) == 2


def test_many_devices_raise_the_severity_one_level(db):
    two = [ospf(n, "down", host, "10.255.0.1") for n, host in enumerate(("R2", "R3"))]
    three = [ospf(n, "down", host, "10.255.0.1") for n, host in enumerate(("R2", "R3", "R4"))]

    (small,), (large,) = run(db, two)[1], run(db, three)[1]

    assert small.severity == "high"
    assert small.severity_reason.startswith('High: the most serious finding is "OSPF adjacency')
    assert large.severity == "critical"
    assert "raised from high because 3 devices are affected" in large.severity_reason


# --- Context -----------------------------------------------------------------------------


def test_config_change_long_before_or_on_another_device_is_not_attached(db):
    drop = [bgp(1000, "down", "R2", "203.0.113.1")]

    def attached(extra):
        upload, (incident,) = run(db, drop + extra)
        return rules_in(db, upload, incident.context_ids)

    assert attached([config(900)]) == ["config_change"]  # 100 seconds before
    assert attached([config(600)]) == []  # more than five minutes before
    assert attached([config(900, host="R3")]) == []  # another device
    assert attached([config(1100)]) == []  # after the failure had already started


def test_routine_findings_alone_never_make_an_incident(db):
    lines = [config(0), config(10, host="R3"), link(20, "down", "SW1"), link(600, "up", "SW1")]

    upload, incidents = run(db, lines)

    assert incidents == []
    assert {f.severity for f in db.findings(upload)} == {"info"}


def test_routine_findings_do_not_bridge_two_problems(db):
    # A flap on R1 and one on R3, with config changes on both in between.
    lines = flap(0, host="R1") + flap(30, host="R3")
    lines += [config(10, host="R1"), config(12, host="R3")]

    _, incidents = run(db, lines)

    assert sorted(i.devices for i in incidents) == [["R1"], ["R3"]]


def test_an_unrelated_port_going_down_on_the_same_device_is_not_attached(db):
    lines = [
        ospf(100, "down", "R1", "10.255.0.2", interface="GigabitEthernet0/1"),
        link(98, "down", "R1", "GigabitEthernet0/1"),
        link(700, "up", "R1", "GigabitEthernet0/1"),
        link(99, "down", "R1", "GigabitEthernet0/9"),  # another port, same moment
        link(700, "up", "R1", "GigabitEthernet0/9"),
    ]

    upload, (incident,) = run(db, lines)

    attached = [f for f in db.findings(upload) if f.id in incident.context_ids]
    assert [f.group["interface"] for f in attached] == ["GigabitEthernet0/1"]


def test_config_change_from_the_attackers_address_is_attached_to_the_attack(db):
    lines = brute(0) + [config(120, host="R2", user="deploy", ip=ATTACKER), config(125, host="R3")]

    upload, (incident,) = run(db, lines)

    changes = [f for f in db.findings(upload) if f.id in incident.context_ids]
    assert [(f.host, f.metrics["src_ip"]) for f in changes] == [("R2", ATTACKER)]


# --- Identity and storage ----------------------------------------------------------------


def test_the_same_input_gives_the_same_incident_ids(tmp_path):
    ids = []
    for name in ("a.db", "b.db"):
        with Database(tmp_path / name) as database:
            _, incidents, _ = scenario(database, "10_overlap")
            ids.append([i.id for i in incidents])

    assert ids[0] == ids[1]
    assert all(i.startswith("inc-") and len(i) == 14 for i in ids[0])
    assert len(set(ids[0])) == 2


def test_incidents_are_stored_replaced_and_deleted_with_the_upload(db):
    upload, first, _ = scenario(db, "02_cascade")

    again = correlate(db, upload)

    assert [i.id for i in again] == [i.id for i in first]
    assert db.get_incident(upload, first[0].id).title == first[0].title
    assert db.get_incident(upload, "inc-missing") is None
    assert db.incidents(upload)[0].upload_id == upload
    db.delete_upload(upload)
    assert db.incidents(upload) == []


# --- Topology ----------------------------------------------------------------------------


def test_owner_is_inferred_when_two_routers_report_each_other(db):
    lines = [
        ospf(0, "down", "R1", "10.255.0.2"), ospf(1, "down", "R2", "10.255.0.1"),
        ospf(60, "up", "R1", "10.255.0.2"), ospf(60, "up", "R2", "10.255.0.1"),
    ]  # fmt: skip
    upload, (incident,) = run(db, lines)

    owners = infer_owners(db, upload, tolerance_seconds=5, min_support=0.5)

    assert owners == {"10.255.0.1": "R1", "10.255.0.2": "R2"}
    assert incident.devices == ["R1", "R2"] and incident.notes == []
    assert incident.links[0].reason == "R1's neighbor 10.255.0.2 is R2 (inferred from the logs)"


def test_owner_is_not_inferred_from_a_single_coincidence(db):
    lines = [ospf(0, "down", "R1", "10.255.0.2"), ospf(1, "down", "R2", "10.255.0.1")]
    upload, incidents = run(db, lines)

    assert infer_owners(db, upload, 5, 0.5) == {}
    assert len(incidents) == 2  # nothing connects them, so nothing is guessed


def test_owner_is_not_inferred_when_several_devices_fit(db):
    lines = []
    for at in (0, 60):
        state = "down" if at == 0 else "up"
        lines += [ospf(at, state, "R1", "10.255.0.9"), ospf(at, state, "R2", "10.255.0.8"),
                  ospf(at, state, "R3", "10.255.0.7")]  # fmt: skip
    upload, _ = run(db, lines)

    assert infer_owners(db, upload, 5, 0.5) == {}


def test_what_the_user_states_wins_over_what_is_inferred(db):
    lines = [
        ospf(0, "down", "R1", "10.255.0.2"), ospf(1, "down", "R2", "10.255.0.1"),
        ospf(60, "up", "R1", "10.255.0.2"), ospf(60, "up", "R2", "10.255.0.1"),
    ]  # fmt: skip
    upload, _ = run(db, lines)
    hints = Topology(owners={"10.255.0.2": "CORE-B"})

    topology = build_topology(db, upload, load_config()["correlation"], hints)

    assert topology.owner("10.255.0.2") == "CORE-B" and "10.255.0.2" not in topology.inferred
    assert topology.owner("10.255.0.1") == "R1" and "10.255.0.1" in topology.inferred


def test_topology_file_is_read(tmp_path):
    topology = load_topology(HINTS)

    assert topology.owner("10.255.0.3") == "R3" and topology.owner("203.0.113.1") is None
    assert topology.peer("R3", "GigabitEthernet0/3") == ("SW1", "GigabitEthernet0/1")
    assert topology.peer("SW1", "GigabitEthernet0/1") == ("R3", "GigabitEthernet0/3")
    assert topology.peer("R3", "GigabitEthernet0/9") is None

    short = tmp_path / "short.toml"
    ends = 'a = { host = "A", interface = "Gi0/1" }\nb = { host = "B", interface = "Te1/1" }\n'
    short.write_text("[[link]]\n" + ends)
    assert load_topology(short).peer("A", "GigabitEthernet0/1") == ("B", "TenGigabitEthernet1/1")


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("[[device]\n", "is not valid TOML"),
        ('[[device]]\naddresses = ["10.0.0.1"]\n', "device 1 has no name"),
        ('[[device]]\nname = "A"\naddresses = "10.0.0.1"\n', "addresses of A must be a list"),
        (
            '[[device]]\nname = "A"\naddresses = ["10.0.0.1"]\n'
            '[[device]]\nname = "B"\naddresses = ["10.0.0.1"]\n',
            "10.0.0.1 is listed for both A and B",
        ),
        ('[[link]]\na = { host = "A" }\nb = { host = "B", interface = "x" }\n', "link 1 needs a ="),
    ],
)
def test_mistakes_in_a_topology_file_are_reported(tmp_path, content, message):
    path = tmp_path / "topology.toml"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(TopologyError, match=message):
        load_topology(path)


def test_missing_topology_file_is_reported(tmp_path):
    with pytest.raises(TopologyError, match="topology file not found"):
        load_topology(tmp_path / "none.toml")
