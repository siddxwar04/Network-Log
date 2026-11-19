import json
import re
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from netlog.correlation.grouping import correlate
from netlog.correlation.priors import PriorError, load_priors, parse_priors
from netlog.correlation.topology import Topology, load_topology
from netlog.detection.engine import detect
from netlog.ingestion.ingest import ingest_file
from netlog.ingestion.reader import RawLine
from netlog.parsers.pipeline import LineParser
from netlog.storage.database import _MIGRATIONS, SCHEMA_VERSION, Database

SCENARIOS = Path("data/scenarios")
HINTS = SCENARIOS / "topology.toml"
START = datetime(2026, 3, 3, 2, 0, 0, tzinfo=UTC)
ATTACKER = "192.0.2.77"
# The label files call a single failed link "link_failure"; the rule is `interface_down`.
LABEL_KINDS = {"link_failure": "interface_down", "brute_force": "brute_force_login"}


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


def outage(start, host="R1", interface="GigabitEthernet0/1", seconds=600):
    return [link(start, "down", host, interface), link(start + seconds, "up", host, interface)]


def bgp(offset, host, neighbor, state="down"):
    tail = "Down BGP Notification sent" if state == "down" else "Up"
    return cisco(offset, host, f"%BGP-5-ADJCHANGE: neighbor {neighbor} {tail}")


def ospf(offset, host, neighbor, interface="GigabitEthernet0/1", reason="Dead timer expired"):
    body = (
        f"%OSPF-5-ADJCHG: Process 1, Nbr {neighbor} on {interface} from FULL to DOWN, "
        f"Neighbor Down: {reason}"
    )
    return cisco(offset, host, body)


def config(offset, host="R2", user="jdoe", ip="10.10.10.53"):
    return cisco(offset, host, f"%SYS-5-CONFIG_I: Configured from console by {user} on vty0 ({ip})")


def run(db, lines, hints=None):
    parser = LineParser(year=2026)
    upload = db.create_upload("test.log")
    ordered = sorted(lines, key=lambda line: line[:15])
    db.add_events(upload, [parser.parse(RawLine(n, line)) for n, line in enumerate(ordered, 1)])
    detect(db, upload)
    return upload, correlate(db, upload, hints=hints)


def scenario(db, name, hints=None):
    upload = ingest_file(db, SCENARIOS / f"{name}.log", year=2026)
    detect(db, upload)
    labels = json.loads((SCENARIOS / f"{name}.labels.json").read_text(encoding="utf-8"))
    return upload, correlate(db, upload, hints=hints), labels["incidents"]


def steps(db, upload, incident):
    """The chain as readable (cause rule on host, effect rule on host, prior) triples."""
    by_id = {f.id: f for f in db.findings(upload)}
    return [
        (f"{by_id[s.cause].rule}@{by_id[s.cause].host}", f"{by_id[s.effect].rule}@{by_id[s.effect].host}", s.prior)  # noqa: E501
        for s in incident.chain
    ]


def assert_matches_label(incident, label):
    root, expected = incident.root_cause, label["root_cause"]
    assert root.kind == LABEL_KINDS.get(expected["kind"], expected["kind"])
    assert root.devices == [expected["device"]]
    assert root.entity == expected["entity"]


# --- Scenarios ---------------------------------------------------------------------------


@pytest.mark.parametrize("hints", [None, HINTS], ids=["logs only", "with topology file"])
def test_cascade_root_cause_is_the_failed_interface_with_high_confidence(db, hints):
    upload, (incident,), (label,) = scenario(db, "02_cascade", hints and load_topology(hints))

    assert_matches_label(incident, label)
    root = incident.root_cause
    assert root.summary.startswith("Interface GigabitEthernet0/1 on R1 was down for")
    assert root.explains == 12 and incident.alternatives == []
    assert incident.confidence == "high"
    assert incident.confidence_reason == (
        "every finding is accounted for, the timing matches how the protocols behave, "
        "and 4 devices report it"
    )
    assert incident.unknowns[0].startswith("Why the interface went down.")


def test_cascade_chain_runs_link_then_ospf_then_bgp(db):
    upload, (incident,), _ = scenario(db, "02_cascade")

    chain = steps(db, upload, incident)
    assert len(chain) == 12  # every finding has exactly one cause

    # On R1 itself: the interface dropped OSPF at once, and BGP followed OSPF.
    on_r1 = [step for step in chain if step[1].endswith("@R1")]
    assert on_r1.count(
        ("interface_down@R1", "ospf_adjacency_loss@R1", "interface_down_drops_ospf_on_it")
    ) == 3
    assert on_r1.count(
        ("ospf_adjacency_loss@R1", "bgp_session_down@R1", "ospf_loss_drops_bgp_on_same_device")
    ) == 3

    # On the other routers: both protocols timed out on R1 going quiet.
    for peer in ("R2", "R3", "R4"):
        assert ("interface_down@R1", f"ospf_adjacency_loss@{peer}",
                "interface_down_silences_router_for_ospf_neighbors") in chain  # fmt: skip
        assert ("interface_down@R1", f"bgp_session_down@{peer}",
                "interface_down_silences_router_for_bgp_neighbors") in chain  # fmt: skip

    by_id = {f.id: f for f in db.findings(upload)}
    for step in incident.chain:
        cause, effect = by_id[step.cause], by_id[step.effect]
        # R1's BGP session to a neighbor follows R1's OSPF loss of that same neighbor.
        if step.prior == "ospf_loss_drops_bgp_on_same_device":
            assert cause.group["neighbor_ip"] == effect.group["neighbor_ip"]
        if step.prior == "interface_down_silences_router_for_ospf_neighbors":
            assert 25 < step.delay_seconds < 45  # the 40-second dead timer
        if step.prior == "interface_down_drops_ospf_on_it":
            assert step.delay_seconds < 1 and step.certainty == "direct"
        assert step.explanation


def test_config_change_is_the_leading_suspect_with_medium_confidence(db):
    upload, (incident,), (label,) = scenario(db, "03_config_bgp")

    assert_matches_label(incident, label)
    root = incident.root_cause
    assert root.summary == (
        "The configuration of R2 was changed by jdoe from 10.10.10.53 shortly before the failure"
    )
    assert steps(db, upload, incident) == [
        ("config_change@R2", "bgp_session_down@R2", "config_change_before_routing_failure")
    ]
    assert incident.chain[0].certainty == "suspect"
    assert 15 < incident.chain[0].delay_seconds < 30
    assert incident.confidence == "medium"
    assert "the logs do not show what was changed" in incident.confidence_reason
    assert re.fullmatch(
        r"Whether the change caused the failure\. The logs show only that jdoe changed the "
        r"configuration of R2 \d\ds before, not what was changed\.",
        incident.unknowns[0],
    )


def test_reload_is_the_root_and_the_neighbor_link_an_effect(db):
    upload, (incident,), (label,) = scenario(db, "07_device_reload", load_topology(HINTS))

    assert_matches_label(incident, label)
    assert incident.root_cause.summary == "Reload of SW1 was requested"
    assert sorted(steps(db, upload, incident)) == [
        ("device_reload@SW1", "device_restart@SW1", "reload_request_restarts_device"),
        ("device_reload@SW1", "interface_down@R3", "reload_takes_down_connected_links"),
    ]
    assert incident.confidence == "high"
    assert "2 devices report it" in incident.confidence_reason


def test_reload_without_a_topology_file_rests_on_one_device(db):
    upload, (incident,), _ = scenario(db, "07_device_reload")

    assert incident.root_cause.kind == "device_reload"
    assert incident.confidence == "medium"
    assert incident.confidence_reason == "the whole chain rests on what one device logged"


@pytest.mark.parametrize("name", ["01_link_flap", "04_brute_force", "05_dhcp_exhaustion"])
def test_a_single_finding_is_its_own_root_cause(db, name):
    upload, (incident,), (label,) = scenario(db, name)

    assert_matches_label(incident, label)
    assert incident.root_cause.finding_ids == incident.finding_ids
    assert incident.root_cause.summary == db.findings(upload)[0].title or incident.chain == []
    assert incident.chain == [] and incident.alternatives == []
    assert incident.confidence == "medium"
    assert incident.confidence_reason.startswith("it is a single finding on one device")


def test_scenario_specific_unknowns(db):
    _, (flap,), _ = scenario(db, "01_link_flap")
    _, (brute,), _ = scenario(db, "04_brute_force")
    _, (dhcp,), _ = scenario(db, "05_dhcp_exhaustion")

    assert flap.unknowns == [
        "Why the interface went down. The logs show that it did, not whether a cable, an "
        "optic or the device at the other end was at fault."
    ]
    assert brute.unknowns == [
        "What was done with the account after the login succeeded. That needs the server's "
        "own command and session logs."
    ]
    assert dhcp.unknowns == []


def test_overlap_gives_each_incident_its_own_root(db):
    _, incidents, labels = scenario(db, "10_overlap")

    by_kind = {i.root_cause.kind: i for i in incidents}
    for label in labels:
        assert_matches_label(by_kind[LABEL_KINDS.get(label["type"], label["type"])], label)


# --- Ordering and timing -----------------------------------------------------------------


def test_an_effect_logged_just_before_its_cause_is_still_ordered_correctly(db):
    # R1's clock is a second behind: its OSPF loss appears to precede the interface failure.
    lines = outage(1) + [ospf(0, "R1", "10.255.0.2", reason="Interface down or detached")]

    upload, (incident,) = run(db, lines)

    assert incident.root_cause.kind == "interface_down"
    (step,) = incident.chain
    assert step.delay_seconds == -1.0 and step.prior == "interface_down_drops_ospf_on_it"


def test_an_effect_too_long_before_the_cause_is_not_linked(db):
    lines = outage(30) + [ospf(0, "R1", "10.255.0.2")]

    _, (incident,) = run(db, lines)

    assert incident.chain == []
    assert incident.root_cause.kind == "ospf_adjacency_loss"


def test_bgp_never_causes_ospf(db):
    # On R2, BGP drops first (short hold timer) and OSPF afterwards.
    upload, (incident,) = run(db, [bgp(0, "R2", "10.255.0.1"), ospf(12, "R2", "10.255.0.1")])

    assert incident.chain == []
    assert len(incident.alternatives) == 1
    assert incident.confidence == "low"
    assert incident.confidence_reason.startswith("the findings happened close together")
    assert incident.unknowns[-1].startswith("Neighbor addresses not matched")
    assert "Whether something else was the cause. Also possible:" in incident.unknowns[0]


def test_ospf_then_bgp_on_one_device_is_a_chain_resting_on_one_device(db):
    upload, (incident,) = run(db, [ospf(0, "R2", "10.255.0.1"), bgp(25, "R2", "10.255.0.1")])

    assert steps(db, upload, incident) == [
        ("ospf_adjacency_loss@R2", "bgp_session_down@R2", "ospf_loss_drops_bgp_on_same_device")
    ]
    assert incident.root_cause.kind == "ospf_adjacency_loss"
    assert incident.root_cause.entity == "10.255.0.1"
    assert incident.confidence == "medium"
    assert incident.confidence_reason == "the whole chain rests on what one device logged"


MEMORY = "%SYS-2-MALLOCFAIL: Memory allocation of 65536 bytes failed from 0x60103098, alignment 0"


def test_findings_with_no_known_link_get_low_confidence_and_no_invented_chain(db):
    memory = MEMORY
    flaps = []
    for n in range(6):
        flaps += [link(n * 10, "down", "R1", "GigabitEthernet0/2"), link(n * 10 + 4, "up", "R1", "GigabitEthernet0/2")]  # noqa: E501

    _, (incident,) = run(db, flaps + [cisco(20, "R1", memory)])

    assert len(incident.finding_ids) == 2 and incident.chain == []
    assert incident.confidence == "low"
    assert len(incident.alternatives) == 1


def test_a_cause_that_explains_only_part_of_the_incident_is_medium(db):
    memory = MEMORY
    lines = outage(0) + [ospf(0, "R1", "10.255.0.2", reason="Interface down or detached")]
    lines += [cisco(30, "R1", memory)]

    _, (incident,) = run(db, lines)

    assert incident.root_cause.kind == "interface_down" and incident.root_cause.explains == 1
    assert incident.confidence == "medium"
    assert incident.confidence_reason == (
        "it accounts for 1 of the 2 findings; the others are not explained by it"
    )
    assert [a.kind for a in incident.alternatives] == ["memory_allocation_failure"]


def test_effects_within_clock_skew_on_other_devices_lower_the_confidence(db):
    hints = Topology(owners={"10.255.0.1": "R1"})
    lines = outage(0) + [ospf(2, "R2", "10.255.0.1"), ospf(3, "R3", "10.255.0.1")]

    _, (incident,) = run(db, lines, hints)

    assert incident.root_cause.kind == "interface_down" and incident.root_cause.explains == 2
    assert incident.confidence == "medium"
    assert "so the order of events is not certain" in incident.confidence_reason


def test_resource_exhaustion_explains_sessions_dropping_on_the_same_device(db):
    cpu = "%SYS-3-CPUHOG: Task is running for (2004)msecs, more than (2000)msecs (1/0),process = BGP Router."  # noqa: E501
    lines = [cisco(n * 30, "R1", cpu) for n in range(4)] + [bgp(100, "R1", "198.51.100.1")]

    upload, (incident,) = run(db, lines)

    assert steps(db, upload, incident) == [
        ("cpu_hog@R1", "bgp_session_down@R1", "resource_exhaustion_drops_own_sessions")
    ]
    assert incident.root_cause.kind == "cpu_hog" and incident.root_cause.entity == "R1"


# --- What cannot be known ----------------------------------------------------------------


def test_a_link_reported_down_from_both_ends_cannot_name_the_end(db):
    hints = Topology()
    hints.add_link(("R1", "GigabitEthernet0/1"), ("R2", "GigabitEthernet0/1"))
    hints.owners.update({"10.255.0.1": "R1", "10.255.0.2": "R2"})
    lines = outage(0, "R1") + outage(1, "R2")
    lines += [
        ospf(0, "R1", "10.255.0.2", reason="Interface down or detached"),
        ospf(1, "R2", "10.255.0.1", reason="Interface down or detached"),
    ]

    upload, (incident,) = run(db, lines, hints)

    root = incident.root_cause
    assert root.kind == "link_failure"
    assert root.devices == ["R1", "R2"] and len(root.finding_ids) == 2
    assert root.summary == (
        "The link between GigabitEthernet0/1 on R1 and GigabitEthernet0/1 on R2 went down"
    )
    assert root.entity == "link between GigabitEthernet0/1 on R1 and GigabitEthernet0/1 on R2"
    assert root.explains == 2 and incident.alternatives == []
    assert incident.unknowns == [
        "Which end failed. Both ends of the link reported it down, so the fault could be "
        "either port, either optic or the cable between them."
    ]
    assert incident.confidence == "high"


def test_several_devices_losing_a_silent_neighbor_name_it_as_the_cause(db):
    # R1's own logs are missing: only R2 and R3 report losing it.
    hints = Topology(owners={"10.255.0.1": "R1"})
    lines = [ospf(0, "R2", "10.255.0.1"), ospf(3, "R3", "10.255.0.1"), bgp(20, "R3", "10.255.0.1")]

    _, (incident,) = run(db, lines, hints)

    root = incident.root_cause
    assert root.kind == "neighbor_unreachable"
    assert root.summary == "R1 (10.255.0.1) became unreachable for 2 devices"
    assert (root.devices, root.entity, root.finding_ids) == (["R1"], "10.255.0.1", [])
    assert root.explains == 3
    assert incident.confidence == "medium"
    assert incident.unknowns == [
        "What happened to R1. Other devices lost it at the same moment and there are no log "
        "lines from it in that period: it may have failed, lost power or been cut off from "
        "the log collector."
    ]


def test_a_silent_neighbor_that_did_log_something_is_described_differently(db):
    hints = Topology(owners={"10.255.0.1": "R1"})
    lines = [ospf(0, "R2", "10.255.0.1"), ospf(3, "R3", "10.255.0.1"), config(5, host="R1")]

    _, (incident,) = run(db, lines, hints)

    assert incident.unknowns[0] == (
        "What happened to R1. Other devices lost it, but its own log lines from that period "
        "show nothing that explains why."
    )


def test_a_silent_neighbor_nobody_can_identify(db):
    _, (incident,) = run(db, [ospf(0, "R2", "10.255.0.1"), ospf(3, "R3", "10.255.0.1")])

    assert incident.root_cause.summary == (
        "The device at 10.255.0.1 became unreachable for 2 devices"
    )
    assert incident.root_cause.devices == []
    assert incident.unknowns[0].startswith("Which device 10.255.0.1 is.")


def test_a_restart_nobody_requested(db):
    hints = Topology(owners={"10.255.0.9": "SW9"})
    restart = cisco(300, "SW9", "%SYS-5-RESTART: System restarted -- Cisco IOS Software")
    lines = [ospf(100, "R2", "10.255.0.9"), restart]

    upload, incidents = run(db, lines, hints)

    # Different devices, four minutes apart: grouping keeps them separate, and each says
    # what it can.
    restarted = next(i for i in incidents if i.root_cause.kind == "device_restart")
    assert restarted.unknowns == [
        "Why the device restarted. No reload was requested in these logs, so it may have "
        "crashed or lost power."
    ]


def test_the_closest_config_change_is_the_suspect(db):
    lines = [config(0, user="alice"), config(200, user="bob"), bgp(230, "R2", "203.0.113.1")]

    upload, (incident,) = run(db, lines)

    assert incident.root_cause.entity == "bob"
    assert "bob changed the configuration of R2 30s before" in incident.unknowns[0]


def test_a_config_change_is_not_blamed_when_something_physical_explains_it(db):
    lines = outage(100, "R2") + [
        config(60, host="R2"),
        ospf(100, "R2", "10.255.0.1", reason="Interface down or detached"),
    ]

    _, (incident,) = run(db, lines)

    assert incident.root_cause.kind == "interface_down"
    assert all(step.certainty != "suspect" for step in incident.chain)


def test_a_config_change_is_not_a_suspect_for_things_it_cannot_cause(db):
    flaps = []
    for n in range(6):
        flaps += [link(100 + n * 10, "down", "R2", "GigabitEthernet0/2"), link(104 + n * 10, "up", "R2", "GigabitEthernet0/2")]  # noqa: E501

    _, (incident,) = run(db, [config(60, host="R2")] + flaps)

    assert incident.root_cause.kind == "link_flap" and incident.chain == []


# --- Priors file and storage -------------------------------------------------------------


def test_built_in_priors_load_and_explain_themselves():
    priors = load_priors()

    assert len(priors) >= 12 and len({p.name for p in priors}) == len(priors)
    assert all(len(p.explanation) > 40 for p in priors)
    # A change is only ever a suspect.
    assert {p.certainty for p in priors if "config_change" in p.cause} == {"suspect"}
    # Nothing in the table lets BGP cause OSPF.
    assert not [p for p in priors if "bgp_session_down" in p.cause]


def test_user_priors_replace_built_in_ones_by_name(tmp_path, monkeypatch):
    path = tmp_path / "mine.toml"
    path.write_text(
        """
        [[prior]]
        name = "ospf_loss_drops_bgp_on_same_device"
        cause = ["ospf_adjacency_loss"]
        effect = ["bgp_session_down"]
        relation = "same_host"
        max_delay_seconds = 5
        certainty = "plausible"
        priority = 90
        explanation = "Shortened for a network with very fast BGP timers."
        """,
        encoding="utf-8",
    )
    monkeypatch.setenv("NETLOG_PRIORS", str(path))

    priors = {p.name: p for p in load_priors()}

    assert priors["ospf_loss_drops_bgp_on_same_device"].max_delay_seconds == 5
    assert priors["reload_request_restarts_device"].max_delay_seconds == 900


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ('relation = "same_host"', "relation must be one of"),
        ('certainty = "direct"', "certainty must be one of"),
        ('cause = ["a"]', "cause must be a list of rule names"),
        ("max_delay_seconds = 5", "max_delay_seconds must be a number, zero or more"),
        ('explanation = "because"', "explanation must say what the mechanism is"),
        ('name = "p"', "a prior has no name"),
    ],
)
def test_mistakes_in_a_priors_file_are_reported(change, message):
    good = (
        '[[prior]]\nname = "p"\ncause = ["a"]\neffect = ["b"]\nrelation = "same_host"\n'
        'max_delay_seconds = 5\ncertainty = "direct"\nexplanation = "because"\n'
    )
    bad = {
        'relation = "same_host"': 'relation = "nearby"',
        'certainty = "direct"': 'certainty = "sure"',
        'cause = ["a"]': "cause = []",
        "max_delay_seconds = 5": "max_delay_seconds = -1",
        'explanation = "because"': 'explanation = " "',
        'name = "p"': "",
    }
    parse_priors(good)

    with pytest.raises(PriorError, match=message):
        parse_priors(good.replace(change, bad[change]))


def test_other_priors_file_problems():
    with pytest.raises(PriorError, match="not valid TOML"):
        parse_priors("[[prior]\n")
    with pytest.raises(PriorError, match="causal priors file not found"):
        load_priors("no-such-file.toml")
    one = '[[prior]]\nname = "p"\ncause = ["a"]\neffect = ["b"]\nrelation = "same_host"\nmax_delay_seconds = 5\ncertainty = "direct"\nexplanation = "x"\n'  # noqa: E501
    with pytest.raises(PriorError, match="defined twice"):
        parse_priors(one + one)
    with pytest.raises(PriorError, match="colour is not a known setting"):
        parse_priors(one + 'colour = "red"\n')


def test_cause_and_effect_are_stored_with_the_incident(db):
    upload, (incident,), _ = scenario(db, "02_cascade")

    stored = db.get_incident(upload, incident.id)

    assert stored.root_cause == incident.root_cause
    assert stored.chain == incident.chain and len(stored.chain) == 12
    assert (stored.confidence, stored.confidence_reason) == ("high", incident.confidence_reason)
    assert stored.unknowns == incident.unknowns and stored.alternatives == []


def test_version_4_database_is_upgraded(tmp_path):
    path = tmp_path / "old.db"
    raw = sqlite3.connect(path)
    for migration in _MIGRATIONS[:4]:
        raw.executescript(migration)
    raw.execute(
        "INSERT INTO uploads (id, filename, created_at) VALUES (1, 'old.log', 0)"
    )
    raw.execute(
        "INSERT INTO incidents VALUES (1, 'inc-old', 'An old incident', 'high', 'High.', 0, 1, "
        "'[\"R1\"]', '[]', '[]', '[]', '[]')"
    )
    raw.execute("PRAGMA user_version = 4")
    raw.commit()
    raw.close()

    with Database(path) as database:
        assert database.schema_version == SCHEMA_VERSION >= 5
        (old,) = database.incidents(1)
        assert (old.title, old.root_cause, old.chain, old.confidence) == (
            "An old incident", None, [], "low",
        )  # fmt: skip
