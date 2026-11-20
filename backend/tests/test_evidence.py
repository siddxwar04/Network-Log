import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from netlog.config import load_config
from netlog.correlation.grouping import correlate
from netlog.detection.engine import detect
from netlog.ingestion.ingest import ingest_file
from netlog.ingestion.reader import RawLine
from netlog.llm.evidence import (
    PACK_VERSION,
    PackTooLarge,
    build_pack,
    outgoing_pack,
    outgoing_packs,
)
from netlog.mining.templates import mine_templates
from netlog.parsers.pipeline import LineParser
from netlog.redaction.redactor import Redactor
from netlog.storage.database import Database

SCENARIOS = Path("data/scenarios")
GOLDEN = Path(__file__).parent / "golden"
START = datetime(2026, 3, 3, 2, 0, 0, tzinfo=UTC)
WITH_INCIDENTS = [
    "01_link_flap",
    "02_cascade",
    "03_config_bgp",
    "04_brute_force",
    "05_dhcp_exhaustion",
    "07_device_reload",
    "10_overlap",
]


@pytest.fixture
def db(tmp_path):
    with Database(tmp_path / "test.db") as database:
        yield database


def analyze(db, name):
    """Run a sample log through the whole pipeline. Returns the upload and its incidents."""
    upload = ingest_file(db, SCENARIOS / f"{name}.log", year=2026)
    mine_templates(db, upload)
    detect(db, upload)
    return upload, correlate(db, upload)


def analyze_lines(db, lines):
    parser = LineParser(year=2026)
    upload = db.create_upload("test.log")
    db.add_events(upload, [parser.parse(RawLine(n, line)) for n, line in enumerate(lines, 1)])
    mine_templates(db, upload)
    detect(db, upload)
    return upload, correlate(db, upload)


def settings(**evidence):
    config = load_config()
    config["evidence"] = {**config["evidence"], **evidence}
    return config


def stamp(offset):
    moment = START + timedelta(seconds=offset)
    return f"{moment:%b} {moment.day:>2} {moment:%H:%M:%S}"


def failed_login(offset, user, source="192.0.2.77"):
    return (
        f"{stamp(offset)} srv1 sshd[{1000 + offset}]: Failed password for invalid user "
        f"{user} from {source} port {20000 + offset % 40000} ssh2"
    )


def check_golden(name: str, text: str) -> None:
    """Compare with a stored pack. Set UPDATE_GOLDEN=1 to rewrite the stored copy after
    a deliberate change to what a pack holds."""
    path = GOLDEN / name
    if os.environ.get("UPDATE_GOLDEN"):
        path.write_text(text, encoding="utf-8", newline="\n")
    assert text == path.read_text(encoding="utf-8")


def check_references(pack):
    """Every id is unique, and every id that an item points at exists."""
    data = pack.data
    sections = ("findings", "chain", "templates", "evidence")
    ids = [item["id"] for name in sections for item in data[name]]
    assert len(ids) == len(set(ids))
    assert set(ids) == pack.ids
    findings = {item["id"] for item in data["findings"]}
    lines = {item["id"] for item in data["evidence"]}

    for item in data["findings"]:
        assert set(item["evidence"]) <= lines
        assert len(item["evidence"]) <= item["evidence_lines"]
    for step in data["chain"]:
        assert step["links"]
        for link in step["links"]:
            assert {link["cause"], link["effect"]} <= findings
    for template in data["templates"]:
        assert set(template["examples"]) <= lines
        assert len(template["examples"]) <= template["count"]
    for change in data["config_changes"]:
        assert change["finding"] in findings
        assert set(change["evidence"]) <= lines
    for root in [data["root_cause"], *data["alternatives"]]:
        assert root is None or set(root["findings"]) <= findings
    assert set(pack.finding_ids) == findings
    assert set(pack.event_ids) == set(pack.line_numbers) == lines


# --- What a pack holds -------------------------------------------------------------------


def test_cascade_pack_matches_the_stored_pack(analyzed):
    db, upload, (incident,) = analyzed("02_cascade")
    pack = build_pack(db, upload, incident)
    check_golden("evidence_cascade.json", pack.to_json(indent=2) + "\n")


def test_cascade_pack_as_sent_matches_the_stored_pack(analyzed):
    db, upload, _ = analyzed("02_cascade")
    ((_, pack),), _ = outgoing_packs(db, upload)
    check_golden("evidence_cascade_redacted.json", pack.to_json(indent=2) + "\n")


def test_the_facts_are_the_ones_the_code_decided(analyzed):
    db, upload, (incident,) = analyzed("02_cascade")
    data = build_pack(db, upload, incident).data

    assert data["version"] == PACK_VERSION
    facts = data["incident"]
    assert facts["id"] == incident.id
    assert facts["severity"] == incident.severity == "critical"
    assert facts["severity_reason"] == incident.severity_reason
    assert facts["confidence"] == incident.confidence == "high"
    assert facts["confidence_reason"] == incident.confidence_reason
    assert facts["devices"] == ["R1", "R2", "R3", "R4"]
    assert facts["types"] == ["bgp_session_down", "ospf_adjacency_loss"]
    assert facts["start"] == "2026-03-03T02:46:11.719Z"
    assert facts["duration_seconds"] == round(incident.duration_seconds, 1)
    assert data["unknowns"] == incident.unknowns

    root = data["root_cause"]
    assert root["kind"] == "interface_down"
    assert root["summary"] == incident.root_cause.summary
    assert root["entity"] == "GigabitEthernet0/1"
    assert (root["explains"], root["of"]) == (12, 12)
    (root_finding,) = [f for f in data["findings"] if f["role"] == "root_cause"]
    assert root["findings"] == [root_finding["id"]]
    assert root_finding["rule"] == "interface_down"
    assert [f["role"] for f in data["findings"]].count("problem") == 12


def test_chain_steps_group_the_links_by_mechanism(analyzed):
    db, upload, (incident,) = analyzed("02_cascade")
    pack = build_pack(db, upload, incident)
    chain = pack.data["chain"]

    assert [step["id"] for step in chain] == ["C1", "C2", "C3", "C4"]
    assert sum(len(step["links"]) for step in chain) == len(incident.chain) == 12
    assert {step["explanation"] for step in chain} == {s.explanation for s in incident.chain}
    assert {step["certainty"] for step in chain} == {"direct", "plausible"}
    # The first step is the interface taking OSPF down with it, at once.
    by_id = {item["id"]: item for item in pack.data["findings"]}
    first = chain[0]["links"][0]
    assert by_id[first["cause"]]["rule"] == "interface_down"
    assert by_id[first["effect"]]["rule"] == "ospf_adjacency_loss"
    assert first["delay_seconds"] == 0.0


@pytest.mark.parametrize("name", WITH_INCIDENTS)
def test_every_id_is_unique_and_every_reference_resolves(analyzed, name):
    db, upload, incidents = analyzed(name)
    assert incidents
    for incident in incidents:
        check_references(build_pack(db, upload, incident))


def test_evidence_lines_are_the_real_lines_of_the_file(analyzed):
    db, upload, (incident,) = analyzed("02_cascade")
    pack = build_pack(db, upload, incident)
    file_lines = (SCENARIOS / "02_cascade.log").read_text(encoding="utf-8").splitlines()

    assert pack.data["evidence"]
    for item in pack.data["evidence"]:
        assert item["text"] == file_lines[item["line"] - 1]
        assert pack.line_numbers[item["id"]] == item["line"]
        assert db.get_event(pack.event_ids[item["id"]]).line_no == item["line"]
    # In time order, so E1 is where the story starts: the interface going down.
    times = [item["time"] for item in pack.data["evidence"]]
    assert times == sorted(times)
    assert "%LINK-3-UPDOWN" in pack.data["evidence"][0]["text"]


def test_templates_count_the_lines_of_this_incident_only(analyzed):
    db, upload, (incident,) = analyzed("04_brute_force")
    data = build_pack(db, upload, incident).data

    assert data["incident"]["evidence_lines"] == 401
    assert sum(t["count"] for t in data["templates"]) == 401
    failed = [t for t in data["templates"] if t["event_key"] == "sshd.failed_password"]
    assert sum(t["count"] for t in failed) == 400  # the file holds other failures too
    (accepted,) = [t for t in data["templates"] if t["event_key"] == "sshd.accepted"]
    assert accepted["count"] == 1
    assert accepted["first_seen"] == accepted["last_seen"] == "2026-03-03T03:34:32Z"
    for template in data["templates"]:
        assert template["first_seen"] <= template["last_seen"]
        assert 1 <= len(template["examples"]) <= 3
    assert data["omitted"] == {"evidence_lines": 401 - len(data["evidence"])}


def test_examples_come_from_different_devices_earliest_first(analyzed):
    db, upload, (incident,) = analyzed("02_cascade")
    data = build_pack(db, upload, incident, settings(max_tokens=20000)).data
    lines = {item["id"]: item for item in data["evidence"]}

    (bgp_down,) = [t for t in data["templates"] if t["pattern"].endswith("Notification sent")]
    assert bgp_down["count"] == 6 and len(bgp_down["examples"]) == 3
    hosts = [lines[e]["text"].split()[3] for e in bgp_down["examples"]]
    assert len(set(hosts)) == 3
    # The very first line of the template is always among them.
    assert lines[bgp_down["examples"][0]]["time"] == bgp_down["first_seen"]
    # A template seen on one device only still gets its three earliest lines.
    (ospf,) = [t for t in data["templates"] if t["pattern"].endswith("down or detached")]
    assert ospf["devices"] == ["R1"] and len(ospf["examples"]) == 3


def test_a_config_change_attached_to_the_incident_is_in_the_pack(analyzed):
    db, upload, (incident,) = analyzed("03_config_bgp")
    data = build_pack(db, upload, incident).data

    (change,) = data["config_changes"]
    assert (change["device"], change["user"], change["from"]) == ("R2", "jdoe", "10.10.10.53")
    assert change["seconds_before_incident"] == pytest.approx(19.1, abs=0.1)
    (line_id,) = change["evidence"]
    (line,) = [item for item in data["evidence"] if item["id"] == line_id]
    assert "%SYS-5-CONFIG_I" in line["text"] and "jdoe" in line["text"]
    assert data["root_cause"]["kind"] == "config_change"
    assert data["root_cause"]["findings"] == [change["finding"]]
    assert data["chain"][0]["certainty"] == "suspect"


def test_rule_internals_are_left_out_of_the_details(analyzed):
    db, upload, (incident,) = analyzed("04_brute_force")
    (finding,) = build_pack(db, upload, incident).data["findings"]

    assert finding["details"]["count"] == 400
    assert finding["details"]["succeeded_username"] == "deploy"
    assert finding["flags"] == ["password_spraying", "succeeded"]
    assert not {"threshold", "window_seconds", "peak_count"} & set(finding["details"])


# --- Determinism -------------------------------------------------------------------------


def test_the_same_incident_gives_the_same_pack_byte_for_byte(analyzed, tmp_path):
    db, upload, (incident,) = analyzed("02_cascade")
    first = build_pack(db, upload, incident)
    second = build_pack(db, upload, incident)
    assert first.to_json() == second.to_json()
    assert first.hash == second.hash
    assert re.fullmatch(r"[0-9a-f]{64}", first.hash)

    # A database that already holds another upload numbers its rows differently. The
    # pack must not show it.
    with Database(tmp_path / "other.db") as other:
        analyze(other, "01_link_flap")
        other_upload, (other_incident,) = analyze(other, "02_cascade")
        assert other_upload != upload
        assert build_pack(other, other_upload, other_incident).to_json() == first.to_json()


def test_the_same_log_gives_the_same_outgoing_packs(analyzed, tmp_path):
    db, upload, _ = analyzed("10_overlap")
    packs, _ = outgoing_packs(db, upload)
    again, _ = outgoing_packs(db, upload)  # the token map is now loaded from the database
    assert len(packs) == 2
    assert [pack.hash for _, pack in packs] == [pack.hash for _, pack in again]

    with Database(tmp_path / "other.db") as other:
        analyze(other, "01_link_flap")
        other_upload, _ = analyze(other, "10_overlap")
        fresh, _ = outgoing_packs(other, other_upload)
        assert [pack.hash for _, pack in fresh] == [pack.hash for _, pack in packs]


def test_a_different_incident_gives_a_different_hash(analyzed):
    db, upload, incidents = analyzed("10_overlap")
    hashes = {build_pack(db, upload, incident).hash for incident in incidents}
    assert len(hashes) == 2


# --- The size limit ----------------------------------------------------------------------


def test_the_limit_holds_for_an_incident_with_thousands_of_events(db):
    lines = [failed_login(n, f"user-{n}-{'x' * 30}") for n in range(5000)]
    upload, incidents = analyze_lines(db, lines)
    config = load_config()
    limit = config["evidence"]["max_tokens"]

    assert sum(len(i.finding_ids) for i in incidents) >= 1
    total = 0
    for incident in incidents:
        pack = build_pack(db, upload, incident, config)
        sent = outgoing_pack(db, upload, incident, Redactor(config), config)
        total += pack.data["incident"]["evidence_lines"]
        for each in (pack, sent):
            assert each.tokens <= limit
            assert each.size_chars <= limit * config["evidence"]["chars_per_token"]
            assert len(each.data["evidence"]) <= config["evidence"]["max_evidence_lines"]
            check_references(each)
        shown = len(pack.data["evidence"])
        assert pack.data["omitted"]["evidence_lines"] == (
            pack.data["incident"]["evidence_lines"] - shown
        )
        # The counts still say how much there was.
        assert sum(t["count"] for t in pack.data["templates"]) == (
            pack.data["incident"]["evidence_lines"]
        )
    assert total >= 4000


@pytest.mark.parametrize("max_tokens", [2500, 1500, 1000, 700])
def test_a_smaller_limit_trims_the_pack_and_says_what_was_left_out(analyzed, max_tokens):
    db, upload, (incident,) = analyzed("02_cascade")
    config = settings(max_tokens=max_tokens)
    pack = build_pack(db, upload, incident, config)
    sent = outgoing_pack(db, upload, incident, Redactor(config), config)

    for each in (pack, sent):
        assert each.tokens <= max_tokens
        check_references(each)
        data = each.data
        # The facts the code decided survive any trimming.
        assert data["incident"]["severity"] == "critical"
        assert data["incident"]["confidence"] == "high"
        assert data["root_cause"]["kind"] == "interface_down"
        (root,) = [f for f in data["findings"] if f["role"] == "root_cause"]
        assert data["root_cause"]["findings"] == [root["id"]]
        # So does the earliest evidence: the line where the root cause begins.
        assert root["evidence"][:1] == ["E1"]
        assert "%LINK-3-UPDOWN" in data["evidence"][0]["text"]
        assert data["omitted"]["evidence_lines"] == 32 - len(data["evidence"])
        left_out = sum(data["omitted"].get("findings", {}).values())
        assert len(data["findings"]) + left_out == 13
        links = sum(len(step["links"]) for step in data["chain"])
        assert links + data["omitted"].get("chain_links", 0) == 12
    assert pack.trimmed


def test_each_chain_step_keeps_its_earliest_evidence_when_lines_are_scarce(analyzed):
    db, upload, (incident,) = analyzed("02_cascade")
    pack = build_pack(db, upload, incident, settings(examples_per_template=1))
    by_id = {item["id"]: item for item in pack.data["findings"]}

    for step in pack.data["chain"]:
        first = step["links"][0]
        assert by_id[first["effect"]]["evidence"], step["id"]
        causes = [by_id[link["cause"]] for link in step["links"]]
        assert min(causes, key=lambda f: f["start"])["evidence"], step["id"]


def test_item_limits_are_hard_limits(analyzed):
    db, upload, (incident,) = analyzed("02_cascade")
    config = settings(
        max_tokens=20000, max_findings=5, max_chain_links=3, max_templates=2, max_evidence_lines=4
    )
    data = build_pack(db, upload, incident, config).data

    assert len(data["findings"]) == 5
    assert sum(len(step["links"]) for step in data["chain"]) <= 3
    assert len(data["templates"]) == 2
    assert len(data["evidence"]) <= 4
    assert sum(data["omitted"]["findings"].values()) == 8
    assert data["omitted"]["templates"] == 6
    # The root cause is kept ahead of everything else.
    assert "root_cause" in [f["role"] for f in data["findings"]]


def test_a_very_long_line_is_cut(db):
    lines = [failed_login(n, "admin") for n in range(30)]
    lines.append(failed_login(30, "A" * 5000))
    upload, (incident,) = analyze_lines(db, lines)
    config = settings(examples_per_template=50, max_evidence_lines=50)
    pack = build_pack(db, upload, incident, config)

    longest = max(len(item["text"]) for item in pack.data["evidence"])
    assert longest == config["evidence"]["max_line_chars"]
    assert pack.tokens <= config["evidence"]["max_tokens"]


def test_a_limit_too_small_for_the_bare_facts_is_an_error(analyzed):
    db, upload, (incident,) = analyzed("02_cascade")
    with pytest.raises(PackTooLarge, match="max_tokens"):
        build_pack(db, upload, incident, settings(max_tokens=50))
    with pytest.raises(ValueError, match="max_tokens"):
        build_pack(db, upload, incident, settings(max_tokens=0))


def test_every_sample_incident_fits_the_default_limit(analyzed):
    limit = load_config()["evidence"]["max_tokens"]
    sizes = {}
    for name in WITH_INCIDENTS:
        db, upload, _ = analyzed(name)
        packs, _ = outgoing_packs(db, upload)
        for incident, pack in packs:
            sizes[(name, incident.id)] = pack.tokens
            assert pack.redacted
    assert len(sizes) == 8
    assert max(sizes.values()) <= limit
    assert min(sizes.values()) > 100


def test_a_log_with_no_incidents_has_no_packs(analyzed):
    db, upload, incidents = analyzed("08_noise")
    assert incidents == []
    assert outgoing_packs(db, upload)[0] == []


def test_a_pack_can_be_built_without_template_mining(db):
    upload = ingest_file(db, SCENARIOS / "01_link_flap.log", year=2026)
    detect(db, upload)
    (incident,) = correlate(db, upload)
    pack = build_pack(db, upload, incident)

    check_references(pack)
    assert [t["pattern"] for t in pack.data["templates"]] == ["LINK-3-UPDOWN"]
    assert json.loads(pack.to_json()) == pack.data
