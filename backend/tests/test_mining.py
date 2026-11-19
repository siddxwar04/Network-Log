import re
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from netlog.config import load_config
from netlog.ingestion.ingest import ingest_file
from netlog.ingestion.reader import RawLine
from netlog.mining.dedup import find_runs
from netlog.mining.templates import mine_templates
from netlog.parsers.pipeline import LineParser
from netlog.storage.database import SCHEMA_VERSION, Database, EventFilter

SCENARIOS = Path("data/scenarios")
LITERAL_VALUE = re.compile(
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b"  # an IPv4 address
    r"|\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b"  # a MAC address
    r"|\b(?:GigabitEthernet|FastEthernet|Gi|Fa|eth)\d"  # an interface name
)


@pytest.fixture
def db(tmp_path):
    with Database(tmp_path / "test.db") as database:
        yield database


def store(db, lines, name="sample.log"):
    parser = LineParser(year=2026)
    upload_id = db.create_upload(name)
    db.add_events(upload_id, [parser.parse(RawLine(n, line)) for n, line in enumerate(lines, 1)])
    return upload_id


def cisco(second, host, body):
    return f"Mar  3 02:00:{second:02d} {host} {100 + second}: Mar  3 02:00:{second:02d}.000: {body}"


def patterns(db, upload_id):
    return {t.pattern: t for t in db.templates(upload_id)}


# --- Template mining ---------------------------------------------------------------------


def test_lines_that_differ_only_in_values_share_a_template(db):
    upload = store(
        db,
        [
            cisco(1, "R1", "%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down"),
            cisco(2, "SW1", "%LINK-3-UPDOWN: Interface Gi0/7, changed state to down"),
            cisco(3, "SW2", "%LINK-3-UPDOWN: Interface FastEthernet0/24, changed state to down"),
            cisco(4, "R2", "%BGP-5-ADJCHANGE: neighbor 10.255.0.1 Down BGP Notification sent"),
            cisco(5, "R3", "%BGP-5-ADJCHANGE: neighbor 2001:db8::1 Down BGP Notification sent"),
            "Mar  3 02:00:06 dhcp1 dhcpd[811]: DHCPDISCOVER from 00:11:22:33:44:55 via eth1",
            "Mar  3 02:00:07 dhcp1 dhcpd[811]: DHCPDISCOVER from aa:bb:cc:dd:ee:ff via eth0",
        ],
    )

    result = mine_templates(db, upload)

    found = patterns(db, upload)
    assert set(found) == {
        "Interface <IF>, changed state to down",
        "neighbor <IP> Down BGP Notification sent",
        "DHCPDISCOVER from <MAC> via <IF>",
    }
    assert [found[p].count for p in sorted(found)] == [2, 3, 2]
    assert (result.lines, result.templates) == (7, 3)
    assert result.compression_ratio == pytest.approx(7 / 3)


def test_different_message_codes_never_share_a_template(db):
    upload = store(
        db,
        [
            cisco(1, "R1", "%LINK-3-UPDOWN: Interface Gi0/1, changed state to down"),
            cisco(2, "R1", "%LINK-5-CHANGED: Interface Gi0/1, changed state to down"),
            cisco(3, "R1", "%FAKE-3-UPDOWN: Interface Gi0/1, changed state to down"),
        ],
    )

    mine_templates(db, upload)

    templates = db.templates(upload)
    assert len(templates) == 3
    assert {t.pattern for t in templates} == {"Interface <IF>, changed state to down"}
    assert {t.event_key for t in templates} == {"LINK-3-UPDOWN", "LINK-5-CHANGED", "FAKE-3-UPDOWN"}
    assert len({t.id for t in templates}) == 3


def test_opposite_state_changes_do_not_share_a_template(db):
    upload = store(
        db,
        [
            cisco(n, "R1", f"%LINK-3-UPDOWN: Interface Gi0/{n}, changed state to {state}")
            for n, state in ((1, "down"), (2, "down"), (3, "up"), (4, "up"))
        ],
    )

    mine_templates(db, upload)

    assert set(patterns(db, upload)) == {
        "Interface <IF>, changed state to down",
        "Interface <IF>, changed state to up",
    }


def test_usernames_and_hostnames_are_masked_whatever_they_contain(db):
    names = ["admin", "my user name", "user", "x'; DROP TABLE users;--", "from", "ro ot"]
    lines = [
        f"Mar  3 02:00:{n:02d} srv1 sshd[{n}]: Failed password for invalid user {name} "
        f"from 192.0.2.77 port {4000 + n} ssh2"
        for n, name in enumerate(names)
    ]
    lines += [
        "Mar  3 02:01:00 dhcp1 dhcpd[811]: DHCPACK on 10.20.0.9 to 00:11:22:33:44:55 (cam-8613) via eth1",  # noqa: E501
        "Mar  3 02:01:01 dhcp1 dhcpd[811]: DHCPACK on 10.20.0.8 to 00:11:22:33:44:56 (my laptop (2)) via eth1",  # noqa: E501
        "Mar  3 02:01:02 srv1 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",  # noqa: E501
        "Mar  3 02:01:03 srv1 sudo:   bob : TTY=pts/3 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/id",  # noqa: E501
    ]
    upload = store(db, lines)

    mine_templates(db, upload)

    found = patterns(db, upload)
    assert set(found) == {
        "Failed password for invalid user <USER> from <IP> port <NUM> ssh2",
        "DHCPACK on <IP> to <MAC> (<HOST>) via <IF>",
        # Only the name itself is masked; the word holding the home folder still differs
        # between the two lines, so Drain turns that whole word into a wildcard.
        "<USER> : TTY=pts/<NUM> ; <*> ; USER=root ; COMMAND=/usr/bin/id",
    }
    assert found["Failed password for invalid user <USER> from <IP> port <NUM> ssh2"].count == 6


def test_template_records_counts_times_hosts_and_examples(db):
    upload = store(
        db,
        [
            cisco(1, "R1", "%LINK-3-UPDOWN: Interface Gi0/1, changed state to down"),
            cisco(2, "R1", "%LINK-3-UPDOWN: Interface Gi0/2, changed state to down"),
            cisco(3, "R1", "%LINK-3-UPDOWN: Interface Gi0/3, changed state to down"),
            cisco(4, "SW1", "%LINK-3-UPDOWN: Interface Gi0/4, changed state to down"),
            cisco(5, "SW2", "%LINK-3-UPDOWN: Interface Gi0/5, changed state to down"),
            cisco(6, "SW2", "%LINK-3-UPDOWN: Interface Gi0/6, changed state to down"),
        ],
    )

    mine_templates(db, upload)

    (template,) = db.templates(upload)
    assert template.count == 6
    assert template.source_type == "cisco_ios" and template.event_key == "LINK-3-UPDOWN"
    assert template.first_seen == datetime(2026, 3, 3, 2, 0, 1, tzinfo=UTC)
    assert template.last_seen == datetime(2026, 3, 3, 2, 0, 6, tzinfo=UTC)
    assert template.hosts == ("R1", "SW1", "SW2")
    # Three examples, one from each device.
    examples = [db.get_event(event_id) for event_id in template.examples]
    assert [e.host for e in examples] == ["R1", "SW1", "SW2"]
    assert db.get_template(upload, template.id) == template
    assert db.get_template(upload, "t-missing") is None


def test_examples_are_filled_from_one_host_when_there_is_only_one(db):
    upload = store(
        db,
        [cisco(n, "R1", f"%LINK-3-UPDOWN: Interface Gi0/{n}, changed state to down") for n in range(1, 6)],  # noqa: E501
    )

    mine_templates(db, upload)

    (template,) = db.templates(upload)
    assert [db.get_event(i).line_no for i in template.examples] == [1, 2, 3]


def test_every_event_gets_its_template_id_and_can_be_filtered_by_it(db):
    upload = store(
        db,
        [
            cisco(1, "R1", "%LINK-3-UPDOWN: Interface Gi0/1, changed state to down"),
            cisco(2, "R1", "%LINK-3-UPDOWN: Interface Gi0/2, changed state to down"),
            cisco(3, "R1", "%SYS-5-CONFIG_I: Configured from console by console"),
            "this is not a log line",
        ],
    )

    mine_templates(db, upload)

    link = patterns(db, upload)["Interface <IF>, changed state to down"]
    assert [e.line_no for e in db.events(upload, EventFilter(template_id=link.id))] == [1, 2]
    by_line = {e.line_no: e.template_id for e in db.events(upload)}
    assert by_line[1] == by_line[2] == link.id
    assert by_line[3] not in (None, link.id)
    # A line no parser understood has no template; parse coverage reports it instead.
    assert by_line[4] is None
    assert sum(t.count for t in db.templates(upload)) == 3


def test_mining_twice_gives_the_same_result(db):
    upload = ingest_file(db, SCENARIOS / "02_cascade.log", year=2026)

    mine_templates(db, upload)
    first = db.templates(upload, limit=500)
    first_ids = [e.template_id for e in db.events(upload, limit=200)]
    mine_templates(db, upload)

    assert db.templates(upload, limit=500) == first
    assert [e.template_id for e in db.events(upload, limit=200)] == first_ids


def test_the_same_file_always_gives_the_same_templates_and_ids(tmp_path):
    results = []
    for name in ("a.db", "b.db"):
        with Database(tmp_path / name) as database:
            upload = ingest_file(database, SCENARIOS / "07_device_reload.log", year=2026)
            mine_templates(database, upload)
            results.append([(t.id, t.pattern, t.count) for t in database.templates(upload, 500)])

    assert results[0] == results[1]
    assert all(re.fullmatch(r"t-[0-9a-f]{10}", template_id) for template_id, _, _ in results[0])


@pytest.mark.parametrize("path", sorted(SCENARIOS.glob("0[1-7]*.log")), ids=lambda p: p.name)
def test_scenario_templates_are_few_and_contain_no_literal_values(db, path):
    upload = ingest_file(db, path, year=2026)

    result = mine_templates(db, upload)

    templates = db.templates(upload, limit=1000)
    assert result.lines == db.count_events(upload)
    assert sum(t.count for t in templates) == result.lines
    assert 10 < len(templates) < 60
    assert result.compression_ratio > 80
    leaked = [t.pattern for t in templates if LITERAL_VALUE.search(t.pattern)]
    assert leaked == []


def test_cascade_templates_tell_the_story(db):
    upload = ingest_file(db, SCENARIOS / "02_cascade.log", year=2026)
    mine_templates(db, upload)

    found = patterns(db, upload)
    dead = "Process <NUM>, Nbr <IP> on <IF> from FULL to DOWN, Neighbor Down: Dead timer expired"

    assert found[dead].count == 3 and found[dead].hosts == ("R2", "R3", "R4")
    assert found["neighbor <IP> Down BGP Notification sent"].count == 6
    assert found["neighbor <IP> Up"].count == 6


def test_settings_come_from_configuration(db, tmp_path):
    lines = [cisco(n, "R1", f"%SYS-5-NOTE: alpha {word} gamma") for n, word in ((1, "one"), (2, "two"))]  # noqa: E501
    config_file = tmp_path / "strict.toml"
    config_file.write_text(
        "[mining]\nsimilarity_threshold = 0.95\nmax_examples = 1\n"
        "[[mining.masks]]\nname = \"WORD\"\npattern = 'gamma'\n",
        encoding="utf-8",
    )
    default_upload, strict_upload = store(db, lines, "a.log"), store(db, lines, "b.log")

    mine_templates(db, default_upload)
    mine_templates(db, strict_upload, load_config(config_file))

    assert set(patterns(db, default_upload)) == {"alpha <*> gamma"}
    assert set(patterns(db, strict_upload)) == {"alpha one <WORD>", "alpha two <WORD>"}
    assert all(len(t.examples) == 1 for t in db.templates(strict_upload))
    # A user file only overrides what it names; the rest keeps its default.
    assert load_config(config_file)["mining"]["depth"] == load_config()["mining"]["depth"]
    assert load_config(config_file)["dedup"] == load_config()["dedup"]


def test_bad_configuration_is_reported_clearly(db, tmp_path):
    broken = tmp_path / "broken.toml"
    broken.write_text("[mining\n", encoding="utf-8")
    bad_mask = load_config()
    bad_mask["mining"]["masks"] = [{"name": "BAD", "pattern": "(unclosed"}]

    with pytest.raises(ValueError, match="not valid TOML"):
        load_config(broken)
    with pytest.raises(ValueError, match="config file not found"):
        load_config(tmp_path / "missing.toml")
    with pytest.raises(ValueError, match="mining mask 'BAD' is not a valid pattern"):
        mine_templates(db, store(db, [cisco(1, "R1", "%SYS-5-NOTE: hello")]), bad_mask)


def test_deleting_an_upload_removes_its_templates(db):
    upload = store(db, [cisco(1, "R1", "%LINK-3-UPDOWN: Interface Gi0/1, changed state to down")])
    mine_templates(db, upload)
    assert db.count_templates(upload) == 1

    db.delete_upload(upload)

    assert db.count_templates(upload) == 0 and db.templates(upload) == []


def test_version_1_database_is_upgraded(tmp_path):
    path = tmp_path / "old.db"
    Database(path).close()
    raw = sqlite3.connect(path)
    raw.execute("DROP INDEX events_by_template")
    raw.execute("PRAGMA user_version = 1")
    raw.close()

    with Database(path) as database:
        assert database.schema_version == SCHEMA_VERSION >= 2
        upload = store(database, [cisco(1, "R1", "%LINK-3-UPDOWN: Interface Gi0/1, changed state to down")])  # noqa: E501
        mine_templates(database, upload)
        assert len(find_runs(database, upload)) == 1


# --- Dedup -------------------------------------------------------------------------------


def no_lease(minute, second, host="dhcp1"):
    return (
        f"Mar  3 03:{minute:02d}:{second:02d} {host} dhcpd[811]: DHCPDISCOVER from "
        f"00:11:22:33:44:{second:02d} via eth1: network 10.20.0.0/24: no free leases"
    )


def test_repeats_collapse_into_one_run(db):
    upload = store(db, [no_lease(0, s) for s in (0, 10, 20, 30, 50)])
    mine_templates(db, upload)

    (run,) = find_runs(db, upload)

    assert run.count == 5 and run.host == "dhcp1"
    assert run.first_seen == datetime(2026, 3, 3, 3, 0, 0, tzinfo=UTC)
    assert run.last_seen - run.first_seen == timedelta(seconds=50)
    assert db.get_event(run.first_event_id).line_no == 1
    assert db.get_event(run.last_event_id).line_no == 5
    # The events themselves are all still stored.
    assert db.count_events(upload) == 5


def test_a_run_breaks_when_the_gap_is_exceeded(db):
    upload = store(db, [no_lease(0, 0), no_lease(0, 30), no_lease(1, 30), no_lease(3, 0), no_lease(3, 59)])  # noqa: E501
    mine_templates(db, upload)

    assert [r.count for r in find_runs(db, upload)] == [3, 2]
    assert [r.count for r in find_runs(db, upload, max_gap_seconds=30)] == [2, 1, 1, 1]
    assert [r.count for r in find_runs(db, upload, max_gap_seconds=600)] == [5]


def test_a_run_breaks_when_the_host_changes(db):
    upload = store(db, [no_lease(0, 0), no_lease(0, 5, "dhcp2"), no_lease(0, 10), no_lease(0, 15, "dhcp2")])  # noqa: E501
    mine_templates(db, upload)

    assert [(r.host, r.count) for r in find_runs(db, upload)] == [("dhcp1", 2), ("dhcp2", 2)]


def test_other_messages_in_between_do_not_break_a_run(db):
    lines = []
    link = "%LINK-3-UPDOWN: Interface Gi0/2, changed state to"
    for n in range(4):
        lines.append(cisco(10 * n, "R1", f"{link} down"))
        lines.append(cisco(10 * n + 4, "R1", f"{link} up"))
    upload = store(db, lines)
    mine_templates(db, upload)

    runs = find_runs(db, upload)

    assert [r.count for r in runs] == [4, 4]
    assert len({r.template_id for r in runs}) == 2


def test_runs_are_returned_in_the_order_they_started(db):
    upload = ingest_file(db, SCENARIOS / "05_dhcp_exhaustion.log", year=2026)
    mine_templates(db, upload)

    runs = find_runs(db, upload)

    assert [r.first_seen for r in runs] == sorted(r.first_seen for r in runs)
    assert sum(r.count for r in runs) == db.count_events(upload)
    refused = db.templates(upload, limit=500)
    refused = next(t for t in refused if t.event_key == "dhcp.no_free_leases")
    longest = max((r for r in runs if r.template_id == refused.id), key=lambda r: r.count)
    assert longest.count > 50 and longest.host == "dhcp1"


def test_runs_before_mining_are_empty(db):
    upload = store(db, [no_lease(0, 0)])

    assert find_runs(db, upload) == []
