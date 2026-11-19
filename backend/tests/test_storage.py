import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from netlog.ingestion.ingest import ingest_file
from netlog.ingestion.reader import BinaryFileError, RawLine
from netlog.parsers.pipeline import LineParser
from netlog.schema import ParseStatus
from netlog.storage.database import SCHEMA_VERSION, Database, EventFilter

ATTACKER = "192.0.2.77"
LINES = [
    "Mar  3 02:00:00 R1 10: Mar  3 02:00:00.100: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down",  # noqa: E501
    "Mar  3 02:00:01 R1 11: Mar  3 02:00:01.100: %LINEPROTO-5-UPDOWN: Line protocol on Interface Gi0/1, changed state to down",  # noqa: E501
    "Mar  3 02:00:30 R2 20: Mar  3 02:00:30.500: %BGP-5-ADJCHANGE: neighbor 10.255.0.1 Down BGP Notification sent",  # noqa: E501
    "Mar  3 02:01:00 srv1 sshd[100]: Failed password for invalid user admin from 192.0.2.77 port 4000 ssh2",  # noqa: E501
    "Mar  3 02:01:05 srv1 sshd[101]: Failed password for root from 192.0.2.77 port 4001 ssh2",
    "Mar  3 02:01:09 srv1 sshd[102]: Accepted password for deploy from 10.10.10.50 port 4002 ssh2",
    "Mar  3 02:02:00 dhcp1 dhcpd[811]: DHCPDISCOVER from 00:11:22:33:44:55 via eth1: network 10.20.0.0/24: no free leases",  # noqa: E501
    "this line is not a log line",
]


def at(hour, minute, second=0):
    return datetime(2026, 3, 3, hour, minute, second, tzinfo=UTC)


@pytest.fixture
def db(tmp_path):
    with Database(tmp_path / "test.db") as database:
        yield database


@pytest.fixture
def parsed():
    parser = LineParser(year=2026)
    return [parser.parse(RawLine(n, line)) for n, line in enumerate(LINES, 1)]


@pytest.fixture
def upload(db, parsed):
    upload_id = db.create_upload("sample.log", 1234)
    db.add_events(upload_id, parsed)
    return upload_id


def lines(events):
    return [e.line_no for e in events]


# --- Round trip ------------------------------------------------------------------------


def test_stored_events_come_back_identical(db, upload, parsed):
    fetched = sorted(db.events(upload, limit=100), key=lambda e: e.line_no)

    assert len(fetched) == len(parsed)
    for before, after in zip(parsed, fetched, strict=True):
        assert after.id is not None and after.upload_id == upload
        assert after.model_dump(exclude={"id", "upload_id"}) == before.model_dump(
            exclude={"id", "upload_id"}
        )


def test_unparsed_line_is_stored_and_comes_first(db, upload):
    first = db.events(upload, limit=1)[0]

    assert first.parse_status is ParseStatus.UNPARSED
    assert first.timestamp is None and first.raw == LINES[-1]


def test_events_are_returned_in_time_order(db, upload):
    times = [e.timestamp for e in db.events(upload) if e.timestamp]

    assert times == sorted(times)
    assert lines(db.events(upload, newest_first=True))[0] == 7


def test_add_events_in_small_batches(db, parsed):
    upload_id = db.create_upload("batched.log")

    assert db.add_events(upload_id, iter(parsed), batch_size=3) == len(parsed)
    assert db.count_events(upload_id) == len(parsed)
    assert db.count_events(upload_id, EventFilter(text="password")) == 3


# --- Filters ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("where", "expected"),
    [
        (EventFilter(start=at(2, 1)), [4, 5, 6, 7]),
        (EventFilter(end=at(2, 1)), [1, 2, 3]),
        (EventFilter(start=at(2, 0, 30), end=at(2, 1, 5)), [3, 4]),
        (EventFilter(host="R1"), [1, 2]),
        (EventFilter(source_type="linux_auth"), [4, 5, 6]),
        (EventFilter(parse_status="unparsed"), [8]),
        (EventFilter(min_severity=3), [1]),
        (EventFilter(min_severity=5), [1, 2, 3]),
        (EventFilter(event_keys=["sshd.failed_password"]), [4, 5]),
        (EventFilter(event_keys=["LINK-3-UPDOWN", "BGP-5-ADJCHANGE"]), [1, 3]),
        (EventFilter(entities={"src_ip": ATTACKER}), [4, 5]),
        (EventFilter(entities={"interface": "GigabitEthernet0/1"}), [1, 2]),
        (EventFilter(entities={"neighbor_ip": "10.255.0.1"}), [3]),
        (EventFilter(entities={"port": 4001}), [5]),
        (EventFilter(entities={"mac": "00:11:22:33:44:55"}), [7]),
        (EventFilter(host="srv1", entities={"src_ip": ATTACKER, "username": "root"}), [5]),
        (EventFilter(text="password"), [4, 5, 6]),
        (EventFilter(text="failed password root"), [5]),
        (EventFilter(text="no free leases"), [7]),
        (EventFilter(text="LINK-3-UPDOWN"), [1]),
        (EventFilter(text="updown R1"), [1, 2]),
        (EventFilter(text="dhcpd"), [7]),
        (EventFilter(text="nonexistentword"), []),
        (EventFilter(host="nobody"), []),
    ],
)
def test_filters(db, upload, where, expected):
    assert sorted(lines(db.events(upload, where))) == expected
    assert db.count_events(upload, where) == len(expected)
    assert sorted(lines(db.iter_events(upload, where))) == expected


def test_filter_rejects_a_field_that_is_not_an_entity(db, upload):
    with pytest.raises(ValueError, match="not an entity field"):
        db.events(upload, EventFilter(entities={"host; DROP TABLE events": "x"}))


def test_filters_only_see_their_own_upload(db, upload, parsed):
    other = db.create_upload("other.log")
    db.add_events(other, parsed[:2])

    assert db.count_events(upload) == 8
    assert db.count_events(other) == 2
    assert db.count_events(other, EventFilter(text="password")) == 0


# --- Pagination ------------------------------------------------------------------------


def test_pagination_covers_everything_once(db, upload):
    pages = [lines(db.events(upload, limit=3, offset=offset)) for offset in (0, 3, 6, 9)]

    assert [len(page) for page in pages] == [3, 3, 2, 0]
    assert sorted(n for page in pages for n in page) == list(range(1, 9))


def test_page_size_zero_returns_nothing(db, upload):
    assert db.events(upload, limit=0) == []


# --- Counts ----------------------------------------------------------------------------


def test_count_by_host_and_event_key(db, upload):
    assert db.count_by(upload, "host") == [("srv1", 3), ("R1", 2), (None, 1), ("R2", 1), ("dhcp1", 1)]  # noqa: E501
    assert db.count_by(upload, "event_key", EventFilter(host="srv1")) == [
        ("sshd.failed_password", 2),
        ("sshd.accepted", 1),
    ]
    assert db.count_by(upload, "src_ip", EventFilter(source_type="linux_auth")) == [
        (ATTACKER, 2),
        ("10.10.10.50", 1),
    ]


def test_count_by_rejects_an_unknown_column(db, upload):
    with pytest.raises(ValueError, match="cannot group by"):
        db.count_by(upload, "raw")


def test_histogram_counts_per_time_bucket(db, upload):
    assert db.histogram(upload, 60) == [(at(2, 0), 3), (at(2, 1), 3), (at(2, 2), 1)]
    assert db.histogram(upload, 3600, EventFilter(host="R1")) == [(at(2, 0), 2)]
    with pytest.raises(ValueError):
        db.histogram(upload, 0)


def test_time_range(db, upload):
    first, last = db.time_range(upload)

    assert first == at(2, 0) + timedelta(milliseconds=100)
    assert last == at(2, 2)
    assert db.time_range(db.create_upload("empty.log")) is None


# --- Raw lines -------------------------------------------------------------------------


def test_raw_line_and_context(db, upload):
    assert db.raw_line(upload, 4) == LINES[3]
    assert db.raw_line(upload, 99) is None
    assert db.context(upload, 4, before=1, after=2) == [(n, LINES[n - 1]) for n in (3, 4, 5, 6)]
    assert db.context(upload, 1, before=5, after=0) == [(1, LINES[0])]


def test_text_that_looks_like_sql_is_stored_and_found_unchanged(db):
    hostile = "Mar  3 02:00:00 srv1 sshd[1]: Failed password for invalid user x'; DROP TABLE events;-- \"q\" from 192.0.2.77 port 1 ssh2"  # noqa: E501
    upload_id = db.create_upload("it's \"quoted\".log")
    db.add_events(upload_id, [LineParser(year=2026).parse(RawLine(1, hostile))])
    username = "x'; DROP TABLE events;-- \"q\""

    (event,) = db.events(upload_id)
    assert event.raw == hostile and event.entities.username == username
    assert lines(db.events(upload_id, EventFilter(entities={"username": username}))) == [1]
    assert lines(db.events(upload_id, EventFilter(text='DROP TABLE "events" OR NOT x*'))) == []
    assert lines(db.events(upload_id, EventFilter(text="DROP TABLE events"))) == [1]
    assert db.count_events(upload_id, EventFilter(text="'\"*^:()")) == 0
    assert db.get_upload(upload_id).filename == "it's \"quoted\".log"


# --- Uploads ---------------------------------------------------------------------------


def test_upload_lifecycle(db, tmp_path):
    path = tmp_path / "small.log"
    path.write_text("\n".join(LINES) + "\n\n", encoding="utf-8")

    upload_id = ingest_file(db, path, year=2026)
    upload = db.get_upload(upload_id)

    assert (upload.filename, upload.status, upload.error) == ("small.log", "done", None)
    assert upload.size_bytes == path.stat().st_size
    assert (upload.line_count, upload.parsed, upload.unparsed, upload.blank) == (8, 7, 1, 1)
    assert upload.classified == 7 and upload.percent_parsed == 87.5
    assert upload.finished_at >= upload.created_at
    assert [u.id for u in db.list_uploads()] == [upload_id]
    assert db.get_upload(999) is None


def test_unreadable_file_is_recorded_as_failed(db, tmp_path):
    path = tmp_path / "image.png"
    path.write_bytes(b"\x89PNG\x00\x00\x00")

    with pytest.raises(BinaryFileError):
        ingest_file(db, path)

    (upload,) = db.list_uploads()
    assert upload.status == "failed" and "not a text file" in upload.error
    assert db.count_events(upload.id) == 0


def test_deleting_an_upload_removes_everything_that_belongs_to_it(db, upload, parsed, tmp_path):
    keep = db.create_upload("keep.log")
    db.add_events(keep, parsed[:3])

    assert db.delete_upload(upload) is True
    assert db.delete_upload(upload) is False

    assert db.get_upload(upload) is None
    assert db.count_events(upload) == 0 and db.raw_line(upload, 1) is None
    assert db.count_events(keep) == 3 and db.raw_line(keep, 1) == LINES[0]
    # The full-text index has forgotten the deleted events too.
    raw = sqlite3.connect(tmp_path / "test.db")
    count = "SELECT COUNT(*) FROM events_fts WHERE events_fts MATCH ?"
    assert raw.execute(count, ("password",)).fetchone()[0] == 0
    assert raw.execute(count, ("sshd",)).fetchone()[0] == 0
    assert raw.execute(count, ("neighbor",)).fetchone()[0] == 1
    raw.close()


# --- The database file -----------------------------------------------------------------


def test_data_survives_reopening(tmp_path, parsed):
    path = tmp_path / "nested" / "folder" / "keep.db"
    with Database(path) as first:
        upload_id = first.create_upload("a.log")
        first.add_events(upload_id, parsed)

    with Database(path) as second:
        assert second.schema_version == SCHEMA_VERSION
        assert second.count_events(upload_id) == len(parsed)


def test_database_from_a_newer_release_is_refused(tmp_path):
    path = tmp_path / "future.db"
    Database(path).close()
    raw = sqlite3.connect(path)
    raw.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    raw.close()

    with pytest.raises(RuntimeError, match="newer release"):
        Database(path)


def test_database_path_comes_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("NETLOG_DB_PATH", str(tmp_path / "from-env.db"))

    Database().close()

    assert (tmp_path / "from-env.db").exists()


def test_scenario_file_loads_and_answers_rule_style_queries(db):
    upload_id = ingest_file(db, Path("data/scenarios/04_brute_force.log"), year=2026)
    failed = EventFilter(event_keys=["sshd.failed_password"], entities={"src_ip": ATTACKER})

    assert db.get_upload(upload_id).percent_parsed == 100.0
    assert db.count_events(upload_id, failed) == 400
    assert db.count_by(upload_id, "src_ip", EventFilter(event_keys=["sshd.failed_password"]))[0] == (ATTACKER, 400)  # noqa: E501
    busiest = max(db.histogram(upload_id, 600, failed), key=lambda bucket: bucket[1])
    assert busiest[1] > 200
