import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from netlog.ingestion.reader import RawLine
from netlog.parsers.syslog import LineFormat, SyslogParser, detect_format, parse_timezone
from netlog.schema import ParseStatus

GOLDEN = json.loads((Path(__file__).parent / "golden" / "syslog.json").read_text(encoding="utf-8"))


def parse(line: str, **options):
    return SyslogParser(year=2026, **options).parse(RawLine(1, line))


def assert_subset(expected, actual, path=""):
    """Every field named in the golden file must match; other fields are not checked."""
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


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("<165>1 2026-03-03T22:14:15Z host app - - - msg", LineFormat.RFC5424),
        ("<34>Oct 11 22:14:15 host su: msg", LineFormat.RFC3164_PRI),
        ("Oct 11 22:14:15 host su: msg", LineFormat.RFC3164),
        ("Mar  3 02:14:07 host su: msg", LineFormat.RFC3164),
        ("2026-03-03 22:14:15 host su: msg", LineFormat.UNKNOWN),
        ("<189>1042: *Mar  1 00:00:52.000: %SYS-5-RESTART: System restarted", LineFormat.UNKNOWN),
        ("", LineFormat.UNKNOWN),
    ],
)
def test_format_detection(line, expected):
    assert detect_format(line) is expected


def test_assumed_timezone_is_applied_to_rfc3164():
    event = parse("Mar  3 07:44:07 host1 app: hi", tz=parse_timezone("+05:30"))

    assert event.timestamp == datetime(2026, 3, 3, 2, 14, 7, tzinfo=UTC)
    assert event.tz_assumed is True


def test_year_advances_when_the_log_crosses_new_year():
    parser = SyslogParser(year=2025)
    lines = [
        "Dec 31 23:59:58 host1 app: last of the old year",
        "Dec 31 23:59:59 host1 app: still the old year",
        "Jan  1 00:00:01 host1 app: first of the new year",
        "Jan  1 00:00:02 host1 app: still the new year",
        "Feb  1 00:00:00 host1 app: a month later",
    ]

    years = [parser.parse(RawLine(n, line)).timestamp.year for n, line in enumerate(lines, 1)]

    assert years == [2025, 2025, 2026, 2026, 2026]


def test_year_does_not_advance_for_a_small_step_backwards():
    parser = SyslogParser(year=2026)
    parser.parse(RawLine(1, "Apr  1 00:00:01 host1 app: a"))

    late_arrival = parser.parse(RawLine(2, "Mar 31 23:59:59 host1 app: logged late"))

    assert late_arrival.timestamp.year == 2026


def test_unparseable_line_does_not_disturb_the_year():
    parser = SyslogParser(year=2025)
    parser.parse(RawLine(1, "Dec 31 23:59:59 host1 app: a"))
    parser.parse(RawLine(2, "Feb 31 00:00:00 host1 app: impossible date"))

    assert parser.parse(RawLine(3, "Dec 31 23:59:59 host1 app: b")).timestamp.year == 2025


def test_truncated_line_is_partial():
    event = SyslogParser(year=2026).parse(
        RawLine(1, "Mar  3 02:14:07 host1 app: cut off he", truncated=True)
    )

    assert event.parse_status is ParseStatus.PARTIAL
    assert event.host == "host1"


def test_truncated_line_that_cannot_be_parsed_is_unparsed():
    event = SyslogParser(year=2026).parse(RawLine(1, "garbage garbage", truncated=True))

    assert event.parse_status is ParseStatus.UNPARSED


def test_default_year_is_the_current_year():
    event = SyslogParser().parse(RawLine(1, "Mar  3 02:14:07 host1 app: hi"))

    assert event.timestamp.year == datetime.now(UTC).year


@pytest.mark.parametrize(
    ("text", "offset"),
    [
        ("UTC", timedelta(0)),
        ("z", timedelta(0)),
        ("+05:30", timedelta(hours=5, minutes=30)),
        ("-0800", timedelta(hours=-8)),
        ("+1:00", timedelta(hours=1)),
    ],
)
def test_parse_timezone(text, offset):
    assert parse_timezone(text).utcoffset(datetime(2026, 3, 3)) == offset


@pytest.mark.parametrize("text", ["+25:00", "Mars/Olympus", ""])
def test_parse_timezone_rejects_nonsense(text):
    with pytest.raises(ValueError):
        parse_timezone(text)
