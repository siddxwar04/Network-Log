"""Line formats found when the tool was first run on logs from real devices (prompt 6.2).

Every case is a sanitized copy of a real line: addresses moved into private and
documentation ranges, names and identifiers replaced. See docs/REAL_LOG_TESTING.md.
"""

import json
from pathlib import Path

import pytest

from netlog.ingestion.reader import RawLine
from netlog.parsers.pipeline import LineParser

GOLDEN = json.loads(
    (Path(__file__).parent / "golden" / "real_world.json").read_text(encoding="utf-8")
)


def assert_subset(expected, actual, path=""):
    if isinstance(expected, dict):
        assert isinstance(actual, dict), f"{path}: expected an object, got {actual!r}"
        for key, value in expected.items():
            assert key in actual, f"{path}.{key} is missing"
            assert_subset(value, actual[key], f"{path}.{key}")
    else:
        assert actual == expected, f"{path}: expected {expected!r}, got {actual!r}"


@pytest.mark.parametrize("case", GOLDEN, ids=[case["name"] for case in GOLDEN])
def test_golden(case):
    event = LineParser(year=2026).parse(RawLine(1, case["line"]))
    assert_subset(case["expect"], event.model_dump(mode="json"))


def test_the_year_in_an_asa_header_carries_to_the_next_line_without_one():
    parser = LineParser(year=2026)
    first = parser.parse(RawLine(1, "Dec 31 2024 23:59:58 FW1 : %ASA-6-302016: x"))
    line = "Jan  1 00:00:01 srv1 sshd[1]: Connection closed by 10.0.0.9 port 2"
    second = parser.parse(RawLine(2, line))
    assert first.timestamp.year == 2024
    assert second.timestamp.year == 2025


def test_a_time_that_is_not_a_date_leaves_the_line_unparsed():
    event = LineParser(year=2026).parse(RawLine(1, "2026-02-30T10:00:00Z srv1 sshd[1]: text"))
    assert event.parse_status.value == "unparsed"
