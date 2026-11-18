from pathlib import Path

import pytest

from netlog.ingestion.reader import BinaryFileError, read_lines
from netlog.parsers.pipeline import Coverage, line_shape, parse_file
from netlog.schema import ParseStatus

LINE = "Mar  3 02:14:07 host1 app: hello"


def write(tmp_path: Path, data: bytes) -> Path:
    path = tmp_path / "sample.log"
    path.write_bytes(data)
    return path


def texts(path, **options):
    return [raw.text for raw in read_lines(path, **options)]


def test_reads_unix_and_windows_line_endings(tmp_path):
    path = write(tmp_path, b"one\ntwo\r\nthree")

    assert texts(path) == ["one", "two", "three"]


def test_strips_utf8_byte_order_mark(tmp_path):
    path = write(tmp_path, b"\xef\xbb\xbf" + LINE.encode() + b"\n")

    assert texts(path) == [LINE]


def test_reads_utf16_as_written_by_powershell(tmp_path):
    path = write(tmp_path, f"{LINE}\r\nsecond\r\n".encode("utf-16"))

    assert texts(path) == [LINE, "second"]


def test_falls_back_when_a_line_is_not_utf8(tmp_path):
    path = write(tmp_path, b"caf\xe9 one\n" + "café two\n".encode())

    assert texts(path) == ["café one", "café two"]


def test_blank_lines_keep_line_numbers_in_step_with_the_file(tmp_path):
    path = write(tmp_path, b"one\n\n   \nfour\n")

    lines = list(read_lines(path))

    assert [(raw.line_no, raw.text) for raw in lines] == [(1, "one"), (2, ""), (3, "   "), (4, "four")]  # noqa: E501


def test_overlong_line_is_cut_and_the_next_line_is_intact(tmp_path):
    path = write(tmp_path, b"a" * 5000 + b"\nshort\n")

    first, second = read_lines(path, max_line_length=100)

    assert (first.text, first.truncated) == ("a" * 100, True)
    assert (second.line_no, second.text, second.truncated) == (2, "short", False)


def test_line_exactly_at_the_limit_is_not_truncated(tmp_path):
    path = write(tmp_path, b"a" * 100 + b"\nnext\n")

    first, second = read_lines(path, max_line_length=100)

    assert (first.text, first.truncated) == ("a" * 100, False)
    assert second.text == "next"


def test_overlong_last_line_without_newline(tmp_path):
    path = write(tmp_path, b"ok\n" + b"b" * 300)

    _, last = read_lines(path, max_line_length=100)

    assert (last.text, last.truncated) == ("b" * 100, True)


def test_truncation_in_the_middle_of_a_character_does_not_fail(tmp_path):
    path = write(tmp_path, ("é" * 200).encode() + b"\n")

    (line,) = read_lines(path, max_line_length=101)

    assert line.truncated and line.text.startswith("é" * 50)


def test_binary_file_is_rejected(tmp_path):
    path = write(tmp_path, b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")

    with pytest.raises(BinaryFileError, match="not a text file"):
        list(read_lines(path))


def test_empty_file_yields_nothing(tmp_path):
    assert texts(write(tmp_path, b"")) == []


def test_parse_file_keeps_every_line_and_counts_coverage(tmp_path):
    path = write(
        tmp_path,
        (
            f"{LINE}\n"
            "\n"
            "not a log line 42\n"
            "not a log line 77\n"
            "<34>Oct 11 22:14:15 mymachine su: failed\n"
            "Mar  3 02:14:08 host1 app: " + "x" * 500 + "\n"
        ).encode(),
    )
    coverage = Coverage()

    events = list(parse_file(path, year=2026, max_line_length=200, coverage=coverage))

    assert [e.line_no for e in events] == [1, 3, 4, 5, 6]
    assert [e.parse_status for e in events] == [
        ParseStatus.PARSED,
        ParseStatus.UNPARSED,
        ParseStatus.UNPARSED,
        ParseStatus.PARSED,
        ParseStatus.PARTIAL,
    ]
    assert events[1].raw == "not a log line 42"
    assert (coverage.parsed, coverage.partial, coverage.unparsed, coverage.blank) == (2, 1, 2, 1)
    assert coverage.total == 5
    assert coverage.percent_parsed == 40.0
    assert coverage.top_unparsed() == [("not a log line N", 2)]


def test_coverage_of_an_empty_file_is_zero():
    assert Coverage().percent_parsed == 0.0


def test_line_shape_groups_lines_that_differ_only_in_numbers():
    assert line_shape("error 17 on port 8080") == line_shape("error 3 on port 22")


@pytest.mark.parametrize("path", sorted(Path("data/scenarios").glob("*.log")), ids=lambda p: p.name)
def test_every_scenario_line_has_a_readable_time_and_host(path):
    coverage = Coverage()
    hosts = set()
    previous = None
    for event in parse_file(path, year=2026, coverage=coverage):
        hosts.add(event.host)
        assert previous is None or event.timestamp >= previous
        previous = event.timestamp

    assert coverage.unparsed == 0 and coverage.partial == 0
    assert hosts <= {"R1", "R2", "R3", "R4", "SW1", "SW2", "srv1", "dhcp1"}
