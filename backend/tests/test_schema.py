from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from netlog.schema import (
    Entities,
    Event,
    ParseStatus,
    Severity,
    SourceType,
    normalize_interface,
    normalize_mac,
)

TS = datetime(2026, 3, 3, 2, 14, 7, tzinfo=UTC)


def make_event(**overrides):
    fields = {
        "line_no": 1,
        "raw": "Mar  3 02:14:07 R1 %LINK-3-UPDOWN: Interface Gi0/1, changed state to down",
        "timestamp": TS,
        "host": "R1",
        "source_type": "cisco_ios",
        "severity": 3,
        "event_key": "LINK-3-UPDOWN",
        "message": "Interface Gi0/1, changed state to down",
    }
    fields.update(overrides)
    return Event(**fields)


def test_valid_event_passes():
    event = make_event(entities={"interface": "Gi0/1", "state_to": "down"})

    assert event.severity is Severity.ERROR
    assert event.source_type is SourceType.CISCO_IOS
    assert event.parse_status is ParseStatus.PARSED
    assert event.entities.interface == "GigabitEthernet0/1"
    assert event.template_id is None


def test_missing_timestamp_is_rejected():
    with pytest.raises(ValidationError, match="timestamp is required"):
        make_event(timestamp=None)


def test_timestamp_without_timezone_is_rejected():
    with pytest.raises(ValidationError, match="timezone-aware"):
        make_event(timestamp=datetime(2026, 3, 3, 2, 14, 7))


def test_timestamp_is_converted_to_utc():
    ist = timezone(timedelta(hours=5, minutes=30))
    event = make_event(timestamp=datetime(2026, 3, 3, 7, 44, 7, tzinfo=ist))

    assert event.timestamp == TS
    assert event.timestamp.utcoffset() == timedelta(0)


@pytest.mark.parametrize("severity", [-1, 8, 99])
def test_severity_out_of_range_is_rejected(severity):
    with pytest.raises(ValidationError):
        make_event(severity=severity)


def test_severity_may_be_absent():
    assert make_event(severity=None).severity is None


def test_unknown_source_type_is_rejected():
    with pytest.raises(ValidationError):
        make_event(source_type="juniper_junos")


def test_unknown_parse_status_is_rejected():
    with pytest.raises(ValidationError):
        make_event(parse_status="maybe")


def test_unknown_field_is_rejected():
    with pytest.raises(ValidationError):
        make_event(colour="red")


@pytest.mark.parametrize("facility", [-1, 24])
def test_facility_out_of_range_is_rejected(facility):
    with pytest.raises(ValidationError):
        make_event(facility=facility)


def test_line_number_starts_at_one():
    with pytest.raises(ValidationError):
        make_event(line_no=0)


def test_unparsed_line_needs_only_identity_and_raw():
    event = Event(line_no=42, raw="\x00garbage that no parser understood", parse_status="unparsed")

    assert event.timestamp is None
    assert event.host is None
    assert event.source_type is SourceType.UNKNOWN
    assert event.entities == Entities()


def test_severity_names_follow_the_syslog_standard():
    assert [s.name for s in Severity] == [
        "EMERGENCY",
        "ALERT",
        "CRITICAL",
        "ERROR",
        "WARNING",
        "NOTICE",
        "INFORMATIONAL",
        "DEBUG",
    ]


@pytest.mark.parametrize("spelling", ["Gi0/1", "GigabitEthernet0/1", "gigabitethernet0/1"])
def test_interface_spellings_normalize_to_the_same_value(spelling):
    assert normalize_interface(spelling) == "GigabitEthernet0/1"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Fa0/24", "FastEthernet0/24"),
        ("Te1/0/1", "TenGigabitEthernet1/0/1"),
        ("Gi0/1.100", "GigabitEthernet0/1.100"),
        ("Po1", "Port-channel1"),
        ("Vl10", "Vlan10"),
        ("Lo0", "Loopback0"),
        ("Se0/0/0:1", "Serial0/0/0:1"),
        ("  Gi0/2 ", "GigabitEthernet0/2"),
        ("GigabitEthernet 0/3", "GigabitEthernet0/3"),
    ],
)
def test_interface_short_forms_expand(name, expected):
    assert normalize_interface(name) == expected


@pytest.mark.parametrize("name", ["eth0", "ens33", "wlan0", "T1/1", "Xyz0/1", "console", ""])
def test_linux_ambiguous_and_unknown_interface_names_are_unchanged(name):
    assert normalize_interface(name) == name


@pytest.mark.parametrize(
    "mac", ["0011.2233.4455", "00:11:22:33:44:55", "00-11-22-33-44-55", "0011.2233.44AA"]
)
def test_mac_notations_normalize(mac):
    assert normalize_mac(mac).startswith("00:11:22:33:44:")
    assert len(normalize_mac(mac)) == 17


def test_invalid_mac_is_rejected():
    with pytest.raises(ValidationError):
        Entities(mac="not-a-mac")


def test_ip_addresses_are_validated_and_normalized():
    entities = Entities(src_ip=" 203.0.113.9 ", neighbor_ip="2001:DB8:0:0:0:0:0:1")

    assert entities.src_ip == "203.0.113.9"
    assert entities.neighbor_ip == "2001:db8::1"


def test_invalid_ip_is_rejected():
    with pytest.raises(ValidationError):
        Entities(src_ip="300.1.1.1")


@pytest.mark.parametrize(("field", "value"), [("vlan", 0), ("vlan", 4095), ("port", 65536)])
def test_vlan_and_port_ranges(field, value):
    with pytest.raises(ValidationError):
        Entities(**{field: value})


def test_username_is_kept_exactly_as_logged():
    hostile = "admin from 10.0.0.1 port 22"

    assert Entities(username=hostile).username == hostile
