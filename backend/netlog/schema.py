"""The normalized event schema.

Every log line, whatever device wrote it, is converted into one `Event`. Parsers
produce events; storage, detection, correlation and the UI only ever read events.
See docs/SCHEMA.md for the field-by-field description and worked examples.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from enum import IntEnum, StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Severity(IntEnum):
    """Syslog severity levels (RFC 5424). Lower numbers are more serious."""

    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFORMATIONAL = 6
    DEBUG = 7


class SourceType(StrEnum):
    """Which kind of log a line came from. Decides which parser handled it."""

    CISCO_IOS = "cisco_ios"
    LINUX_AUTH = "linux_auth"
    DHCP = "dhcp"
    SYSLOG_GENERIC = "syslog_generic"
    UNKNOWN = "unknown"


class ParseStatus(StrEnum):
    """How much of the line the parsers understood."""

    PARSED = "parsed"
    PARTIAL = "partial"
    UNPARSED = "unparsed"


# Canonical long names for Cisco interface types. A short form is expanded when it
# is an unambiguous prefix of exactly one of these ("Gi" -> GigabitEthernet).
_INTERFACE_TYPES = (
    "FastEthernet",
    "GigabitEthernet",
    "TenGigabitEthernet",
    "TwentyFiveGigE",
    "FortyGigabitEthernet",
    "HundredGigE",
    "Ethernet",
    "Loopback",
    "Port-channel",
    "Vlan",
    "Serial",
    "Tunnel",
    "Null",
)

_INTERFACE_RE = re.compile(r"^([A-Za-z][A-Za-z-]*?)\s*(\d[\d/.:]*)$")


def normalize_interface(name: str) -> str:
    """Return the canonical long form of an interface name.

    `Gi0/1`, `gigabitethernet0/1` and `GigabitEthernet0/1` all become
    `GigabitEthernet0/1`, so events about the same port compare as equal.

    Linux-style names (all lowercase with no slash, such as `eth0` or `ens33`) are
    returned unchanged: expanding `eth0` to `Ethernet0` would invent a name the
    server never used. Names with an unknown or ambiguous type are also unchanged.
    """
    name = name.strip()
    match = _INTERFACE_RE.match(name)
    if not match:
        return name
    if name.islower() and "/" not in name:
        return name

    prefix, number = match.group(1).lower(), match.group(2)
    candidates = [t for t in _INTERFACE_TYPES if t.lower().startswith(prefix)]
    if len(candidates) != 1:
        return name
    return f"{candidates[0]}{number}"


_MAC_SEPARATORS = re.compile(r"[.:\-]")
_MAC_HEX = re.compile(r"^[0-9a-f]{12}$")


def normalize_mac(value: str) -> str:
    """Return a MAC address as lowercase colon-separated pairs.

    Accepts Cisco dotted (`0011.2233.4455`), colon and dash notations.
    """
    digits = _MAC_SEPARATORS.sub("", value.strip().lower())
    if not _MAC_HEX.match(digits):
        raise ValueError(f"not a MAC address: {value!r}")
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def _normalize_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


class Entities(BaseModel):
    """The named things a log line talks about. All optional.

    Detection rules group and match on these, for example "failed logins per
    `src_ip`" or "state changes per `interface`".
    """

    model_config = ConfigDict(extra="forbid")

    interface: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    neighbor_ip: str | None = None
    username: str | None = None
    mac: str | None = None
    vlan: int | None = Field(default=None, ge=1, le=4094)
    protocol: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    state_from: str | None = None
    state_to: str | None = None
    reason: str | None = None
    extra: dict[str, str] = Field(default_factory=dict)

    @field_validator("interface")
    @classmethod
    def _canonical_interface(cls, value: str | None) -> str | None:
        return None if value is None else normalize_interface(value)

    @field_validator("src_ip", "dst_ip", "neighbor_ip")
    @classmethod
    def _valid_ip(cls, value: str | None) -> str | None:
        return None if value is None else _normalize_ip(value)

    @field_validator("mac")
    @classmethod
    def _canonical_mac(cls, value: str | None) -> str | None:
        return None if value is None else normalize_mac(value)


class Event(BaseModel):
    """One log line in normalized form."""

    model_config = ConfigDict(extra="forbid")

    # Identity
    id: int | None = None
    upload_id: int | None = None
    line_no: int = Field(ge=1)
    raw: str

    # Time
    timestamp: datetime | None = None
    year_assumed: bool = False
    tz_assumed: bool = False

    # Origin
    host: str | None = None
    source_type: SourceType = SourceType.UNKNOWN
    app: str | None = None

    # Classification
    facility: int | None = Field(default=None, ge=0, le=23)
    severity: Severity | None = None
    event_key: str | None = None

    # Content
    message: str = ""
    entities: Entities = Field(default_factory=Entities)

    # Processing
    parse_status: ParseStatus = ParseStatus.PARSED
    template_id: str | None = None

    @field_validator("timestamp")
    @classmethod
    def _timestamp_in_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _timestamp_required_unless_unparsed(self) -> Event:
        if self.parse_status is not ParseStatus.UNPARSED and self.timestamp is None:
            raise ValueError("timestamp is required unless parse_status is 'unparsed'")
        return self
