"""DNS server logs: ISC BIND (named) and dnsmasq.

Event keys:

  dns.query         a client asked a question
  dns.reply         the server answered: dnsmasq's reply, cached and config lines, and
                    BIND's response log (`responselog`, BIND 9.20.3 and later)
  dns.query_failed  the server could not answer (BIND's query-errors category)
  dns.forwarded     the server passed the question on to another server (dnsmasq)

`src_ip` is the client that asked, `extra.qname` the name asked for and `extra.qtype`
the record type (A, AAAA, MX ...). An answer carries `extra.rcode`: NOERROR, NXDOMAIN
(the name does not exist), SERVFAIL (the server could not get an answer), REFUSED, or
TIMEOUT. An answer that is an address or a name is NOERROR, with the answer in
`extra.answer`.

Names are chosen by whoever asks, so a name can be anything, including text that imitates
an instruction. It is only ever stored and shown as text. In message templates the name is
masked by its position, like a username.

BIND lines can come through syslog (`named[812]: client ...`) or from BIND's own log file
(`21-Nov-2026 10:00:00.123 queries: info: client ...`); `parse_bind_file_line` reads the
second form, which has no host name.
"""

from __future__ import annotations

import re
from datetime import datetime, tzinfo

from netlog.ingestion.reader import RawLine
from netlog.parsers.patterns import PatternSet, Span, clean
from netlog.parsers.syslog import MONTHS
from netlog.schema import Entities, Event, ParseStatus, SourceType

PROGRAMS = ("named", "dnsmasq")

_BIND = PatternSet()
_DNSMASQ = PatternSet()

# `client @0x7f3a2c0a1b70 10.20.0.15#53211 (example.com): ` - the object address appears
# in BIND 9.11 and later, the name in brackets in 9.10 and later, `view x: ` with views.
_CLIENT = (
    r"client (?:@0x[0-9a-fA-F]+ )?(?P<client>[0-9a-fA-F.:]+)#(?P<cport>\d+)"
    r"(?: \([^)]*\))?: (?:view (?P<view>\S+): )?"
)
# The question's name. Called `hostname` so template mining masks it as client-chosen text.
_NAME = r"(?P<hostname>\S+)"


def _rcode(text: str) -> str:
    """BIND and dnsmasq spell the outcome in several ways; one word for each."""
    word = text.strip().upper()
    if "TIMED OUT" in word or word == "TIMEOUT":
        return "TIMEOUT"
    if word in ("NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR", "NOTIMP", "NOERROR"):
        return word
    if word.startswith("NODATA"):
        return "NOERROR"  # the name exists, it has no record of that type
    return word


@_BIND.rule(
    "dns.query",
    "^" + _CLIENT + r"query: " + _NAME + r" (?P<qclass>\S+) (?P<qtype>\S+) (?P<flags>\S*)"
    r"(?: \((?P<server>[0-9a-fA-F.:]+)\))?",
)
def _bind_query(m):
    return {
        "src_ip": m["client"],
        "dst_ip": m["server"],
        "protocol": "dns",
        "extra": clean(
            {"qname": m["hostname"], "qtype": m["qtype"], "qclass": m["qclass"],
             "flags": m["flags"], "src_port": m["cport"], "view": m["view"]}
        ),
    }  # fmt: skip


# BIND 9.20.3 and later with `responselog yes;`: name, class, type, rcode, the counts of
# answer, authority and additional records, the flags and the server's address. Read from
# BIND's source (query.c); no official example line was found.
@_BIND.rule(
    "dns.reply",
    "^" + _CLIENT + r"response: " + _NAME + r" (?P<qclass>\S+) (?P<qtype>\S+) (?P<rcode>\S+)"
    r" (?P<answers>\d+) \d+ \d+ (?P<flags>\S*)(?: \((?P<server>[0-9a-fA-F.:]+)\))?",
)
def _bind_response(m):
    return {
        "src_ip": m["client"],
        "dst_ip": m["server"],
        "protocol": "dns",
        "extra": clean(
            {"qname": m["hostname"], "qtype": m["qtype"], "qclass": m["qclass"],
             "rcode": _rcode(m["rcode"]), "answers": m["answers"], "src_port": m["cport"],
             "view": m["view"]}
        ),
    }  # fmt: skip


@_BIND.rule(
    "dns.query_failed",
    "^" + _CLIENT + r"query failed \((?P<reason>[^)]+)\) for (?P<hostname>[^/\s]+)"
    r"/(?P<qclass>[^/\s]+)/(?P<qtype>\S+)",
)
def _bind_failed(m):
    return {
        "src_ip": m["client"],
        "protocol": "dns",
        "reason": m["reason"],
        "extra": clean(
            {"qname": m["hostname"], "qtype": m["qtype"], "qclass": m["qclass"],
             "rcode": _rcode(m["reason"]), "src_port": m["cport"], "view": m["view"]}
        ),
    }  # fmt: skip


# dnsmasq with log-queries=extra puts a serial number and the client in front of each line:
# `45 10.20.0.15/53211 query[A] example.com from 10.20.0.15`.
_EXTRA = r"^(?:(?P<serial>\d+) (?P<client>[0-9a-fA-F.:]+)/(?P<cport>\d+) )?"


def _dnsmasq_extra(m, **extra) -> dict:
    return clean({"serial": m["serial"], "src_port": m["cport"], **extra})


@_DNSMASQ.rule(
    "dns.query",
    _EXTRA + r"query\[(?P<qtype>[^\]]+)\] " + _NAME + r" from (?P<asker>[0-9a-fA-F.:]+)$",
)
def _dnsmasq_query(m):
    return {
        "src_ip": m["asker"],
        "protocol": "dns",
        "extra": _dnsmasq_extra(m, qname=m["hostname"], qtype=m["qtype"]),
    }


@_DNSMASQ.rule(
    "dns.forwarded",
    _EXTRA + r"forwarded " + _NAME + r" to (?P<upstream>[0-9a-fA-F.:#]+)$",
)
def _dnsmasq_forwarded(m):
    return {
        "src_ip": m["client"],
        "dst_ip": m["upstream"].split("#")[0],
        "protocol": "dns",
        "extra": _dnsmasq_extra(m, qname=m["hostname"]),
    }


@_DNSMASQ.rule(
    "dns.reply",
    _EXTRA + r"(?P<source>reply|cached|config|cached-stale) " + _NAME + r" is (?P<answer>.+?)\s*$",
)
def _dnsmasq_reply(m):
    answer = m["answer"]
    # An upstream error is logged as `reply error is SERVFAIL`: the word "error" stands
    # where the name would be, so the name is not known from this line.
    error = m["hostname"] == "error"
    named = error or re.fullmatch(r"(?:NXDOMAIN|NODATA(?:-IPv[46])?)", answer)
    rcode = _rcode(answer) if named else "NOERROR"
    if error and answer == "not implemented":
        rcode = "NOTIMP"
    return {
        "src_ip": m["client"],
        "protocol": "dns",
        "extra": _dnsmasq_extra(
            m, qname=None if error else m["hostname"], rcode=rcode,
            answer=None if named else answer,
            source=None if m["source"] == "reply" else m["source"],
        ),
    }  # fmt: skip


_BY_PROGRAM = {"named": _BIND, "dnsmasq": _DNSMASQ}


def spans(event: Event) -> list[Span]:
    """Where the name asked for sits in the event's message."""
    patterns = _BY_PROGRAM.get((event.app or "").lower())
    found = patterns.spans(event.message) if patterns else None
    return found or []


def known_event_keys() -> set[str]:
    return {"dns.query", "dns.reply", "dns.query_failed", "dns.forwarded"}


def apply(event: Event) -> Event:
    """Recognize a line from named or dnsmasq. Other events are returned untouched."""
    patterns = _BY_PROGRAM.get((event.app or "").lower())
    if event.parse_status is ParseStatus.UNPARSED or patterns is None:
        return event
    event.source_type = SourceType.DNS
    patterns.apply(event)
    return event


# --- BIND's own log file ------------------------------------------------------------------------

# `21-Nov-2026 10:00:00.123 queries: info: client ...`. The category and the severity are
# printed only when BIND is told to (print-category, print-severity).
_BIND_FILE = re.compile(
    r"^(?P<day>\d{2})-(?P<month>[A-Z][a-z]{2})-(?P<year>\d{4}) "
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?:\.(?P<ms>\d{3}))? "
    r"(?:(?P<category>[a-z][a-z-]*): )?(?:(?P<level>[a-z]+(?: \d+)?): )?(?P<message>client .*)$"
)


def parse_bind_file_line(raw: RawLine, tz: tzinfo) -> Event | None:
    """A line of BIND's own query log, or None if the line is not one. Its time has a
    year but no timezone, so the devices' timezone is assumed."""
    match = _BIND_FILE.match(raw.text)
    if not match or match["month"] not in MONTHS:
        return None
    try:
        when = datetime(
            int(match["year"]), MONTHS[match["month"]], int(match["day"]),
            int(match["hour"]), int(match["minute"]), int(match["second"]),
            int(match["ms"] or 0) * 1000, tzinfo=tz,
        )  # fmt: skip
    except ValueError:
        return None
    event = Event(
        line_no=raw.line_no,
        raw=raw.text,
        timestamp=when,
        tz_assumed=True,
        app="named",
        source_type=SourceType.DNS,
        message=match["message"],
        entities=Entities(extra=clean({"category": match["category"]})),
    )
    if raw.truncated:
        event.parse_status = ParseStatus.PARTIAL
    return apply(event)
