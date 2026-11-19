"""Linux authentication logs: sshd, sudo and PAM session messages.

Usernames are typed by whoever is trying to log in, so they can contain spaces or text
that imitates the rest of the message (`admin from 10.0.0.1 port 22`). The address and
port that sshd itself appends are always at the end of the line, so every pattern here
is anchored at the end and lets the username take whatever is left.
"""

from __future__ import annotations

from netlog.parsers.patterns import PatternSet, clean, is_ip
from netlog.schema import Event, ParseStatus, SourceType

# Programs whose lines belong to the authentication log, by lowercased name.
PROGRAMS = ("sshd", "sudo", "cron")

_SSHD = PatternSet()
_SUDO = PatternSet()
_PAM = PatternSet()

_FROM = r" from (?P<src>\S+) port (?P<port>\d+)"


def _source(match, **fields) -> dict:
    """Common fields for sshd messages. A source that is a hostname goes into `extra`."""
    src = match["src"]
    extra = fields.pop("extra", {})
    if not is_ip(src):
        extra["src_host"], src = src, None
    port = match.groupdict().get("port")
    return {
        "protocol": "ssh",
        "src_ip": src,
        "port": int(port) if port else None,
        "extra": clean(extra),
        **fields,
    }


def _invalid(match) -> dict[str, str | None]:
    return {"invalid_user": "true" if match["kind"] and "invalid" in match["kind"] else None}


@_SSHD.rule(
    "sshd.failed_password",
    r"^Failed (?P<method>\S+) for (?P<kind>invalid user )?(?P<user>.*)" + _FROM + r"(?: ssh2)?$",
)
def _failed(m):
    extra = {**_invalid(m), "method": None if m["method"] == "password" else m["method"]}
    return _source(m, username=m["user"], extra=extra)


@_SSHD.rule(
    "sshd.accepted",
    r"^Accepted (?P<method>\S+) for (?P<user>.*)" + _FROM + r"(?: ssh2)?(?:: .*)?$",
)
def _accepted(m):
    return _source(m, username=m["user"], extra={"method": m["method"]})


@_SSHD.rule(
    "sshd.max_auth_attempts",
    r"maximum authentication attempts exceeded for (?P<kind>invalid user )?(?P<user>.*)"
    + _FROM
    + r"(?: ssh2)?(?: \[preauth\])?$",
)
def _max_attempts(m):
    return _source(m, username=m["user"], extra=_invalid(m))


@_SSHD.rule(
    "sshd.invalid_user", r"^Invalid user (?P<user>.*) from (?P<src>\S+)(?: port (?P<port>\d+))?$"
)
def _invalid_user(m):
    return _source(m, username=m["user"], extra={"invalid_user": "true"})


@_SSHD.rule(
    "sshd.connection_closed",
    r"^(?:Connection closed by|Disconnected from|Disconnecting)"
    r"(?: (?P<kind>invalid|authenticating) user (?P<user>.*))? (?P<src>\S+) port (?P<port>\d+)"
    r"(?::\s*(?P<reason>.*?))?(?: \[preauth\])?$",
)
def _closed(m):
    return _source(m, username=m["user"], reason=m["reason"] or None, extra=_invalid(m))


@_SSHD.rule(
    "sshd.auth_failure",
    r"^pam_unix\(sshd:auth\): authentication failure;.*?rhost=(?P<src>\S+)"
    r"(?:\s+user=(?P<user>.*))?$",
)
def _pam_auth_failure(m):
    return _source(m, username=m["user"])


@_SUDO.rule(
    "sudo.command",
    r"^(?P<user>\S+) : (?:(?P<note>.*?) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; "
    r"USER=(?P<target>\S+) ; COMMAND=(?P<command>.*)$",
)
def _sudo(m):
    fields = {
        "username": m["user"],
        "extra": {"target_user": m["target"], "command": m["command"], "tty": m["tty"]},
    }
    note = m["note"] or ""
    if "incorrect password" in note:
        fields["event_key"] = "sudo.auth_failure"
        fields["extra"]["attempts"] = note.split()[0]
    elif "NOT in sudoers" in note:
        fields["event_key"] = "sudo.not_in_sudoers"
    return fields


# `pam_unix(sshd:session): session opened for user alice(uid=1002) by (uid=0)`
@_PAM.rule(
    "session",
    r"^pam_unix\((?P<service>[\w-]+):session\): session (?P<state>opened|closed) "
    r"for user (?P<user>[^\s(]+)",
)
def _session(m):
    return {
        "event_key": f"{m['service'].lower()}.session_{m['state']}",
        "username": m["user"],
        "state_to": m["state"],
    }


_BY_PROGRAM = {"sshd": (_SSHD, _PAM), "sudo": (_SUDO, _PAM), "cron": (_PAM,)}


def apply(event: Event) -> Event:
    """Recognize a line from sshd, sudo or cron. Other events are returned untouched."""
    program = (event.app or "").lower()
    if event.parse_status is ParseStatus.UNPARSED or program not in _BY_PROGRAM:
        return event
    event.source_type = SourceType.LINUX_AUTH
    for patterns in _BY_PROGRAM[program]:
        patterns.apply(event)
        if event.event_key:
            break
    return event
