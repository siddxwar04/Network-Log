"""`netlog alerts ...`: check the alert setup, and silence alerts for maintenance.

    netlog alerts test                          send a clearly labelled test alert
    netlog alerts list                          the silences and the latest alerts
    netlog alerts silence --device R1 --for 2h  no alerts about R1 for two hours
    netlog alerts unsilence 3                   end silence 3 now

They work on the same database as the web API (NETLOG_DB_PATH, data/netlog.db by
default), so a silence set here applies to a listener that is already running.
"""

from __future__ import annotations

import re
import sys
from datetime import UTC, datetime

from netlog.alerts.alerter import add_silence, alerter_from_config
from netlog.config import load_config
from netlog.storage.database import Database, default_db_path

EXIT_OK, EXIT_FAILED, EXIT_ERROR = 0, 1, 2
_LENGTH = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([mhd]?)\s*$", re.IGNORECASE)
_UNIT_MINUTES = {"": 1, "m": 1, "h": 60, "d": 1440}


def minutes_of(text: str) -> float:
    """"90", "90m", "2h" or "1d" as minutes."""
    match = _LENGTH.match(text)
    if not match:
        raise ValueError(f"{text!r} is not a length of time; write it like 30m, 2h or 1d")
    return float(match[1]) * _UNIT_MINUTES[match[2].lower()]


def add_parser(commands) -> None:
    alerts = commands.add_parser(
        "alerts",
        help="test alerts and silence them for maintenance",
        description="Check that alerts reach your chat, and silence them for planned "
        "maintenance. Webhook addresses are read from NETLOG_ALERT_SLACK_URL and "
        "NETLOG_ALERT_WEBHOOK_URL, in .env or the environment.",
    )
    sub = alerts.add_subparsers(dest="alerts_command", required=True, metavar="command")
    test = sub.add_parser(
        "test",
        help="send a clearly labelled test alert",
        description="Send a test alert to every webhook that is set, and say whether each "
        "one arrived.",
        epilog="Exit code: 0 delivered everywhere, 1 a delivery failed, 2 no webhook is set.",
    )
    show = sub.add_parser("list", help="show the silences and the latest alerts")
    show.add_argument("--limit", type=int, default=20, help="how many alerts (default: 20)")
    silence = sub.add_parser(
        "silence",
        help="silence a device, an incident type or everything for a while",
        description="Stop alerts about a device, an incident type, or everything, for a "
        "while. Incidents are still detected and recorded.",
    )
    which = silence.add_mutually_exclusive_group(required=True)
    which.add_argument("--device", help="a device name, such as R1")
    which.add_argument(
        "--type", help="an incident type: a rule name such as link_flap, or link_failure"
    )
    which.add_argument("--all", action="store_true", help="every alert")
    silence.add_argument(
        "--for", dest="length", required=True, metavar="LENGTH",
        help="how long: 30m, 2h, 1d",
    )  # fmt: skip
    silence.add_argument("--reason", default="", help="why, such as planned maintenance")
    end = sub.add_parser("unsilence", help="end a silence now")
    end.add_argument("id", type=int, help="the silence's number, as `netlog alerts list` shows")
    for command in (test, show, silence, end):
        command.add_argument("--config", help="a settings file that overrides the defaults")


def _when(moment: datetime | None) -> str:
    return moment.strftime("%Y-%m-%d %H:%M UTC") if moment else "-"


def alerts_command(args) -> int:
    now = datetime.now(UTC)
    try:
        config = load_config(args.config)
        alerter = alerter_from_config(default_db_path(), config)
    except ValueError as error:
        print(f"netlog: {error}", file=sys.stderr)
        return EXIT_ERROR
    command = args.alerts_command

    if command == "test":
        if not alerter.enabled:
            print(
                "netlog: no webhook is set; put NETLOG_ALERT_SLACK_URL or "
                "NETLOG_ALERT_WEBHOOK_URL in .env",
                file=sys.stderr,
            )
            return EXIT_ERROR
        result = alerter.send_test(now)
        for delivery in result["deliveries"]:
            if delivery["ok"]:
                print(f"{delivery['target']}: delivered")
            else:
                tries = delivery["attempts"]
                print(f"{delivery['target']}: FAILED after {tries} tries ({delivery['error']})")
        return EXIT_OK if result["sent"] else EXIT_FAILED

    if command == "silence":
        scope = "device" if args.device else "type" if args.type else "all"
        value = args.device or args.type
        try:
            made = add_silence(
                default_db_path(), alerter.settings, scope, value, minutes_of(args.length),
                args.reason, now,
            )  # fmt: skip
        except ValueError as error:
            print(f"netlog: {error}", file=sys.stderr)
            return EXIT_ERROR
        what = "every alert" if scope == "all" else f"{scope} {value}"
        print(f"Silence {made['id']}: no alerts for {what} until {_when(made['ends_at'])}.")
        return EXIT_OK

    with Database(default_db_path()) as db:
        if command == "unsilence":
            if not db.end_silence(args.id, now):
                print(f"netlog: there is no silence {args.id}", file=sys.stderr)
                return EXIT_ERROR
            print(f"Silence {args.id} ended.")
            return EXIT_OK

        targets = ", ".join(t.name for t in alerter.settings.targets) or "none set"
        print(f"Webhooks: {targets}. Alerts at {alerter.settings.min_severity} and above.")
        active = [s for s in db.silences() if s["starts_at"] <= now < s["ends_at"]]
        print(f"\nSilences in force: {len(active) or 'none'}")
        for s in active:
            what = "everything" if s["scope"] == "all" else f"{s['scope']} {s['value']}"
            reason = f" ({s['reason']})" if s["reason"] else ""
            print(f"  {s['id']:>4}  {what} until {_when(s['ends_at'])}{reason}")
        recent = db.alerts(limit=max(1, args.limit))
        print(f"\nLatest alerts: {len(recent) or 'none'}")
        for a in recent:
            title = a["message"].get("title") or ""
            about = a["incident_id"] or ""
            print(f"  {a['id']:>4}  {_when(a['created_at'])}  {a['kind']:<7} {a['status']:<9} "
                  f"{(a['severity'] or ''):<8} {about} {title}")  # fmt: skip
    return EXIT_OK

