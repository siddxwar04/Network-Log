"""The command line.

    netlog analyze <file>             analyze a log file and print a report
    netlog postmortem <file>          draft the post-mortem of one incident in a log file
    netlog demo-explanations --yes    have the LLM explain the demo scenarios once, and
                                      store the answers with them
    netlog rules test <rules> <log>   try a rule file on a log file before relying on it
    netlog replay <file>              send a log file to the live listener, as if now

Exit codes, so the tool can be used in scripts:
    0   nothing found at or above the minimum severity
    1   at least one finding at or above the minimum severity
    2   the analysis could not be done (file missing, not a log, bad option)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from netlog import __version__
from netlog.config import load_config
from netlog.correlation.grouping import correlate
from netlog.correlation.priors import load_priors
from netlog.correlation.topology import load_topology
from netlog.demo import demo_explanations
from netlog.detection.engine import detect
from netlog.detection.rules import LEVELS, load_rule_set
from netlog.ingestion.ingest import ingest_file
from netlog.ingestion.reader import BinaryFileError
from netlog.live.replay import replay, sender
from netlog.llm.explanation import MODES
from netlog.llm.provider import Provider
from netlog.llm.settings import llm_settings, load_env_file
from netlog.mining.templates import mine_templates
from netlog.parsers.syslog import parse_timezone
from netlog.report.build import Report, build_report, to_json
from netlog.report.explain import explain_incidents
from netlog.report.postmortem import postmortem_markdown
from netlog.report.render import render_markdown, render_text
from netlog.rules_cli import rules_test
from netlog.storage.database import Database, default_db_path

EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


class UsageError(Exception):
    """Something the user can fix: a missing file, a bad option, a file that is not a log."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netlog",
        description="Find and explain the problems in a network log file.",
    )
    parser.add_argument("--version", action="version", version=f"netlog {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="command")

    # What both analyze and postmortem need to read a file the same way.
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument(
        "--year", type=int, help="year of the first log line (default: the current year)"
    )
    shared.add_argument(
        "--timezone",
        help="timezone of the devices' clocks: UTC, or an offset such as +05:30 (default: UTC)",
    )
    shared.add_argument(
        "--topology",
        type=Path,
        help="a file saying which address is which device and which interfaces are connected",
    )
    shared.add_argument(
        "--audience",
        choices=MODES,
        default="senior",
        help="who the explanation is written for: junior explains terms and reasoning, "
        "senior is terse (default: senior)",
    )
    shared.add_argument(
        "--no-llm",
        action="store_true",
        help="never ask an LLM; explain every incident with the built-in templates",
    )
    shared.add_argument("--rules", type=Path, help="a rule file that adds to the built-in rules")
    shared.add_argument("--config", type=Path, help="a settings file that overrides the defaults")
    shared.add_argument("--quiet", "-q", action="store_true", help="do not show progress")

    analyze = commands.add_parser(
        "analyze",
        parents=[shared],
        help="analyze a log file and print a report",
        description="Analyze a log file and print a report of what was found.",
        epilog="Exit code: 0 nothing found, 1 something found, 2 the file could not be analyzed.",
    )
    analyze.add_argument("file", type=Path, help="the log file to analyze")
    analyze.add_argument(
        "--format",
        choices=("text", "markdown", "json"),
        default="text",
        help="output format (default: text)",
    )
    analyze.add_argument("--output", "-o", type=Path, help="write the report to this file")
    analyze.add_argument(
        "--min-severity",
        choices=LEVELS,
        default="low",
        help="lowest severity to report (default: low, which hides routine info findings)",
    )
    analyze.add_argument(
        "--findings",
        action="store_true",
        help="also list the individual findings inside each incident",
    )
    analyze.add_argument(
        "--usage", action="store_true", help="show how many LLM tokens the report cost"
    )
    analyze.add_argument("--no-color", action="store_true", help="never use color")

    postmortem = commands.add_parser(
        "postmortem",
        parents=[shared],
        help="draft the post-mortem of one incident, in Markdown",
        description="Analyze a log file and draft the post-mortem of one of its incidents, "
        "in Markdown, for a team to review and file.",
        epilog="Exit code: 0 written, 2 the file could not be analyzed or has no such incident.",
    )
    postmortem.add_argument("file", type=Path, help="the log file to analyze")
    postmortem.add_argument(
        "--incident",
        help="the id of the incident, as the report shows it (default: the most severe)",
    )
    postmortem.add_argument("--output", "-o", type=Path, help="write it to this file")

    demo = commands.add_parser(
        "demo-explanations",
        help="have the LLM explain the demo scenarios once and store the answers",
        description="Run every built-in demo scenario, ask the configured LLM to explain "
        "each incident for both audiences, and store the answers that pass every check in "
        "the file named by [demo] explanations. The demo then works with no API key. This "
        "costs one or two requests per incident and audience.",
    )
    demo.add_argument(
        "--yes", action="store_true", help="go ahead; without it, only say what would be done"
    )
    demo.add_argument("--output", "-o", type=Path, help="write to this file instead")
    demo.add_argument("--config", type=Path, help="a settings file that overrides the defaults")

    rules = commands.add_parser(
        "rules", help="work with rule files", description="Work with detection rule files."
    )
    rules_commands = rules.add_subparsers(dest="rules_command", required=True, metavar="command")
    trial = rules_commands.add_parser(
        "test",
        help="run a rule file over a log file and show what it would find",
        description="Run the built-in rules, changed and added to by a rule file, over one "
        "log file, and show how many times each rule triggered and what it found. Nothing "
        "is stored. A rule file with a mistake is refused with a message saying what is "
        "wrong.",
        epilog="Exit code: 0 nothing triggered, 1 something did, 2 the rule file or the log "
        "could not be used.",
    )
    trial.add_argument("rule_file", type=Path, help="the rule file to try")
    trial.add_argument("log_file", type=Path, help="the log file to try it on")
    trial.add_argument(
        "--year", type=int, help="year of the first log line (default: the current year)"
    )
    trial.add_argument("--timezone", help="timezone of the devices' clocks (default: UTC)")
    trial.add_argument("--config", type=Path, help="a settings file that overrides the defaults")

    replay = commands.add_parser(
        "replay",
        help="send a log file to the live listener, with its times moved to now",
        description="Send the lines of a log file to the live syslog listener, with every "
        "timestamp moved so the first line happens now, at real speed or faster. For "
        "testing and demos.",
    )
    replay.add_argument("file", type=Path, help="the log file to send")
    replay.add_argument(
        "--host", default="127.0.0.1", help="the listener's address (default: 127.0.0.1)"
    )
    replay.add_argument(
        "--port", type=int, default=5514, help="the listener's port (default: 5514)"
    )
    replay.add_argument("--tcp", action="store_true", help="send over TCP instead of UDP")
    replay.add_argument(
        "--speed", type=float, default=1.0,
        help="how many times faster than it happened: 60 sends an hour in a minute (default: 1)",
    )  # fmt: skip
    replay.add_argument("--start", metavar="HH:MM", help="skip lines before this time of day")
    replay.add_argument("--end", metavar="HH:MM", help="stop after this time of day")
    return parser


def _use_color(args: argparse.Namespace) -> bool:
    if args.no_color or args.output or args.format != "text" or os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False  # piped or redirected
    if sys.platform == "win32":
        os.system("")  # switches the Windows console to understand color codes
    return True


class _Progress:
    """Short status lines on the terminal while a large file is processed."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self._shown = False

    def show(self, text: str) -> None:
        if self.enabled:
            sys.stderr.write(f"\r{text:<60}")
            sys.stderr.flush()
            self._shown = True

    def clear(self) -> None:
        if self._shown:
            sys.stderr.write("\r" + " " * 60 + "\r")
            sys.stderr.flush()


def analyze(
    args: argparse.Namespace, progress: _Progress, provider: Provider | None = None
) -> tuple[Report, str | None]:
    """Run the whole pipeline on the file. `provider` replaces the configured LLM
    provider, which is how tests supply a fake. For `postmortem`, the post-mortem of the
    chosen incident comes back as well."""
    path: Path = args.file
    if not path.exists():
        raise UsageError(f"file not found: {path}")
    if path.is_dir():
        raise UsageError(f"{path} is a folder; give a log file")
    if path.stat().st_size == 0:
        raise UsageError(f"{path} is empty")
    if args.year is not None and not 1970 <= args.year <= 2100:
        raise UsageError(f"--year {args.year} is not a plausible year")

    try:
        tz = parse_timezone(args.timezone) if args.timezone else UTC
        config = load_config(args.config)
        ruleset = load_rule_set(args.rules, config)
        hints = load_topology(args.topology) if args.topology else None
        priors = load_priors()
        settings = llm_settings(config)
    except ValueError as error:  # includes RuleError, TopologyError and PriorError
        raise UsageError(str(error)) from None

    for warning in ruleset.warnings:
        progress.clear()
        print(f"netlog: warning: {warning}", file=sys.stderr)

    assumed_year = datetime.now(UTC).year
    with tempfile.TemporaryDirectory(prefix="netlog-") as workdir:
        with Database(Path(workdir) / "analysis.db") as db:
            try:
                upload_id = ingest_file(
                    db,
                    path,
                    year=args.year,
                    tz=tz,
                    on_progress=lambda n: progress.show(f"Reading: {n:,} lines"),
                )
            except BinaryFileError:
                raise UsageError(f"{path} is not a text file, so it cannot be a log") from None
            except PermissionError:
                raise UsageError(f"{path} cannot be read: permission denied") from None

            upload = db.get_upload(upload_id)
            if upload.line_count == 0:
                raise UsageError(f"{path} contains only blank lines")
            if upload.parsed + upload.partial == 0:
                raise UsageError(
                    f"no recognizable log lines in {path}. Supported: syslog (RFC 3164 and "
                    "RFC 5424), Cisco IOS, Linux sshd and sudo, ISC dhcpd."
                )

            progress.show(f"Finding message patterns in {upload.line_count:,} lines")
            mine_templates(db, upload_id, config)
            progress.show("Running detection rules")
            detect(db, upload_id, ruleset.rules, ruleset.severity_settings(config))
            progress.show("Grouping findings into incidents")
            correlate(db, upload_id, config, hints, priors)

            # Everything above is decided. The explanation only puts it into words.
            postmortem = args.command == "postmortem"
            min_severity = "info" if postmortem else args.min_severity
            floor = LEVELS.index(min_severity)
            listed = [
                incident.id
                for incident in db.incidents(upload_id)
                if LEVELS.index(incident.severity) >= floor
            ]
            if postmortem:
                listed = [_chosen_incident(db, upload_id, path, args.incident)]
            use_llm = not args.no_llm
            asks = use_llm and (provider is not None or settings.configured)
            # Stored answers live in the local database. It is only opened when an LLM
            # may be asked; otherwise nothing is written outside the temporary folder.
            cache = Database(default_db_path()) if asks and listed else db
            try:
                explanations = explain_incidents(
                    db,
                    upload_id,
                    listed,
                    cache,
                    args.audience,
                    use_llm=use_llm,
                    provider=provider,
                    settings=settings,
                    config=config,
                    on_progress=lambda n, total: progress.show(
                        f"Explaining incident {n} of {total}"
                    ),
                )
            except ValueError as error:  # a pack limit set too low to hold an incident
                raise UsageError(str(error)) from None
            finally:
                if cache is not db:
                    cache.close()
            report = build_report(
                db,
                upload_id,
                min_severity=min_severity,
                year=args.year,
                assumed_year=assumed_year,
                timezone=args.timezone,
                show_findings=getattr(args, "findings", False),
                show_usage=getattr(args, "usage", False),
                explanations=explanations,
            )
            if not postmortem:
                return report, None
            (chosen,) = listed
            text = postmortem_markdown(db, upload, report, chosen, explanations[chosen])
            return report, text + "\n"


def replay_file(args: argparse.Namespace) -> int:
    """The `netlog replay` command."""
    if not args.file.is_file():
        print(f"netlog: file not found: {args.file}", file=sys.stderr)
        return EXIT_ERROR
    if args.speed <= 0:
        print("netlog: --speed must be greater than zero", file=sys.stderr)
        return EXIT_ERROR
    lines = args.file.read_text(encoding="utf-8", errors="replace").splitlines()
    # The time of day of a line is at the same place in a syslog header: "Mar  3 02:46:12".
    if args.start:
        lines = [line for line in lines if line[7:12] >= args.start]
    if args.end:
        lines = [line for line in lines if line[7:12] <= args.end]
    try:
        send, close = sender(args.host, args.port, args.tcp)
    except OSError as error:
        print(f"netlog: cannot reach {args.host}:{args.port}: {error}", file=sys.stderr)
        return EXIT_ERROR
    how = "TCP" if args.tcp else "UDP"
    print(
        f"Sending {len(lines):,} lines to {args.host}:{args.port} over {how} at {args.speed:g}x..."
    )
    try:
        sent = replay(lines, send, speed=args.speed)
    except OSError as error:
        print(f"netlog: sending failed: {error}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("netlog: stopped", file=sys.stderr)
        return EXIT_ERROR
    finally:
        close()
    print(f"Sent {sent:,} lines.")
    return EXIT_CLEAN


def _chosen_incident(db: Database, upload_id: int, path: Path, wanted: str | None) -> str:
    """The incident a post-mortem is for: the one asked for, or else the most severe."""
    incidents = sorted(
        db.incidents(upload_id),
        key=lambda incident: (-LEVELS.index(incident.severity), incident.start, incident.id),
    )
    if not incidents:
        raise UsageError(f"no incidents found in {path}, so there is no post-mortem to write")
    if wanted is None:
        return incidents[0].id
    if wanted not in {incident.id for incident in incidents}:
        known = ", ".join(incident.id for incident in incidents[:10])
        raise UsageError(f"{path} has no incident {wanted!r}; it has: {known}")
    return wanted


def _render(report: Report, args: argparse.Namespace) -> str:
    if args.format == "json":
        return json.dumps(to_json(report), indent=2, ensure_ascii=False) + "\n"
    if args.format == "markdown":
        return render_markdown(report)
    return render_text(report, color=_use_color(args))


def main(argv: list[str] | None = None, provider: Provider | None = None) -> int:
    args = _parser().parse_args(argv)
    load_env_file()  # the LLM provider and its key, if the user has set them up
    # A log line may hold characters the console cannot show. Print a "?" for those
    # instead of failing.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    if args.command == "demo-explanations":
        return demo_explanations(args, provider)
    if args.command == "rules":
        return rules_test(args)
    if args.command == "replay":
        return replay_file(args)

    progress = _Progress(enabled=not args.quiet and sys.stderr.isatty())
    try:
        report, document = analyze(args, progress, provider)
        text = document if document is not None else _render(report, args)
        progress.clear()
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text, encoding="utf-8", newline="\n")
            if document is not None:
                print(f"Post-mortem written to {args.output}. Review it before filing it.")
            else:
                summary = f"{len(report.incidents)} incident(s) at {args.min_severity} or above"
                print(f"Report written to {args.output} ({summary}).")
        else:
            sys.stdout.write(text)
    except UsageError as error:
        progress.clear()
        print(f"netlog: {error}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as error:
        progress.clear()
        where = f": {error.filename}" if error.filename else ""
        print(f"netlog: {error.strerror or error}{where}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        progress.clear()
        print("netlog: stopped", file=sys.stderr)
        return EXIT_ERROR
    if document is not None:
        return EXIT_CLEAN
    return EXIT_FINDINGS if report.has_something else EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
