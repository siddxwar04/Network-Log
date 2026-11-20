"""The command line: `netlog analyze <file>`.

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
from netlog.detection.engine import detect
from netlog.detection.rules import LEVELS, load_rules
from netlog.ingestion.ingest import ingest_file
from netlog.ingestion.reader import BinaryFileError
from netlog.llm.explanation import MODES
from netlog.llm.provider import Provider
from netlog.llm.settings import llm_settings, load_env_file
from netlog.mining.templates import mine_templates
from netlog.parsers.syslog import parse_timezone
from netlog.report.build import Report, build_report, to_json
from netlog.report.explain import explain_incidents
from netlog.report.render import render_markdown, render_text
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

    analyze = commands.add_parser(
        "analyze",
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
        "--year", type=int, help="year of the first log line (default: the current year)"
    )
    analyze.add_argument(
        "--timezone",
        help="timezone of the devices' clocks: UTC, or an offset such as +05:30 (default: UTC)",
    )
    analyze.add_argument(
        "--topology",
        type=Path,
        help="a file saying which address is which device and which interfaces are connected",
    )
    analyze.add_argument(
        "--findings",
        action="store_true",
        help="also list the individual findings inside each incident",
    )
    analyze.add_argument(
        "--audience",
        choices=MODES,
        default="senior",
        help="who the explanation is written for: junior explains terms and reasoning, "
        "senior is terse (default: senior)",
    )
    analyze.add_argument(
        "--no-llm",
        action="store_true",
        help="never ask an LLM; explain every incident with the built-in templates",
    )
    analyze.add_argument(
        "--usage", action="store_true", help="show how many LLM tokens the report cost"
    )
    analyze.add_argument("--rules", type=Path, help="a rule file that adds to the built-in rules")
    analyze.add_argument("--config", type=Path, help="a settings file that overrides the defaults")
    analyze.add_argument("--no-color", action="store_true", help="never use color")
    analyze.add_argument("--quiet", "-q", action="store_true", help="do not show progress")
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
) -> Report:
    """Run the whole pipeline on the file. `provider` replaces the configured LLM
    provider, which is how tests supply a fake."""
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
        rules = load_rules(args.rules)
        hints = load_topology(args.topology) if args.topology else None
        priors = load_priors()
        settings = llm_settings(config)
    except ValueError as error:  # includes RuleError, TopologyError and PriorError
        raise UsageError(str(error)) from None

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
            detect(db, upload_id, rules, config)
            progress.show("Grouping findings into incidents")
            correlate(db, upload_id, config, hints, priors)

            # Everything above is decided. The explanation only puts it into words.
            floor = LEVELS.index(args.min_severity)
            listed = [
                incident.id
                for incident in db.incidents(upload_id)
                if LEVELS.index(incident.severity) >= floor
            ]
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
            return build_report(
                db,
                upload_id,
                min_severity=args.min_severity,
                year=args.year,
                assumed_year=assumed_year,
                timezone=args.timezone,
                show_findings=args.findings,
                show_usage=args.usage,
                explanations=explanations,
            )


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

    progress = _Progress(enabled=not args.quiet and sys.stderr.isatty())
    try:
        report = analyze(args, progress, provider)
        text = _render(report, args)
        progress.clear()
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(text, encoding="utf-8", newline="\n")
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
    return EXIT_FINDINGS if report.has_something else EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
