"""`netlog rules test <rule file> <log file>`: try a rule file before relying on it.

It runs the built-in rules, changed and added to by the rule file, over one log file and
prints how many times each rule triggered and what each finding says. An admin can lower
a threshold, run this against last month's logs, and see how many more alerts it would
have given, before changing anything for real.
"""

from __future__ import annotations

import sys
import tempfile
from collections import Counter
from datetime import UTC
from pathlib import Path

from netlog.config import load_config
from netlog.detection.engine import detect
from netlog.detection.rules import RuleError, load_rule_set
from netlog.ingestion.ingest import ingest_file
from netlog.ingestion.reader import BinaryFileError
from netlog.parsers.syslog import parse_timezone
from netlog.storage.database import Database

# A rule that fires a lot shows this many findings, then a count of the rest.
SHOWN = 10


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def rules_test(args) -> int:
    """Exit code 0 when no rule triggered, 1 when one did, 2 when it could not run."""
    rule_file: Path = args.rule_file
    log_file: Path = args.log_file
    try:
        config = load_config(args.config)
        ruleset = load_rule_set(rule_file, config)
        tz = parse_timezone(args.timezone) if args.timezone else UTC
    except (RuleError, ValueError) as error:
        print(f"netlog: {error}", file=sys.stderr)
        return 2
    if not log_file.is_file():
        print(f"netlog: file not found: {log_file}", file=sys.stderr)
        return 2
    for warning in ruleset.warnings:
        print(f"netlog: warning: {warning}", file=sys.stderr)

    origins = Counter(ruleset.origin.values())
    changed = [name for name, where in ruleset.origin.items() if where == "built-in, changed"]
    added = [name for name, where in ruleset.origin.items() if where == "your file"]
    disabled = [rule.name for rule in ruleset.rules if not rule.enabled]
    print(
        f"Rules: {origins['built-in'] + len(changed)} built-in; from {rule_file.name}: "
        f"{len(changed)} changed{f' ({chr(44).join(changed)})' if changed else ''}, "
        f"{len(added)} added{f' ({chr(44).join(added)})' if added else ''}"
        + (f"; switched off: {', '.join(disabled)}" if disabled else "")
    )

    with tempfile.TemporaryDirectory(prefix="netlog-rules-") as workdir:
        with Database(Path(workdir) / "rules.db") as db:
            try:
                upload_id = ingest_file(db, log_file, year=args.year, tz=tz)
            except BinaryFileError:
                print(f"netlog: {log_file} is not a text file", file=sys.stderr)
                return 2
            upload = db.get_upload(upload_id)
            print(f"Log: {log_file.name}, {_plural(upload.line_count, 'line')}")
            print()
            findings = detect(db, upload_id, ruleset.rules, ruleset.severity_settings(config))

    by_rule: dict[str, list] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule, []).append(finding)
    for rule in ruleset.rules:
        found = by_rule.get(rule.name)
        if not found:
            continue
        print(f"{rule.name}: triggered {_plural(len(found), 'time')}")
        for finding in found[:SHOWN]:
            print(f"  {finding.severity:<8} {finding.title}")
        if len(found) > SHOWN:
            print(f"  ... and {len(found) - SHOWN} more")
    print("No rule triggered." if not by_rule else "No other rule triggered.")
    return 1 if by_rule else 0
