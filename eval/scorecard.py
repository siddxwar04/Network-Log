"""Scorecard: runs every labelled scenario and compares what the tool found with the
answer key.

    python -m eval.scorecard
    python -m eval.scorecard --topology data/scenarios/topology.toml

An incident the tool found matches a labelled one when its root cause is of the same
kind and on the same device. For each match it then checks the root-cause entity, the
severity, the devices involved and the start time.
"""

from __future__ import annotations

import argparse
import json
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from netlog.correlation.grouping import correlate
from netlog.correlation.incident import Incident
from netlog.correlation.topology import Topology, load_topology
from netlog.detection.engine import detect
from netlog.ingestion.ingest import ingest_file
from netlog.storage.database import Database

# The label files name some root causes differently from the rules.
ROOT_KINDS = {"link_failure": "interface_down", "brute_force": "brute_force_login"}
START_TOLERANCE = timedelta(seconds=10)


@dataclass
class Check:
    scenario: str
    expected: int
    found: int
    root_cause: bool = True
    severity: bool = True
    devices: bool = True
    start: bool = True
    problems: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.expected == self.found and not self.problems


def _match(label: dict, incidents: list[Incident]) -> Incident | None:
    root = label["root_cause"]
    kind = ROOT_KINDS.get(root["kind"], root["kind"])
    for incident in incidents:
        cause = incident.root_cause
        if cause and cause.kind == kind and root["device"] in cause.devices:
            return incident
    return None


def score_scenario(db: Database, log: Path, year: int, hints: Topology | None) -> Check:
    labels = json.loads(log.with_suffix(".labels.json").read_text(encoding="utf-8"))["incidents"]
    upload = ingest_file(db, log, year=year)
    detect(db, upload)
    incidents = correlate(db, upload, hints=hints)
    check = Check(log.stem, expected=len(labels), found=len(incidents))
    if check.expected != check.found:
        check.problems.append(f"expected {check.expected} incident(s), found {check.found}")

    for label in labels:
        root = label["root_cause"]
        incident = _match(label, incidents)
        if incident is None:
            check.root_cause = False
            named = sorted({i.root_cause.kind for i in incidents if i.root_cause})
            check.problems.append(
                f"no incident with root cause {root['kind']} on {root['device']} "
                f"(found: {', '.join(named) or 'none'})"
            )
            continue
        if incident.root_cause.entity != root["entity"]:
            check.root_cause = False
            check.problems.append(
                f"root cause names {incident.root_cause.entity}, expected {root['entity']}"
            )
        if incident.severity != label["expected_severity"]:
            check.severity = False
            check.problems.append(
                f"severity {incident.severity}, expected {label['expected_severity']}"
            )
        if sorted(incident.devices) != sorted(label["devices"]):
            check.devices = False
            check.problems.append(
                f"devices {', '.join(incident.devices)}, expected {', '.join(label['devices'])}"
            )
        expected_start = datetime.fromisoformat(label["start"].replace("Z", "+00:00"))
        first = min(incident.start, *(_root_start(db, upload, incident),))
        if abs(first - expected_start) > START_TOLERANCE:
            check.start = False
            check.problems.append(
                f"starts {first:%H:%M:%S}, expected {expected_start:%H:%M:%S}"
            )
    return check


def _root_start(db: Database, upload: int, incident: Incident) -> datetime:
    """When the root cause began, which can be before the first problem it led to."""
    by_id = {f.id: f for f in db.findings(upload)}
    starts = [by_id[i].start for i in incident.root_cause.finding_ids if i in by_id]
    return min(starts, default=incident.start)


def score_all(
    scenarios: Path = Path("data/scenarios"), hints: Topology | None = None, year: int = 2026
) -> list[Check]:
    checks = []
    with tempfile.TemporaryDirectory(prefix="netlog-eval-") as workdir:
        with Database(Path(workdir) / "eval.db") as db:
            for log in sorted(scenarios.glob("*.log")):
                checks.append(score_scenario(db, log, year, hints))
    return checks


def to_markdown(checks: list[Check]) -> str:
    def mark(ok: bool) -> str:
        return "yes" if ok else "NO"

    lines = [
        "| Scenario | Expected | Found | Root cause | Severity | Devices | Start | Result |",
        "|---|---:|---:|---|---|---|---|---|",
    ]
    for check in checks:
        if check.expected == 0:
            columns = ["n/a"] * 4
        else:
            results = (check.root_cause, check.severity, check.devices, check.start)
            columns = [mark(ok) for ok in results]
        lines.append(
            f"| {check.scenario} | {check.expected} | {check.found} | "
            + " | ".join(columns)
            + f" | {'pass' if check.passed else 'FAIL'} |"
        )
    failed = [check for check in checks if not check.passed]
    lines += ["", f"{len(checks) - len(failed)} of {len(checks)} scenarios pass."]
    for check in failed:
        lines.append(f"- {check.scenario}: " + "; ".join(check.problems))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m eval.scorecard", description=__doc__)
    parser.add_argument("--scenarios", type=Path, default=Path("data/scenarios"))
    parser.add_argument("--topology", type=Path, help="a topology file to give the tool")
    args = parser.parse_args(argv)
    hints = load_topology(args.topology) if args.topology else None
    checks = score_all(args.scenarios, hints)
    print(to_markdown(checks))
    return 0 if all(check.passed for check in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
