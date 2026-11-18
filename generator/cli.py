"""Command line for the generator.

    python -m generator --scenario cascade --seed 1
    python -m generator --scenario all
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

from generator.records import render
from generator.scenarios import SCENARIOS, build

DEFAULT_START = "2026-03-03T00:00:00"


def _iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat() + "Z"


def generate(
    name: str,
    seed: int = 1,
    lines: int = 5000,
    start: datetime | None = None,
    hours: float = 6.0,
) -> tuple[str, dict]:
    """Return the log text and the label data for one scenario. Same inputs, same output."""
    start = start or datetime.fromisoformat(DEFAULT_START)
    end = start + timedelta(hours=hours)
    rng = random.Random(f"{name}:{seed}")

    built = build(name, rng, start, end, lines)
    rendered = render(built.recs, rng)

    incidents = []
    for incident in built.incidents:
        first, last = rendered.incident_times[incident.id]
        incidents.append(
            {
                "id": incident.id,
                "type": incident.type,
                "title": incident.title,
                "start": _iso(first),
                "end": _iso(last),
                "root_cause": incident.root_cause,
                "devices": incident.devices,
                "expected_severity": incident.expected_severity,
                "facts": incident.facts,
                "notes": incident.notes,
                "lines": rendered.incident_lines[incident.id],
            }
        )

    labels = {
        "scenario": name,
        "seed": seed,
        "year": start.year,
        "timezone": "UTC",
        "start": _iso(start),
        "end": _iso(end),
        "total_lines": len(rendered.lines),
        "incidents": incidents,
    }
    return "\n".join(rendered.lines) + "\n", labels


def write(out_dir: Path, prefix: str, text: str, labels: dict) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / f"{prefix}.log"
    with open(log_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    with open(out_dir / f"{prefix}.labels.json", "w", encoding="utf-8", newline="\n") as handle:
        json.dump(labels, handle, indent=2)
        handle.write("\n")
    return log_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m generator",
        description="Generate synthetic network logs with known incidents and a label file.",
    )
    parser.add_argument("--scenario", required=True, choices=[*SCENARIOS, "all"])
    parser.add_argument("--seed", type=int, default=1, help="same seed, same output (default 1)")
    parser.add_argument("--out", type=Path, default=Path("data/scenarios"), help="output folder")
    parser.add_argument("--lines", type=int, default=5000, help="approximate total lines")
    parser.add_argument("--start", default=DEFAULT_START, help="start date and time, ISO format")
    parser.add_argument("--hours", type=float, default=6.0, help="time span the log covers")
    args = parser.parse_args(argv)

    start = datetime.fromisoformat(args.start)
    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    jobs = [(SCENARIOS[n][0], n, args.lines, args.hours) for n in names]
    if args.scenario == "all":
        jobs.append(("08_noise_50k", "noise", 50000, 24.0))

    for prefix, name, lines, hours in jobs:
        text, labels = generate(name, args.seed, lines, start, hours)
        path = write(args.out, prefix, text, labels)
        print(f"{path}  {labels['total_lines']} lines, {len(labels['incidents'])} incident(s)")
    return 0
