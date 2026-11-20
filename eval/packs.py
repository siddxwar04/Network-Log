"""Evidence packs: builds the pack of every incident in every labelled scenario and
reports how large each one is.

    python -m eval.packs
    python -m eval.packs --show 02_cascade
    python -m eval.packs --show 02_cascade --plain

`--show` prints the pack of each incident in one scenario as it would be sent to an LLM:
redacted. `--plain` prints it with the real addresses and names instead.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from netlog.config import load_config
from netlog.correlation.grouping import correlate
from netlog.correlation.topology import Topology, load_topology
from netlog.detection.engine import detect
from netlog.ingestion.ingest import ingest_file
from netlog.llm.evidence import EvidencePack, build_pack, outgoing_packs
from netlog.mining.templates import mine_templates
from netlog.storage.database import Database


@dataclass
class PackSize:
    scenario: str
    incident: str
    severity: str
    findings: int
    log_lines: int  # evidence lines the incident rests on
    plain: EvidencePack
    sent: EvidencePack


def measure(
    db: Database,
    log: Path,
    year: int = 2026,
    hints: Topology | None = None,
    config: dict | None = None,
) -> list[PackSize]:
    """Run one scenario through the pipeline and build the pack of each incident."""
    config = config or load_config()
    upload = ingest_file(db, log, year=year)
    mine_templates(db, upload, config)
    detect(db, upload, config=config)
    correlate(db, upload, config, hints)
    packs, _ = outgoing_packs(db, upload, config)
    return [
        PackSize(
            scenario=log.stem,
            incident=incident.id,
            severity=incident.severity,
            findings=len(incident.finding_ids) + len(incident.context_ids),
            log_lines=sent.data["incident"]["evidence_lines"],
            plain=build_pack(db, upload, incident, config),
            sent=sent,
        )
        for incident, sent in packs
    ]


def measure_all(
    scenarios: Path = Path("data/scenarios"),
    hints: Topology | None = None,
    config: dict | None = None,
) -> list[PackSize]:
    sizes: list[PackSize] = []
    with tempfile.TemporaryDirectory(prefix="netlog-packs-") as workdir:
        with Database(Path(workdir) / "packs.db") as db:
            for log in sorted(scenarios.glob("*.log")):
                sizes += measure(db, log, hints=hints, config=config)
    return sizes


def to_markdown(sizes: list[PackSize], limit: int) -> str:
    lines = [
        "| Scenario | Incident | Severity | Findings | Log lines | Lines in pack "
        "| Characters | Tokens (est.) | Trimmed |",
        "|---|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for size in sizes:
        lines.append(
            f"| {size.scenario} | {size.incident} | {size.severity} | {size.findings} "
            f"| {size.log_lines} | {len(size.sent.data['evidence'])} | {size.sent.size_chars:,} "
            f"| {size.sent.tokens:,} | {'yes' if size.sent.trimmed else 'no'} |"
        )
    largest = max((size.sent.tokens for size in sizes), default=0)
    lines += [
        "",
        f"{len(sizes)} pack(s). Largest: about {largest:,} tokens; the limit is {limit:,}. "
        "Sizes are of the redacted pack, which is the one that is sent.",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m eval.packs",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--scenarios", type=Path, default=Path("data/scenarios"))
    parser.add_argument("--topology", type=Path, help="a topology file to give the tool")
    parser.add_argument("--config", type=Path, help="a settings file that overrides the defaults")
    parser.add_argument("--show", metavar="SCENARIO", help="print the packs of one scenario")
    parser.add_argument("--plain", action="store_true", help="with --show: do not redact")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    try:
        config = load_config(args.config)
        hints = load_topology(args.topology) if args.topology else None
    except ValueError as error:
        parser.error(str(error))

    if not args.show:
        sizes = measure_all(args.scenarios, hints, config)
        print(to_markdown(sizes, config["evidence"]["max_tokens"]))
        return 0

    log = args.scenarios / f"{args.show}.log"
    if not log.exists():
        parser.error(f"no such scenario: {log}")
    with tempfile.TemporaryDirectory(prefix="netlog-packs-") as workdir:
        with Database(Path(workdir) / "packs.db") as db:
            sizes = measure(db, log, hints=hints, config=config)
    if not sizes:
        print(f"{args.show} has no incidents, so there is no pack.")
    for size in sizes:
        pack = size.plain if args.plain else size.sent
        print(pack.to_json(indent=2))
        print(f"# {size.incident}: {pack.size_chars:,} characters, about {pack.tokens:,} tokens")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
