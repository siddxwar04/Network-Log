"""The evaluation harness: an automatic exam. It runs the tool on logs whose answers are
known and counts how often it is right.

    python -m eval.heldout          generate the held-out and noise sets (once)
    python -m eval.harness          run all three sets, write eval/results/latest.*

Three sets, reported separately:

  - tuned: data/scenarios/, the files the rules were developed against;
  - held-out: freshly generated variants the rules have never seen (the headline);
  - noise: normal traffic only, for false alarms.

The matching rule, the same everywhere: a found incident matches an expected one when
  1. it is of the same type (its likely cause, or one of its findings, is of that kind),
  2. its likely cause is on the same device, and
  3. their time spans overlap, allowing TIME_TOLERANCE for the logs' one-second steps.
Each expected incident is matched to at most one found incident, the one sharing the most
log lines with it, and the other way round.

The scoring is kept apart from running the tool (`score_file` takes plain records), so it
can be checked on its own: a perfect detector must score 100% and a wrong one badly.

These are synthetic logs from this project's own generator. The numbers show the tool is
consistent with its design, not that it works on every real network.
"""

from __future__ import annotations

import argparse
import json
import platform
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from netlog.config import load_config
from netlog.correlation.grouping import correlate
from netlog.correlation.incident import Incident
from netlog.correlation.topology import Topology, load_topology
from netlog.detection.engine import detect
from netlog.detection.rules import LEVELS
from netlog.ingestion.ingest import ingest_file
from netlog.llm.evidence import outgoing_packs
from netlog.mining.templates import mine_templates
from netlog.storage.database import Database

TIME_TOLERANCE = timedelta(seconds=10)
# An unexpected incident is a false alarm from this severity up. Below it, an incident is
# routine (a single config change, an interface someone shut) and is not counted.
ALARM_SEVERITY = "medium"
RESULTS = Path("eval/results")
MATCHING_RULE = (
    "A found incident matches an expected one when it is of the same type (its likely "
    "cause, or one of its findings, is of that kind), its likely cause is on the same "
    f"device, and their time spans overlap (within {TIME_TOLERANCE.seconds} seconds). Each "
    "expected incident matches at most one found incident. An unexpected incident counts "
    f"as a false alarm at {ALARM_SEVERITY.capitalize()} or above."
)
LIMITS = (
    "These are synthetic logs from this project's own generator, so the numbers show the "
    "tool is consistent with its design, not that it works on every real network."
)

# The names the tool gives kinds of cause and finding, in the label files' words.
KIND_NAMES = {
    "interface_down": "link_failure",
    "link_failure": "link_failure",
    "brute_force_login": "brute_force",
    "ospf_adjacency_loss": "ospf_adjacency_loss",
    "device_restart": "device_reload",
    "dns_failure_spike": "dns_failure",
}


def type_name(kind: str | None) -> str:
    return KIND_NAMES.get(kind or "", kind or "unknown")


# --- Plain records, so scoring needs no database -------------------------------------------


@dataclass
class Found:
    """One incident the tool found, reduced to what scoring needs."""

    id: str
    types: set[str]  # the kind of its likely cause and of each finding, in label words
    cause_type: str  # the kind of its likely cause, in label words
    cause_devices: list[str]
    cause_entity: str | None
    severity: str
    start: datetime
    end: datetime
    lines: set[int] = field(default_factory=set)
    devices: list[str] = field(default_factory=list)

    @property
    def alarm(self) -> bool:
        return LEVELS.index(self.severity) >= LEVELS.index(ALARM_SEVERITY)


@dataclass
class Expected:
    id: str
    type: str
    cause_type: str
    device: str
    entity: str | None
    severity: str
    start: datetime
    end: datetime
    lines: set[int] = field(default_factory=set)
    devices: list[str] = field(default_factory=list)

    @classmethod
    def from_label(cls, label: dict) -> Expected:
        root = label["root_cause"]
        return cls(
            id=label["id"],
            type=label["type"],
            cause_type=type_name(root["kind"]),
            device=root["device"],
            entity=root.get("entity"),
            severity=label["expected_severity"],
            start=_time(label["start"]),
            end=_time(label["end"]),
            lines=set(label.get("lines", [])),
            devices=list(label.get("devices", [])),
        )


def _time(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def matches(expected: Expected, found: Found) -> bool:
    """The matching rule."""
    return (
        expected.type in found.types
        and expected.device in found.cause_devices
        and found.start - TIME_TOLERANCE <= expected.end
        and expected.start <= found.end + TIME_TOLERANCE
    )


@dataclass
class FileResult:
    name: str
    lines: int
    expected: list[Expected]
    found: list[Found]
    pairs: list[tuple[Expected, Found]] = field(default_factory=list)
    missed: list[Expected] = field(default_factory=list)
    false_alarms: list[Found] = field(default_factory=list)
    split: list[Expected] = field(default_factory=list)  # one incident found as several
    merged: list[Found] = field(default_factory=list)  # several found as one
    seconds: float = 0.0
    note: str = ""  # what the variant tests


def score_file(name: str, lines: int, expected: list[Expected], found: list[Found]) -> FileResult:
    """Compare what was found in one file with what was expected."""
    result = FileResult(name, lines, expected, found)
    used: set[str] = set()
    candidates = {e.id: [f for f in found if matches(e, f)] for e in expected}
    for exp in expected:
        free = [f for f in candidates[exp.id] if f.id not in used]
        if not free:
            result.missed.append(exp)
            continue
        best = max(
            free,
            key=lambda f: (len(f.lines & exp.lines), -abs((f.start - exp.start).total_seconds())),
        )
        used.add(best.id)
        result.pairs.append((exp, best))
    # Split: the lines of one expected incident spread over several found incidents.
    for exp in expected:
        holders = [f for f in found if f.lines & exp.lines and (f.alarm or f.id in used)]
        if len(holders) > 1:
            result.split.append(exp)
    # Merged: one found incident holding the lines of several expected ones.
    for f in found:
        if sum(1 for exp in expected if f.lines & exp.lines) > 1:
            result.merged.append(f)
    # Another piece of a split incident is not also a false alarm.
    pieces = {f.id for exp in expected for f in candidates[exp.id]}
    result.false_alarms = [f for f in found if f.alarm and f.id not in used and f.id not in pieces]
    return result


# --- Metrics -------------------------------------------------------------------------------


def _ratio(part: int, whole: int) -> float | None:
    return part / whole if whole else None


def _f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None or precision + recall == 0:
        return None if precision is None or recall is None else 0.0
    return 2 * precision * recall / (precision + recall)


def summarize(results: list[FileResult]) -> dict:
    """Detection, root cause, severity and correlation numbers over a set of files."""
    by_type: dict[str, Counter] = defaultdict(Counter)
    for result in results:
        for exp in result.expected:
            by_type[exp.type]["expected"] += 1
        for exp, _found in result.pairs:
            by_type[exp.type]["found"] += 1
        for alarm in result.false_alarms:
            by_type[alarm.cause_type]["false_alarms"] += 1

    def block(counts: Counter) -> dict:
        tp, fp, expected = counts["found"], counts["false_alarms"], counts["expected"]
        precision, recall = _ratio(tp, tp + fp), _ratio(tp, expected)
        return {
            "expected": expected,
            "found": tp,
            "false_alarms": fp,
            "precision": precision,
            "recall": recall,
            "f1": _f1(precision, recall),
        }

    total = sum(by_type.values(), Counter())
    pairs = [pair for result in results for pair in result.pairs]
    root_ok = [
        (exp, f)
        for exp, f in pairs
        if f.cause_type == exp.cause_type and (exp.entity is None or f.cause_entity == exp.entity)
    ]
    severity_ok = [(exp, f) for exp, f in pairs if f.severity == exp.severity]
    devices_ok = [(exp, f) for exp, f in pairs if sorted(f.devices) == sorted(exp.devices)]
    lines = sum(result.lines for result in results)
    alarms = sum(len(result.false_alarms) for result in results)
    seconds = sum(result.seconds for result in results)
    return {
        "files": len(results),
        "lines": lines,
        "overall": block(total),
        "by_type": {name: block(counts) for name, counts in sorted(by_type.items())},
        "root_cause": {
            "correct": len(root_ok),
            "of": len(pairs),
            "rate": _ratio(len(root_ok), len(pairs)),
        },
        "severity": {
            "correct": len(severity_ok),
            "of": len(pairs),
            "rate": _ratio(len(severity_ok), len(pairs)),
        },
        "devices": {
            "correct": len(devices_ok),
            "of": len(pairs),
            "rate": _ratio(len(devices_ok), len(pairs)),
        },
        "correlation": {
            "split": sum(len(r.split) for r in results),
            "merged": sum(len(r.merged) for r in results),
            "expected": total["expected"],
        },
        "false_alarms_per_10k_lines": alarms / lines * 10_000 if lines else None,
        "lines_per_second": lines / seconds if seconds else None,
    }


def problems(results: list[FileResult], set_name: str) -> list[dict]:
    """Every miss, false alarm, wrong cause, severity or devices, split and merge, one line
    each, so it can be looked into."""
    out = []

    def add(result: FileResult, kind: str, reason: str) -> None:
        scenario, _, seed = result.name.rpartition("-")
        out.append(
            {
                "set": set_name,
                "file": result.name,
                "scenario": scenario if seed.isdigit() else result.name,
                "seed": int(seed) if seed.isdigit() else None,
                "variant": result.note,
                "kind": kind,
                "reason": reason,
            }
        )

    for result in results:
        for exp in result.missed:
            near = [f for f in result.found if exp.device in f.cause_devices or f.lines & exp.lines]
            seen = (
                "; ".join(
                    f"{f.cause_type} on {', '.join(f.cause_devices)} ({f.severity})" for f in near
                )
                or "nothing near it"
            )
            add(result, "miss", f"expected {exp.type} on {exp.device}; found: {seen}")
        for f in result.false_alarms:
            add(
                result,
                "false alarm",
                f"{f.cause_type} on {', '.join(f.cause_devices)} "
                f"({f.severity}), {f.start:%H:%M:%S} to {f.end:%H:%M:%S}",
            )
        for exp, f in result.pairs:
            if f.cause_type != exp.cause_type or (exp.entity and f.cause_entity != exp.entity):
                add(
                    result,
                    "wrong cause",
                    f"expected {exp.cause_type} {exp.entity} on "
                    f"{exp.device}, found {f.cause_type} {f.cause_entity}",
                )
            if f.severity != exp.severity:
                add(
                    result,
                    "wrong severity",
                    f"{exp.type}: expected {exp.severity}, found {f.severity}",
                )
            if sorted(f.devices) != sorted(exp.devices):
                add(
                    result,
                    "wrong devices",
                    f"{exp.type}: expected {', '.join(sorted(exp.devices))}, "
                    f"found {', '.join(sorted(f.devices))}",
                )
        for exp in result.split:
            add(result, "split", f"{exp.type} on {exp.device} was found as several incidents")
        for f in result.merged:
            add(
                result,
                "merged",
                f"one incident ({f.cause_type} on "
                f"{', '.join(f.cause_devices)}) holds several expected ones",
            )
    return out


# --- Running the tool ----------------------------------------------------------------------


def found_incidents(db: Database, upload: int, incidents: list[Incident]) -> list[Found]:
    findings = {f.id: f for f in db.findings(upload)}
    events = {}
    wanted = {e for f in findings.values() for e in f.evidence}
    for event in db.events_by_id(sorted(wanted)):
        events[event.id] = event.line_no
    out = []
    for incident in incidents:
        members = [
            findings[i] for i in [*incident.finding_ids, *incident.context_ids] if i in findings
        ]
        problems_ = [findings[i] for i in incident.finding_ids if i in findings]
        root = incident.root_cause
        root_findings = [findings[i] for i in (root.finding_ids if root else []) if i in findings]
        start = min([incident.start, *(f.start for f in root_findings)])
        cause_type = type_name(root.kind if root else None)
        out.append(
            Found(
                id=incident.id,
                types={cause_type, *(type_name(f.rule) for f in problems_)},
                cause_type=cause_type,
                cause_devices=list(root.devices) if root else list(incident.devices),
                cause_entity=root.entity if root else None,
                severity=incident.severity,
                start=start,
                end=incident.end,
                lines={events[e] for f in members for e in f.evidence if e in events},
                devices=list(incident.devices),
            )
        )
    return out


def run_file(db: Database, log: Path, hints: Topology | None = None) -> FileResult:
    labels = json.loads(log.with_suffix(".labels.json").read_text(encoding="utf-8"))
    began = time.perf_counter()
    upload = ingest_file(db, log, year=labels.get("year", 2026))
    detect(db, upload)
    incidents = correlate(db, upload, hints=hints)
    seconds = time.perf_counter() - began
    expected = [Expected.from_label(label) for label in labels["incidents"]]
    result = score_file(
        log.stem, labels["total_lines"], expected, found_incidents(db, upload, incidents)
    )
    result.seconds = seconds
    result.note = labels.get("variant") or labels.get("negative") or ""
    db.delete_upload(upload)
    return result


def run_set(folder: Path, hints: Topology | None = None, on_file=None) -> list[FileResult]:
    logs = sorted(folder.glob("*.log"))
    with tempfile.TemporaryDirectory(prefix="netlog-eval-") as workdir:
        with Database(Path(workdir) / "eval.db") as db:
            results = []
            for n, log in enumerate(logs, 1):
                if on_file:
                    on_file(n, len(logs), log.name)
                results.append(run_file(db, log, hints))
    return results


def efficiency(folder: Path) -> dict:
    """How much the tool shrinks a log, and how large what an LLM would be shown is, over
    the files of the tuned set."""
    config = load_config()
    lines = templates = 0
    pack_tokens: list[int] = []
    with tempfile.TemporaryDirectory(prefix="netlog-eval-") as workdir:
        with Database(Path(workdir) / "eval.db") as db:
            for log in sorted(folder.glob("*.log")):
                labels = json.loads(log.with_suffix(".labels.json").read_text(encoding="utf-8"))
                upload = ingest_file(db, log, year=labels.get("year", 2026))
                mine_templates(db, upload)
                detect(db, upload)
                correlate(db, upload)
                lines += db.get_upload(upload).line_count
                templates += len(db.templates(upload, limit=1_000_000))
                packs, _ = outgoing_packs(db, upload, config)
                pack_tokens += [pack.tokens for _, pack in packs]
    pack_tokens.sort()
    return {
        "compression_ratio": lines / templates if templates else None,
        "lines": lines,
        "templates": templates,
        "evidence_pack_tokens": {
            "incidents": len(pack_tokens),
            "median": pack_tokens[len(pack_tokens) // 2] if pack_tokens else None,
            "largest": pack_tokens[-1] if pack_tokens else None,
            "limit": config["evidence"]["max_tokens"],
        },
    }


# --- Writing the results -------------------------------------------------------------------


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def to_markdown(data: dict) -> str:
    sets = data["sets"]
    lines = [
        f"_{LIMITS}_",
        "",
        f"Matching rule: {MATCHING_RULE}",
        "",
        "| Set | Files | Lines | Incidents | Found | False alarms | Precision | Recall | F1 "
        "| Root cause | Severity | Devices | Split / merged |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for key, title in (("heldout", "**Held-out**"), ("tuned", "Tuned"), ("noise", "Noise only")):
        s = sets.get(key)
        if not s:
            continue
        o = s["overall"]
        lines.append(
            f"| {title} | {s['files']} | {s['lines']:,} | {o['expected']} | {o['found']} | "
            f"{o['false_alarms']} | {_pct(o['precision'])} | {_pct(o['recall'])} | "
            f"{_pct(o['f1'])} | {_pct(s['root_cause']['rate'])} | {_pct(s['severity']['rate'])} | "
            f"{_pct(s['devices']['rate'])} | "
            f"{s['correlation']['split']} / {s['correlation']['merged']} |"
        )
    held = sets.get("heldout")
    if held:
        lines += [
            "",
            "Held-out, by incident type:",
            "",
            "| Type | Incidents | Found | False alarms | Precision | Recall | F1 |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        for name, b in held["by_type"].items():
            lines.append(
                f"| {name} | {b['expected']} | {b['found']} | {b['false_alarms']} | "
                f"{_pct(b['precision'])} | {_pct(b['recall'])} | {_pct(b['f1'])} |"
            )
    noise = sets.get("noise")
    eff = data.get("efficiency") or {}
    lines += ["", "Other measures:", ""]
    if noise:
        lines.append(
            f"- False alarms on normal traffic: {noise['false_alarms_per_10k_lines']:.2f} "
            f"per 10,000 lines ({noise['lines']:,} lines)."
        )
    all_seconds = [s["lines_per_second"] for s in sets.values() if s.get("lines_per_second")]
    if all_seconds:
        lines.append(
            f"- Speed: {min(all_seconds):,.0f} to {max(all_seconds):,.0f} lines per "
            "second for reading, detection and correlation, by set."
        )
    if eff.get("compression_ratio"):
        packs = eff["evidence_pack_tokens"]
        lines.append(
            f"- Compression: {eff['lines']:,} lines of the tuned set become "
            f"{eff['templates']} message patterns, {eff['compression_ratio']:.0f} to 1."
        )
        lines.append(
            f"- Evidence pack, what an LLM would be shown: median {packs['median']} and "
            f"largest {packs['largest']} tokens (estimated) for {packs['incidents']} "
            f"incidents, against a limit of {packs['limit']}."
        )
    lines.append(
        "- Explanations (citation validity, fallback rate, tokens and latency of real "
        "requests): not measured here, since it needs a real LLM and costs requests."
    )
    lines += ["", "Where these numbers are weak:", "", *(f"- {w}" for w in weaknesses(data))]
    found = data.get("problems", [])
    lines += [
        "",
        "Every miss, false alarm and wrong cause, severity or device list is in latest.json "
        f"({len(found)} items).",
    ]
    return "\n".join(lines) + "\n"


def weaknesses(data: dict) -> list[str]:
    """What the numbers do not show, said plainly next to them."""
    out = [
        "The held-out files come from the same generator as the tuned ones, with the same "
        "message wording. They vary how strong each incident is, how much traffic surrounds "
        "it and how many devices it reaches, not how devices word their messages. A perfect "
        "score here shows the rules hold across those variations; it says nothing about "
        "wording they have not seen. Logs from real devices are the real test.",
        "The rules and the generator were written from the same understanding of how "
        "protocols fail. A shared misunderstanding would not show here.",
        "Only the incident types the generator can make are measured: the CPU, memory and "
        "MAC flapping rules have no scenario yet.",
    ]
    found = data.get("problems", [])
    wrong = Counter(p["scenario"] for p in found if p["kind"] == "wrong devices")
    if wrong:
        where = ", ".join(f"{name} ({count})" for name, count in sorted(wrong.items()))
        out.append(
            f"The devices involved are incomplete in {sum(wrong.values())} files: {where}. "
            + (
                "This happens even with a topology file."
                if data.get("topology")
                else "Without a topology file the tool cannot know which router is cabled to "
                "a switch, so the router whose link drops when the switch reloads is left out. "
                "Run with --topology data/scenarios/topology.toml to measure it with one."
            )
        )
    if not (data.get("explanations") or {}).get("measured"):
        out.append(
            "Explanations are not measured: that needs a real LLM and costs requests. The "
            "manual rubric in docs/EXPLANATION_RUBRIC.md covers their quality."
        )
    return out


def evaluate(
    tuned: Path, heldout: Path | None, noise: Path | None, hints: Topology | None, progress=None
) -> dict:
    sets: dict[str, dict] = {}
    found_problems: list[dict] = []
    for key, folder in (("tuned", tuned), ("heldout", heldout), ("noise", noise)):
        if folder is None or not any(folder.glob("*.log")):
            continue
        results = run_set(
            folder, hints, progress and (lambda n, total, name, k=key: progress(k, n, total, name))
        )
        sets[key] = summarize(results)
        found_problems += problems(results, key)
    return {
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "limits": LIMITS,
        "matching_rule": MATCHING_RULE,
        "topology": hints is not None,
        "machine": f"{platform.system()} {platform.machine()}, Python {platform.python_version()}",
        "sets": sets,
        "efficiency": efficiency(tuned),
        "explanations": {
            "measured": False,
            "why": "needs a real LLM provider and costs requests; ask first",
        },
        "problems": found_problems,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m eval.harness",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--tuned", type=Path, default=Path("data/scenarios"))
    parser.add_argument("--heldout", type=Path, default=Path("data/eval/heldout"))
    parser.add_argument("--noise", type=Path, default=Path("data/eval/noise"))
    parser.add_argument("--topology", type=Path, help="give the tool a topology file")
    parser.add_argument("--out", type=Path, default=RESULTS, help="where to write latest.*")
    args = parser.parse_args(argv)
    if not any(args.heldout.glob("*.log")):
        print(f"No held-out files in {args.heldout}. Generate them first: python -m eval.heldout")
        return 2
    hints = load_topology(args.topology) if args.topology else None

    def progress(key, n, total, name):
        print(f"\r{key}: {n}/{total} {name:<40}", end="", flush=True)

    data = evaluate(args.tuned, args.heldout, args.noise, hints, progress)
    print("\r" + " " * 70 + "\r", end="")
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "latest.json").write_text(
        json.dumps(data, indent=2, default=str) + "\n", encoding="utf-8"
    )
    text = to_markdown(data)
    (args.out / "latest.md").write_text(text, encoding="utf-8")
    print(text)
    for item in data["problems"]:
        print(
            f"- [{item['set']}] {item['file']} ({item['variant']}): {item['kind']}: "
            f"{item['reason']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
