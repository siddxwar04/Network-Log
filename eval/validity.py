"""Validity: explains every incident of every scenario and counts how the explanations
fared against the validator.

    python -m eval.validity
    python -m eval.validity --yes
    python -m eval.validity --mode junior --yes

For each incident it reports who wrote the explanation that was kept: the LLM at the
first attempt, the LLM after one retry, or the built-in fallback. It also reports the
citation validity rate: of all the evidence ids the LLM cited, the share that exist.

With no provider configured, every incident gets the fallback, and the table shows that
the fallback passes the validator. With a provider configured this makes real, paid
requests (up to two per incident that is not already cached), so it does nothing until
`--yes` is given.
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
from netlog.llm.evidence import outgoing_packs
from netlog.llm.explain import ExplanationResult, explain_incident
from netlog.llm.explanation import MODES
from netlog.llm.fallback import fallback_explanation
from netlog.llm.provider import Provider
from netlog.llm.settings import LLMSettings, llm_settings, load_env_file
from netlog.llm.validate import validate_explanation
from netlog.mining.templates import mine_templates
from netlog.storage.database import Database, default_db_path

OUTCOMES = {
    "first_time": "LLM, first attempt",
    "retry": "LLM, after one retry",
    "cache": "LLM, from the cache",
    "fallback": "fallback",
}


@dataclass
class Row:
    scenario: str
    incident: str
    severity: str
    result: ExplanationResult
    # Whether the built-in explanation of this incident passes the validator.
    fallback_valid: bool


def explain_all(
    cache: Database,
    scenarios: Path = Path("data/scenarios"),
    mode: str = "senior",
    *,
    provider: Provider | None = None,
    settings: LLMSettings | None = None,
    config: dict | None = None,
    hints: Topology | None = None,
    year: int = 2026,
) -> list[Row]:
    """Explain every incident of every scenario. `provider` replaces the configured one."""
    config = config or load_config()
    rows: list[Row] = []
    with tempfile.TemporaryDirectory(prefix="netlog-validity-") as workdir:
        with Database(Path(workdir) / "analysis.db") as db:
            for log in sorted(scenarios.glob("*.log")):
                upload = ingest_file(db, log, year=year)
                mine_templates(db, upload, config)
                detect(db, upload, config=config)
                correlate(db, upload, config, hints)
                packs, _ = outgoing_packs(db, upload, config)
                for incident, pack in packs:
                    result = explain_incident(
                        cache, pack, mode, provider=provider, settings=settings, config=config
                    )
                    builtin = fallback_explanation(pack, config)
                    rows.append(
                        Row(
                            scenario=log.stem,
                            incident=incident.id,
                            severity=incident.severity,
                            result=result,
                            fallback_valid=not validate_explanation(builtin, pack, config),
                        )
                    )
    return rows


def summarize(rows: list[Row]) -> dict:
    """The counts the table ends with."""
    tries = [attempt for row in rows for attempt in row.result.tries]
    asked = [row for row in rows if row.result.tries]
    cited = sum(attempt.citations for attempt in tries)
    valid = sum(attempt.valid_citations for attempt in tries)
    return {
        "incidents": len(rows),
        "first_time": sum(1 for row in rows if row.result.outcome == "first_time"),
        "retry": sum(1 for row in rows if row.result.outcome == "retry"),
        "cache": sum(1 for row in rows if row.result.outcome == "cache"),
        "fallback": sum(1 for row in rows if row.result.outcome == "fallback"),
        # Incidents for which the LLM gave at least one answer.
        "asked": len(asked),
        "first_answer_valid": sum(1 for row in asked if row.result.tries[0].passed),
        "citations": cited,
        "valid_citations": valid,
        "fallback_valid": sum(1 for row in rows if row.fallback_valid),
    }


def _percent(part: int, whole: int) -> str:
    return f"{100 * part / whole:.0f}%" if whole else "n/a"


def to_markdown(rows: list[Row]) -> str:
    lines = [
        "| Scenario | Incident | Severity | Written by | Citations valid | Fallback valid |",
        "|---|---|---|---|---:|---|",
    ]
    for row in rows:
        tries = row.result.tries
        cited = sum(attempt.citations for attempt in tries)
        valid = sum(attempt.valid_citations for attempt in tries)
        lines.append(
            f"| {row.scenario} | {row.incident} | {row.severity} "
            f"| {OUTCOMES[row.result.outcome]} | {f'{valid} of {cited}' if tries else 'n/a'} "
            f"| {'yes' if row.fallback_valid else 'NO'} |"
        )
    totals = summarize(rows)
    lines += [
        "",
        f"{totals['incidents']} incident(s): {totals['first_time']} explained by the LLM at "
        f"the first attempt, {totals['retry']} after one retry, {totals['cache']} from the "
        f"cache, {totals['fallback']} by the fallback.",
        f"First-time validity: {totals['first_answer_valid']} of {totals['asked']} first "
        f"answers passed every check ({_percent(totals['first_answer_valid'], totals['asked'])}).",
        f"Citation validity: {totals['valid_citations']} of {totals['citations']} cited ids "
        f"exist ({_percent(totals['valid_citations'], totals['citations'])}).",
        f"The fallback passes the validator for {totals['fallback_valid']} of "
        f"{totals['incidents']} incident(s).",
    ]
    for row in rows:
        if row.result.outcome in ("retry", "fallback") and row.result.tries:
            lines.append(f"\n{row.scenario} {row.incident}, first answer rejected:")
            lines += [f"- {problem}" for problem in row.result.tries[0].problems[:8]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m eval.validity",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--mode", choices=MODES, default="senior")
    parser.add_argument("--scenarios", type=Path, default=Path("data/scenarios"))
    parser.add_argument("--topology", type=Path, help="a topology file to give the tool")
    parser.add_argument("--config", type=Path, help="a settings file that overrides the defaults")
    parser.add_argument("--cache", type=Path, help="the database that holds cached answers")
    parser.add_argument(
        "--yes", action="store_true", help="make real requests to the configured provider"
    )
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    load_env_file()
    try:
        config = load_config(args.config)
        settings = llm_settings(config)
        hints = load_topology(args.topology) if args.topology else None
    except ValueError as error:
        parser.error(str(error))

    if settings.configured and not args.yes:
        print(
            f"The provider {settings.provider} is configured. This command would make real, "
            "paid requests: up to two for every incident that is not already cached.\n"
            "Run it again with --yes to go ahead."
        )
        return 2
    if not settings.configured:
        print(
            "No LLM provider is configured, so every incident gets the built-in fallback "
            "and no request is made.\n"
        )

    with Database(args.cache or default_db_path()) as cache:
        rows = explain_all(
            cache, args.scenarios, args.mode, settings=settings, config=config, hints=hints
        )
    print(to_markdown(rows))
    return 0 if all(row.fallback_valid for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
