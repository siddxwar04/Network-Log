"""Explanations: explains each incident of one scenario and prints the explanation with
the real addresses and names put back.

    python -m eval.explain 02_cascade
    python -m eval.explain 02_cascade --mode junior

With a provider configured, this makes a real, paid request for every incident that is
not already in the cache (two, if the first answer fails validation). The provider and
the key are read from the environment or from a file named .env:

    NETLOG_LLM_PROVIDER=openai
    NETLOG_LLM_API_KEY=...

Answers that pass validation are cached in the local database (data/netlog.db), so
running the same command again costs nothing.

With no provider configured, or when the LLM's answer is rejected twice, the built-in
explanation is printed instead, and the last line says so.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from netlog.config import load_config
from netlog.correlation.grouping import correlate
from netlog.correlation.topology import load_topology
from netlog.detection.engine import detect
from netlog.ingestion.ingest import ingest_file
from netlog.llm.evidence import outgoing_packs
from netlog.llm.explain import explain_incident, restore_explanation
from netlog.llm.explanation import MODES
from netlog.llm.settings import ENV_KEY, ENV_PROVIDER, llm_settings, load_env_file
from netlog.mining.templates import mine_templates
from netlog.storage.database import Database, default_db_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m eval.explain",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("scenario", help="a sample log, such as 02_cascade")
    parser.add_argument("--mode", choices=MODES, default="senior")
    parser.add_argument("--scenarios", type=Path, default=Path("data/scenarios"))
    parser.add_argument("--topology", type=Path, help="a topology file to give the tool")
    parser.add_argument("--config", type=Path, help="a settings file that overrides the defaults")
    parser.add_argument("--cache", type=Path, help="the database that holds cached answers")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    load_env_file()
    log = args.scenarios / f"{args.scenario}.log"
    if not log.exists():
        parser.error(f"no such scenario: {log}")
    try:
        config = load_config(args.config)
        settings = llm_settings(config)
        hints = load_topology(args.topology) if args.topology else None
    except ValueError as error:
        parser.error(str(error))

    with tempfile.TemporaryDirectory(prefix="netlog-explain-") as workdir:
        with Database(Path(workdir) / "analysis.db") as db:
            upload = ingest_file(db, log, year=2026)
            mine_templates(db, upload, config)
            detect(db, upload, config=config)
            correlate(db, upload, config, hints)
            packs, redactor = outgoing_packs(db, upload, config)
    if not packs:
        print(f"{args.scenario} has no incidents, so there is nothing to explain.")
        return 0

    with Database(args.cache or default_db_path()) as cache:
        for incident, pack in packs:
            result = explain_incident(cache, pack, args.mode, settings=settings, config=config)
            print(f"# {incident.id}: {redactor.restore(pack.data['incident']['title'])}")
            shown = restore_explanation(result.explanation, redactor)
            print(json.dumps(shown.model_dump(), indent=2, ensure_ascii=False))

            rejected = [attempt for attempt in result.tries if not attempt.passed]
            for number, attempt in enumerate(rejected, 1):
                print(f"# Answer {number} from the LLM was rejected by the validator:")
                for problem in attempt.problems:
                    print(f"#   - {problem}")
            if result.source == "fallback":
                why = (result.reason or "").splitlines()[0].rstrip(":")
                print(f"# Written by the built-in fallback, because {why}.")
                if not settings.configured:
                    print(f"# Set {ENV_PROVIDER}=openai and {ENV_KEY}=... in a file named .env.")
                continue
            origin = "from the cache, no request made" if result.cache_hit else "a new request"
            checked = "passed validation" + (" on the second attempt" if rejected else "")
            print(
                f"# Written by {result.provider} {result.model}, {args.mode} mode, {origin}, "
                f"{checked}. Tokens: {result.input_tokens:,} in, {result.output_tokens:,} out. "
                f"Pack sent: {pack.size_chars:,} characters."
                + ("" if result.cache_hit else f" Took {result.latency_ms / 1000:.1f} s.")
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
