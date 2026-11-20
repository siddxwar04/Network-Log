"""Writing the explanations that are stored with the demo scenarios.

`netlog demo-explanations --yes` runs every built-in scenario through the pipeline exactly
as the web app does when a demo card is clicked, asks the configured LLM to explain each
incident for both audiences, and stores the answers that pass every check. Afterwards the
demo shows LLM-written explanations to anyone, with no API key and no request.

It costs requests, so it does nothing without `--yes`, and it refuses to run when no LLM
is configured.
"""

from __future__ import annotations

import json
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from netlog.config import load_config
from netlog.correlation.grouping import correlate
from netlog.detection.engine import detect
from netlog.detection.rules import load_rule_set
from netlog.ingestion.ingest import ingest_file
from netlog.llm.evidence import outgoing_packs
from netlog.llm.explain import explain_pack, make_provider
from netlog.llm.explanation import MODES
from netlog.llm.prompt import load_prompt
from netlog.llm.provider import Provider, ProviderError
from netlog.llm.settings import llm_settings
from netlog.llm.stored import StoredAnswer, stored_path, write_stored
from netlog.mining.templates import mine_templates
from netlog.storage.database import Database


def demo_scenarios(folder: Path) -> list[tuple[str, Path, int | None]]:
    """The built-in scenarios: (name, log file, year), read the way the web app reads
    them, from the label file beside each log."""
    found = []
    for labels in sorted(folder.glob("*.labels.json")):
        name = labels.name.removesuffix(".labels.json")
        log = labels.with_name(f"{name}.log")
        if not log.is_file():
            continue
        try:
            year = json.loads(labels.read_text(encoding="utf-8")).get("year")
        except (OSError, ValueError):
            year = None
        found.append((name, log, year))
    return found


def write_demo_explanations(
    config: dict,
    provider: Provider,
    output: Path,
    *,
    say: Callable[[str], None] = print,
) -> tuple[int, int]:
    """Explain every incident of every demo scenario for both audiences and store the
    answers that passed. Returns (stored, failed)."""
    settings = llm_settings(config)
    model = settings.model_for(provider.name)
    version = load_prompt(settings.prompt).version
    answers: list[StoredAnswer] = []
    failed = 0
    folder = Path(config["api"]["demo_dir"])
    with tempfile.TemporaryDirectory(prefix="netlog-demo-") as workdir:
        with Database(Path(workdir) / "demo.db") as db:
            for name, log, year in demo_scenarios(folder):
                upload_id = db.create_upload(
                    log.name, log.stat().st_size, year=year, timezone="UTC", source="demo"
                )
                ingest_file(db, log, year=year, tz=UTC, upload_id=upload_id)
                mine_templates(db, upload_id, config)
                ruleset = load_rule_set(config=config)  # as the web app runs them
                detect(db, upload_id, ruleset.rules, ruleset.severity_settings(config))
                correlate(db, upload_id, config)
                packs, _ = outgoing_packs(db, upload_id, config)
                for incident, pack in packs:
                    for mode in MODES:
                        result = explain_pack(
                            db, pack, mode, provider=provider, settings=settings,
                            config=config, refresh=True,
                        )  # fmt: skip
                        if result.source != "llm" or result.explanation is None:
                            failed += 1
                            say(f"  {name} {incident.id} {mode}: not stored ({result.reason})")
                            continue
                        answers.append(
                            StoredAnswer(
                                scenario=name,
                                pack_hash=pack.hash,
                                mode=mode,
                                provider=provider.name,
                                model=model,
                                prompt_version=version,
                                content=result.explanation.model_dump_json(),
                                created_at=datetime.now(UTC).strftime("%Y-%m-%d"),
                            )
                        )
                        say(f"  {name} {incident.id} {mode}: stored")
    write_stored(output, answers)
    return len(answers), failed


def demo_explanations(args, provider: Provider | None = None) -> int:
    """The `netlog demo-explanations` command. Exit code 0 when every answer was stored."""
    try:
        config = load_config(args.config)
    except ValueError as error:
        print(f"netlog: {error}")
        return 2
    output = args.output or stored_path(config)
    scenarios = demo_scenarios(Path(config["api"]["demo_dir"]))
    if provider is None:
        try:
            provider = make_provider(llm_settings(config))
        except ProviderError as error:
            print(f"netlog: {error}")
            return 2
    if provider is None:
        print(
            "netlog: no LLM is configured, so there is nothing to ask. Set NETLOG_LLM_PROVIDER "
            "and its API key in .env first."
        )
        return 2
    if not args.yes:
        print(
            f"This would explain the incidents of {len(scenarios)} demo scenarios for both "
            f"audiences with {provider.name}, one or two requests each, and write the answers "
            f"to {output}. Run it again with --yes to go ahead."
        )
        return 0
    print(f"Explaining the demo scenarios with {provider.name}...")
    stored, failed = write_demo_explanations(config, provider, output)
    print(f"Stored {stored} explanations in {output}" + (f"; {failed} failed." if failed else "."))
    return 0 if not failed else 1
