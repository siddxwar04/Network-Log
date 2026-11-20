"""Gets the explanation of each incident ready for the report.

For every incident the report lists, this module builds the evidence pack, asks for the
explanation (from the LLM when one is configured, from the built-in templates
otherwise), and then turns it into something a person can read and check:

  - the stand-ins that were sent to the LLM (HOST_1, IP_3) are replaced by the real
    names and addresses, which never left this machine;
  - every cited evidence id (E3, F1, C2) is replaced by the line numbers in the original
    log file that it stands for, so the reader can open the file and look.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from netlog.llm.evidence import EvidencePack, outgoing_packs
from netlog.llm.explain import ExplanationResult, explain_incident, restore_explanation
from netlog.llm.provider import Provider
from netlog.llm.settings import LLMSettings
from netlog.redaction.redactor import Redactor
from netlog.report.build import Cited, ReportExplanation
from netlog.storage.database import Database

_TOKEN_LEFT = re.compile(r"(?<![A-Za-z0-9_])(?:IP|USER|HOST|MAC|TEXT)_\d+(?![A-Za-z0-9_])")


class _Lines:
    """Which lines of the original file each id of one pack stands for."""

    def __init__(self, db: Database, upload_id: int, pack: EvidencePack) -> None:
        data = pack.data
        self._line = {item["id"]: item["line"] for item in data["evidence"]}
        self._finding: dict[str, list[int]] = {}
        stored = {finding.id: finding for finding in db.findings(upload_id)}
        for item in data["findings"]:
            lines = [self._line[cid] for cid in item["evidence"] if cid in self._line]
            if not lines:
                # None of this finding's lines made it into the pack. It still rests on
                # log lines; point at the first of them.
                finding = stored.get(pack.finding_ids.get(item["id"], -1))
                first = db.events_by_id(finding.evidence[:1]) if finding else []
                lines = [event.line_no for event in first]
            self._finding[item["id"]] = lines
        self._chain = {
            step["id"]: [
                line
                for link in step["links"]
                for line in self._finding.get(link["effect"], [])[:1]
            ]
            for step in data["chain"]
        }
        self._template = {
            item["id"]: [self._line[cid] for cid in item["examples"] if cid in self._line]
            for item in data["templates"]
        }

    def of(self, ids: list[str]) -> list[int]:
        """The line numbers a list of cited ids stands for, in file order."""
        found: set[int] = set()
        for cid in ids:
            if cid in self._line:
                found.add(self._line[cid])
            for table in (self._finding, self._chain, self._template):
                found.update(table.get(cid, []))
        return sorted(found)


def _source(result: ExplanationResult) -> str:
    if result.source == "fallback":
        why = (result.reason or "").splitlines()[0].rstrip(":;.") if result.reason else ""
        return "the built-in templates, not an LLM" + (f" ({why})" if why else "")
    written = f"{result.provider} {result.model}".strip()
    cached = ", read from the cache" if result.source == "cache" else ""
    return f"an LLM ({written}), checked against the evidence{cached}"


def present(
    db: Database,
    upload_id: int,
    pack: EvidencePack,
    result: ExplanationResult,
    redactor: Redactor,
) -> ReportExplanation:
    """An explanation as the report shows it: real names, and line numbers for citations."""
    lines = _Lines(db, upload_id, pack)
    shown = restore_explanation(result.explanation, redactor)
    return ReportExplanation(
        source=result.source,
        written_by=_source(result),
        mode=result.mode,
        provider=result.provider,
        model=result.model,
        reason=result.reason if result.source == "fallback" else None,
        summary=shown.summary,
        timeline=[Cited(s.text, lines.of(s.evidence), list(s.evidence)) for s in shown.timeline],
        hypotheses=[
            Cited(
                h.text,
                lines.of(h.supporting),
                list(h.supporting),
                against=lines.of(h.contradicting),
                against_ids=list(h.contradicting),
            )
            for h in shown.hypotheses
        ],
        impact=[Cited(i.text, lines.of(i.evidence), list(i.evidence)) for i in shown.impact],
        fix_steps=[(step.text, step.changes_configuration) for step in shown.fix_steps],
        commands=[(c.command, c.purpose) for c in shown.verification_commands],
        unknowns=list(shown.unknowns),
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        latency_ms=result.latency_ms,
        requests=len(result.tries),
        # A stand-in that survived would mean the explanation names something that was
        # never in the pack. The validator rejects that; this is the last look.
        leftover_tokens=sorted(set(_TOKEN_LEFT.findall(shown.model_dump_json()))),
    )


def explain_incidents(
    db: Database,
    upload_id: int,
    incident_ids: list[str],
    cache: Database,
    mode: str = "senior",
    *,
    use_llm: bool = True,
    provider: Provider | None = None,
    settings: LLMSettings | None = None,
    config: dict | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> dict[str, ReportExplanation]:
    """The explanation of each of the given incidents of an upload, by incident id.

    `cache` is the database that holds stored LLM answers; `db` holds the analysis.
    """
    wanted = set(incident_ids)
    packs, redactor = outgoing_packs(db, upload_id, config)
    explained: dict[str, ReportExplanation] = {}
    for incident, pack in packs:
        if incident.id not in wanted:
            continue
        if on_progress:
            on_progress(len(explained) + 1, len(wanted))
        result = explain_incident(
            cache,
            pack,
            mode,
            use_llm=use_llm,
            provider=provider,
            settings=settings,
            config=config,
        )
        explained[incident.id] = present(db, upload_id, pack, result, redactor)
    return explained
