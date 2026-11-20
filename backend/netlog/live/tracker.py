"""Keeping track of live incidents between one detection pass and the next.

Each pass runs the ordinary rules and correlation over the recent window of messages,
which gives incidents with fresh ids and findings with fresh numbers. This module matches
them to the incidents already known, so that an incident keeps one id for its whole
life: from the first finding, as it grows, until it closes after a quiet period.

A finding is recognized across passes by its key: the rule, the thing it is about (its
group, such as a device and an interface) and when it started. An open incident takes
in any new incident that shares a finding with it, by rule and group; a closed one only
an exact finding, so a new problem on the same interface next week is a new incident.

What each live incident holds is kept as plain data (a snapshot), with findings referred
to by key, so it survives a restart and can be written back to the database under the
incident's own id.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import datetime

from netlog.correlation.incident import CausalStep, Incident, Link, RootCause
from netlog.detection.finding import Finding
from netlog.detection.rules import LEVELS

# A finding's evidence is capped in a snapshot; the first and the latest lines are kept.
MAX_EVIDENCE = 200


def group_key(finding: Finding | dict) -> str:
    rule = finding["rule"] if isinstance(finding, dict) else finding.rule
    group = finding["group"] if isinstance(finding, dict) else finding.group
    return f"{rule}|{json.dumps(group, sort_keys=True)}"


def finding_key(finding: Finding) -> str:
    return f"{group_key(finding)}|{finding.start.isoformat()}"


def finding_to_dict(finding: Finding) -> dict:
    data = asdict(finding)
    data["start"], data["end"] = finding.start.isoformat(), finding.end.isoformat()
    data.pop("id", None)
    data.pop("upload_id", None)
    return data


def finding_from_dict(data: dict) -> Finding:
    values = {**data}
    values["start"] = datetime.fromisoformat(values["start"])
    values["end"] = datetime.fromisoformat(values["end"])
    return Finding(**values)


def incident_to_dict(incident: Incident, key_of: dict[int, str]) -> dict:
    """An incident as plain data, every finding number replaced by the finding's key."""

    def keys(ids: list[int]) -> list[str]:
        return [key_of[i] for i in ids if i in key_of]

    def root(item: RootCause | None) -> dict | None:
        return None if item is None else {**asdict(item), "finding_ids": keys(item.finding_ids)}

    return {
        "title": incident.title,
        "severity": incident.severity,
        "severity_reason": incident.severity_reason,
        "start": incident.start.isoformat(),
        "end": incident.end.isoformat(),
        "devices": list(incident.devices),
        "finding_ids": keys(incident.finding_ids),
        "context_ids": keys(incident.context_ids),
        "links": [
            [key_of[link.a], key_of[link.b], link.reason]
            for link in incident.links
            if link.a in key_of and link.b in key_of
        ],
        "notes": list(incident.notes),
        "chain": [
            {**asdict(step), "cause": key_of[step.cause], "effect": key_of[step.effect]}
            for step in incident.chain
            if step.cause in key_of and step.effect in key_of
        ],
        "root_cause": root(incident.root_cause),
        "alternatives": [root(item) for item in incident.alternatives],
        "confidence": incident.confidence,
        "confidence_reason": incident.confidence_reason,
        "unknowns": list(incident.unknowns),
    }


def incident_from_dict(incident_id: str, data: dict, id_of: dict[str, int]) -> Incident:
    """The incident back from plain data, with finding keys turned into finding numbers."""

    def ids(keys: list[str]) -> list[int]:
        return [id_of[key] for key in keys if key in id_of]

    def root(item: dict | None) -> RootCause | None:
        return (
            None if item is None else RootCause(**{**item, "finding_ids": ids(item["finding_ids"])})
        )

    return Incident(
        id=incident_id,
        title=data["title"],
        severity=data["severity"],
        severity_reason=data["severity_reason"],
        start=datetime.fromisoformat(data["start"]),
        end=datetime.fromisoformat(data["end"]),
        devices=list(data["devices"]),
        finding_ids=ids(data["finding_ids"]),
        context_ids=ids(data["context_ids"]),
        links=[
            Link(id_of[a], id_of[b], why)
            for a, b, why in data["links"]
            if a in id_of and b in id_of
        ],
        notes=list(data["notes"]),
        chain=[
            CausalStep(**{**step, "cause": id_of[step["cause"]], "effect": id_of[step["effect"]]})
            for step in data["chain"]
            if step["cause"] in id_of and step["effect"] in id_of
        ],
        root_cause=root(data["root_cause"]),
        alternatives=[item for item in (root(a) for a in data["alternatives"]) if item],
        confidence=data["confidence"],
        confidence_reason=data["confidence_reason"],
        unknowns=list(data["unknowns"]),
    )


def new_id(first_key: str, taken: set[str]) -> str:
    """A live incident's id, made from its first finding, so the same messages give the
    same id."""
    digest = hashlib.sha1(first_key.encode()).hexdigest()
    for size in range(10, 41):
        candidate = f"live-{digest[:size]}"
        if candidate not in taken:
            return candidate
    raise RuntimeError("no free live incident id")  # sha1 has 40 digits; never happens


def _higher(a: str, b: str) -> str:
    return a if LEVELS.index(a) >= LEVELS.index(b) else b


def merge_findings(
    old: dict[str, dict], new: dict[str, dict]
) -> tuple[dict[str, dict], bool, dict[str, str]]:
    """The findings of a snapshot updated with those of the latest pass. Returns them,
    whether anything grew (a new finding, more evidence, a later end, a higher severity),
    and the new keys that stand for a finding already known under another key.

    A finding whose start moved later only because its first messages left the window is
    the same finding: the earlier one is kept and extended."""
    merged = dict(old)
    grew = False
    alias: dict[str, str] = {}
    by_group: dict[str, str] = {}
    for key, finding in old.items():
        by_group.setdefault(group_key(finding), key)
    for key, finding in new.items():
        if key in merged:
            before = merged[key]
            # Only new messages count as change. An outage that is still going on gets a
            # later end on every pass by the clock alone; that is not news.
            if set(finding["evidence"]) - set(before["evidence"]) or LEVELS.index(
                finding["severity"]
            ) > LEVELS.index(before["severity"]):
                grew = True
            merged[key] = finding
            continue
        earlier = by_group.get(group_key(finding))
        if (
            earlier is not None
            and merged[earlier]["start"] < finding["start"] <= merged[earlier]["end"]
        ):
            alias[key] = earlier
            kept = merged[earlier]
            if set(finding["evidence"]) - set(kept["evidence"]):
                grew = True
            evidence = list(dict.fromkeys([*kept["evidence"], *finding["evidence"]]))
            if len(evidence) > MAX_EVIDENCE:
                evidence = evidence[: MAX_EVIDENCE // 2] + evidence[-MAX_EVIDENCE // 2 :]
            merged[earlier] = {
                **kept,
                "end": max(kept["end"], finding["end"]),
                "evidence": evidence,
            }
            continue
        merged[key] = finding
        by_group.setdefault(group_key(finding), key)
        grew = True
    return merged, grew, alias


def translate(incident: dict, alias: dict[str, str]) -> dict:
    """An incident's finding keys with the aliases of `merge_findings` applied."""
    if not alias:
        return incident

    def one(key: str) -> str:
        return alias.get(key, key)

    def many(keys: list[str]) -> list[str]:
        return list(dict.fromkeys(one(key) for key in keys))

    out = {**incident, "finding_ids": many(incident["finding_ids"])}
    out["context_ids"] = many(incident["context_ids"])
    out["links"] = [[one(a), one(b), why] for a, b, why in incident["links"]]
    out["chain"] = [
        {**step, "cause": one(step["cause"]), "effect": one(step["effect"])}
        for step in incident["chain"]
    ]
    for name in ("root_cause",):
        if out[name]:
            out[name] = {**out[name], "finding_ids": many(out[name]["finding_ids"])}
    out["alternatives"] = [
        {**a, "finding_ids": many(a["finding_ids"])} for a in incident["alternatives"]
    ]
    return out


def merge_incident(old: dict | None, new: dict, findings: dict[str, dict]) -> dict:
    """The incident part of a snapshot. The latest pass's view replaces the old one when it
    still sees every finding; otherwise (the first findings have left the window) the old
    structure is kept, with the new findings, the later end and a higher severity added."""
    if old is None:
        return new
    if set(old["finding_ids"]) | set(old["context_ids"]) <= set(new["finding_ids"]) | set(
        new["context_ids"]
    ):
        merged = dict(new)
        merged["start"] = min(old["start"], new["start"])
    else:
        merged = dict(old)
        merged["finding_ids"] = list(dict.fromkeys([*old["finding_ids"], *new["finding_ids"]]))
        merged["end"] = max(old["end"], new["end"])
        merged["devices"] = sorted(set(old["devices"]) | set(new["devices"]))
    merged["severity"] = _higher(old["severity"], new["severity"])
    if merged["severity"] != new["severity"]:
        merged["severity_reason"] = old["severity_reason"]
    known = set(findings)
    for name in ("finding_ids", "context_ids"):
        merged[name] = [key for key in merged[name] if key in known]
    return merged
