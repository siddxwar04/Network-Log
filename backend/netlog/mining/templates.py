"""Template mining: thousands of similar lines become a handful of patterns with counts.

    Interface GigabitEthernet0/1, changed state to down
    Interface GigabitEthernet0/7, changed state to down
    Interface FastEthernet0/3, changed state to down

all become one template:

    Interface <IF>, changed state to down

Two steps do the work:
  1. Masking replaces values that are obviously variable (addresses, interface names,
     numbers) with a placeholder such as <IP>.
  2. Drain groups the masked messages by similarity and turns the words that still
     differ, such as usernames, into the wildcard <*>.

Messages are mined separately for each event key, so two Cisco messages with different
codes can never share a template however alike their wording is. A state change is also
kept apart by the state it ends in: "changed state to down" and "changed state to up"
differ by one word, which Drain would merge, but they mean opposite things.

Values the parsers already identified as chosen by a person or a client (the username,
the DHCP hostname) are masked too. Such a value can be anything, including several
words, and without this each odd username would create a template of its own.

Templates are for summarizing a log and for the explanations later. Detection rules do
not use them; rules work on event keys and entities.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime

from drain3 import TemplateMiner
from drain3.masking import MaskingInstruction
from drain3.template_miner_config import TemplateMinerConfig

from netlog.config import load_config
from netlog.parsers.pipeline import free_text_spans
from netlog.schema import Event
from netlog.storage.database import Database, EventFilter, Template

_EMPTY_MESSAGE = "<empty>"


@dataclass
class MiningResult:
    lines: int
    templates: int

    @property
    def compression_ratio(self) -> float:
        """How many lines there are per template."""
        return self.lines / self.templates if self.templates else 0.0


@dataclass
class _Cluster:
    """What is collected about one Drain cluster while events stream past."""

    count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    hosts: set[str] = field(default_factory=set)
    event_ids: list[int] = field(default_factory=list)
    # The first event seen from each host, so examples can come from different devices.
    first_by_host: dict[str | None, int] = field(default_factory=dict)

    def add(self, event: Event) -> None:
        self.count += 1
        self.event_ids.append(event.id)
        if event.timestamp is not None:
            if self.first_seen is None or event.timestamp < self.first_seen:
                self.first_seen = event.timestamp
            if self.last_seen is None or event.timestamp > self.last_seen:
                self.last_seen = event.timestamp
        if event.host:
            self.hosts.add(event.host)
        self.first_by_host.setdefault(event.host, event.id)

    def examples(self, limit: int) -> tuple[int, ...]:
        chosen = sorted(self.first_by_host.values())[:limit]
        for event_id in self.event_ids:
            if len(chosen) >= limit:
                break
            if event_id not in chosen:
                chosen.append(event_id)
        return tuple(sorted(chosen))


def _drain_config(settings: dict) -> TemplateMinerConfig:
    config = TemplateMinerConfig()
    config.drain_sim_th = float(settings["similarity_threshold"])
    config.drain_depth = int(settings["depth"])
    config.drain_max_children = int(settings["max_children"])
    config.profiling_enabled = False
    config.mask_prefix, config.mask_suffix = "<", ">"
    config.masking_instructions = []
    for mask in settings["masks"]:
        try:
            re.compile(mask["pattern"])
        except re.error as error:
            raise ValueError(
                f"mining mask {mask['name']!r} is not a valid pattern: {error}"
            ) from None
        config.masking_instructions.append(MaskingInstruction(mask["pattern"], mask["name"]))
    return config


def _mask_free_text(event: Event) -> str:
    """Replace the username and client hostname in an event's message with placeholders.

    The parsers say exactly where those values sit, so a username that happens to be an
    ordinary word of the message (someone logging in as "user" or "from") is replaced in
    the right place and nowhere else.
    """
    message = event.message
    for start, end, placeholder in sorted(free_text_spans(event), reverse=True):
        message = message[:start] + placeholder + message[end:]
    return message


def _template_id(source_type: str, group: str, pattern: str) -> str:
    """An id derived from the template's content, so the same log always gives the same ids."""
    digest = hashlib.sha1(f"{source_type}\x1f{group}\x1f{pattern}".encode()).hexdigest()
    return f"t-{digest[:10]}"


def mine_templates(db: Database, upload_id: int, config: dict | None = None) -> MiningResult:
    """Mine the templates of an upload, store them, and write each event's template id.

    Running it again replaces the previous result. Lines no parser understood are left
    without a template; they are reported through parse coverage instead.
    """
    settings = (config or load_config())["mining"]
    drain_config = _drain_config(settings)

    miners: dict[tuple[str, str], TemplateMiner] = {}
    clusters: dict[tuple[str, str, int], _Cluster] = {}
    keys: dict[tuple[str, str], str | None] = {}

    lines = 0
    for event in db.iter_events(upload_id, EventFilter(parse_status_not="unparsed")):
        lines += 1
        # One miner per kind of message and end state. Lines with no event key are
        # grouped by program.
        kind = event.event_key or f"app:{event.app or ''}"
        group = (str(event.source_type), f"{kind}\x1f{event.entities.state_to or ''}")
        miner = miners.get(group)
        if miner is None:
            miner = miners[group] = TemplateMiner(config=drain_config)
            keys[group] = event.event_key
        message = _mask_free_text(event) or _EMPTY_MESSAGE
        cluster_id = miner.add_log_message(message)["cluster_id"]
        clusters.setdefault((*group, cluster_id), _Cluster()).add(event)

    # A cluster's pattern can keep changing until the last line, so templates are only
    # read from Drain once every event has been seen.
    merged: dict[str, tuple[str, str, str, list[_Cluster]]] = {}
    for group, miner in miners.items():
        for drain_cluster in miner.drain.clusters:
            pattern = drain_cluster.get_template()
            template_id = _template_id(*group, pattern)
            entry = merged.setdefault(template_id, (group[0], keys[group], pattern, []))
            entry[3].append(clusters[(*group, drain_cluster.cluster_id)])

    templates, assignments = [], []
    max_examples = int(settings["max_examples"])
    for template_id, (source_type, event_key, pattern, parts) in merged.items():
        total = _Cluster()
        for part in parts:  # normally one; two clusters can end up with the same pattern
            total.count += part.count
            total.hosts |= part.hosts
            total.event_ids += part.event_ids
            for host, event_id in part.first_by_host.items():
                total.first_by_host[host] = min(event_id, total.first_by_host.get(host, event_id))
            seen = [t for t in (total.first_seen, part.first_seen) if t]
            total.first_seen = min(seen, default=None)
            seen = [t for t in (total.last_seen, part.last_seen) if t]
            total.last_seen = max(seen, default=None)
        templates.append(
            Template(
                id=template_id,
                source_type=source_type,
                event_key=event_key,
                pattern=pattern,
                count=total.count,
                first_seen=total.first_seen,
                last_seen=total.last_seen,
                hosts=tuple(sorted(total.hosts)),
                examples=total.examples(max_examples),
            )
        )
        assignments.extend((template_id, event_id) for event_id in total.event_ids)

    db.save_templates(upload_id, templates, assignments)
    return MiningResult(lines=lines, templates=len(templates))
