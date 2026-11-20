"""SQLite storage for uploads, raw lines, events and templates.

Nothing outside this module writes SQL. Every value that comes from a log line reaches
the database as a bound parameter, never as part of the SQL text; the only names placed
into SQL are column names taken from the fixed lists in this file.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from itertools import islice
from pathlib import Path

from netlog.correlation.incident import CausalStep, Incident, Link, RootCause
from netlog.detection.finding import Finding
from netlog.schema import Entities, Event, ParseStatus, Severity, SourceType

DEFAULT_DB_PATH = "data/netlog.db"
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

# Entity fields stored as their own columns, so rules can filter and group on them.
ENTITY_COLUMNS = (
    "interface",
    "src_ip",
    "dst_ip",
    "neighbor_ip",
    "username",
    "mac",
    "vlan",
    "protocol",
    "port",
    "state_from",
    "state_to",
    "reason",
)
GROUP_COLUMNS = ("host", "source_type", "app", "severity", "event_key", "parse_status") + (
    ENTITY_COLUMNS
)

# One entry per schema version. To change the schema, append a new entry; never edit an
# old one, or existing databases will not be upgraded.
_MIGRATIONS = (
    """
    CREATE TABLE uploads (
        id          INTEGER PRIMARY KEY,
        filename    TEXT NOT NULL,
        size_bytes  INTEGER NOT NULL DEFAULT 0,
        status      TEXT NOT NULL DEFAULT 'processing',
        error       TEXT,
        line_count  INTEGER NOT NULL DEFAULT 0,
        parsed      INTEGER NOT NULL DEFAULT 0,
        partial     INTEGER NOT NULL DEFAULT 0,
        unparsed    INTEGER NOT NULL DEFAULT 0,
        blank       INTEGER NOT NULL DEFAULT 0,
        classified  INTEGER NOT NULL DEFAULT 0,
        created_at  INTEGER NOT NULL,
        finished_at INTEGER
    );

    CREATE TABLE raw_lines (
        upload_id INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
        line_no   INTEGER NOT NULL,
        text      TEXT NOT NULL,
        PRIMARY KEY (upload_id, line_no)
    ) WITHOUT ROWID;

    CREATE TABLE events (
        id           INTEGER PRIMARY KEY,
        upload_id    INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
        line_no      INTEGER NOT NULL,
        ts           INTEGER,
        year_assumed INTEGER NOT NULL,
        tz_assumed   INTEGER NOT NULL,
        host         TEXT,
        source_type  TEXT NOT NULL,
        app          TEXT,
        facility     INTEGER,
        severity     INTEGER,
        event_key    TEXT,
        message      TEXT NOT NULL,
        parse_status TEXT NOT NULL,
        template_id  TEXT,
        interface    TEXT,
        src_ip       TEXT,
        dst_ip       TEXT,
        neighbor_ip  TEXT,
        username     TEXT,
        mac          TEXT,
        vlan         INTEGER,
        protocol     TEXT,
        port         INTEGER,
        state_from   TEXT,
        state_to     TEXT,
        reason       TEXT,
        extra        TEXT NOT NULL
    );
    CREATE INDEX events_by_time      ON events (upload_id, ts);
    CREATE INDEX events_by_key       ON events (upload_id, event_key, ts);
    CREATE INDEX events_by_host      ON events (upload_id, host, ts);
    CREATE INDEX events_by_src_ip    ON events (upload_id, src_ip, ts);
    CREATE INDEX events_by_interface ON events (upload_id, interface, ts);

    CREATE VIRTUAL TABLE events_fts USING fts5(
        message, event_key, host, app, content='events', content_rowid='id'
    );
    CREATE TRIGGER events_fts_delete AFTER DELETE ON events BEGIN
        INSERT INTO events_fts (events_fts, rowid, message, event_key, host, app)
        VALUES ('delete', old.id, old.message, old.event_key, old.host, old.app);
    END;

    CREATE TABLE templates (
        upload_id   INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
        id          TEXT NOT NULL,
        source_type TEXT NOT NULL,
        event_key   TEXT,
        pattern     TEXT NOT NULL,
        count       INTEGER NOT NULL,
        first_seen  INTEGER,
        last_seen   INTEGER,
        hosts       TEXT NOT NULL,
        examples    TEXT NOT NULL,
        PRIMARY KEY (upload_id, id)
    ) WITHOUT ROWID;
    """,
    # Version 2: finding the repeats of a template on a device (template mining, dedup).
    """
    CREATE INDEX events_by_template ON events (upload_id, template_id, host, ts);
    """,
    # Version 3: findings produced by the detection rules.
    """
    CREATE TABLE findings (
        id              INTEGER PRIMARY KEY,
        upload_id       INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
        rule            TEXT NOT NULL,
        incident_type   TEXT NOT NULL,
        title           TEXT NOT NULL,
        host            TEXT,
        group_values    TEXT NOT NULL,
        start_ts        INTEGER NOT NULL,
        end_ts          INTEGER NOT NULL,
        metrics         TEXT NOT NULL,
        flags           TEXT NOT NULL,
        evidence        TEXT NOT NULL,
        strength        REAL NOT NULL,
        severity        TEXT,
        severity_reason TEXT
    );
    CREATE INDEX findings_by_time ON findings (upload_id, start_ts);
    """,
    # Version 4: incidents, which group related findings.
    """
    CREATE TABLE incidents (
        upload_id       INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
        id              TEXT NOT NULL,
        title           TEXT NOT NULL,
        severity        TEXT NOT NULL,
        severity_reason TEXT NOT NULL,
        start_ts        INTEGER NOT NULL,
        end_ts          INTEGER NOT NULL,
        devices         TEXT NOT NULL,
        finding_ids     TEXT NOT NULL,
        context_ids     TEXT NOT NULL,
        links           TEXT NOT NULL,
        notes           TEXT NOT NULL,
        PRIMARY KEY (upload_id, id)
    ) WITHOUT ROWID;
    """,
    # Version 5: cause and effect inside an incident.
    """
    ALTER TABLE incidents ADD COLUMN chain TEXT NOT NULL DEFAULT '[]';
    ALTER TABLE incidents ADD COLUMN root_cause TEXT;
    ALTER TABLE incidents ADD COLUMN alternatives TEXT NOT NULL DEFAULT '[]';
    ALTER TABLE incidents ADD COLUMN confidence TEXT NOT NULL DEFAULT 'low';
    ALTER TABLE incidents ADD COLUMN confidence_reason TEXT NOT NULL DEFAULT '';
    ALTER TABLE incidents ADD COLUMN unknowns TEXT NOT NULL DEFAULT '[]';
    """,
    # Version 6: the stand-ins used for addresses and names in what is sent to an LLM.
    # This table is the only place the real values are kept next to their tokens.
    """
    CREATE TABLE redaction_map (
        upload_id INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
        token     TEXT NOT NULL,
        kind      TEXT NOT NULL,
        original  TEXT NOT NULL,
        PRIMARY KEY (upload_id, token)
    ) WITHOUT ROWID;
    CREATE UNIQUE INDEX redaction_by_original ON redaction_map (upload_id, original);
    """,
    # Version 7: explanations written by an LLM, kept so the same question is never paid
    # for twice, and a record of every request. Neither belongs to an upload: the same
    # incident in a file uploaded again is the same question.
    """
    CREATE TABLE explanations (
        cache_key      TEXT PRIMARY KEY,
        pack_hash      TEXT NOT NULL,
        prompt_version TEXT NOT NULL,
        provider       TEXT NOT NULL,
        model          TEXT NOT NULL,
        mode           TEXT NOT NULL,
        content        TEXT NOT NULL,
        input_tokens   INTEGER NOT NULL,
        output_tokens  INTEGER NOT NULL,
        created_at     INTEGER NOT NULL
    ) WITHOUT ROWID;

    CREATE TABLE llm_calls (
        id            INTEGER PRIMARY KEY,
        incident_id   TEXT,
        cache_key     TEXT,
        provider      TEXT NOT NULL,
        model         TEXT NOT NULL,
        mode          TEXT NOT NULL,
        status        TEXT NOT NULL,
        cache_hit     INTEGER NOT NULL,
        error         TEXT,
        input_tokens  INTEGER NOT NULL DEFAULT 0,
        output_tokens INTEGER NOT NULL DEFAULT 0,
        latency_ms    INTEGER NOT NULL DEFAULT 0,
        attempts      INTEGER NOT NULL DEFAULT 0,
        created_at    INTEGER NOT NULL
    );
    """,
)
SCHEMA_VERSION = len(_MIGRATIONS)

_EVENT_COLUMNS = (
    "upload_id",
    "line_no",
    "ts",
    "year_assumed",
    "tz_assumed",
    "host",
    "source_type",
    "app",
    "facility",
    "severity",
    "event_key",
    "message",
    "parse_status",
    "template_id",
    *ENTITY_COLUMNS,
    "extra",
)
_INSERT_EVENT = (
    f"INSERT INTO events ({', '.join(_EVENT_COLUMNS)}) "
    f"VALUES ({', '.join('?' * len(_EVENT_COLUMNS))})"
)
_SELECT_EVENT = (
    "SELECT e.*, r.text AS raw FROM events e "
    "JOIN raw_lines r ON r.upload_id = e.upload_id AND r.line_no = e.line_no"
)


def default_db_path() -> str:
    return os.environ.get("NETLOG_DB_PATH", DEFAULT_DB_PATH)


def _to_micros(moment: datetime | None) -> int | None:
    """Timestamps are stored as whole microseconds since 1970, in UTC."""
    if moment is None:
        return None
    return (moment - _EPOCH) // timedelta(microseconds=1)


def _from_micros(micros: int | None) -> datetime | None:
    return None if micros is None else _EPOCH + timedelta(microseconds=micros)


@dataclass(frozen=True)
class Upload:
    id: int
    filename: str
    size_bytes: int
    status: str
    error: str | None
    line_count: int
    parsed: int
    partial: int
    unparsed: int
    blank: int
    classified: int
    created_at: datetime
    finished_at: datetime | None

    @property
    def percent_parsed(self) -> float:
        return 100.0 * self.parsed / self.line_count if self.line_count else 0.0


@dataclass(frozen=True)
class Template:
    """A message pattern shared by many events, such as `Interface <IF>, changed state to down`."""

    id: str
    source_type: str
    event_key: str | None
    pattern: str
    count: int
    first_seen: datetime | None
    last_seen: datetime | None
    hosts: tuple[str, ...]
    examples: tuple[int, ...]  # ids of up to a few events that match the pattern


@dataclass(frozen=True)
class StoredExplanation:
    """An LLM's answer as it was received, with what produced it."""

    cache_key: str
    pack_hash: str
    prompt_version: str
    provider: str
    model: str
    mode: str
    content: str
    input_tokens: int
    output_tokens: int
    created_at: datetime


@dataclass(frozen=True)
class LLMCall:
    """One request for an explanation: answered by the provider, by the cache, or not."""

    id: int
    incident_id: str | None
    cache_key: str | None
    provider: str
    model: str
    mode: str
    status: str  # ok, cached, malformed, error
    cache_hit: bool
    error: str | None
    input_tokens: int
    output_tokens: int
    latency_ms: int
    attempts: int
    created_at: datetime


@dataclass
class EventFilter:
    """Which events to return. Every condition given must hold."""

    start: datetime | None = None  # at or after
    end: datetime | None = None  # strictly before
    host: str | None = None
    source_type: str | None = None
    parse_status: str | None = None
    parse_status_not: str | None = None
    template_id: str | None = None
    # "At or above" in seriousness: 3 returns severities 0 to 3 (error and worse).
    min_severity: int | None = None
    event_keys: tuple[str, ...] | list[str] = ()
    # Entity values that must match exactly, for example {"src_ip": "192.0.2.77"}.
    entities: dict[str, str | int] = field(default_factory=dict)
    # Words that must all appear in the message, event key, host or program name.
    text: str | None = None

    def to_sql(self, upload_id: int) -> tuple[str, list]:
        clauses, params = ["e.upload_id = ?"], [upload_id]

        def add(clause: str, *values) -> None:
            clauses.append(clause)
            params.extend(values)

        if self.start is not None:
            add("e.ts >= ?", _to_micros(self.start))
        if self.end is not None:
            add("e.ts < ?", _to_micros(self.end))
        if self.host is not None:
            add("e.host = ?", self.host)
        if self.source_type is not None:
            add("e.source_type = ?", str(self.source_type))
        if self.parse_status is not None:
            add("e.parse_status = ?", str(self.parse_status))
        if self.parse_status_not is not None:
            add("e.parse_status != ?", str(self.parse_status_not))
        if self.template_id is not None:
            add("e.template_id = ?", self.template_id)
        if self.min_severity is not None:
            add("e.severity <= ?", int(self.min_severity))
        if self.event_keys:
            marks = ", ".join("?" * len(self.event_keys))
            add(f"e.event_key IN ({marks})", *self.event_keys)
        for column, value in self.entities.items():
            if column not in ENTITY_COLUMNS:
                raise ValueError(f"not an entity field: {column!r}")
            add(f"e.{column} = ?", value)
        if self.text is not None:
            add("e.id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)", _fts(self.text))
        return " AND ".join(clauses), params


def _fts(text: str) -> str:
    """Turn free text into a full-text query for "all of these words".

    Each word is quoted, so nothing the user types is read as search syntax.
    """
    words = re.findall(r"\w+", text)
    return " ".join(f'"{word}"' for word in words) if words else '""'


class Database:
    def __init__(self, path: str | Path | None = None) -> None:
        path = Path(path if path is not None else default_db_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute("PRAGMA synchronous = NORMAL")
        self._db.execute("PRAGMA foreign_keys = ON")
        self._migrate()

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def _migrate(self) -> None:
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(
                f"database is at schema version {version}, but this program only knows "
                f"version {SCHEMA_VERSION}; it was created by a newer release"
            )
        for number in range(version, SCHEMA_VERSION):
            self._db.executescript(f"BEGIN; {_MIGRATIONS[number]} COMMIT;")
            self._db.execute(f"PRAGMA user_version = {number + 1}")

    @property
    def schema_version(self) -> int:
        return self._scalar("PRAGMA user_version")

    def _scalar(self, sql: str, params: Iterable = ()):
        return self._db.execute(sql, tuple(params)).fetchone()[0]

    # --- Uploads --------------------------------------------------------------------------

    def create_upload(self, filename: str, size_bytes: int = 0) -> int:
        with self._db:
            cursor = self._db.execute(
                "INSERT INTO uploads (filename, size_bytes, created_at) VALUES (?, ?, ?)",
                (filename, size_bytes, _to_micros(datetime.now(UTC))),
            )
        return cursor.lastrowid

    def finish_upload(self, upload_id: int, coverage) -> None:
        """Record the parse coverage of an upload and mark it as done."""
        with self._db:
            self._db.execute(
                "UPDATE uploads SET status = 'done', finished_at = ?, line_count = ?, parsed = ?, "
                "partial = ?, unparsed = ?, blank = ?, classified = ? WHERE id = ?",
                (
                    _to_micros(datetime.now(UTC)),
                    coverage.total,
                    coverage.parsed,
                    coverage.partial,
                    coverage.unparsed,
                    coverage.blank,
                    coverage.classified,
                    upload_id,
                ),
            )

    def fail_upload(self, upload_id: int, error: str) -> None:
        with self._db:
            self._db.execute(
                "UPDATE uploads SET status = 'failed', error = ?, finished_at = ? WHERE id = ?",
                (error, _to_micros(datetime.now(UTC)), upload_id),
            )

    def get_upload(self, upload_id: int) -> Upload | None:
        row = self._db.execute("SELECT * FROM uploads WHERE id = ?", (upload_id,)).fetchone()
        return self._upload(row) if row else None

    def list_uploads(self, limit: int = 50, offset: int = 0) -> list[Upload]:
        rows = self._db.execute(
            "SELECT * FROM uploads ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset)
        )
        return [self._upload(row) for row in rows]

    def delete_upload(self, upload_id: int) -> bool:
        """Delete an upload and everything that belongs to it."""
        with self._db:
            cursor = self._db.execute("DELETE FROM uploads WHERE id = ?", (upload_id,))
        return cursor.rowcount > 0

    @staticmethod
    def _upload(row: sqlite3.Row) -> Upload:
        values = dict(row)
        values["created_at"] = _from_micros(values["created_at"])
        values["finished_at"] = _from_micros(values["finished_at"])
        return Upload(**values)

    # --- Writing events -------------------------------------------------------------------

    def add_events(self, upload_id: int, events: Iterable[Event], batch_size: int = 5000) -> int:
        """Store events and their raw lines. Returns how many were stored."""
        stored = 0
        iterator = iter(events)
        while batch := list(islice(iterator, batch_size)):
            with self._db:
                last_old = self._scalar("SELECT COALESCE(MAX(id), 0) FROM events")
                self._db.executemany(
                    "INSERT INTO raw_lines (upload_id, line_no, text) VALUES (?, ?, ?)",
                    ((upload_id, e.line_no, e.raw) for e in batch),
                )
                self._db.executemany(_INSERT_EVENT, (self._row(upload_id, e) for e in batch))
                # Index the new messages for full-text search in one statement per batch.
                self._db.execute(
                    "INSERT INTO events_fts (rowid, message, event_key, host, app) "
                    "SELECT id, message, event_key, host, app FROM events WHERE id > ?",
                    (last_old,),
                )
            stored += len(batch)
        return stored

    @staticmethod
    def _row(upload_id: int, event: Event) -> tuple:
        entities = event.entities
        return (
            upload_id,
            event.line_no,
            _to_micros(event.timestamp),
            event.year_assumed,
            event.tz_assumed,
            event.host,
            str(event.source_type),
            event.app,
            event.facility,
            None if event.severity is None else int(event.severity),
            event.event_key,
            event.message,
            str(event.parse_status),
            event.template_id,
            *(getattr(entities, column) for column in ENTITY_COLUMNS),
            json.dumps(entities.extra, ensure_ascii=False),
        )

    # --- Reading events -------------------------------------------------------------------

    def events(
        self,
        upload_id: int,
        where: EventFilter | None = None,
        *,
        limit: int = 100,
        offset: int = 0,
        newest_first: bool = False,
    ) -> list[Event]:
        """One page of matching events, in time order. Events with no time come first."""
        clause, params = (where or EventFilter()).to_sql(upload_id)
        direction = "DESC" if newest_first else "ASC"
        rows = self._db.execute(
            f"{_SELECT_EVENT} WHERE {clause} "
            f"ORDER BY e.ts {direction}, e.line_no {direction} LIMIT ? OFFSET ?",
            (*params, limit, offset),
        )
        return [self._event(row) for row in rows]

    def iter_events(self, upload_id: int, where: EventFilter | None = None) -> Iterator[Event]:
        """Every matching event in time order, without paging. For detection rules."""
        clause, params = (where or EventFilter()).to_sql(upload_id)
        rows = self._db.execute(
            f"{_SELECT_EVENT} WHERE {clause} ORDER BY e.ts, e.line_no", params
        )
        for row in rows:
            yield self._event(row)

    def count_events(self, upload_id: int, where: EventFilter | None = None) -> int:
        clause, params = (where or EventFilter()).to_sql(upload_id)
        return self._scalar(f"SELECT COUNT(*) FROM events e WHERE {clause}", params)

    def count_by(
        self, upload_id: int, column: str, where: EventFilter | None = None, limit: int = 100
    ) -> list[tuple[str | int | None, int]]:
        """How many matching events there are per value of `column`, most common first."""
        if column not in GROUP_COLUMNS:
            raise ValueError(f"cannot group by {column!r}")
        clause, params = (where or EventFilter()).to_sql(upload_id)
        rows = self._db.execute(
            f"SELECT e.{column}, COUNT(*) AS n FROM events e WHERE {clause} "
            f"GROUP BY e.{column} ORDER BY n DESC, e.{column} LIMIT ?",
            (*params, limit),
        )
        return [(row[0], row[1]) for row in rows]

    def histogram(
        self, upload_id: int, bucket_seconds: int, where: EventFilter | None = None
    ) -> list[tuple[datetime, int]]:
        """Matching events counted per time bucket. Buckets with no events are left out."""
        if bucket_seconds <= 0:
            raise ValueError("bucket_seconds must be positive")
        clause, params = (where or EventFilter()).to_sql(upload_id)
        size = bucket_seconds * 1_000_000
        rows = self._db.execute(
            f"SELECT (e.ts / ?) * ? AS bucket, COUNT(*) FROM events e "
            f"WHERE {clause} AND e.ts IS NOT NULL GROUP BY bucket ORDER BY bucket",
            (size, size, *params),
        )
        return [(_from_micros(row[0]), row[1]) for row in rows]

    def time_range(self, upload_id: int) -> tuple[datetime, datetime] | None:
        """The earliest and latest event time of an upload."""
        row = self._db.execute(
            "SELECT MIN(ts), MAX(ts) FROM events WHERE upload_id = ?", (upload_id,)
        ).fetchone()
        return None if row[0] is None else (_from_micros(row[0]), _from_micros(row[1]))

    def count_assumed(self, upload_id: int) -> tuple[int, int]:
        """How many events had their year assumed, and how many their timezone."""
        row = self._db.execute(
            "SELECT COALESCE(SUM(year_assumed), 0), COALESCE(SUM(tz_assumed), 0) "
            "FROM events WHERE upload_id = ?",
            (upload_id,),
        ).fetchone()
        return row[0], row[1]

    def raw_line(self, upload_id: int, line_no: int) -> str | None:
        row = self._db.execute(
            "SELECT text FROM raw_lines WHERE upload_id = ? AND line_no = ?", (upload_id, line_no)
        ).fetchone()
        return row[0] if row else None

    def context(
        self, upload_id: int, line_no: int, before: int = 3, after: int = 3
    ) -> list[tuple[int, str]]:
        """A line and its neighbors in the original file, as (line number, text)."""
        rows = self._db.execute(
            "SELECT line_no, text FROM raw_lines WHERE upload_id = ? AND line_no BETWEEN ? AND ? "
            "ORDER BY line_no",
            (upload_id, line_no - before, line_no + after),
        )
        return [(row[0], row[1]) for row in rows]

    # --- Templates ------------------------------------------------------------------------

    def save_templates(
        self,
        upload_id: int,
        templates: Iterable[Template],
        assignments: Iterable[tuple[str, int]],
    ) -> None:
        """Replace an upload's templates. `assignments` pairs a template id with an event id."""
        with self._db:
            self._db.execute("DELETE FROM templates WHERE upload_id = ?", (upload_id,))
            self._db.execute(
                "UPDATE events SET template_id = NULL WHERE upload_id = ?", (upload_id,)
            )
            self._db.executemany(
                "UPDATE events SET template_id = ? WHERE id = ? AND upload_id = ?",
                ((template_id, event_id, upload_id) for template_id, event_id in assignments),
            )
            self._db.executemany(
                "INSERT INTO templates (upload_id, id, source_type, event_key, pattern, count, "
                "first_seen, last_seen, hosts, examples) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    (
                        upload_id,
                        t.id,
                        t.source_type,
                        t.event_key,
                        t.pattern,
                        t.count,
                        _to_micros(t.first_seen),
                        _to_micros(t.last_seen),
                        json.dumps(list(t.hosts)),
                        json.dumps(list(t.examples)),
                    )
                    for t in templates
                ),
            )

    def templates(self, upload_id: int, limit: int = 100, offset: int = 0) -> list[Template]:
        """An upload's templates, the most frequent first."""
        rows = self._db.execute(
            "SELECT * FROM templates WHERE upload_id = ? ORDER BY count DESC, id LIMIT ? OFFSET ?",
            (upload_id, limit, offset),
        )
        return [self._template(row) for row in rows]

    def get_template(self, upload_id: int, template_id: str) -> Template | None:
        row = self._db.execute(
            "SELECT * FROM templates WHERE upload_id = ? AND id = ?", (upload_id, template_id)
        ).fetchone()
        return self._template(row) if row else None

    def count_templates(self, upload_id: int) -> int:
        return self._scalar("SELECT COUNT(*) FROM templates WHERE upload_id = ?", (upload_id,))

    def iter_template_sequence(
        self, upload_id: int
    ) -> Iterator[tuple[str | None, str, datetime, int]]:
        """(host, template id, time, event id) for every templated event, grouped by host
        and template and in time order within each group. Used to find repeats."""
        rows = self._db.execute(
            "SELECT host, template_id, ts, id FROM events "
            "WHERE upload_id = ? AND template_id IS NOT NULL AND ts IS NOT NULL "
            "ORDER BY template_id, host, ts, line_no",
            (upload_id,),
        )
        for host, template_id, micros, event_id in rows:
            yield host, template_id, _from_micros(micros), event_id

    # --- Findings -------------------------------------------------------------------------

    def save_findings(self, upload_id: int, findings: Iterable[Finding]) -> None:
        """Replace an upload's findings."""
        with self._db:
            self._db.execute("DELETE FROM findings WHERE upload_id = ?", (upload_id,))
            self._db.executemany(
                "INSERT INTO findings (upload_id, rule, incident_type, title, host, group_values, "
                "start_ts, end_ts, metrics, flags, evidence, strength, severity, severity_reason) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    (
                        upload_id,
                        f.rule,
                        f.incident_type,
                        f.title,
                        f.host,
                        json.dumps(f.group, ensure_ascii=False),
                        _to_micros(f.start),
                        _to_micros(f.end),
                        json.dumps(f.metrics, ensure_ascii=False),
                        json.dumps(f.flags),
                        json.dumps(f.evidence),
                        f.strength,
                        f.severity,
                        f.severity_reason,
                    )
                    for f in findings
                ),
            )

    def findings(self, upload_id: int) -> list[Finding]:
        """An upload's findings, in the order they started."""
        rows = self._db.execute(
            "SELECT * FROM findings WHERE upload_id = ? ORDER BY start_ts, id", (upload_id,)
        )
        return [
            Finding(
                id=row["id"],
                upload_id=row["upload_id"],
                rule=row["rule"],
                incident_type=row["incident_type"],
                title=row["title"],
                host=row["host"],
                group=json.loads(row["group_values"]),
                start=_from_micros(row["start_ts"]),
                end=_from_micros(row["end_ts"]),
                metrics=json.loads(row["metrics"]),
                flags=json.loads(row["flags"]),
                evidence=json.loads(row["evidence"]),
                strength=row["strength"],
                severity=row["severity"],
                severity_reason=row["severity_reason"],
            )
            for row in rows
        ]

    # --- Incidents ------------------------------------------------------------------------

    def save_incidents(self, upload_id: int, incidents: Iterable[Incident]) -> None:
        """Replace an upload's incidents."""
        with self._db:
            self._db.execute("DELETE FROM incidents WHERE upload_id = ?", (upload_id,))
            self._db.executemany(
                "INSERT INTO incidents (upload_id, id, title, severity, severity_reason, "
                "start_ts, end_ts, devices, finding_ids, context_ids, links, notes, chain, "
                "root_cause, alternatives, confidence, confidence_reason, unknowns) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    (
                        upload_id,
                        i.id,
                        i.title,
                        i.severity,
                        i.severity_reason,
                        _to_micros(i.start),
                        _to_micros(i.end),
                        json.dumps(i.devices),
                        json.dumps(i.finding_ids),
                        json.dumps(i.context_ids),
                        json.dumps([[link.a, link.b, link.reason] for link in i.links]),
                        json.dumps(i.notes),
                        json.dumps([asdict(step) for step in i.chain]),
                        json.dumps(asdict(i.root_cause)) if i.root_cause else None,
                        json.dumps([asdict(root) for root in i.alternatives]),
                        i.confidence,
                        i.confidence_reason,
                        json.dumps(i.unknowns),
                    )
                    for i in incidents
                ),
            )

    def incidents(self, upload_id: int) -> list[Incident]:
        """An upload's incidents, in the order they started."""
        rows = self._db.execute(
            "SELECT * FROM incidents WHERE upload_id = ? ORDER BY start_ts, id", (upload_id,)
        )
        return [self._incident(row) for row in rows]

    def get_incident(self, upload_id: int, incident_id: str) -> Incident | None:
        row = self._db.execute(
            "SELECT * FROM incidents WHERE upload_id = ? AND id = ?", (upload_id, incident_id)
        ).fetchone()
        return self._incident(row) if row else None

    @staticmethod
    def _incident(row: sqlite3.Row) -> Incident:
        return Incident(
            id=row["id"],
            upload_id=row["upload_id"],
            title=row["title"],
            severity=row["severity"],
            severity_reason=row["severity_reason"],
            start=_from_micros(row["start_ts"]),
            end=_from_micros(row["end_ts"]),
            devices=json.loads(row["devices"]),
            finding_ids=json.loads(row["finding_ids"]),
            context_ids=json.loads(row["context_ids"]),
            links=[Link(a, b, reason) for a, b, reason in json.loads(row["links"])],
            notes=json.loads(row["notes"]),
            chain=[CausalStep(**step) for step in json.loads(row["chain"])],
            root_cause=RootCause(**json.loads(row["root_cause"])) if row["root_cause"] else None,
            alternatives=[RootCause(**root) for root in json.loads(row["alternatives"])],
            confidence=row["confidence"],
            confidence_reason=row["confidence_reason"],
            unknowns=json.loads(row["unknowns"]),
        )

    # --- Redaction ------------------------------------------------------------------------

    def save_redaction_map(self, upload_id: int, entries: Iterable[tuple[str, str, str]]) -> None:
        """Add (token, kind, original) entries to an upload's redaction map. Entries that
        are already stored are left as they are: a token never changes its meaning."""
        with self._db:
            self._db.executemany(
                "INSERT OR IGNORE INTO redaction_map (upload_id, token, kind, original) "
                "VALUES (?, ?, ?, ?)",
                ((upload_id, token, kind, original) for token, kind, original in entries),
            )

    def redaction_map(self, upload_id: int) -> list[tuple[str, str, str]]:
        """An upload's redaction map as (token, kind, original)."""
        rows = self._db.execute(
            "SELECT token, kind, original FROM redaction_map WHERE upload_id = ? ORDER BY token",
            (upload_id,),
        )
        return [(row[0], row[1], row[2]) for row in rows]

    # --- Explanations ---------------------------------------------------------------------

    def save_explanation(
        self,
        cache_key: str,
        *,
        pack_hash: str,
        prompt_version: str,
        provider: str,
        model: str,
        mode: str,
        content: str,
        input_tokens: int,
        output_tokens: int,
    ) -> None:
        with self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO explanations (cache_key, pack_hash, prompt_version, "
                "provider, model, mode, content, input_tokens, output_tokens, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    cache_key,
                    pack_hash,
                    prompt_version,
                    provider,
                    model,
                    mode,
                    content,
                    input_tokens,
                    output_tokens,
                    _to_micros(datetime.now(UTC)),
                ),
            )

    def get_explanation(self, cache_key: str) -> StoredExplanation | None:
        row = self._db.execute(
            "SELECT * FROM explanations WHERE cache_key = ?", (cache_key,)
        ).fetchone()
        if row is None:
            return None
        values = dict(row)
        values["created_at"] = _from_micros(values["created_at"])
        return StoredExplanation(**values)

    def add_llm_call(
        self,
        *,
        incident_id: str | None,
        cache_key: str | None,
        provider: str,
        model: str,
        mode: str,
        status: str,
        cache_hit: bool = False,
        error: str | None = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
        latency_ms: int = 0,
        attempts: int = 0,
    ) -> None:
        with self._db:
            self._db.execute(
                "INSERT INTO llm_calls (incident_id, cache_key, provider, model, mode, status, "
                "cache_hit, error, input_tokens, output_tokens, latency_ms, attempts, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    incident_id,
                    cache_key,
                    provider,
                    model,
                    mode,
                    status,
                    int(cache_hit),
                    error,
                    input_tokens,
                    output_tokens,
                    latency_ms,
                    attempts,
                    _to_micros(datetime.now(UTC)),
                ),
            )

    def llm_calls(self, incident_id: str | None = None) -> list[LLMCall]:
        """Every request for an explanation, oldest first; for one incident if given."""
        sql, params = "SELECT * FROM llm_calls", ()
        if incident_id is not None:
            sql, params = sql + " WHERE incident_id = ?", (incident_id,)
        calls = []
        for row in self._db.execute(sql + " ORDER BY id", params):
            values = dict(row)
            values["cache_hit"] = bool(values["cache_hit"])
            values["created_at"] = _from_micros(values["created_at"])
            calls.append(LLMCall(**values))
        return calls

    def events_by_id(self, event_ids: Iterable[int]) -> list[Event]:
        """The events with the given ids, in time order."""
        ids = list(event_ids)
        events: list[Event] = []
        for offset in range(0, len(ids), 500):  # stay under SQLite's parameter limit
            chunk = ids[offset : offset + 500]
            marks = ", ".join("?" * len(chunk))
            rows = self._db.execute(f"{_SELECT_EVENT} WHERE e.id IN ({marks})", chunk)
            events += [self._event(row) for row in rows]
        events.sort(key=lambda e: (e.timestamp is not None, e.timestamp, e.line_no))
        return events

    def get_event(self, event_id: int) -> Event | None:
        row = self._db.execute(f"{_SELECT_EVENT} WHERE e.id = ?", (event_id,)).fetchone()
        return self._event(row) if row else None

    @staticmethod
    def _template(row: sqlite3.Row) -> Template:
        return Template(
            id=row["id"],
            source_type=row["source_type"],
            event_key=row["event_key"],
            pattern=row["pattern"],
            count=row["count"],
            first_seen=_from_micros(row["first_seen"]),
            last_seen=_from_micros(row["last_seen"]),
            hosts=tuple(json.loads(row["hosts"])),
            examples=tuple(json.loads(row["examples"])),
        )

    @staticmethod
    def _event(row: sqlite3.Row) -> Event:
        # Rows were validated when they were written, so they are rebuilt without
        # validating again; this is several times faster when reading many events.
        entities = Entities.model_construct(
            **{column: row[column] for column in ENTITY_COLUMNS}, extra=json.loads(row["extra"])
        )
        severity = row["severity"]
        return Event.model_construct(
            id=row["id"],
            upload_id=row["upload_id"],
            line_no=row["line_no"],
            raw=row["raw"],
            timestamp=_from_micros(row["ts"]),
            year_assumed=bool(row["year_assumed"]),
            tz_assumed=bool(row["tz_assumed"]),
            host=row["host"],
            source_type=SourceType(row["source_type"]),
            app=row["app"],
            facility=row["facility"],
            severity=None if severity is None else Severity(severity),
            event_key=row["event_key"],
            message=row["message"],
            entities=entities,
            parse_status=ParseStatus(row["parse_status"]),
            template_id=row["template_id"],
        )
