"""The web API: the pipeline of phases 1 to 3 behind HTTP.

    python -m uvicorn netlog.api.app:app
    then open http://127.0.0.1:8000/docs

A file is uploaded and an id comes back at once; the pipeline runs in the background and
`/status` says how far it has got. Everything else reads what the pipeline stored.

A few rules hold for every endpoint:

  - Log content is returned as plain data in JSON. The API never builds HTML.
  - An uploaded file is stored under a generated name. The name the user gave is kept
    only as a label and is never used as a path.
  - Errors have one shape, `{"error": {"code", "message"}}`, and never carry a stack trace.
  - Every list is paged with `limit` and `offset` and reports its `total`.
  - Only the browser origins named in the settings may call the API.

There is no login: this is a single-user tool for one person's machine.
"""

import json
import logging
import math
import re
import uuid
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from fastapi import FastAPI, File, Form, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from netlog import __version__
from netlog.alerts.alerter import Alerter, add_silence, alerter_from_config
from netlog.api.pipeline import STAGES, Job, PipelineRunner
from netlog.config import load_config
from netlog.detection.rules import (
    LEVELS,
    Rule,
    RuleError,
    RuleSet,
    event_keys_of,
    load_rule_set,
    user_rules_path,
    with_override,
)
from netlog.ingestion.reader import looks_binary
from netlog.live.service import LiveService, live_enabled
from netlog.llm.provider import Provider
from netlog.llm.settings import LLMSettings, llm_settings, load_env_file
from netlog.llm.stored import load_stored, stored_path
from netlog.parsers.syslog import parse_timezone
from netlog.report.build import build_report, explanation_json, to_json
from netlog.report.explain import explain_one
from netlog.report.postmortem import postmortem_markdown
from netlog.storage.database import Database, EventFilter, Template, Upload, default_db_path

log = logging.getLogger("netlog.api")

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_CHUNK = 1024 * 1024
# Round bucket lengths for the events-over-time chart, in seconds.
_BUCKETS = (1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 21600, 43200, 86400)
# Which kind of event a message type is, for the timeline's legend. The first prefix
# that matches wins.
_KINDS = (
    ("LINK-", "link"),
    ("LINEPROTO-", "link"),
    ("OSPF-", "ospf"),
    ("BGP-", "bgp"),
    ("SYS-5-CONFIG", "config"),
    ("SEC_LOGIN-", "login"),
    ("sshd.", "login"),
    ("sudo.", "login"),
    ("dhcp.", "dhcp"),
)
KINDS = ("link", "ospf", "bgp", "login", "config", "dhcp", "system")
# Firewall and DNS events have no kind of their own on the timeline yet: they are shown
# as "system".
_CLI_HINTS = (" Use --year to set it.", " Use --timezone to set it.")

DESCRIPTION = """
Reads network logs, finds the incidents in them with deterministic rules, and explains
each one in plain English with every statement linked to the log lines behind it.

**How to use it:** upload a file with `POST /api/uploads`, poll
`GET /api/uploads/{id}/status` until the stage is `done`, then read the incidents.

Every list takes `limit` and `offset` and returns `{items, total, limit, offset}`.
Every error is `{"error": {"code", "message"}}`. Log content is always plain data.
There is no login: this is a single-user tool.
"""


class ApiError(Exception):
    """An error to answer with: an HTTP status, a short code and a readable message."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


@dataclass(frozen=True)
class ApiSettings:
    db_path: Path
    upload_dir: Path
    demo_dir: Path
    max_upload_bytes: int
    max_upload_mb: float  # the same limit as it is written in the settings
    allowed_origins: tuple[str, ...]
    default_page_size: int
    max_page_size: int
    timeline_max_events: int
    histogram_buckets: int
    workers: int
    max_context_lines: int = 10
    evaluation_results: Path = Path("eval/results/latest.json")


def api_settings(config: dict | None = None, db_path: str | Path | None = None) -> ApiSettings:
    settings = (config or load_config())["api"]
    for name in (
        "max_upload_mb", "default_page_size", "max_page_size", "timeline_max_events",
        "histogram_buckets", "workers", "max_context_lines",
    ):  # fmt: skip
        if settings[name] <= 0:
            raise ValueError(f"api.{name} must be greater than zero")
    if settings["default_page_size"] > settings["max_page_size"]:
        raise ValueError("api.default_page_size cannot be larger than api.max_page_size")
    if "*" in settings["allowed_origins"]:
        raise ValueError(
            "api.allowed_origins may not contain '*'; list the addresses of your frontend"
        )
    return ApiSettings(
        db_path=Path(db_path or default_db_path()),
        upload_dir=Path(settings["upload_dir"]),
        demo_dir=Path(settings["demo_dir"]),
        max_upload_bytes=int(settings["max_upload_mb"] * 1024 * 1024),
        max_upload_mb=settings["max_upload_mb"],
        allowed_origins=tuple(settings["allowed_origins"]),
        default_page_size=int(settings["default_page_size"]),
        max_page_size=int(settings["max_page_size"]),
        timeline_max_events=int(settings["timeline_max_events"]),
        histogram_buckets=int(settings["histogram_buckets"]),
        workers=int(settings["workers"]),
        max_context_lines=int(settings["max_context_lines"]),
        evaluation_results=Path(settings["evaluation_results"]),
    )


# --- Turning stored things into plain data ----------------------------------------------


def _iso(moment: datetime | None) -> str | None:
    return None if moment is None else moment.isoformat().replace("+00:00", "Z")


def label_of(filename: str | None) -> str:
    """The name to show for an uploaded file: its last path component, without control
    characters, cut to a sensible length. It is a label and is never used as a path."""
    name = (filename or "").replace("\\", "/").split("/")[-1]
    name = _CONTROL.sub("", name).strip()[:200]
    return name if name.strip(". ") else "upload.log"


def upload_json(upload: Upload) -> dict:
    return {
        "id": upload.id,
        "filename": upload.filename,
        "source": upload.source,
        "size_bytes": upload.size_bytes,
        "status": upload.status,
        "stage": upload.stage,
        "failed_stage": upload.failed_stage,
        "error": upload.error,
        "year": upload.year,
        "timezone": upload.timezone,
        "lines": upload.line_count,
        "blank_lines": upload.blank,
        "parsed": upload.parsed,
        "partial": upload.partial,
        "unparsed": upload.unparsed,
        "classified": upload.classified,
        "percent_parsed": round(upload.percent_parsed, 2),
        "created_at": _iso(upload.created_at),
        "finished_at": _iso(upload.finished_at),
    }


def template_json(template: Template) -> dict:
    return {
        "id": template.id,
        "pattern": template.pattern,
        "event_key": template.event_key,
        "source_type": template.source_type,
        "count": template.count,
        "first_seen": _iso(template.first_seen),
        "last_seen": _iso(template.last_seen),
        "hosts": list(template.hosts),
    }


def rule_json(rule: Rule, ruleset: RuleSet) -> dict:
    """One rule as the API shows it: what it looks for, its settings, and where it comes
    from."""
    data = {
        "name": rule.name,
        "kind": rule.kind,
        "incident_type": rule.incident_type,
        "description": rule.description,
        "enabled": rule.enabled,
        "severity": rule.severity,
        "severity_because": rule.severity_because,
        "event_keys": event_keys_of(rule),
        "origin": ruleset.origin.get(rule.name, "built-in"),
        "override": ruleset.overrides.get(rule.name, {}),
    }
    if rule.kind == "threshold":
        data.update(
            threshold=rule.threshold,
            window_seconds=rule.window_seconds,
            group_by=list(rule.group_by),
            count_distinct=rule.count_distinct,
        )
    elif rule.kind == "share":
        data.update(
            threshold=rule.threshold,
            window_seconds=rule.window_seconds,
            share=rule.share,
            group_by=list(rule.group_by),
        )
    else:
        data.update(within_seconds=rule.within_seconds, same=list(rule.same))
    return data


class RuleChange(BaseModel):
    """The settings of a rule to change. Leave out what should stay as it is."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    severity: Literal["info", "low", "medium", "high", "critical"] | None = None
    threshold: int | None = Field(
        None, description="For a threshold or share rule: how many events."
    )
    window_seconds: float | None = Field(
        None, description="For a threshold or share rule: within how long."
    )
    share: float | None = Field(
        None, gt=0, le=1, description="For a share rule: the share, from 0 to 1."
    )
    within_seconds: float | None = Field(
        None, description="For a sequence or absence rule: the time limit."
    )


class SilenceRequest(BaseModel):
    """What to silence and for how long. Name a device, or an incident type, or set
    `all`; exactly one of the three."""

    model_config = ConfigDict(extra="forbid")

    device: str | None = Field(None, max_length=200, description="A device name, such as R1.")
    type: str | None = Field(
        None, max_length=100, description="A rule name such as link_flap, or link_failure."
    )
    all: bool = Field(False, description="Silence every alert.")
    minutes: float = Field(..., gt=0, description="How long the silence lasts.")
    reason: str = Field("", max_length=200, description="Why, such as planned maintenance.")


def alert_json(alert: dict) -> dict:
    """A recorded alert as the API shows it. The webhook address is never part of it."""
    message = alert["message"]
    return {
        "id": alert["id"],
        "kind": alert["kind"],
        "incident_id": alert["incident_id"],
        "severity": alert["severity"],
        "status": alert["status"],
        "title": message.get("title"),
        "created_at": _iso(alert["created_at"]),
        "sent_at": _iso(alert["sent_at"]),
        "deliveries": alert["deliveries"],
        "digest_id": alert["digest_id"],
        "silence_id": alert["silence_id"],
    }


def silence_json(silence: dict, now: datetime) -> dict:
    return {
        "id": silence["id"],
        "scope": silence["scope"],
        "value": silence["value"],
        "starts_at": _iso(silence["starts_at"]),
        "ends_at": _iso(silence["ends_at"]),
        "active": silence["starts_at"] <= now < silence["ends_at"],
        "reason": silence["reason"],
    }


def kind_of(event_key: str | None) -> str:
    for prefix, kind in _KINDS:
        if event_key and event_key.startswith(prefix):
            return kind
    return "system"


def line_json(event, findings: list[int] | None = None) -> dict:
    """One log line as evidence: where it is, when, on which device, and its text."""
    data = {
        "line": event.line_no,
        "time": _iso(event.timestamp),
        "host": event.host,
        "event_key": event.event_key,
        "kind": kind_of(event.event_key),
        "text": event.raw,
    }
    if findings is not None:
        data["findings"] = findings
    return data


def _moment(value: str | None, name: str) -> datetime | None:
    if value is None:
        return None
    try:
        moment = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise ApiError(
            400, "invalid_time", f"{name} is not a time; write it like 2026-03-03T02:46:00Z"
        ) from None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def _bucket_seconds(span: float, bars: int) -> int:
    wanted = span / bars
    return next((size for size in _BUCKETS if size >= wanted), math.ceil(wanted))


# --- The application ----------------------------------------------------------------------


def create_app(
    config: dict | None = None,
    *,
    settings: ApiSettings | None = None,
    llm: LLMSettings | None = None,
    provider: Provider | None = None,
    alerts: Alerter | None = None,
) -> FastAPI:
    """Build the API. `provider` replaces the configured LLM provider, which is how tests
    supply a fake; `settings`, `llm` and `alerts` replace what the settings files and the
    environment say."""
    config = config or load_config()
    settings = settings or api_settings(config)
    llm = llm or llm_settings(config)
    # A rule file with a mistake stops the server from starting, with a message naming
    # the rule, the setting and the problem, rather than running with a rule ignored.
    for warning in load_rule_set(config=config).warnings:
        log.warning("rules: %s", warning)
    runner = PipelineRunner(settings.workers)
    alerts = alerts or alerter_from_config(settings.db_path, config)
    # The live syslog listener runs inside the API when it is switched on.
    live = (
        LiveService(settings.db_path, config, llm=llm, provider=provider, alerts=alerts)
        if live_enabled(config)
        else None
    )

    @contextmanager
    def database():
        # A connection per request: SQLite connections belong to the thread that opened
        # them, and requests are served by a pool of threads.
        db = Database(settings.db_path)
        try:
            yield db
        finally:
            db.close()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        with database() as db:
            stopped = db.fail_interrupted(
                "The server stopped while this upload was being processed. Upload it again."
            )
        if stopped:
            log.warning("%d upload(s) were left unfinished by a previous run", stopped)
        if live is not None:
            await live.start()
        try:
            yield
        finally:
            if live is not None:
                await live.stop()
            runner.shutdown()

    app = FastAPI(
        title="netlog API",
        version=__version__,
        description=DESCRIPTION,
        lifespan=lifespan,
        openapi_tags=[
            {"name": "uploads", "description": "Upload a log file and follow its pipeline."},
            {"name": "results", "description": "What the pipeline found in an upload."},
            {"name": "incidents", "description": "One incident: facts, explanation, timeline."},
            {"name": "demo", "description": "Built-in scenarios that need no file of your own."},
            {"name": "rules", "description": "The detection rules in force, and changing them."},
            {"name": "live", "description": "Messages sent by devices as things happen."},
            {"name": "alerts", "description": "Chat messages about serious live incidents."},
            {"name": "evaluation", "description": "How accurate the tool is on known logs."},
            {"name": "system", "description": "Whether the API is up."},
        ],
    )
    app.state.runner = runner
    app.state.live = live
    app.state.alerts = alerts
    app.state.settings = settings
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.allowed_origins),
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["*"],
    )

    # --- Errors: one shape, no stack traces -----------------------------------------------

    def error(status: int, code: str, message: str, **extra) -> JSONResponse:
        return JSONResponse({"error": {"code": code, "message": message, **extra}}, status)

    @app.exception_handler(ApiError)
    async def _api_error(_request: Request, exc: ApiError) -> JSONResponse:
        return error(exc.status, exc.code, exc.message)

    @app.exception_handler(RequestValidationError)
    async def _invalid(_request: Request, exc: RequestValidationError) -> JSONResponse:
        details = [
            {
                "field": ".".join(str(part) for part in issue["loc"][1:]) or str(issue["loc"][0]),
                "problem": issue["msg"],
            }
            for issue in exc.errors()
        ]
        listed = "; ".join(f"{item['field']}: {item['problem']}" for item in details[:5])
        return error(422, "invalid_request", f"The request is not valid. {listed}", details=details)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        codes = {404: "not_found", 405: "method_not_allowed"}
        messages = {404: "There is nothing at this address.", 405: "This method is not allowed."}
        return error(
            exc.status_code,
            codes.get(exc.status_code, "error"),
            messages.get(exc.status_code, str(exc.detail)),
        )

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception) -> JSONResponse:
        log.error("unhandled error for %s %s", request.method, request.url.path, exc_info=exc)
        return error(
            500,
            "internal_error",
            "Something went wrong on the server. The details are in the server log.",
        )

    @app.middleware("http")
    async def _refuse_oversized(request: Request, call_next):
        # Refuse a file that says it is too large before reading any of it. A request
        # that does not say is counted while it is copied.
        if request.method == "POST" and request.url.path == "/api/uploads":
            declared = request.headers.get("content-length", "")
            # The body is the file plus a little form wrapping.
            if declared.isdigit() and int(declared) > settings.max_upload_bytes + 64 * 1024:
                return too_large()
        return await call_next(request)

    def too_large() -> JSONResponse:
        return error(
            413,
            "file_too_large",
            f"The file is larger than the {settings.max_upload_mb:g} MB limit. Split it, or raise "
            "api.max_upload_mb in the settings.",
        )

    # --- Helpers that need the settings ---------------------------------------------------

    Limit = Annotated[
        int,
        Query(ge=1, le=settings.max_page_size, description="How many items to return."),
    ]
    Offset = Annotated[int, Query(ge=0, description="How many items to skip.")]
    Mode = Annotated[
        Literal["junior", "senior"],
        Query(description="Who the explanation is written for."),
    ]
    page_default = settings.default_page_size

    def page(items: list, total: int, limit: int, offset: int) -> dict:
        return {"items": items, "total": total, "limit": limit, "offset": offset}

    def need_upload(db: Database, upload_id: int) -> Upload:
        upload = db.get_upload(upload_id)
        if upload is None:
            raise ApiError(404, "upload_not_found", f"There is no upload with id {upload_id}.")
        return upload

    def need_incident(db: Database, upload_id: int, incident_id: str):
        need_upload(db, upload_id)
        incident = db.get_incident(upload_id, incident_id)
        if incident is None:
            raise ApiError(
                404,
                "incident_not_found",
                f"Upload {upload_id} has no incident with id {incident_id!r}.",
            )
        return incident

    def report_of(db: Database, upload: Upload):
        report = build_report(
            db,
            upload.id,
            year=upload.year,
            assumed_year=upload.created_at.year,
            timezone=upload.timezone,
        )
        for hint in _CLI_HINTS:  # advice that only makes sense on the command line
            report.assumptions = [text.replace(hint, "") for text in report.assumptions]
        return report

    def severity_counts(db: Database, upload_id: int) -> dict[str, int]:
        counts = {level: 0 for level in reversed(LEVELS)}
        for incident in db.incidents(upload_id):
            counts[incident.severity] += 1
        return counts

    def launch(upload_id: int, path: Path, year: int | None, timezone: str | None) -> None:
        runner.submit(
            Job(
                db_path=settings.db_path,
                upload_id=upload_id,
                path=path,
                year=year,
                tz=parse_timezone(timezone) if timezone else UTC,
                config=config,
                settings=llm,
                provider=provider,
            )
        )

    def demo_scenarios() -> dict[str, dict]:
        """The built-in scenarios by name, read from the label files in the demo folder."""
        found: dict[str, dict] = {}
        if not settings.demo_dir.is_dir():
            return found
        for labels_path in sorted(settings.demo_dir.glob("*.labels.json")):
            name = labels_path.name.removesuffix(".labels.json")
            log_path = labels_path.with_name(f"{name}.log")
            if not log_path.is_file():
                continue
            try:
                labels = json.loads(labels_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            incidents = labels.get("incidents", [])
            found[name] = {
                "name": name,
                "description": "; ".join(str(i.get("title", "")) for i in incidents)
                or "A normal day. No incident.",
                "lines": labels.get("total_lines"),
                "year": labels.get("year"),
                "incidents": [
                    {
                        "type": i.get("type"),
                        "title": i.get("title"),
                        "expected_severity": i.get("expected_severity"),
                    }
                    for i in incidents
                ],
                "_path": log_path,
            }
        return found

    # --- System ---------------------------------------------------------------------------

    @app.get("/api/health", tags=["system"], summary="Health check")
    def health() -> dict:
        """Says whether the API is up and can reach its database, which LLM provider is
        configured (never the key), whether it runs in demo mode, and the upload size
        limit. With no LLM configured the app is in demo mode: the demo scenarios use the
        explanations stored with them, other files get the built-in explanations."""
        with database() as db:
            schema = db.schema_version
        configured = llm.configured or provider is not None
        return {
            "status": "ok",
            "version": __version__,
            "database_schema": schema,
            "llm": {"configured": configured, "provider": llm.provider},
            "demo": {
                "active": not configured,
                "stored_explanations": len(load_stored(stored_path(config))),
            },
            "max_upload_bytes": settings.max_upload_bytes,
            "stages": list(STAGES),
        }

    # --- Uploads --------------------------------------------------------------------------

    @app.post("/api/uploads", status_code=202, tags=["uploads"], summary="Upload a log file")
    def create_upload(
        file: Annotated[UploadFile, File(description="The log file.")],
        year: Annotated[
            int | None,
            Form(ge=1970, le=2100, description="Year of the first line; classic syslog has none."),
        ] = None,
        timezone: Annotated[
            str | None,
            Form(description="Timezone of the devices' clocks: UTC, or an offset like +05:30."),
        ] = None,
    ):
        """Stores the file under a generated name, starts the pipeline in the background
        and returns the upload's id at once. Poll `/api/uploads/{id}/status` to follow it.

        Refused: an empty file, a file that is not text, and a file over the size limit.
        """
        if timezone:
            try:
                parse_timezone(timezone)
            except ValueError as problem:
                raise ApiError(400, "invalid_timezone", str(problem)) from None

        settings.upload_dir.mkdir(parents=True, exist_ok=True)
        stored_name = f"{uuid.uuid4().hex}.log"
        target = settings.upload_dir / stored_name
        size = 0
        try:
            with open(target, "wb") as out:
                while chunk := file.file.read(_CHUNK):
                    if size == 0 and looks_binary(chunk[:4096]):
                        raise ApiError(
                            400, "not_text", "The file is not a text file, so it cannot be a log."
                        )
                    size += len(chunk)
                    if size > settings.max_upload_bytes:
                        raise ApiError(413, "file_too_large", "")
                    out.write(chunk)
            if size == 0:
                raise ApiError(400, "empty_file", "The file is empty.")
        except ApiError as problem:
            target.unlink(missing_ok=True)
            if problem.code == "file_too_large":
                return too_large()
            raise

        with database() as db:
            upload_id = db.create_upload(
                label_of(file.filename), size, stored_name=stored_name, year=year, timezone=timezone
            )
            launch(upload_id, target, year, timezone)
            return upload_json(need_upload(db, upload_id))

    @app.get("/api/uploads", tags=["uploads"], summary="List uploads")
    def list_uploads(limit: Limit = page_default, offset: Offset = 0) -> dict:
        """Every upload, newest first, each with how many incidents it has per severity."""
        with database() as db:
            items = []
            for upload in db.list_uploads(limit, offset):
                item = upload_json(upload)
                item["incidents_by_severity"] = severity_counts(db, upload.id)
                items.append(item)
            return page(items, db.count_uploads(), limit, offset)

    @app.get("/api/uploads/{upload_id}", tags=["uploads"], summary="Get one upload")
    def get_upload(upload_id: int) -> dict:
        """An upload with its status and its statistics: lines, parse coverage, counts of
        message patterns, findings and incidents."""
        with database() as db:
            upload = need_upload(db, upload_id)
            return {
                **upload_json(upload),
                "counts": db.progress(upload_id),
                "incidents_by_severity": severity_counts(db, upload_id),
            }

    @app.get("/api/uploads/{upload_id}/status", tags=["uploads"], summary="Pipeline status")
    def upload_status(upload_id: int) -> dict:
        """Which stage the pipeline is in (`queued`, `parsing`, `templates`, `detection`,
        `correlation`, `explanation`, `done` or `failed`) and the running counts of lines,
        message patterns, findings and incidents. After a failure, `failed_stage` and
        `error` say where and why."""
        with database() as db:
            upload = need_upload(db, upload_id)
            return {
                "id": upload.id,
                "status": upload.status,
                "stage": upload.stage,
                "failed_stage": upload.failed_stage,
                "error": upload.error,
                "finished": upload.status in ("done", "failed"),
                "stages": list(STAGES),
                "counts": db.progress(upload_id),
            }

    @app.delete(
        "/api/uploads/{upload_id}", status_code=204, tags=["uploads"], summary="Delete an upload"
    )
    def delete_upload(upload_id: int) -> Response:
        """Deletes an upload and everything that belongs to it: its lines, events, message
        patterns, findings, incidents and its stored file. Refused while the pipeline is
        still running."""
        with database() as db:
            upload = need_upload(db, upload_id)
            if upload.status == "processing":
                raise ApiError(
                    409,
                    "still_processing",
                    "This upload is still being processed. Delete it when it has finished.",
                )
            if upload.source == "live" and live is not None:
                raise ApiError(
                    409,
                    "live_running",
                    "This is where the live listener stores messages. Stop the listener first.",
                )
            db.delete_upload(upload_id)
        if upload.stored_name and re.fullmatch(r"[0-9a-f]{32}\.log", upload.stored_name):
            (settings.upload_dir / upload.stored_name).unlink(missing_ok=True)
        return Response(status_code=204)

    # --- What the pipeline found ----------------------------------------------------------

    @app.get("/api/uploads/{upload_id}/events", tags=["results"], summary="Events of an upload")
    def list_events(
        upload_id: int,
        start: Annotated[str | None, Query(description="At or after this time (ISO 8601).")] = None,
        end: Annotated[str | None, Query(description="Before this time (ISO 8601).")] = None,
        host: Annotated[str | None, Query(description="Only this device.")] = None,
        severity: Annotated[
            int | None,
            Query(ge=0, le=7, description="Syslog severity at least this serious: 3 gives 0 to 3."),
        ] = None,
        event_key: Annotated[
            list[str] | None, Query(description="Only these message types; may be repeated.")
        ] = None,
        q: Annotated[
            str | None, Query(max_length=200, description="Words that must all appear.")
        ] = None,
        parse_status: Annotated[
            Literal["parsed", "partial", "unparsed"] | None,
            Query(description="Only lines the parsers understood fully, partly, or not at all."),
        ] = None,
        order: Annotated[Literal["asc", "desc"], Query(description="Oldest or newest first.")] = (
            "asc"
        ),
        limit: Limit = page_default,
        offset: Offset = 0,
    ) -> dict:
        """The parsed events of an upload, one per log line, in time order. Filter by time
        range, device, severity, message type, text, and whether the line was understood:
        `parse_status=unparsed` lists the lines no parser recognized."""
        where = EventFilter(
            start=_moment(start, "start"),
            end=_moment(end, "end"),
            host=host,
            min_severity=severity,
            event_keys=tuple(event_key or ()),
            text=q if q and q.strip() else None,
            parse_status=parse_status,
        )
        with database() as db:
            need_upload(db, upload_id)
            events = db.events(
                upload_id, where, limit=limit, offset=offset, newest_first=order == "desc"
            )
            items = [event.model_dump(mode="json") for event in events]
            return page(items, db.count_events(upload_id, where), limit, offset)

    @app.get("/api/uploads/{upload_id}/lines", tags=["results"], summary="Lines around a line")
    def lines_around(
        upload_id: int,
        around: Annotated[int, Query(ge=1, description="The line number in the file.")],
        context: Annotated[
            int, Query(ge=0, description="How many lines to show before and after it.")
        ] = 3,
    ) -> dict:
        """A log line with the lines just before and after it in the uploaded file, so a
        piece of evidence can be read in its surroundings. Blank lines are not stored, so
        fewer lines may come back than asked for."""
        if context > settings.max_context_lines:
            raise ApiError(
                400,
                "too_much_context",
                f"Ask for at most {settings.max_context_lines} lines on each side.",
            )
        with database() as db:
            need_upload(db, upload_id)
            numbers = range(max(1, around - context), around + context + 1)
            events = db.events_by_line(upload_id, numbers)
        return {
            "upload_id": upload_id,
            "around": around,
            "context": context,
            "lines": [line_json(event) for event in events],
        }

    @app.get("/api/uploads/{upload_id}/templates", tags=["results"], summary="Message patterns")
    def list_templates(
        upload_id: int,
        sort: Annotated[
            Literal["count_desc", "count_asc"],
            Query(description="Most frequent first, or rarest first."),
        ] = "count_desc",
        limit: Limit = page_default,
        offset: Offset = 0,
    ) -> dict:
        """The message patterns the lines of an upload collapse into, with how often each
        occurs. The rarest patterns are often the interesting ones."""
        with database() as db:
            need_upload(db, upload_id)
            templates = db.templates(upload_id, limit, offset, rarest_first=sort == "count_asc")
            return page(
                [template_json(t) for t in templates], db.count_templates(upload_id), limit, offset
            )

    @app.get("/api/uploads/{upload_id}/incidents", tags=["results"], summary="Incidents")
    def list_incidents(
        upload_id: int,
        sort: Annotated[
            Literal["severity", "time"], Query(description="By severity, or by start time.")
        ] = "severity",
        order: Annotated[
            Literal["asc", "desc"], Query(description="For severity, desc is most severe first.")
        ] = "desc",
        limit: Limit = page_default,
        offset: Offset = 0,
    ) -> dict:
        """The incidents of an upload, each with its severity, likely root cause, devices,
        duration and confidence. Sorted most severe first unless asked otherwise."""
        with database() as db:
            upload = need_upload(db, upload_id)
            entries = to_json(report_of(db, upload))["incidents"]
        if sort == "time":
            entries.sort(key=lambda e: (e["start"], e["id"]), reverse=order == "desc")
        else:
            sign = -1 if order == "desc" else 1
            entries.sort(key=lambda e: (sign * LEVELS.index(e["severity"]), e["start"], e["id"]))
        items = [
            {
                "id": e["id"],
                "headline": e["headline"],
                "title": e["title"],
                "severity": e["severity"],
                "severity_reason": e["severity_reason"],
                "start": e["start"],
                "end": e["end"],
                "duration_seconds": e["duration_seconds"],
                "devices": e["devices"],
                "root_cause": e["root_cause"],
                "confidence": e["confidence"],
                "confidence_reason": e["confidence_reason"],
                "findings": len(e["findings"]),
            }
            for e in entries[offset : offset + limit]
        ]
        return page(items, len(entries), limit, offset)

    @app.get("/api/uploads/{upload_id}/summary", tags=["results"], summary="File-level summary")
    def upload_summary(upload_id: int) -> dict:
        """The overview of one upload: lines and parse coverage, devices, time span, counts
        by severity, the most frequent message patterns, events over time in buckets, when
        each incident happened, and anything that was assumed (a year, a timezone)."""
        with database() as db:
            upload = need_upload(db, upload_id)
            report = report_of(db, upload)
            data = to_json(report)
            buckets: list[dict] = []
            size = None
            if report.time_range:
                first, last = report.time_range
                size = _bucket_seconds(
                    max((last - first).total_seconds(), 1.0), settings.histogram_buckets
                )
                buckets = [
                    {"start": _iso(moment), "count": count}
                    for moment, count in db.histogram(upload_id, size)
                ]
        return {
            "upload": upload_json(upload),
            "file": data["file"],
            "summary": data["summary"],
            "top_templates": data["templates"],
            "events_over_time": {"bucket_seconds": size, "buckets": buckets},
            "incident_periods": [
                {
                    "id": e["id"],
                    "headline": e["headline"],
                    "severity": e["severity"],
                    "start": e["start"],
                    "end": e["end"],
                }
                for e in data["incidents"]
            ],
            "assumptions": data["assumptions"],
            "warnings": data["warnings"],
        }

    # --- One incident ---------------------------------------------------------------------

    base = "/api/uploads/{upload_id}/incidents/{incident_id}"

    @app.get(base, tags=["incidents"], summary="One incident in full")
    def get_incident(upload_id: int, incident_id: str) -> dict:
        """Everything the rules decided about one incident: its facts, the findings inside
        it, the chain of cause and effect, what is not known, and the log lines it rests
        on, each with its line number in the uploaded file.

        Incident ids are derived from the findings inside, so they are unique within an
        upload, not across uploads."""
        with database() as db:
            upload = need_upload(db, upload_id)
            incident = need_incident(db, upload_id, incident_id)
            data = to_json(report_of(db, upload))
            entry = next((e for e in data["incidents"] if e["id"] == incident_id), None)
            if entry is None:
                raise ApiError(404, "incident_not_found", f"No incident with id {incident_id!r}.")
            entry.pop("explanation", None)
            findings = [f for f in data["findings"] if f["incident"] == incident_id]

            # The first and last lines of each finding: where it began, and where a
            # recovery or a successful login sits.
            by_finding = {f.id: f for f in db.findings(upload_id)}
            cited: dict[int, list[int]] = {}
            for finding_id in [*incident.finding_ids, *incident.context_ids]:
                evidence = by_finding[finding_id].evidence
                for event_id in dict.fromkeys([*evidence[:3], *evidence[-2:]]):
                    cited.setdefault(event_id, []).append(finding_id)
            events = db.events_by_id(list(cited))
        evidence_lines = [line_json(event, cited[event.id]) for event in events]
        evidence_lines.sort(key=lambda item: item["line"])
        return {"upload_id": upload_id, **entry, "finding_details": findings,
                "evidence": evidence_lines}  # fmt: skip

    def explanation_of(upload_id: int, incident_id: str, mode: str, refresh: bool) -> dict:
        with database() as db:
            incident = need_incident(db, upload_id, incident_id)
            explanation = explain_one(
                db,
                upload_id,
                incident,
                db,
                mode,
                refresh=refresh,
                provider=provider,
                settings=llm,
                config=config,
            )
            cited = [*explanation.timeline, *explanation.hypotheses, *explanation.impact]
            numbers = sorted({line for item in cited for line in [*item.lines, *item.against]})
            events = db.events_by_line(upload_id, numbers)
        return {
            "upload_id": upload_id,
            "incident_id": incident_id,
            **explanation_json(explanation),
            "cited_lines": [line_json(event) for event in events],
        }

    @app.get(f"{base}/explanation", tags=["incidents"], summary="Explanation of an incident")
    def get_explanation(upload_id: int, incident_id: str, mode: Mode = "senior") -> dict:
        """The plain-English explanation of an incident for a junior or a senior reader.
        A stored LLM answer is returned if there is one; otherwise it is written now: by
        the LLM when one is configured and its answer passes validation, by the built-in
        templates if not. `source` says which. Real names are in place of the stand-ins,
        and `cited_lines` holds every log line a statement points to."""
        return explanation_of(upload_id, incident_id, mode, refresh=False)

    @app.post(
        f"{base}/explanation/regenerate", tags=["incidents"], summary="Regenerate an explanation"
    )
    def regenerate_explanation(upload_id: int, incident_id: str, mode: Mode = "senior") -> dict:
        """Asks the LLM again, ignoring the stored answer, and stores the new one. This
        costs a request when an LLM is configured. With none, the built-in explanation is
        returned again: it is the same every time."""
        return explanation_of(upload_id, incident_id, mode, refresh=True)

    @app.get(f"{base}/postmortem", tags=["incidents"], summary="Post-mortem of an incident")
    def get_postmortem(upload_id: int, incident_id: str, mode: Mode = "senior") -> Response:
        """The incident as a post-mortem document in Markdown, ready to download: what
        happened and when, the likely root cause, what was done and should be done, what
        cannot be determined, a checklist of follow-up actions for the team, and the log
        lines behind it. It says at the top that it was drafted automatically and needs
        review. Uses the explanation for the given audience."""
        with database() as db:
            upload = need_upload(db, upload_id)
            incident = need_incident(db, upload_id, incident_id)
            explanation = explain_one(
                db, upload_id, incident, db, mode, refresh=False,
                provider=provider, settings=llm, config=config,
            )  # fmt: skip
            text = postmortem_markdown(db, upload, report_of(db, upload), incident_id, explanation)
        stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(label_of(upload.filename)).stem)[:60] or "log"
        name = f"postmortem-{stem}-{incident_id}.md"
        return Response(
            text,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{name}"'},
        )

    @app.get(f"{base}/timeline", tags=["incidents"], summary="Timeline of an incident")
    def get_timeline(upload_id: int, incident_id: str) -> dict:
        """The log events behind an incident in time order, ready for a chart with one lane
        per device: each event has its device, time, kind (`link`, `ospf`, `bgp`, `login`,
        `config`, `dhcp` or `system`), line number and text, and says whether it belongs to
        the root cause. Devices are listed with the root-cause device first."""
        with database() as db:
            incident = need_incident(db, upload_id, incident_id)
            by_finding = {f.id: f for f in db.findings(upload_id)}
            root_ids = set(incident.root_cause.finding_ids) if incident.root_cause else set()
            owners: dict[int, list[int]] = {}
            for finding_id in [*incident.finding_ids, *incident.context_ids]:
                for event_id in by_finding[finding_id].evidence:
                    owners.setdefault(event_id, []).append(finding_id)
            events = db.events_by_id(list(owners))
        total = len(events)
        events = events[: settings.timeline_max_events]
        items = []
        for event in events:
            item = line_json(event, owners[event.id])
            item["id"] = event.id
            item["root_cause"] = bool(root_ids & set(owners[event.id]))
            items.append(item)

        first_seen: dict[str, str] = {}
        for item in items:
            if item["host"] and item["time"]:
                first_seen.setdefault(item["host"], item["time"])
        root_devices = list(incident.root_cause.devices) if incident.root_cause else []
        devices = dict.fromkeys([*root_devices, *incident.devices, *first_seen])
        lanes = sorted(
            devices,
            key=lambda host: (host not in root_devices, first_seen.get(host, "~"), host),
        )
        times = [item["time"] for item in items if item["time"]]
        return {
            "upload_id": upload_id,
            "incident_id": incident_id,
            "start": min(times, default=None),
            "end": max(times, default=None),
            "lanes": lanes,
            "kinds": list(KINDS),
            "events": items,
            "total_events": total,
            "truncated": total > len(items),
        }

    # --- Rules ----------------------------------------------------------------------------

    def ruleset_now():
        try:
            return load_rule_set(config=config)
        except RuleError as error:
            raise ApiError(500, "rule_file_error", str(error)) from None

    @app.get("/api/rules", tags=["rules"], summary="The detection rules in force")
    def list_rules() -> dict:
        """Every detection rule with its settings: the built-in ones, changed or added to by
        the user's rule file (`[rules] user_file`). `origin` says where each comes from,
        and `override` what the user file changes. `warnings` lists possible typos, such
        as a message type no parser produces."""
        ruleset = ruleset_now()
        items = [rule_json(rule, ruleset) for rule in ruleset.rules]
        return {
            **page(items, len(items), len(items), 0),
            "user_file": str(ruleset.user_file or user_rules_path(config) or ""),
            "warnings": ruleset.warnings,
            "critical": {
                "devices": ruleset.critical_devices,
                "interfaces": ruleset.critical_interfaces,
            },
        }

    @app.patch("/api/rules/{name}", tags=["rules"], summary="Change a rule's settings")
    def change_rule(name: str, change: RuleChange) -> dict:
        """Change a rule's threshold, window, severity, or switch it on or off. The change
        is written to the user's rule file as an [[override]] and applies to analyses
        started from now on; results already shown stay as they were. A value that does
        not fit the rule is refused with a message saying why, and the file is left as
        it was."""
        path = user_rules_path(config)
        if path is None:
            raise ApiError(409, "no_rule_file", "No user rule file is set in [rules] user_file.")
        ruleset = ruleset_now()
        if ruleset.by_name(name) is None:
            raise ApiError(404, "rule_not_found", f"There is no rule named {name!r}.")
        wanted = {**ruleset.overrides.get(name, {}), **change.model_dump(exclude_none=True)}
        before = path.read_text(encoding="utf-8") if path.is_file() else ""
        after = with_override(before, name, wanted)
        candidate = path.with_name(path.name + ".checking")
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            candidate.write_text(after, encoding="utf-8")
            checked = load_rule_set(candidate, config)
        except RuleError as error:
            raise ApiError(400, "invalid_rule_change", str(error)) from None
        finally:
            candidate.unlink(missing_ok=True)
        path.write_text(after, encoding="utf-8")
        checked.user_file = path
        return rule_json(checked.by_name(name), checked)

    # --- Live ------------------------------------------------------------------------------

    @app.get("/api/live", tags=["live"], summary="The live syslog listener")
    def live_status() -> dict:
        """Whether the live listener is running and where it listens, how many messages
        came in and why any were dropped, the current rate, the senders seen, and the live
        incidents: open ones first, then recently closed. Each incident opens on the
        ordinary incident page under the live upload's id."""
        if live is None:
            return {"enabled": False}
        status = live.status()
        with database() as db:
            upload = db.get_upload(live.upload_id) if live.upload_id else None
            items = db.live_incidents(live.upload_id) if upload else []
            entries = (
                {e["id"]: e for e in to_json(report_of(db, upload))["incidents"]} if items else {}
            )
        incidents = []
        for item in items:
            entry = entries.get(item["id"])
            if entry is None:
                continue
            incidents.append(
                {
                    **{key: entry[key] for key in (
                        "id", "headline", "title", "severity", "severity_reason", "start",
                        "end", "duration_seconds", "devices", "root_cause", "confidence",
                        "confidence_reason",
                    )},
                    "findings": len(entry["findings"]),
                    "state": item["state"],
                    "opened_at": _iso(item["opened_at"]),
                    "changed_at": _iso(item["changed_at"]),
                    "closed_at": _iso(item["closed_at"]),
                }
            )  # fmt: skip
        incidents.sort(key=lambda i: (i["state"] != "open", i["closed_at"] or "", i["opened_at"]))
        open_ones = [i for i in incidents if i["state"] == "open"]
        closed = sorted(
            (i for i in incidents if i["state"] == "closed"),
            key=lambda i: i["closed_at"],
            reverse=True,
        )
        return {
            "enabled": True,
            **status,
            "lines": upload.line_count if upload else 0,
            "open_incidents": open_ones,
            "closed_incidents": closed[:20],
        }

    # --- Alerts ----------------------------------------------------------------------------

    @app.get("/api/alerts", tags=["alerts"], summary="Alert settings, silences, recent alerts")
    def alerts_status(limit: Limit = page_default, offset: Offset = 0) -> dict:
        """Whether alerts are on and which kinds of webhook are set (never their
        addresses), the rules for sending, the silences, and the alerts recorded, newest
        first: sent, failed, held back for a digest, or silenced."""
        now = datetime.now(UTC)
        with database() as db:
            recorded = db.alerts()
            silences = db.silences()
        return {
            "enabled": alerts.enabled,
            "listener_running": live is not None,
            **alerts.settings.public(),
            "silences": [silence_json(s, now) for s in silences[:50]],
            "alerts": page(
                [alert_json(a) for a in recorded[offset : offset + limit]],
                len(recorded), limit, offset,
            ),
        }  # fmt: skip

    @app.post("/api/alerts/test", tags=["alerts"], summary="Send a test alert")
    def send_test_alert() -> dict:
        """Sends a clearly labelled test alert to every webhook that is set, straight
        away, to check the setup. Says for each whether it arrived, and if not, why."""
        if not alerts.enabled:
            raise ApiError(
                409, "alerts_off",
                "No webhook is set. Put NETLOG_ALERT_SLACK_URL or NETLOG_ALERT_WEBHOOK_URL "
                "in .env and restart the server.",
            )  # fmt: skip
        return alerts.send_test(datetime.now(UTC))

    @app.post(
        "/api/alerts/silences", status_code=201, tags=["alerts"], summary="Silence alerts"
    )
    def create_silence(request: SilenceRequest) -> dict:
        """Silences a device, an incident type, or everything, for a number of minutes,
        for planned maintenance. Incidents are still detected and recorded; only the chat
        messages stop. An incident alerted as silenced is not alerted again at the same
        severity when the silence ends."""
        chosen = [scope for scope, given in (("device", request.device), ("type", request.type),
                                             ("all", request.all)) if given]  # fmt: skip
        if len(chosen) != 1:
            raise ApiError(400, "invalid_silence", "Give exactly one of: device, type, or all.")
        scope = chosen[0]
        value = None if scope == "all" else getattr(request, scope)
        try:
            silence = add_silence(
                settings.db_path, alerts.settings, scope, value, request.minutes,
                request.reason, datetime.now(UTC),
            )  # fmt: skip
        except ValueError as error:
            raise ApiError(400, "invalid_silence", str(error)) from None
        return silence_json(silence, datetime.now(UTC))

    @app.delete(
        "/api/alerts/silences/{silence_id}", tags=["alerts"], summary="End a silence early"
    )
    def end_silence(silence_id: int) -> dict:
        """Ends a silence now, before the time it was set for. It stays in the list, with
        its new end, as a record of the maintenance."""
        now = datetime.now(UTC)
        with database() as db:
            if not db.end_silence(silence_id, now):
                raise ApiError(404, "silence_not_found", "There is no silence with that id.")
            silence = next(s for s in db.silences() if s["id"] == silence_id)
        return silence_json(silence, now)

    # --- Evaluation ---------------------------------------------------------------------------

    @app.get("/api/evaluation", tags=["evaluation"], summary="The latest accuracy results")
    def evaluation() -> dict:
        """The latest results of the evaluation harness: precision, recall and F1 on the
        held-out, tuned and noise sets, root cause, severity and device accuracy, false
        alarms, speed, and every miss with its scenario and seed. Made by running
        `python -m eval.harness`; this only reads the file it wrote."""
        path = settings.evaluation_results
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise ApiError(
                404, "no_results",
                "No evaluation results yet. Run python -m eval.heldout, then "
                "python -m eval.harness.",
            ) from None  # fmt: skip
        except (OSError, ValueError):
            data = None
        if not isinstance(data, dict) or "sets" not in data:
            raise ApiError(500, "bad_results", "The evaluation results file cannot be read.")
        return data

    # --- Demo scenarios -------------------------------------------------------------------

    @app.get("/api/demo/scenarios", tags=["demo"], summary="List the demo scenarios")
    def list_demo(limit: Limit = page_default, offset: Offset = 0) -> dict:
        """The built-in scenarios: generated logs with a known incident inside, each with a
        one-line description of what happens in it."""
        found = [
            {key: value for key, value in item.items() if not key.startswith("_")}
            for item in demo_scenarios().values()
        ]
        return page(found[offset : offset + limit], len(found), limit, offset)

    @app.post(
        "/api/demo/scenarios/{name}", status_code=202, tags=["demo"], summary="Load a demo scenario"
    )
    def load_demo(name: str) -> dict:
        """Loads a built-in scenario as a new upload and starts the pipeline, exactly as if
        its file had been uploaded. Returns the upload's id at once."""
        scenario = demo_scenarios().get(name)  # looked up by name, never built into a path
        if scenario is None:
            raise ApiError(404, "scenario_not_found", "There is no demo scenario with that name.")
        path: Path = scenario["_path"]
        with database() as db:
            upload_id = db.create_upload(
                f"{name}.log", path.stat().st_size, year=scenario["year"], timezone="UTC",
                source="demo",
            )  # fmt: skip
            launch(upload_id, path, scenario["year"], "UTC")
            return upload_json(need_upload(db, upload_id))

    return app


def __getattr__(name: str):
    """`netlog.api.app:app` is built the first time it is asked for, which is when a
    server starts. Importing this module, as the tests do, reads no .env file and builds
    nothing."""
    if name == "app":
        load_env_file()  # the LLM provider and its key, if the user has set them up
        built = create_app()
        globals()["app"] = built
        return built
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
