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
from starlette.exceptions import HTTPException as StarletteHTTPException

from netlog import __version__
from netlog.api.pipeline import STAGES, Job, PipelineRunner
from netlog.config import load_config
from netlog.detection.rules import LEVELS
from netlog.ingestion.reader import looks_binary
from netlog.llm.provider import Provider
from netlog.llm.settings import LLMSettings, llm_settings, load_env_file
from netlog.parsers.syslog import parse_timezone
from netlog.report.build import build_report, explanation_json, to_json
from netlog.report.explain import explain_one
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


def api_settings(config: dict | None = None, db_path: str | Path | None = None) -> ApiSettings:
    settings = (config or load_config())["api"]
    for name in (
        "max_upload_mb", "default_page_size", "max_page_size", "timeline_max_events",
        "histogram_buckets", "workers",
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
) -> FastAPI:
    """Build the API. `provider` replaces the configured LLM provider, which is how tests
    supply a fake; `settings` and `llm` replace what the settings files say."""
    config = config or load_config()
    settings = settings or api_settings(config)
    llm = llm or llm_settings(config)
    runner = PipelineRunner(settings.workers)

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
        yield
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
            {"name": "system", "description": "Whether the API is up."},
        ],
    )
    app.state.runner = runner
    app.state.settings = settings
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.allowed_origins),
        allow_methods=["GET", "POST", "DELETE"],
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
        configured (never the key), and the upload size limit."""
        with database() as db:
            schema = db.schema_version
        return {
            "status": "ok",
            "version": __version__,
            "database_schema": schema,
            "llm": {"configured": llm.configured or provider is not None, "provider": llm.provider},
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
        order: Annotated[Literal["asc", "desc"], Query(description="Oldest or newest first.")] = (
            "asc"
        ),
        limit: Limit = page_default,
        offset: Offset = 0,
    ) -> dict:
        """The parsed events of an upload, one per log line, in time order. Filter by time
        range, device, severity, message type and text."""
        where = EventFilter(
            start=_moment(start, "start"),
            end=_moment(end, "end"),
            host=host,
            min_severity=severity,
            event_keys=tuple(event_key or ()),
            text=q if q and q.strip() else None,
        )
        with database() as db:
            need_upload(db, upload_id)
            events = db.events(
                upload_id, where, limit=limit, offset=offset, newest_first=order == "desc"
            )
            items = [event.model_dump(mode="json") for event in events]
            return page(items, db.count_events(upload_id, where), limit, offset)

    @app.get(
        "/api/uploads/{upload_id}/templates", tags=["results"], summary="Message patterns"
    )
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
            numbers = sorted(
                {line for item in cited for line in [*item.lines, *item.against]}
            )
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
