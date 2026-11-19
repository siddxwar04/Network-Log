"""Loads a log file into the database: read, parse, store."""

from __future__ import annotations

from datetime import UTC, tzinfo
from pathlib import Path

from netlog.parsers.pipeline import Coverage, parse_file
from netlog.storage.database import Database


def ingest_file(
    db: Database,
    path: str | Path,
    *,
    year: int | None = None,
    tz: tzinfo = UTC,
    filename: str | None = None,
) -> int:
    """Parse a file and store its events. Returns the id of the new upload.

    If the file cannot be read, the upload is kept with status `failed` and the reason,
    and the error is raised again for the caller to report.
    """
    path = Path(path)
    upload_id = db.create_upload(filename or path.name, path.stat().st_size)
    coverage = Coverage()
    try:
        db.add_events(upload_id, parse_file(path, year=year, tz=tz, coverage=coverage))
    except Exception as error:
        db.fail_upload(upload_id, str(error))
        raise
    db.finish_upload(upload_id, coverage)
    return upload_id
