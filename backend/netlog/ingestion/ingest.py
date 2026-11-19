"""Loads a log file into the database: read, parse, store."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, tzinfo
from pathlib import Path

from netlog.parsers.pipeline import Coverage, parse_file
from netlog.schema import Event
from netlog.storage.database import Database


def ingest_file(
    db: Database,
    path: str | Path,
    *,
    year: int | None = None,
    tz: tzinfo = UTC,
    filename: str | None = None,
    on_progress: Callable[[int], None] | None = None,
    progress_every: int = 5000,
) -> int:
    """Parse a file and store its events. Returns the id of the new upload.

    If the file cannot be read, the upload is kept with status `failed` and the reason,
    and the error is raised again for the caller to report. `on_progress` is called with
    the number of lines handled so far, every `progress_every` lines.
    """
    path = Path(path)
    upload_id = db.create_upload(filename or path.name, path.stat().st_size)
    coverage = Coverage()

    def events() -> Iterator[Event]:
        for count, event in enumerate(parse_file(path, year=year, tz=tz, coverage=coverage), 1):
            if on_progress and count % progress_every == 0:
                on_progress(count)
            yield event

    try:
        db.add_events(upload_id, events())
    except Exception as error:
        db.fail_upload(upload_id, str(error))
        raise
    db.finish_upload(upload_id, coverage)
    return upload_id
