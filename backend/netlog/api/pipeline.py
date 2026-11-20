"""Runs the pipeline for one upload in the background and records how far it has got.

The API hands out an upload id at once and the work happens here, on a worker thread:

    queued -> parsing -> templates -> detection -> correlation -> explanation -> done

The current stage is written to the upload's row as each one starts, which is what the
status endpoint reads. If a stage fails, the upload is marked `failed` with the stage it
was in and a reason a person can read. A reason never contains a stack trace: an error
nobody expected is written to the server log and described to the user in general terms.
"""

from __future__ import annotations

import logging
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import tzinfo
from pathlib import Path

from netlog.correlation.grouping import correlate
from netlog.detection.engine import detect
from netlog.ingestion.ingest import ingest_file
from netlog.ingestion.reader import BinaryFileError
from netlog.llm.provider import Provider
from netlog.llm.settings import LLMSettings
from netlog.mining.templates import mine_templates
from netlog.report.explain import explain_incidents
from netlog.storage.database import Database

log = logging.getLogger("netlog.api")

# The stages in order. `failed` is not one of them: it replaces whichever was running.
STAGES = ("queued", "parsing", "templates", "detection", "correlation", "explanation", "done")
# What each stage is doing, for a failure message.
_DOING = {
    "queued": "starting",
    "parsing": "reading the file",
    "templates": "finding message patterns",
    "detection": "running the detection rules",
    "correlation": "grouping findings into incidents",
    "explanation": "explaining the incidents",
}
SUPPORTED = (
    "Supported: syslog (RFC 3164 and RFC 5424), Cisco IOS, Linux sshd and sudo, ISC dhcpd."
)


class PipelineError(Exception):
    """The upload cannot be analyzed, for a reason the user can be told."""


@dataclass
class Job:
    """Everything the pipeline needs for one upload."""

    db_path: Path
    upload_id: int
    path: Path
    year: int | None
    tz: tzinfo
    config: dict
    settings: LLMSettings
    provider: Provider | None = None
    mode: str = "senior"


def run_pipeline(job: Job) -> None:
    """Run every stage for one upload. Never raises: a failure is recorded on the upload."""
    stage = "queued"
    with Database(job.db_path) as db:

        def enter(name: str) -> None:
            nonlocal stage
            stage = name
            db.set_stage(job.upload_id, name)

        try:
            enter("parsing")
            ingest_file(
                db, job.path, year=job.year, tz=job.tz, upload_id=job.upload_id, done=False
            )
            upload = db.get_upload(job.upload_id)
            if upload.line_count == 0:
                raise PipelineError("The file contains only blank lines.")
            if upload.parsed + upload.partial == 0:
                raise PipelineError(f"No recognizable log lines in the file. {SUPPORTED}")

            enter("templates")
            mine_templates(db, job.upload_id, job.config)
            enter("detection")
            detect(db, job.upload_id, config=job.config)
            enter("correlation")
            incidents = correlate(db, job.upload_id, job.config)

            # The explanation never fails the pipeline: with no LLM, or one that is down
            # or wrong, each incident gets the built-in explanation.
            enter("explanation")
            explain_incidents(
                db,
                job.upload_id,
                [incident.id for incident in incidents],
                db,
                job.mode,
                provider=job.provider,
                settings=job.settings,
                config=job.config,
            )
            db.complete_upload(job.upload_id)
        except PipelineError as error:
            db.fail_upload(job.upload_id, str(error))
        except BinaryFileError:
            db.fail_upload(job.upload_id, "The file is not a text file, so it cannot be a log.")
        except FileNotFoundError:
            db.fail_upload(job.upload_id, "The stored file could not be found.")
        except Exception:
            log.exception("pipeline failed for upload %s during %s", job.upload_id, stage)
            db.fail_upload(
                job.upload_id,
                f"An unexpected error occurred while {_DOING.get(stage, stage)}. "
                "The details are in the server log.",
            )


class PipelineRunner:
    """A small pool of worker threads that pipelines are handed to."""

    def __init__(self, workers: int = 1) -> None:
        self._pool = ThreadPoolExecutor(
            max_workers=max(int(workers), 1), thread_name_prefix="netlog-pipeline"
        )
        self._jobs: list[Future] = []

    def submit(self, job: Job) -> None:
        self._jobs = [future for future in self._jobs if not future.done()]
        self._jobs.append(self._pool.submit(run_pipeline, job))

    def wait(self, timeout: float | None = None) -> None:
        """Block until every pipeline handed in so far has finished."""
        for future in list(self._jobs):
            future.result(timeout)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=True)
