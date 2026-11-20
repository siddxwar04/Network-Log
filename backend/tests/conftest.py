"""Fixtures shared by the test files."""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path

import pytest

from netlog.correlation.grouping import correlate
from netlog.detection.engine import detect
from netlog.ingestion.ingest import ingest_file
from netlog.mining.templates import mine_templates
from netlog.storage.database import Database

SCENARIOS = Path("data/scenarios")


def pytest_configure(config):
    """Before any fixture runs, even the module-wide ones: the explanations kept with the
    demo scenarios must never answer in place of a test's fake LLM."""
    os.environ["NETLOG_DEMO_EXPLANATIONS"] = str(
        Path(tempfile.gettempdir()) / "netlog-tests-no-stored-explanations.json"
    )
    # Nor may a developer's own rule file change what the tests find.
    os.environ["NETLOG_USER_RULES"] = str(
        Path(tempfile.gettempdir()) / "netlog-tests-no-rules.toml"
    )


@pytest.fixture(autouse=True)
def _no_llm_from_the_environment(monkeypatch, tmp_path):
    """The test suite must never make a real API call. Whatever provider and key the
    developer has set for their own use are hidden from every test."""
    for name in ("NETLOG_LLM_PROVIDER", "NETLOG_LLM_MODEL", "NETLOG_LLM_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    # Nor may a test post to the developer's own chat channel.
    for name in ("NETLOG_ALERT_SLACK_URL", "NETLOG_ALERT_WEBHOOK_URL"):
        monkeypatch.delenv(name, raising=False)
    # The commands read a .env file; keep them away from the developer's own.
    monkeypatch.setenv("NETLOG_ENV_FILE", "no-such-file.env")
    # Stored LLM answers go to a database of the test's own, never to data/netlog.db.
    monkeypatch.setenv("NETLOG_DB_PATH", str(tmp_path / "netlog-cache.db"))


@pytest.fixture(scope="session")
def _analyzed_files(tmp_path_factory):
    """A database file per sample log, holding the log after the whole pipeline has run.

    Running the pipeline takes a couple of seconds per log, so it is done once per test
    session and each test works on its own copy of the file.
    """
    folder = tmp_path_factory.mktemp("analyzed")
    files: dict[str, tuple[Path, int]] = {}

    def get(name: str) -> tuple[Path, int]:
        if name not in files:
            path = folder / f"{name}.db"
            with Database(path) as db:
                upload = ingest_file(db, SCENARIOS / f"{name}.log", year=2026)
                mine_templates(db, upload)
                detect(db, upload)
                correlate(db, upload)
            files[name] = (path, upload)
        return files[name]

    return get


@pytest.fixture
def analyzed(_analyzed_files, tmp_path):
    """`analyzed("02_cascade")` gives a database of the test's own with that sample log
    already analyzed, the upload id and the incidents."""
    opened: list[Database] = []

    def get(name: str):
        source, upload = _analyzed_files(name)
        path = tmp_path / f"{name}-{len(opened)}.db"
        shutil.copyfile(source, path)
        db = Database(path)
        opened.append(db)
        return db, upload, db.incidents(upload)

    yield get
    for db in opened:
        db.close()
