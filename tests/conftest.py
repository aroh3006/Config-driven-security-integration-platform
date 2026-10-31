"""Shared fixtures. Every test gets its own empty database file."""

import pytest

from app import engine_client, engine_stubs
from store import db

STUBBED_NAMES = (
    "validate_config",
    "load_config",
    "run_connector",
    "test_connection",
    "profile_sample",
    "replay_record",
    "start_scheduler",
    "pause",
    "resume",
    "set_fault",
    "clear_fault",
)


@pytest.fixture(autouse=True)
def temp_db(tmp_path, monkeypatch):
    path = tmp_path / "test.db"
    monkeypatch.setenv("INTEGRATION_DB", str(path))
    db.init_db()
    return path


@pytest.fixture(autouse=True)
def isolated_app(tmp_path, monkeypatch):
    """App tests run on the stubs, whatever the engine folder holds by then."""
    folder = tmp_path / "configs"
    folder.mkdir()
    monkeypatch.setenv("INTEGRATION_CONFIGS", str(folder))
    monkeypatch.delenv("SLACK_WEBHOOK", raising=False)
    for name in STUBBED_NAMES:
        monkeypatch.setattr(engine_client, name, getattr(engine_stubs, name))
    engine_stubs._faults.clear()
    yield folder
    engine_stubs._faults.clear()
