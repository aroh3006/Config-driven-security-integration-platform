import hashlib

import pytest

from app import engine_client, engine_stubs as stubs
from store import db

GOOD_CONFIG = """\
name: demo
entity: user
source: { type: http, base_url: https://x.example.com, allow_hosts: [x.example.com] }
auth: { type: bearer, secret: demo_token }
pagination: { type: page_number }
schedule: every 15m
map: { id: id }
"""


@pytest.fixture(autouse=True)
def clear_faults(isolated_app):
    stubs._faults.clear()
    yield
    stubs._faults.clear()


@pytest.fixture
def connector():
    digest = hashlib.sha256(GOOD_CONFIG.encode()).hexdigest()
    db.save_connector("demo", "user", GOOD_CONFIG, digest)
    db.approve_connector("demo", digest)
    return "demo"


def test_validate_accepts_good_config_and_draft():
    assert stubs.validate_config(GOOD_CONFIG) == []
    assert stubs.validate_config(stubs.DRAFT_YAML) == []


@pytest.mark.parametrize(
    "text, path",
    [
        ("name: [unclosed", ""),
        ("just text", ""),
        ("entity: user\nsource: {}\nmap: {}", "name"),
        (GOOD_CONFIG.replace("entity: user", "entity: printer"), "entity"),
        (GOOD_CONFIG.replace("type: bearer", "type: magic"), "auth.type"),
        (GOOD_CONFIG.replace("type: page_number", "type: scroll"), "pagination.type"),
    ],
)
def test_validate_reports_the_problem_path(text, path):
    problems = stubs.validate_config(text)
    assert path in [p["path"] for p in problems]
    assert all({"path", "message", "hint"} <= set(p) for p in problems)


def test_load_config_reads_fields_and_rejects_bad_yaml():
    config = stubs.load_config(GOOD_CONFIG)
    assert (config.name, config.entity, config.schedule) == ("demo", "user", "every 15m")
    with pytest.raises(ValueError, match="invalid config"):
        stubs.load_config("entity: user")


def test_run_stores_rows_and_marks_healthy(connector):
    result = stubs.run_connector(connector)
    assert (result.status, result.records_pulled, result.records_bad) == ("success", 5, 0)
    assert len(db.query_records("user", source=connector)) == 5
    assert db.last_run(connector)["status"] == "success"
    assert db.get_connector(connector)["status"] == "healthy"


def test_rerun_does_not_duplicate(connector):
    stubs.run_connector(connector)
    stubs.run_connector(connector)
    assert len(db.query_records("user", source=connector)) == 5


def test_run_unknown_connector_fails_cleanly():
    result = stubs.run_connector("missing")
    assert result.status == "failed"
    assert "unknown connector" in result.last_error


def test_test_connection_stores_nothing(connector):
    result = stubs.test_connection(connector)
    assert result.status == "success"
    assert len(result.sample_mapped) == 3
    assert db.query_records("user", source=connector) == []
    assert db.last_run(connector) is None
    assert db.get_connector(connector)["status"] == "never_run"


@pytest.mark.parametrize(
    "mode, run_status, connector_status, retries",
    [
        ("503x3", "success", "healthy", 3),
        ("503x4", "failed", "failing", 3),
        ("429:30", "success", "healthy", 1),
        ("timeout", "failed", "failing", 3),
        ("badrecord", "partial", "degraded", 0),
    ],
)
def test_fault_modes(connector, mode, run_status, connector_status, retries):
    stubs.set_fault(connector, mode)
    result = stubs.run_connector(connector)
    assert (result.status, result.retries) == (run_status, retries)
    assert db.get_connector(connector)["status"] == connector_status


def test_bad_record_lands_in_quarantine(connector):
    stubs.set_fault(connector, "badrecord")
    result = stubs.run_connector(connector)
    assert (result.records_pulled, result.records_bad) == (5, 1)
    assert len(db.query_records("user", source=connector)) == 4
    assert "missing required field" in db.list_quarantine(connector)[0]["reason"]


def test_failures_count_up_then_reset(connector):
    stubs.set_fault(connector, "timeout")
    stubs.run_connector(connector)
    stubs.run_connector(connector)
    assert db.get_connector(connector)["consecutive_failures"] == 2
    stubs.clear_fault(connector)
    stubs.run_connector(connector)
    assert db.get_connector(connector)["consecutive_failures"] == 0


def test_unknown_fault_mode_is_rejected():
    with pytest.raises(ValueError, match="unknown fault mode"):
        stubs.set_fault("demo", "explode")


def test_pause_and_resume(connector):
    stubs.run_connector(connector)
    stubs.pause(connector)
    paused = db.get_connector(connector)
    assert (paused["enabled"], paused["status"]) == (0, "paused")
    stubs.resume(connector)
    resumed = db.get_connector(connector)
    assert (resumed["enabled"], resumed["status"]) == (1, "healthy")


def test_profile_sample_returns_a_valid_draft():
    result = stubs.profile_sample('{"items": [{"id": 1}, {"id": 2}]}', entity="device")
    assert stubs.validate_config(result["draft_yaml"]) == []
    assert "entity: device" in result["draft_yaml"]
    assert result["preview_raw"] == [{"id": 1}, {"id": 2}]
    assert stubs.profile_sample("not json")["preview_raw"] == []


def _write_fake_package(root, name, files):
    package = root / name
    package.mkdir()
    (package / "__init__.py").write_text("")
    for filename, body in files.items():
        (package / filename).write_text(body)


def test_client_prefers_the_real_function(tmp_path, monkeypatch):
    _write_fake_package(tmp_path, "fakeengine_a", {"mod.py": "def run(): return 'real'\n"})
    monkeypatch.syspath_prepend(tmp_path)
    function, is_stub = engine_client._load("fakeengine_a.mod", "run", lambda: "stub")
    assert (function(), is_stub) == ("real", False)


def test_client_falls_back_when_module_or_function_is_missing(tmp_path, monkeypatch):
    _write_fake_package(tmp_path, "fakeengine_b", {"mod.py": "x = 1\n"})
    monkeypatch.syspath_prepend(tmp_path)
    stub = lambda: "stub"
    assert engine_client._load("no_such_engine.mod", "run", stub) == (stub, True)
    assert engine_client._load("fakeengine_b.absent", "run", stub) == (stub, True)
    assert engine_client._load("fakeengine_b.mod", "run", stub) == (stub, True)


def test_client_does_not_hide_a_broken_engine_module(tmp_path, monkeypatch):
    _write_fake_package(
        tmp_path,
        "fakeengine_c",
        {"mod.py": "import fakeengine_c.not_written_yet\n", "bad.py": "def broken(:\n"},
    )
    monkeypatch.syspath_prepend(tmp_path)
    with pytest.raises(ModuleNotFoundError):
        engine_client._load("fakeengine_c.mod", "run", lambda: "stub")
    with pytest.raises(SyntaxError):
        engine_client._load("fakeengine_c.bad", "run", lambda: "stub")
