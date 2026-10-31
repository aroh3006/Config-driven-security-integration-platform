"""Saved run logs, live state and the scenario page, using the real engine."""

import base64
import json
import sqlite3
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

import engine
from app import connectors, engine_client, live, pages, patch, runlog, scenarios
from app.api import create_app
from engine import faults
from engine import http as engine_http
from engine import runner as engine_runner
from mock_server import __main__ as mock_main
from mock_server import app as mock_app
from mock_server import data, saas
from store import db

REPO_CONFIGS = Path(__file__).resolve().parent.parent / "configs"
SECRET = "okta-SECRET-0123456789"
BASIC = base64.b64encode(f"{saas.JIRA_EMAIL}:{saas.JIRA_TOKEN}".encode()).decode()


@pytest.fixture
def mock_transport():
    server = TestClient(mock_app.create_app(), base_url="http://localhost:9000")

    def handle(request):
        headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
        reply = server.request(request.method, str(request.url.raw_path, "ascii"), headers=headers, content=request.content)
        kept = [(k, v) for k, v in reply.headers.multi_items() if k.lower() != "content-encoding"]
        return httpx.Response(reply.status_code, headers=kept, content=reply.content)

    return httpx.MockTransport(handle)


@pytest.fixture
def wired(config_folder, monkeypatch, mock_transport):
    """Real engine and store. No real sleeps. Runs happen before the POST returns."""
    monkeypatch.setenv("MOCK_OKTA_KEY", saas.OKTA_KEY)
    monkeypatch.setenv("MOCK_JIRA_EMAIL", saas.JIRA_EMAIL)
    monkeypatch.setenv("MOCK_JIRA_TOKEN", saas.JIRA_TOKEN)
    monkeypatch.setattr(engine.memstore, "_default_store", db)
    monkeypatch.setattr(pages, "_spawn", lambda target: target())
    monkeypatch.setattr(engine_client, "start_scheduler", lambda: None)
    real_run = engine.run_connector

    def run_on_mock(target, **kwargs):
        return real_run(target, store=db, transport=mock_transport, sleeper=lambda _: None, resolver=lambda _: ["127.0.0.1"], **kwargs)

    monkeypatch.setattr(engine_client, "run_connector", run_on_mock)
    live.reset()
    faults._faults.clear()
    yield run_on_mock
    live.reset()
    faults._faults.clear()


@pytest.fixture
def client(wired):
    with TestClient(create_app()) as test_client:
        for name in ("mock-okta-users", "mock-jira-tickets"):
            text = (REPO_CONFIGS / f"{name}.yaml").read_text(encoding="utf-8")
            assert connectors.save_and_approve(text, "test") == []
        yield test_client


def press(client, name, scenario):
    return client.post(f"/ui/live/{name}/scenario", data={"scenario": scenario}, follow_redirects=True)


# Request log in the engine

def test_log_entries_hold_time_auth_type_and_retry_after(runner, store):
    text = (
        "name: logged\nentity: user\nsource: { base_url: 'https://x.example.com', allow_hosts: [x.example.com] }\n"
        "auth: { type: api_key, header: Authorization, prefix: 'SSWS ', secret: okta_key }\nmap: { id: id }\n"
    )
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "7"}, json={})
        return httpx.Response(200, json=[{"id": "1"}])

    result = runner(text, handler)
    first, second = result.requests
    assert first["status"] == 429 and first["retry_after"] == "7" and first["waited_s"] == 7
    assert first["auth_type"] == "api_key" and first["at"].endswith("Z")
    assert "retry_after" not in second and "waited_s" not in second
    assert SECRET not in json.dumps(result.requests)


def test_wait_hook_gets_name_seconds_and_reason(runner, monkeypatch):
    seen = []
    monkeypatch.setattr(engine_http, "on_wait", [lambda name, seconds, reason: seen.append((name, seconds, reason))])
    text = "name: hooked\nentity: user\nsource: { base_url: 'https://x.example.com', allow_hosts: [x.example.com] }\nmap: { id: id }\n"
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(429, headers={"Retry-After": "3"}) if len(calls) == 1 else httpx.Response(200, json=[{"id": "1"}])

    runner(text, handler)
    assert seen == [("hooked", 3, "rate limit")]


def test_broken_wait_hook_does_not_break_a_run(runner, monkeypatch):
    def broken(*_):
        raise RuntimeError("boom")

    monkeypatch.setattr(engine_http, "on_wait", [broken])
    text = "name: hooked\nentity: user\nsource: { base_url: 'https://x.example.com', allow_hosts: [x.example.com] }\nmap: { id: id }\n"
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(503) if len(calls) == 1 else httpx.Response(200, json=[{"id": "1"}])

    assert runner(text, handler).status == "success"


# Store

def test_old_database_gets_the_new_column_and_keeps_rows(tmp_path, monkeypatch):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, connector TEXT NOT NULL, started_at TEXT NOT NULL, "
        "finished_at TEXT, status TEXT NOT NULL DEFAULT 'running', records_pulled INTEGER NOT NULL DEFAULT 0, "
        "records_bad INTEGER NOT NULL DEFAULT 0, pages INTEGER NOT NULL DEFAULT 0, retries INTEGER NOT NULL DEFAULT 0, last_error TEXT)"
    )
    conn.execute("INSERT INTO runs (connector, started_at) VALUES ('old', '2026-10-01T00:00:00Z')")
    conn.commit()
    conn.close()
    monkeypatch.setenv("INTEGRATION_DB", str(path))
    db.init_db()
    db.init_db()
    run = db.last_run("old")
    assert run["connector"] == "old"
    assert db.get_run_log(run["id"]) == {"requests": [], "waits": [], "dropped": 0}
    db.save_run_log(run["id"], [{"status": 200}], [])
    assert db.get_run_log(run["id"])["requests"] == [{"status": 200}]


def test_run_log_masks_secrets_and_stays_valid_json():
    run_id = db.start_run("c")
    entries = [{"url_masked": "https://x/?api_key=abc123", "note": 'Authorization: Bearer abc123', "token": "abc123"}]
    db.save_run_log(run_id, entries, [1.0])
    log = db.get_run_log(run_id)
    assert "abc123" not in json.dumps(log)
    assert log["waits"] == [1.0]


def test_run_log_is_capped_and_keeps_the_latest():
    run_id = db.start_run("c")
    db.save_run_log(run_id, [{"n": n} for n in range(250)], [])
    log = db.get_run_log(run_id)
    assert len(log["requests"]) == db.MAX_LOGGED_REQUESTS and log["requests"][-1] == {"n": 249}
    assert log["dropped"] == 50


def test_run_lists_leave_out_the_log():
    run_id = db.start_run("c")
    db.save_run_log(run_id, [{"n": 1}], [])
    assert "request_log" not in db.last_run("c")
    assert db.get_run_log(9999)["requests"] == []


# Live state

def test_live_begin_refuses_a_second_run():
    live.reset()
    assert live.begin("c", "timeout") is True
    assert live.begin("c") is False
    live.finish("c")
    assert live.begin("c") is True
    live.reset()


def test_live_wait_counts_as_active_then_ends(monkeypatch):
    live.reset()
    clock = [1000.0]
    monkeypatch.setattr(live.time, "time", lambda: clock[0])
    live.note_wait("c", 30, "rate limit")
    state = live.snapshot("c")
    assert state["active"] and state["waiting"] and state["reason"] == "rate limit" and state["remaining"] == 30
    assert state["resumes_at"]
    clock[0] = 1031.0
    assert live.snapshot("c")["active"] is False
    live.reset()


def test_unknown_connector_has_an_idle_snapshot():
    live.reset()
    assert live.snapshot("nobody")["active"] is False


def test_hooks_install_once_and_uninstall():
    runlog.uninstall()
    runlog.install()
    runlog.install()
    assert engine_runner.on_run_finished.count(runlog.save_result) == 1
    assert engine_http.on_wait.count(live.note_wait) == 1
    runlog.uninstall()
    assert runlog.save_result not in engine_runner.on_run_finished


# Timeline

def test_timeline_trim_keeps_warnings_and_the_last_line():
    lines = [{"at": "", "text": f"step {n}", "tone": ""} for n in range(20)]
    lines[1]["tone"] = "amber"
    lines[3]["tone"] = "red"
    trimmed = scenarios._trim_timeline(lines)
    texts = [line["text"] for line in trimmed]
    assert "step 1" in texts and "step 3" in texts and texts[-1] == "step 19"
    assert len(trimmed) == scenarios.TIMELINE_LIMIT + 1
    assert texts[0] == "13 routine steps not shown"


def test_short_timeline_is_left_alone():
    lines = [{"at": "", "text": "only", "tone": ""}]
    assert scenarios._trim_timeline(lines) == lines


# Scenario pills

def test_each_pill_maps_to_one_fixed_mode():
    modes = {key: item["mode"] for key, item in scenarios.SCENARIOS.items()}
    assert modes == {"healthy": "off", "rate_limit": "429:30", "timeout": "timeoutx4", "wrong_key": "401", "bad_record": "badrecord"}


def test_page_loads_with_no_runs_and_has_no_script(client):
    page = client.get("/ui/live/mock-okta-users").text
    assert "Never run" in page and "<script" not in page
    assert 'http-equiv="refresh"' not in page
    assert page.count('name="scenario"') == 5


def test_live_entry_opens_the_worst_connector(client):
    press(client, "mock-okta-users", "healthy")
    press(client, "mock-jira-tickets", "wrong_key")
    response = client.get("/ui/live", follow_redirects=False)
    assert response.headers["location"] == "/ui/live/mock-jira-tickets"


def test_healthy_scenario_saves_the_log_and_labels_it(client):
    page = press(client, "mock-okta-users", "healthy").text
    run = db.last_run("mock-okta-users")
    log = db.get_run_log(run["id"])
    assert len(log["requests"]) == 3
    assert "/okta/api/v1/users" in page
    assert "ADDRESS · from the config" in page
    assert "Authorization: SSWS ••••••••" in page
    assert "secret mock_okta_key, masked" in page
    assert saas.OKTA_KEY not in page
    assert "NEXT PAGE · 3 pages fetched" in page
    assert "Requested page 1" in page


def test_rate_limit_scenario_shows_the_wait(client):
    page = press(client, "mock-okta-users", "rate_limit").text
    assert "429 Too Many Requests · Retry-After: 30" in page
    assert "RATE LIMIT · waits 30 s, then resumes · injected" in page
    assert "Got 429. Told to wait 30 s" in page
    assert "injected fault" in page
    assert db.last_run("mock-okta-users")["records_pulled"] == 120


def test_timeout_scenario_shows_backoff_and_gives_up(client):
    page = press(client, "mock-okta-users", "timeout").text
    assert "Failed: timeout" in page
    assert "TIMEOUT · retry in 1 s" in page and "TIMEOUT · retry in 4 s" in page
    assert "GAVE UP · as the rules say" in page
    assert "Timed out. Retry in 2 s" in page
    assert "failed runs in a row: 1" in page


def test_wrong_key_scenario_is_not_retried(client):
    page = press(client, "mock-okta-users", "wrong_key").text
    assert "Failed: login rejected" in page
    assert "401 Unauthorized" in page
    assert "NOT RETRIED" in page
    assert db.last_run("mock-okta-users")["retries"] == 0
    assert "[ Alert ]" in page
    assert "Sends to Slack at 3 failures in a row. Now at 1." in page


def test_rejected_login_behind_a_200_is_explained(client, monkeypatch):
    monkeypatch.setenv("MOCK_JIRA_TOKEN", "wrong-value-123")
    page = press(client, "mock-jira-tickets", "healthy").text
    assert "Failed: login rejected" in page
    assert "credentials rejected" in page
    assert "wrong-value-123" not in page


@pytest.mark.parametrize("scenario", sorted(scenarios.SCENARIOS))
def test_scenario_refused_when_a_secret_is_missing(client, monkeypatch, scenario):
    monkeypatch.setenv("MOCK_JIRA_EMAIL", "")
    monkeypatch.setenv("MOCK_JIRA_TOKEN", "")
    page = press(client, "mock-jira-tickets", scenario).text
    assert "Nothing ran. mock-jira-tickets needs MOCK_JIRA_EMAIL, MOCK_JIRA_TOKEN in .env." in page
    assert db.last_run("mock-jira-tickets") is None
    assert faults.list_faults() == {}
    assert live.snapshot("mock-jira-tickets")["active"] is False


def test_scenario_names_only_the_secret_that_is_missing(client, monkeypatch):
    monkeypatch.setenv("MOCK_JIRA_EMAIL", "")
    page = press(client, "mock-jira-tickets", "healthy").text
    assert "needs MOCK_JIRA_EMAIL in .env" in page
    assert saas.JIRA_TOKEN not in page


def test_missing_secret_does_not_claim_a_401(client, wired, monkeypatch):
    monkeypatch.setenv("MOCK_JIRA_EMAIL", "")
    wired("mock-jira-tickets")
    page = client.get("/ui/live/mock-jira-tickets").text
    assert "Failed: secret missing" in page
    assert "no request sent" in page and "401" not in page
    assert "Failed: login rejected" not in page and "a wrong key" not in page.lower()
    assert "LOGIN · stopped before any data" in page


def test_panel_shows_the_fault_then_healthy_sources(client):
    rows = [
        {"name": "watched", "status": "auth_failed", "mock": True},
        {"name": "other-fault", "status": "failing", "mock": False},
        {"name": "fine", "status": "healthy", "mock": True},
        {"name": "fine-too", "status": "healthy", "mock": False},
    ]
    assert [row["name"] for row in patch.choose(rows, 3, "watched", healthy_first=True)] == ["watched", "fine-too", "fine"]
    assert [row["name"] for row in patch.choose(rows, 3)][0] == "other-fault"


def test_clean_mock_data_is_healthy_until_a_fault_is_pressed(config_folder, monkeypatch):
    monkeypatch.setattr(data, "MESSY", False)
    server = TestClient(mock_app.create_app(), base_url="http://localhost:9000")

    def handle(request):
        headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
        reply = server.request(request.method, str(request.url.raw_path, "ascii"), headers=headers, content=request.content)
        kept = [(k, v) for k, v in reply.headers.multi_items() if k.lower() != "content-encoding"]
        return httpx.Response(reply.status_code, headers=kept, content=reply.content)

    monkeypatch.setenv("MOCK_OKTA_KEY", saas.OKTA_KEY)
    monkeypatch.setattr(engine.memstore, "_default_store", db)
    text = (REPO_CONFIGS / "mock-okta-users.yaml").read_text(encoding="utf-8")
    assert connectors.save_and_approve(text, "test") == []
    options = {"store": db, "transport": httpx.MockTransport(handle), "sleeper": lambda _: None, "resolver": lambda _: ["127.0.0.1"]}

    clean = engine.run_connector("mock-okta-users", **options)
    assert (clean.status, clean.records_bad) == ("success", 0)
    assert db.get_connector("mock-okta-users")["status"] == "healthy"

    faults.set_fault("mock-okta-users", "badrecord")
    assert engine.run_connector("mock-okta-users", **options).records_bad == 1
    faults._faults.clear()


def test_running_server_is_clean_unless_asked(monkeypatch, tmp_path):
    monkeypatch.setattr(data, "MESSY", True)
    monkeypatch.setattr(mock_main.uvicorn, "run", lambda *_, **__: None)
    monkeypatch.setattr(mock_main.Path, "write_text", lambda *_, **__: 0)
    monkeypatch.setattr(mock_main.sys, "argv", ["mock_server"])
    mock_main.main()
    assert data.MESSY is False
    monkeypatch.setattr(mock_main.sys, "argv", ["mock_server", "--messy"])
    mock_main.main()
    assert data.MESSY is True


def test_bad_record_scenario_shows_the_broken_record(client):
    page = press(client, "mock-okta-users", "bad_record").text
    assert "[ One broken record, labelled ]" in page
    assert "set aside" in page
    assert "[ Quarantine · " in page
    assert "REPLAY · after a fix" in page
    assert 'class="tray"' in page


def test_pressing_healthy_clears_a_failure(client):
    press(client, "mock-okta-users", "wrong_key")
    assert db.get_connector("mock-okta-users")["consecutive_failures"] == 1
    press(client, "mock-okta-users", "healthy")
    assert db.get_connector("mock-okta-users")["consecutive_failures"] == 0


def test_fault_never_outlives_its_run(client, monkeypatch):
    monkeypatch.setattr(engine_client, "run_connector", lambda name: engine.RunResult(connector=name, status="skipped"))
    press(client, "mock-okta-users", "wrong_key")
    assert faults.list_faults() == {}


def test_only_named_scenarios_are_accepted(client):
    assert client.post("/ui/live/mock-okta-users/scenario", data={"scenario": "503x9"}).status_code == 400
    assert client.post("/ui/live/mock-okta-users/scenario").status_code == 400
    assert client.post("/ui/live/nope/scenario", data={"scenario": "healthy"}).status_code == 404
    assert client.get("/ui/live/nope").status_code == 404


def test_scenario_refused_while_running(client):
    live.begin("mock-okta-users")
    page = press(client, "mock-okta-users", "wrong_key").text
    assert "already running" in page
    assert faults.list_faults() == {}
    assert db.last_run("mock-okta-users") is None
    assert 'http-equiv="refresh" content="5"' in page


def test_scenario_refused_when_paused_or_changed(client):
    client.post("/connectors/mock-okta-users/pause")
    assert "is paused" in press(client, "mock-okta-users", "healthy").text
    client.post("/connectors/mock-okta-users/resume")
    connector = db.get_connector("mock-okta-users")
    db.save_connector("mock-okta-users", "user", connector["config_yaml"] + "# edit\n", "other-hash")
    assert "changed config" in press(client, "mock-okta-users", "healthy").text
    assert db.last_run("mock-okta-users") is None


def test_cross_site_scenario_post_is_refused(client):
    response = client.post(
        "/ui/live/mock-okta-users/scenario", data={"scenario": "wrong_key"}, headers={"Origin": "https://evil.example.com"}
    )
    assert response.status_code == 403
    assert faults.list_faults() == {}


def test_scenario_is_audited(client):
    press(client, "mock-okta-users", "healthy")
    assert any(entry["action"] == "scenario.start" for entry in db.list_audit())


def test_page_shows_waiting_state_and_refreshes(client):
    press(client, "mock-okta-users", "healthy")
    live.begin("mock-okta-users", "rate_limit")
    live.note_wait("mock-okta-users", 30, "rate limit")
    page = client.get("/ui/live/mock-okta-users").text
    assert "Slowed down: rate limit" in page
    assert "wait 30 s" in page
    assert "429 Too Many Requests · waiting 30 s" in page
    assert 'http-equiv="refresh" content="5"' in page
    assert "Pausing mock-okta-users only" in page


def test_page_escapes_log_and_record_values(client):
    run_id = db.start_run("mock-okta-users")
    db.finish_run(run_id, "partial", 2, 1, 1, 0, "<script>x</script>")
    db.save_run_log(run_id, [{"method": "GET", "url_masked": "https://x/<script>y</script>", "status": 200, "attempt": 1, "at": "2026-10-31T00:00:00Z"}], [])
    db.add_quarantine("mock-okta-users", run_id, {"id": "<script>z</script>"}, "missing required field 'email' <script>")
    assert "<script" not in client.get("/ui/live/mock-okta-users").text
