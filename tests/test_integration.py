"""The real engine, the SQLite store and the mock server working together."""

from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

import engine
from app import connectors, engine_client, health
from app.api import create_app
from engine import faults
from mock_server import app as mock_app
from mock_server import saas, styles
from store import db

REPO_CONFIGS = Path(__file__).resolve().parent.parent / "configs"
MOCK_SECRETS = {
    "MOCK_FIREWALL_KEY": mock_app.FIREWALL_KEY,
    "MOCK_EDR_CLIENT_ID": mock_app.EDR_CLIENT_ID,
    "MOCK_EDR_CLIENT_SECRET": mock_app.EDR_CLIENT_SECRET,
    "MOCK_CLOUD_KEY": mock_app.CLOUD_KEY,
    "MOCK_OKTA_KEY": saas.OKTA_KEY,
    "MOCK_GITHUB_TOKEN": saas.GITHUB_TOKEN,
    "MOCK_JIRA_EMAIL": saas.JIRA_EMAIL,
    "MOCK_JIRA_TOKEN": saas.JIRA_TOKEN,
    "MOCK_FMC_USER": styles.FMC_USER,
    "MOCK_FMC_PASSWORD": styles.FMC_PASSWORD,
    "MOCK_WIZ_CLIENT_ID": styles.WIZ_CLIENT_ID,
    "MOCK_WIZ_CLIENT_SECRET": styles.WIZ_CLIENT_SECRET,
    "MOCK_CORTEX_KEY": styles.CORTEX_KEY,
    "MOCK_CORTEX_KEY_ID": styles.CORTEX_KEY_ID,
}


@pytest.fixture
def mock_transport():
    server = TestClient(mock_app.create_app(), base_url="http://localhost:9000")

    def handle(request: httpx.Request) -> httpx.Response:
        headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
        reply = server.request(
            request.method, str(request.url.raw_path, "ascii"), headers=headers, content=request.content
        )
        passed_on = [(k, v) for k, v in reply.headers.multi_items() if k.lower() != "content-encoding"]
        return httpx.Response(reply.status_code, headers=passed_on, content=reply.content)

    return httpx.MockTransport(handle)


@pytest.fixture
def run(mock_transport, config_folder, monkeypatch):
    for key, value in MOCK_SECRETS.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(engine.memstore, "_default_store", db)

    def go(name, **kwargs):
        text = (REPO_CONFIGS / f"{name}.yaml").read_text(encoding="utf-8")
        if db.get_connector(name) is None:
            assert connectors.save_and_approve(text, "test") == []
        return engine.run_connector(
            name, store=db, transport=mock_transport, sleeper=lambda _: None, resolver=lambda _: ["127.0.0.1"], **kwargs
        )

    return go


def test_client_uses_the_real_engine():
    assert engine_client.stubbed_functions() == []
    assert engine_client.run_connector is engine.run_connector


@pytest.mark.parametrize("path", sorted(REPO_CONFIGS.glob("*.yaml")), ids=lambda p: p.stem)
def test_every_repo_config_passes_the_real_validator(path):
    problems = engine.validate_config(path.read_text(encoding="utf-8"))
    assert connectors.errors_only(problems) == []


@pytest.mark.parametrize(
    "name, entity, total",
    [
        ("mock-firewall", "alert", 300),
        ("mock-edr-hosts", "device", 200),
        ("mock-edr-detections", "alert", 300),
        ("mock-cloud-audit", "alert", 300),
        ("mock-cisco-fmc-devices", "device", 60),
        ("mock-wiz-issues", "alert", 120),
        ("mock-cortex-alerts", "alert", 250),
    ],
)
def test_mock_sources_run_end_to_end(run, name, entity, total):
    result = run(name)
    assert result.status == "partial", result.last_error
    assert result.records_pulled == total
    assert 0 < result.records_bad < total * 0.03
    stored = db.count_records(entity, name)
    assert stored == total - result.records_bad
    assert len(db.list_quarantine(name, limit=500)) == result.records_bad
    assert db.get_connector(name)["status"] == "degraded"


@pytest.mark.parametrize(
    "name, entity, total, pages",
    [
        ("mock-okta-users", "user", 120, 3),
        ("mock-github-members", "user", 130, 4),
        ("mock-jira-tickets", "alert", 150, 3),
    ],
)
def test_core_three_differ_in_login_and_paging_and_all_load(run, name, entity, total, pages):
    result = run(name)
    assert result.status == "partial", result.last_error
    assert (result.records_pulled, result.pages) == (total, pages)
    assert result.records_bad == 1
    assert db.count_records(entity, name) == total - 1


def test_dependabot_loads_open_alerts_with_real_cves(run):
    result = run("mock-github-dependabot")
    assert result.ok, result.last_error
    rows = db.query_records("alert", source="mock-github-dependabot", limit=100)
    assert rows and all(row["cve"].startswith("CVE-") for row in rows)
    assert {row["severity"] for row in rows} <= {"high", "critical"}


def test_okta_signins_stop_on_empty_page_and_advance_the_watermark(run):
    first = run("mock-okta-signins")
    assert first.status == "partial", first.last_error
    assert first.records_bad == 1
    assert first.more_pages is False
    mark = db.get_checkpoint("mock-okta-signins")
    assert mark["watermark"] and mark["resume_state"] is None

    second = run("mock-okta-signins")
    assert second.status == "success", second.last_error
    assert second.pages <= 2
    assert second.records_pulled < first.records_pulled


def test_people_view_joins_across_mock_sources(run, monkeypatch):
    run("mock-okta-users")
    run("mock-github-members")
    run("mock-okta-signins")
    run("mock-edr-hosts")
    records = db.person_records("ann@example.com")
    # GitHub's member list has no email. GitHub rows cannot join on it.
    assert {row["source"] for row in records["users"]} == {"mock-okta-users"}
    assert records["devices"]
    assert records["alerts"]


@pytest.mark.parametrize("name, entity", [("mock-edr-detections", "alert"), ("mock-cloud-audit", "alert"), ("mock-edr-hosts", "device")])
def test_wrong_type_records_are_quarantined_not_stored(run, name, entity):
    run(name)
    stored = db.query_records(entity, source=name, limit=1000)
    columns = ("id", "type", "severity", "description", "os", "hostname")
    assert not any("unexpected" in str(row.get(column)) for row in stored for column in columns)
    reasons = [item["reason"] for item in db.list_quarantine(name, limit=50)]
    assert any("expected a single value, got an object" in reason for reason in reasons)


def test_jira_timestamps_with_no_colon_offset_parse(run):
    run("mock-jira-tickets")
    rows = db.query_records("alert", source="mock-jira-tickets", limit=200)
    assert all(row["timestamp"].endswith("Z") for row in rows)
    assert {row["severity"] for row in rows} <= {"critical", "high", "medium", "low"}


def test_common_schema_values_are_clean(run):
    run("mock-firewall")
    rows = db.query_records("alert", source="mock-firewall", limit=500)
    assert {row["severity"] for row in rows} <= {"info", "low", "medium", "high", "critical"}
    assert all(row["timestamp"].endswith("Z") for row in rows)
    assert any(row["cve"] for row in rows)


def test_device_file_source_quarantines_the_row_with_no_id(run, monkeypatch):
    monkeypatch.chdir(REPO_CONFIGS.parent)
    result = run("devices-file")
    assert (result.status, result.records_pulled, result.records_bad) == ("partial", 12, 1)
    assert db.count_records("device", "devices-file") == 11


def test_rerun_does_not_duplicate(run):
    run("mock-edr-hosts")
    first = db.count_records("device", "mock-edr-hosts")
    run("mock-edr-hosts")
    assert db.count_records("device", "mock-edr-hosts") == first


def test_wrong_jira_key_is_auth_failed_not_an_empty_success(run, monkeypatch):
    monkeypatch.setenv("MOCK_JIRA_TOKEN", "wrong-key-value")
    result = run("mock-jira-tickets")
    assert (result.status, result.records_pulled) == ("auth_failed", 0)
    assert "credentials rejected" in result.last_error
    assert "wrong-key-value" not in result.last_error


def test_session_login_wrong_password_is_auth_failed(run, monkeypatch):
    monkeypatch.setenv("MOCK_FMC_PASSWORD", "wrong-password-value")
    result = run("mock-cisco-fmc-devices")
    assert (result.status, result.records_pulled) == ("auth_failed", 0)
    assert "wrong-password-value" not in result.last_error


def test_expired_session_logs_in_again_without_failing(run, mock_transport):
    first = run("mock-cisco-fmc-devices")
    with httpx.Client(transport=mock_transport, base_url="http://localhost:9000") as admin:
        assert admin.post("/admin/expire-tokens").json()["expired"] >= 1
    second = run("mock-cisco-fmc-devices")
    assert (first.records_pulled, second.records_pulled) == (60, 60)
    assert second.status == "partial"


def test_wrong_second_header_is_auth_failed(run, monkeypatch):
    monkeypatch.setenv("MOCK_CORTEX_KEY_ID", "99")
    assert run("mock-cortex-alerts").status == "auth_failed"


def test_graphql_mock_pages_through_nested_cursor(run):
    result = run("mock-wiz-issues")
    assert (result.records_pulled, result.pages) == (120, 3)


def test_wrong_key_gives_auth_failed(run, monkeypatch):
    monkeypatch.setenv("MOCK_FIREWALL_KEY", "wrong-key-value")
    result = run("mock-firewall")
    assert result.status == "auth_failed"
    assert result.retries == 0
    connector = db.get_connector("mock-firewall")
    assert (connector["status"], connector["consecutive_failures"]) == ("auth_failed", 1)
    assert "wrong-key-value" not in (db.last_run("mock-firewall")["last_error"] or "")


def test_retry_limits(run):
    faults.set_fault("mock-firewall", "503x3")
    recovered = run("mock-firewall")
    assert recovered.retries == 3
    assert recovered.records_pulled == 300

    faults.set_fault("mock-firewall", "503x4")
    assert run("mock-firewall").status == "failed"
    assert db.get_connector("mock-firewall")["status"] == "failing"


def test_changed_config_refuses_to_run(run):
    run("mock-firewall")
    connector = db.get_connector("mock-firewall")
    db.save_connector("mock-firewall", "alert", connector["config_yaml"] + "# edited\n", "other")
    result = run("mock-firewall")
    assert result.status == "config_changed"
    assert db.get_connector("mock-firewall")["status"] == "config_changed"


def test_pause_shows_in_store_and_stops_runs(run):
    run("mock-firewall")
    before = len(db.list_runs("mock-firewall"))
    engine.scheduler.pause("mock-firewall")
    connector = db.get_connector("mock-firewall")
    assert connector["enabled"] is False
    assert run("mock-firewall").status == "paused"
    assert len(db.list_runs("mock-firewall")) == before
    assert health.connector_row(connector)["next_run"] == "-"

    engine.scheduler.resume("mock-firewall")
    assert db.get_connector("mock-firewall")["enabled"] is True
    assert run("mock-firewall").ok


def test_replay_uses_the_real_mapper(run):
    run("mock-firewall")
    item = db.list_quarantine("mock-firewall", limit=500)[-1]
    assert engine_client.replay_record("mock-firewall", connectors.load_raw(item))["ok"] is False

    fixed = {"externalId": "fw-fixed", "rt": 1793385725000, "severity": 7, "name": "Fixed"}
    outcome = engine_client.replay_record("mock-firewall", fixed)
    assert outcome["ok"] is True
    assert outcome["row"]["severity"] == "high"
    assert outcome["row"]["timestamp"].endswith("Z")


def test_validation_warning_does_not_block_saving(monkeypatch, config_folder):
    monkeypatch.delenv("MOCK_FIREWALL_KEY", raising=False)
    text = (REPO_CONFIGS / "mock-firewall.yaml").read_text(encoding="utf-8")
    problems = engine.validate_config(text)
    assert connectors.warnings_only(problems)
    assert connectors.save_and_approve(text, "test") == []


def test_internal_address_config_runs_are_blocked(run, config_folder):
    text = (
        "name: evil\nentity: alert\nsource: { base_url: 'https://meta.example.com', allow_hosts: [meta.example.com] }\n"
        "map: { id: id, timestamp: t }\n"
    )
    assert connectors.save_and_approve(text, "test") == []
    result = engine.run_connector("evil", store=db, resolver=lambda _: ["169.254.169.254"], sleeper=lambda _: None)
    assert result.status == "failed"
    assert "metadata" in result.last_error


def test_metadata_address_as_literal_ip_is_blocked(config_folder):
    text = (
        "name: metadata\nentity: alert\nsource: { base_url: 'https://169.254.169.254', allow_hosts: ['169.254.169.254'] }\n"
        "map: { id: id, timestamp: t }\n"
    )
    assert connectors.save_and_approve(text, "test") == []
    result = engine.run_connector("metadata", store=db, sleeper=lambda _: None)
    assert result.status == "failed"
    assert "metadata" in result.last_error


def test_web_app_on_the_real_engine(monkeypatch, config_folder, mock_transport):
    for key, value in MOCK_SECRETS.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(engine.memstore, "_default_store", db)
    monkeypatch.setattr(engine_client, "start_scheduler", lambda: None)
    text = (REPO_CONFIGS / "cisa-kev.yaml").read_text(encoding="utf-8")
    (config_folder / "cisa-kev.yaml").write_text(text, encoding="utf-8")

    with TestClient(create_app()) as client:
        assert db.get_connector("cisa-kev")["approved_hash"]
        page = client.get("/ui/health").text
        assert "Engine stubs active" not in page
        assert "cisa-kev" in page

        body = client.post("/onboard/sample", json={"text": '{"items": [{"id": "a", "ts": "2026-10-01"}]}'}).json()
        assert "draft_yaml" in body
        filled = client.post("/ui/add", data={"action": "sample", "sample": '{"items": [{"id": "a"}]}', "entity": "alert"})
        assert "Draft made from your sample" in filled.text

        assert client.post("/connectors/cisa-kev/pause").json()["status"] == "paused"
        assert "Resume" in client.get("/ui/health").text
        assert client.post("/faults", json={"connector": "cisa-kev", "mode": "503x3"}).status_code == 200
        assert client.post("/faults", json={"connector": "cisa-kev", "mode": "off"}).status_code == 200
