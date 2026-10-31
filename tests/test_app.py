import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from app import cli as cli_module
from app import connectors, formbuilder, health, notify
from app import engine_client as engine
from app.api import create_app
from store import db

CONFIG = """\
name: demo
entity: user
source: { type: http, base_url: https://x.example.com, allow_hosts: [x.example.com] }
auth: { type: bearer, secret: demo_token }
pagination: { type: page_number }
schedule: every 15m
map: { id: id }
notify: { slack_after_failures: 2 }
"""
REPO_CONFIGS = Path(__file__).resolve().parent.parent / "configs"
pytestmark = pytest.mark.usefixtures("isolated_app")


@pytest.fixture
def client():
    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture
def demo(client):
    assert client.post("/connectors", json={"yaml": CONFIG}).status_code == 201
    return "demo"


# Config import and approval

def test_save_writes_the_file_and_approves(isolated_app):
    assert connectors.save_and_approve(CONFIG, "t") == []
    assert (isolated_app / "demo.yaml").read_text(encoding="utf-8") == CONFIG
    connector = db.get_connector("demo")
    assert connector["approved_hash"] == connector["config_hash"]


def test_save_rejects_a_name_that_could_escape_the_folder(isolated_app):
    text = CONFIG.replace("name: demo", "name: ../../evil")
    assert connectors.save_and_approve(text, "t")[0]["path"] == "name"
    assert db.get_connector("../../evil") is None


def test_import_adds_then_flags_a_changed_file(isolated_app):
    path = isolated_app / "demo.yaml"
    path.write_text(CONFIG, encoding="utf-8")
    assert connectors.import_configs()["added"] == ["demo"]
    assert connectors.import_configs()["unchanged"] == ["demo"]

    path.write_text(CONFIG.replace("every 15m", "every 1m"), encoding="utf-8")
    assert connectors.import_configs()["changed"] == ["demo"]
    assert db.get_connector("demo")["status"] == "config_changed"
    result = engine.run_connector("demo")
    assert "changed since approval" in result.last_error
    assert db.last_run("demo") is None

    connectors.approve("demo", "t")
    assert engine.run_connector("demo").status == "success"


def test_import_skips_placeholders_and_reports_invalid(isolated_app):
    (isolated_app / "a.yaml").write_text("name: YOUR-ORG\n", encoding="utf-8")
    (isolated_app / "b.yaml").write_text("name: b\n", encoding="utf-8")
    report = connectors.import_configs()
    assert report["skipped"] == ["a.yaml"]
    assert report["invalid"][0]["file"] == "b.yaml"


@pytest.mark.parametrize("path", sorted(REPO_CONFIGS.glob("*.yaml")), ids=lambda p: p.stem)
def test_every_repo_config_is_valid_and_named_after_its_file(path):
    text = path.read_text(encoding="utf-8")
    assert engine.validate_config(text) == []
    config = yaml.safe_load(text)
    assert config["name"] == path.stem
    assert "id" in config["map"]


def test_repo_configs_hold_secret_names_only():
    for path in REPO_CONFIGS.glob("*.yaml"):
        auth = yaml.safe_load(path.read_text(encoding="utf-8")).get("auth", {})
        for key in ("secret", "username_secret", "client_id_secret", "client_secret_secret"):
            if key in auth:
                assert formbuilder.SECRET_NAME_RE.match(auth[key])


def test_core_sources_differ_in_login_and_paging():
    pairs = set()
    for name in ("okta-users", "github-members", "jira-tickets"):
        config = yaml.safe_load((REPO_CONFIGS / f"{name}.yaml").read_text(encoding="utf-8"))
        pairs.add(config["auth"]["type"])
        pairs.add(config["pagination"]["type"])
    assert len(pairs) == 6


# Health view

@pytest.mark.parametrize(
    "text, seconds",
    [("every 30s", 30), ("every 15m", 900), ("every 2h", 7200), ("every 0m", None), ("hourly", None), (None, None)],
)
def test_parse_schedule(text, seconds):
    assert health.parse_schedule(text) == seconds


def test_time_ago_wording():
    now = datetime(2026, 10, 31, 12, tzinfo=timezone.utc)
    assert health.time_ago(None, now) == "never"
    assert health.time_ago(now - timedelta(seconds=5), now) == "just now"
    assert health.time_ago(now - timedelta(minutes=2), now) == "2 min ago"
    assert health.time_ago(now - timedelta(hours=3), now) == "3 h ago"
    assert health.time_ago(now - timedelta(days=2), now) == "2 d ago"


def test_health_summary_reads_like_the_brief(demo):
    engine.run_connector(demo)
    row = health.health_rows()[0]
    assert row["summary"] == "demo: healthy, just now, 5 users"
    assert row["next_run"] == "in 14 min" or row["next_run"] == "in 15 min"


def test_never_run_connector_is_due_now(demo):
    row = health.health_rows()[0]
    assert (row["status"], row["last_run"], row["next_run"]) == ("never_run", "never", "due now")


def test_paused_connector_has_no_next_run(demo):
    engine.pause(demo)
    assert health.health_rows()[0]["next_run"] == "-"


# JSON API

def test_validate_route(client):
    assert client.post("/connectors/validate", json={"yaml": CONFIG}).json()["valid"] is True
    body = client.post("/connectors/validate", json={"yaml": "entity: user"}).json()
    assert body["valid"] is False
    assert body["problems"][0]["path"] == "name"


def test_create_rejects_bad_config(client):
    response = client.post("/connectors", json={"yaml": "entity: user"})
    assert response.status_code == 422
    assert db.list_connectors() == []


def test_run_test_and_detail_routes(client, demo):
    assert client.post(f"/connectors/{demo}/test").json()["status"] == "success"
    assert db.last_run(demo) is None
    assert client.post(f"/connectors/{demo}/run").json()["records_pulled"] == 5
    detail = client.get(f"/connectors/{demo}").json()
    assert detail["health"]["status"] == "healthy"
    assert len(detail["runs"]) == 1
    assert len(client.get("/records/user", params={"source": demo}).json()) == 5


def test_unknown_things_give_404(client):
    assert client.get("/connectors/nope").status_code == 404
    assert client.post("/connectors/nope/run").status_code == 404
    assert client.get("/records/widgets").status_code == 404
    assert client.post("/quarantine/99/replay").status_code == 404
    assert client.get("/ui/connector/nope").status_code == 404
    assert client.get("/ui/records/widgets").status_code == 404


def test_pause_resume_routes_are_audited(client, demo):
    assert client.post(f"/connectors/{demo}/pause").json()["status"] == "paused"
    assert client.post(f"/connectors/{demo}/resume").json()["status"] == "never_run"
    actions = [entry["action"] for entry in client.get("/audit").json()]
    assert "connector.pause" in actions and "connector.resume" in actions


def test_health_route_reports_stubs(client, demo):
    body = client.get("/health").json()
    assert body["connectors"][0]["name"] == demo
    assert "stubbed" in body


def test_fault_route(client, demo):
    assert client.post("/faults", json={"connector": demo, "mode": "503x4"}).status_code == 200
    assert client.post(f"/connectors/{demo}/run").json()["status"] == "failed"
    client.post("/faults", json={"connector": demo, "mode": "off"})
    assert client.post(f"/connectors/{demo}/run").json()["status"] == "success"
    assert client.post("/faults", json={"connector": demo, "mode": "explode"}).status_code == 400


def test_onboard_route(client):
    body = client.post("/onboard/sample", json={"text": '{"items": [{"id": 1}]}'}).json()
    assert engine.validate_config(body["draft_yaml"]) == []


def test_quarantine_replay_route(client, demo):
    client.post("/faults", json={"connector": demo, "mode": "badrecord"})
    client.post(f"/connectors/{demo}/run")
    item = client.get("/quarantine", params={"connector": demo}).json()[0]
    outcome = client.post(f"/quarantine/{item['id']}/replay").json()
    assert outcome["ok"] is False
    assert db.get_quarantine(item["id"])["replayed"] == 0

    good = db.add_quarantine(demo, None, {"id": "fixed-1"}, "was bad")
    assert client.post(f"/quarantine/{good}/replay").json()["ok"] is True
    assert db.get_quarantine(good)["replayed"] == 1
    assert any(r["id"] == "fixed-1" for r in db.query_records("user", source=demo))


def test_cross_site_posts_are_refused(client, demo):
    evil = {"Origin": "https://evil.example.com"}
    assert client.post(f"/connectors/{demo}/pause", headers=evil).status_code == 403
    assert client.post(f"/connectors/{demo}/pause", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert db.get_connector(demo)["status"] != "paused"
    same = {"Origin": "http://testserver"}
    assert client.post(f"/connectors/{demo}/pause", headers=same).status_code == 200


def test_server_errors_are_masked(monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("failed with Authorization: Bearer abc123secret")

    with TestClient(create_app(), raise_server_exceptions=False) as client:
        client.post("/connectors", json={"yaml": CONFIG})
        monkeypatch.setattr(engine, "run_connector", boom)
        response = client.post("/connectors/demo/run")
    assert response.status_code == 500
    assert "abc123secret" not in response.text


# Web pages

@pytest.mark.parametrize(
    "path",
    ["/", "/ui/add", "/ui/records/users", "/ui/records/devices", "/ui/records/alerts", "/ui/people", "/ui/kev", "/ui/demo", "/ui/audit"],
)
def test_pages_load_empty(client, path):
    response = client.get(path)
    assert response.status_code == 200
    assert "<script" not in response.text


def test_health_page_shows_row_and_stub_banner(client, demo):
    client.post(f"/connectors/{demo}/run")
    page = client.get("/").text
    assert "demo" in page and "healthy" in page
    assert 'http-equiv="refresh" content="10"' in page
    if engine.stubbed_functions():
        assert "Engine stubs active" in page


def test_web_actions_redirect_and_work(client, demo):
    response = client.post(f"/ui/connector/{demo}/run", follow_redirects=False)
    assert response.status_code == 303
    assert db.last_run(demo)["status"] == "success"
    client.post(f"/ui/connector/{demo}/pause")
    assert db.get_connector(demo)["enabled"] == 0
    assert "Resume" in client.get("/").text
    client.post(f"/ui/connector/{demo}/resume")
    assert db.get_connector(demo)["enabled"] == 1
    assert client.post(f"/ui/connector/{demo}/nope").status_code == 404


def test_connector_page_test_shows_raw_and_mapped(client, demo):
    page = client.post(f"/ui/connector/{demo}/test").text
    assert "Raw and mapped" in page
    assert "stub_only_field" in page
    assert "demo_token" in page


def test_connector_page_flags_changed_config_and_approves(client, demo):
    db.save_connector(demo, "user", CONFIG + "# edited\n", "other-hash")
    assert "changed since it was approved" in client.get(f"/ui/connector/{demo}").text
    client.post(f"/ui/connector/{demo}/approve")
    assert "changed since it was approved" not in client.get(f"/ui/connector/{demo}").text


def test_pages_escape_record_values(client, demo):
    db.upsert("user", demo, [{"id": "1", "name": "<script>alert(1)</script>"}])
    db.add_quarantine(demo, None, {"x": "<script>alert(2)</script>"}, "<script>alert(3)</script>")
    for path in ("/ui/records/users", f"/ui/connector/{demo}"):
        assert "<script>" not in client.get(path).text


def test_flash_message_is_escaped(client):
    assert "<script>" not in client.get("/", params={"msg": "<script>x</script>"}).text


FORM = {
    "name": "kev-live",
    "entity": "alert",
    "base_url": "https://www.example.com",
    "auth_type": "none",
    "method": "GET",
    "path": "/feed.json",
    "params": "",
    "format": "json",
    "records_path": "vulnerabilities",
    "paging_type": "none",
    "schedule": "every 1h",
    "map": "id: cveID\ntimestamp: { path: dateAdded, transform: to_utc }\n",
    "auth_send_as": "body",
    "paging_token_in": "query",
    "yaml": "",
    "sample": "",
}


def test_form_builds_valid_yaml():
    text, problems = formbuilder.form_to_yaml(FORM)
    assert problems == []
    assert engine.validate_config(text) == []
    config = yaml.safe_load(text)
    assert config["source"]["allow_hosts"] == ["www.example.com"]
    assert config["auth"] == {"type": "none"}
    assert config["request"]["records_path"] == "vulnerabilities"


def test_form_keeps_only_fields_of_the_chosen_types():
    form = {
        **FORM,
        "auth_type": "api_key",
        "auth_header": "Authorization",
        "auth_prefix": "SSWS ",
        "auth_secret": "okta_key",
        "auth_token_url": "https://ignored.example.com",
        "paging_type": "offset",
        "paging_offset_param": "startIndex",
        "paging_limit_param": "resultsPerPage",
        "paging_limit": "100",
        "paging_token_path": "ignored",
    }
    config = yaml.safe_load(formbuilder.form_to_yaml(form)[0])
    assert config["auth"] == {"type": "api_key", "header": "Authorization", "prefix": "SSWS ", "secret": "okta_key"}
    assert config["pagination"] == {
        "type": "offset",
        "offset_param": "startIndex",
        "limit_param": "resultsPerPage",
        "limit": 100,
    }


@pytest.mark.parametrize(
    "change, path",
    [
        ({"name": "Bad Name"}, "name"),
        ({"base_url": "ftp://x"}, "source.base_url"),
        ({"schedule": "often"}, "schedule"),
        ({"map": ""}, "map"),
        ({"map": ": : :"}, "map"),
        ({"params": "[1, 2]"}, "request.params"),
        ({"auth_type": "bearer", "auth_secret": "ghp_RealLookingToken123"}, "auth.secret"),
    ],
)
def test_form_reports_problems(change, path):
    _, problems = formbuilder.form_to_yaml({**FORM, **change})
    assert path in [p["path"] for p in problems]


def test_yaml_round_trips_through_the_form():
    form = formbuilder.yaml_to_form((REPO_CONFIGS / "mock-edr-hosts.yaml").read_text(encoding="utf-8"))
    config = yaml.safe_load(formbuilder.form_to_yaml(form)[0])
    assert config["auth"]["type"] == "oauth2_client_credentials"
    assert config["auth"]["client_id_secret"] == "mock_edr_client_id"
    assert config["pagination"]["token_path"] == "meta.pagination.next"
    assert config["map"]["hostname"] == "hostname"


FULL_CONFIG = """\
name: kept
entity: alert
mock: false
description: keep me
source:
  type: http
  base_url: https://api.example.com
  allow_hosts: [api.example.com, auth.example.com]
  allow_private_network: true
auth:
  type: basic
  username: plain-user
  username_secret: site_email
  secret: site_token
auth_failure: { header: X-Seraph-LoginReason, contains: AUTHENTICATED_FAILED }
request:
  method: POST
  read_only_post: true
  path: /search
  headers: { Accept: application/json }
  body: { size: 50 }
  format: json
  records_path: issues
pagination:
  type: body_token
  token_path: next
  token_param: next
  token_in: body
  stop_path: isLast
schedule: every 1h
retry: { delays_s: [1, 2] }
rate_limit: { max_rps: 1 }
incremental: { field: updated, param: since, template: "{checkpoint}" }
limits: { max_pages: 5 }
required: [id]
notify: { slack_after_failures: 2 }
brand_new_key: { nested: true }
map:
  id: key
  timestamp: { path: created, transform: to_utc }
"""


def rebuild(text, **changes):
    form = {**formbuilder.yaml_to_form(text), **changes}
    built, problems = formbuilder.form_to_yaml(form)
    assert problems == []
    return yaml.safe_load(built)


def test_build_keeps_auth_failure():
    assert rebuild(FULL_CONFIG)["auth_failure"] == {"header": "X-Seraph-LoginReason", "contains": "AUTHENTICATED_FAILED"}


def test_build_keeps_every_key_the_form_does_not_know():
    original = yaml.safe_load(FULL_CONFIG)
    assert rebuild(FULL_CONFIG) == original


def test_build_applies_form_edits_on_top_of_kept_keys():
    config = rebuild(FULL_CONFIG, schedule="every 5m", path="/other", auth_secret="new_token")
    assert config["schedule"] == "every 5m"
    assert config["request"]["path"] == "/other"
    assert config["request"]["read_only_post"] is True
    assert config["auth"]["secret"] == "new_token"
    assert config["auth"]["username"] == "plain-user"
    assert config["retry"] == {"delays_s": [1, 2]}


def test_clearing_a_form_field_removes_that_key():
    assert "params" not in rebuild(FULL_CONFIG.replace("  path: /search", "  path: /search\n  params: { a: 1 }"), params="")["request"]
    assert "prefix" not in rebuild(FULL_CONFIG.replace("type: basic", "type: api_key\n  header: H\n  prefix: 'x '"), auth_type="api_key", auth_prefix="")["auth"]


def test_changing_login_or_paging_type_drops_the_old_keys():
    config = rebuild(FULL_CONFIG, auth_type="bearer", auth_secret="tok", paging_type="link_header")
    assert config["auth"] == {"type": "bearer", "secret": "tok"}
    assert config["pagination"] == {"type": "link_header"}
    assert config["auth_failure"]["contains"] == "AUTHENTICATED_FAILED"


def test_allowlist_is_kept_for_the_same_host_and_reset_for_a_new_one():
    assert rebuild(FULL_CONFIG)["source"]["allow_hosts"] == ["api.example.com", "auth.example.com"]
    moved = rebuild(FULL_CONFIG, base_url="https://new.example.com")
    assert moved["source"]["allow_hosts"] == ["new.example.com"]
    assert moved["source"]["allow_private_network"] is True


def test_build_keeps_a_file_source():
    text = (REPO_CONFIGS / "devices-file.yaml").read_text(encoding="utf-8")
    config = rebuild(text)
    assert config["source"] == {"type": "file", "path": "data/devices.csv"}
    assert "path" not in config["request"]


@pytest.mark.parametrize("path", sorted(REPO_CONFIGS.glob("*.yaml")), ids=lambda p: p.stem)
def test_every_repo_config_survives_form_and_back(path):
    text = path.read_text(encoding="utf-8")
    config = yaml.safe_load(text)
    assert rebuild(text) == {**config, "mock": bool(config.get("mock"))} | {"request": {**config["request"], **_request_defaults(config)}}


def _request_defaults(config):
    request = config["request"]
    defaults = {"method": "GET", "records_path": ""}
    return {key: request.get(key, value) for key, value in defaults.items()}


def test_unreadable_yaml_box_is_reported_and_build_still_works():
    built, problems = formbuilder.form_to_yaml({**FORM, "yaml": "[unclosed"})
    assert [p["path"] for p in problems] == ["yaml"]
    assert yaml.safe_load(built)["name"] == "kev-live"


def test_add_page_build_keeps_auth_failure(client):
    form = {**formbuilder.yaml_to_form(FULL_CONFIG), "action": "build", "sample": ""}
    page = client.post("/ui/add", data=form).text
    assert "AUTHENTICATED_FAILED" in page and "brand_new_key" in page


def test_add_page_has_every_field_and_action(client):
    page = client.get("/ui/add").text
    for name in (
        "name", "entity", "mock", "base_url", "schedule", "auth_type", "auth_secret", "auth_header",
        "auth_query_param", "auth_prefix", "auth_username_secret", "auth_token_url", "auth_client_id_secret",
        "auth_client_secret_secret", "auth_scope", "auth_send_as", "path", "format", "records_path", "method",
        "params", "paging_type", "paging_page_param", "paging_size_param", "paging_size", "paging_start",
        "paging_offset_param", "paging_limit_param", "paging_limit", "paging_total_path", "paging_token_path",
        "paging_token_param", "paging_token_in", "paging_next_url_path", "map", "yaml", "sample",
    ):
        assert f'name="{name}"' in page, name
    for action in ("sample", "build", "validate", "test", "save"):
        assert f'value="{action}"' in page, action


def test_add_page_inputs_have_labels(client):
    page = client.get("/ui/add").text
    ids = re.findall(r'<(?:input|select|textarea) id="([^"]+)"', page)
    assert ids
    for field_id in ids:
        assert f'<label for="{field_id}"' in page or f'for="{field_id}"' in page, field_id


def test_add_page_secret_field_appears_once(client):
    assert client.get("/ui/add").text.count('name="auth_secret"') == 1


def test_add_page_shows_field_suggestions(client):
    page = client.post("/ui/add", data={"action": "sample", "sample": '{"items": [{"id": 1}]}', "entity": "alert"}).text
    assert "Field suggestions" in page
    assert "not found · pick one" in page


def test_suggestions_handle_every_guess_shape():
    rows = formbuilder.suggestions(
        {"guesses": {"id": {"spec": "cveID"}, "timestamp": {"spec": {"path": "added", "transform": "to_utc"}}, "type": "kind"}},
        "alert",
    )
    by_field = {row["field"]: row["code"] for row in rows}
    assert by_field["id"] == "cveID"
    assert "to_utc" in by_field["timestamp"]
    assert by_field["type"] == "kind"
    assert by_field["severity"] is None


def test_yaml_to_form_survives_bad_yaml():
    assert formbuilder.yaml_to_form("[unclosed")["name"] == ""


def test_add_page_full_flow(client, isolated_app):
    built = client.post("/ui/add", data={**FORM, "action": "build"}).text
    assert "kev-live" in built and "allow_hosts" in built

    text = formbuilder.form_to_yaml(FORM)[0]
    assert "The config is valid" in client.post("/ui/add", data={**FORM, "yaml": text, "action": "validate"}).text
    assert "Test result" in client.post("/ui/add", data={**FORM, "yaml": text, "action": "test"}).text
    assert db.get_connector("kev-live") is None

    saved = client.post("/ui/add", data={**FORM, "yaml": text, "action": "save"}, follow_redirects=False)
    assert saved.status_code == 303
    assert (isolated_app / "kev-live.yaml").exists()
    assert db.get_connector("kev-live")["approved_hash"]


def test_add_page_sample_fills_the_form(client):
    page = client.post(
        "/ui/add", data={**FORM, "name": "", "action": "sample", "sample": '{"items": [{"id": 1}]}'}
    ).text
    assert "Draft made from your sample" in page
    assert "new-source" in page


def test_add_page_shows_errors(client):
    assert "paste a sample first" in client.post("/ui/add", data={**FORM, "action": "sample"}).text
    assert "Fix these first" in client.post("/ui/add", data={**FORM, "yaml": "entity: user", "action": "save"}).text
    assert db.list_connectors() == []


def test_records_page_filters(client):
    db.upsert("alert", "a", [{"id": "1", "description": "needle"}])
    db.upsert("alert", "b", [{"id": "2", "description": "other"}])
    page = client.get("/ui/records/alerts", params={"source": "a"}).text
    assert "needle" in page and "other" not in page
    assert "needle" not in client.get("/ui/records/alerts", params={"q": "other"}).text


def test_people_view_joins_sources():
    db.upsert("user", "okta", [{"id": "1", "email": "Ann@Example.com", "name": "Ann"}])
    db.upsert("user", "jira", [{"id": "9", "email": "ann@example.com"}])
    db.upsert("device", "edr", [{"id": "d1", "owner": "ann@example.com"}])
    db.upsert("alert", "signins", [{"id": "a1", "description": "Login : ann@example.com"}])
    db.upsert("user", "okta", [{"id": "2", "email": "bob@example.com"}])
    assert db.list_emails() == ["ann@example.com", "bob@example.com"]
    records = db.person_records("ANN@example.com")
    assert {r["source"] for r in records["users"]} == {"okta", "jira"}
    assert len(records["devices"]) == len(records["alerts"]) == 1


def test_people_page(client):
    db.upsert("user", "okta", [{"id": "1", "email": "ann@example.com", "name": "Ann Rao"}])
    assert "Ann Rao" in client.get("/ui/people", params={"email": "ann@example.com"}).text


def test_kev_match():
    db.upsert("alert", "cisa-kev", [{"id": "CVE-1", "cve": "CVE-1"}])
    db.upsert("alert", "edr", [{"id": "a", "cve": "CVE-1"}, {"id": "b", "cve": "CVE-2"}, {"id": "c"}])
    assert [row["id"] for row in db.kev_matches("cisa-kev")] == ["a"]


def test_kev_page(client):
    assert "has no rows yet" in client.get("/ui/kev").text
    db.upsert("alert", "cisa-kev", [{"id": "CVE-1", "cve": "CVE-1"}])
    db.upsert("alert", "edr", [{"id": "match-row", "cve": "CVE-1"}])
    assert "match-row" in client.get("/ui/kev").text


def test_demo_page_sets_and_clears_fault(client, demo):
    client.post("/ui/demo", data={"connector": demo, "mode": "timeoutx4"})
    assert client.post(f"/connectors/{demo}/run").json()["status"] == "failed"
    client.post("/ui/demo", data={"connector": demo, "mode": "off"})
    assert client.post(f"/connectors/{demo}/run").json()["status"] == "success"
    assert client.post("/ui/demo", data={"connector": demo, "mode": "bad"}).status_code == 400


# Slack alerts

@pytest.fixture
def slack(monkeypatch):
    sent = []

    def fake_post(url, json, timeout):
        sent.append(json["text"])
        return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setenv("SLACK_WEBHOOK", "https://hooks.example.com/services/x")
    monkeypatch.setattr(notify.httpx, "post", fake_post)
    return sent


def fail_runs(name, count):
    engine.set_fault(name, "timeout")
    for _ in range(count):
        engine.run_connector(name)
        notify.sweep()
    engine.clear_fault(name)


def test_alert_fires_once_at_threshold(demo, slack):
    fail_runs(demo, 1)
    assert slack == []
    fail_runs(demo, 3)
    assert len(slack) == 1
    assert "2 failed runs in a row" in slack[0]
    assert "request timed out" in slack[0]


def test_alert_again_on_recovery_then_can_fire_again(demo, slack):
    fail_runs(demo, 2)
    engine.run_connector(demo)
    notify.sweep()
    notify.sweep()
    assert len(slack) == 2
    assert "recovered" in slack[1]
    fail_runs(demo, 2)
    assert len(slack) == 3


def test_no_recovery_message_without_a_failure_alert(demo, slack):
    engine.run_connector(demo)
    notify.sweep()
    assert slack == []


def test_no_alert_without_a_threshold(client, slack):
    client.post("/connectors", json={"yaml": CONFIG.replace("notify: { slack_after_failures: 2 }\n", "")})
    fail_runs("demo", 4)
    assert slack == []


def test_failed_post_is_retried_and_does_not_leak_the_webhook(demo, monkeypatch, caplog):
    secret_url = "https://hooks.example.com/services/very-secret"
    monkeypatch.setenv("SLACK_WEBHOOK", secret_url)

    def broken(url, json, timeout):
        raise httpx.ConnectError(f"cannot reach {url}")

    monkeypatch.setattr(notify.httpx, "post", broken)
    fail_runs(demo, 2)
    assert db.last_alert_sent(demo) is None
    assert "very-secret" not in caplog.text


def test_no_webhook_means_no_record(demo):
    fail_runs(demo, 2)
    assert db.last_alert_sent(demo) is None


# CLI

runner = CliRunner()


def invoke(*args):
    return runner.invoke(cli_module.cli, list(args))


def test_cli_validate(tmp_path):
    good = tmp_path / "good.yaml"
    good.write_text(CONFIG, encoding="utf-8")
    bad = tmp_path / "bad.yaml"
    bad.write_text("entity: user", encoding="utf-8")
    assert invoke("validate", str(good)).exit_code == 0
    result = invoke("validate", str(bad))
    assert result.exit_code == 1
    assert "name: required field is missing" in result.output


def test_cli_import_run_health_flow(isolated_app):
    (isolated_app / "demo.yaml").write_text(CONFIG, encoding="utf-8")
    assert "added: demo" in invoke("import-configs").output
    assert "status=success" in invoke("test", "demo").output
    assert db.last_run("demo") is None
    assert "pulled=5" in invoke("run", "demo").output
    assert "demo: healthy, just now, 5 users" in invoke("health").output
    assert "paused" in invoke("pause", "demo").output
    assert db.get_connector("demo")["enabled"] == 0
    assert "resumed" in invoke("resume", "demo").output


def test_cli_failed_run_exits_nonzero(isolated_app):
    connectors.save_and_approve(CONFIG, "t")
    engine.set_fault("demo", "503x4")
    result = invoke("run", "demo")
    assert result.exit_code == 1
    assert "HTTP 503" in result.output


def test_cli_unknown_connector(isolated_app):
    assert invoke("run", "missing").exit_code == 2


def test_cli_quarantine(isolated_app):
    connectors.save_and_approve(CONFIG, "t")
    assert "Nothing quarantined" in invoke("quarantine", "list").output
    bad = db.add_quarantine("demo", None, {"x": 1}, "missing required field: id")
    good = db.add_quarantine("demo", None, {"id": "ok"}, "was bad")
    assert "missing required field" in invoke("quarantine", "list").output
    assert invoke("quarantine", "replay", str(bad)).exit_code == 1
    assert invoke("quarantine", "replay", str(good)).exit_code == 0
    assert db.get_quarantine(good)["replayed"] == 1
    assert invoke("quarantine", "replay", "999").exit_code == 2


def test_cli_onboard(tmp_path):
    sample = tmp_path / "s.json"
    sample.write_text('{"items": [{"id": 1}]}', encoding="utf-8")
    assert "new-source" in invoke("onboard", str(sample)).output


def test_cli_approve_after_file_change(isolated_app):
    path = isolated_app / "demo.yaml"
    path.write_text(CONFIG, encoding="utf-8")
    invoke("import-configs")
    path.write_text(CONFIG + "# edited\n", encoding="utf-8")
    assert "will not run until approved" in invoke("import-configs").output
    invoke("approve", "demo")
    connector = db.get_connector("demo")
    assert connector["approved_hash"] == connector["config_hash"]
