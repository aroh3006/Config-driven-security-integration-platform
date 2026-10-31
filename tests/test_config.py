from engine import load_config, validate_config
from engine.config import schedule_seconds

OKTA = """
name: okta-users
entity: user
source: {base_url: https://dev-1.okta.com, allow_hosts: [dev-1.okta.com]}
auth: {type: api_key, header: Authorization, prefix: "SSWS ", secret: okta_key}
request: {method: GET, path: /api/v1/users, params: {limit: 200}}
pagination: {type: link_header}
schedule: every 15m
map:
  id: id
  name: { join: [profile.firstName, profile.lastName], sep: " " }
  email: profile.login
  status: { path: status, transform: lower }
  last_login: { path: lastLogin, transform: to_utc }
"""


def errors(text):
    return [e for e in validate_config(text) if e["level"] == "error"]


def test_prd_example_config_is_valid():
    assert errors(OKTA) == []
    cfg = load_config(OKTA)
    assert cfg.interval_s == 900 and cfg.auth.prefix == "SSWS "


def test_prd_fr1_example_shape():
    text = OKTA.replace('{type: api_key, header: Authorization, prefix: "SSWS ", secret: okta_key}',
                        "{ type: api_key, header: X-API-Key, secret: okta_key }")
    assert errors(text) == []


def test_typo_key_gets_did_you_mean():
    e = errors(OKTA.replace("header: Authorization", "heder: Authorization"))
    assert e[0]["path"] == "auth.heder" and "header" in e[0]["hint"]


def test_unknown_type_gets_suggestion():
    e = errors(OKTA.replace("type: link_header", "type: link_headr"))
    assert e[0]["path"] == "pagination" and "link_header" in e[0]["hint"]


def test_unknown_target_field():
    e = errors(OKTA.replace("email: profile.login", "emial: profile.login"))
    assert any(x["path"] == "map.emial" and "email" in x["hint"] for x in e)


def test_bad_transform_named():
    e = errors(OKTA.replace("transform: lower", "transform: lowr"))
    assert any("lower" in x["message"] for x in e)


def test_host_must_be_allowed():
    e = errors(OKTA.replace("allow_hosts: [dev-1.okta.com]", "allow_hosts: [evil.example.com]"))
    assert e[0]["path"] == "source.allow_hosts"


def test_post_needs_read_only_flag():
    e = errors(OKTA.replace("method: GET", "method: POST"))
    assert any("read_only_post" in x["message"] for x in e)


def test_delete_method_rejected():
    assert errors(OKTA.replace("method: GET", "method: DELETE"))


def test_missing_secret_is_a_warning_not_an_error(monkeypatch):
    monkeypatch.delenv("OKTA_KEY")
    problems = validate_config(OKTA)
    assert [p for p in problems if p["level"] == "warning" and "OKTA_KEY" in p["hint"]]
    assert errors(OKTA) == []


def test_yaml_syntax_error_reports_line():
    e = errors("name: x\n  bad: [unclosed\n")
    assert "line" in e[0]["message"]


def test_required_field_needs_mapping():
    e = errors(OKTA.replace("  id: id\n", ""))
    assert any(x["path"] == "map.id" for x in e)


def test_prd_last_seen_alias_for_users():
    assert errors(OKTA.replace("last_login: {", "last_seen: {")) == []
    cfg = load_config(OKTA.replace("last_login: {", "last_seen: {"))
    assert "last_login" in cfg.field_specs()


def test_schedule_parsing():
    assert schedule_seconds("every 15m") == 900
    assert schedule_seconds("every 1h") == 3600
    assert schedule_seconds("30s") == 30
    assert errors(OKTA.replace("every 15m", "sometimes"))
