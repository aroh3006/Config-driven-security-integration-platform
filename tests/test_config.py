import json

import pytest

from engine import load_config, run_connector, save_and_approve, validate_config
from engine.config import schedule_seconds
from engine.errors import ConfigError

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


# Configs hold names only

PASTED_TOKENS = [
    "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789",
    "ghp_SECRETtoken0123456789",
    "Bearer abc123",
    "AKIAIOSFODNN7EXAMPLE",
    "7d9f3c2a-1b4e-4f6a-8c3d-2e5f7a9b0c1d",
    "a7d93c2a1b4e4f6a8c3d2e5f7a9b0c1d",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "eyJhbGciOiJIUzI1NiJ9.e30.c2lnbmF0dXJl",
    "abc+/def==",
    "fw-SECRET-key-42",
    "Password1",
]
TOKEN = PASTED_TOKENS[0]
OKTA_AUTH = '{type: api_key, header: Authorization, prefix: "SSWS ", secret: okta_key}'
OAUTH = "{{type: oauth2_client_credentials, token_url: {url}, client_id_secret: {client_id}, client_secret_secret: {secret}}}"
LOGIN = "{{type: session_login, login_url: {url}, username_secret: {user}, password_secret: {password}}}"
LOGIN_URL = "https://dev-1.okta.com/login"


def with_auth(block):
    return OKTA.replace(OKTA_AUTH, block)


def with_request(line):
    return OKTA.replace("params: {limit: 200}", line)


def assert_not_echoed(value, problems):
    """Upper-case forms count too: the missing-secret hint turns a name into an env var."""
    assert value.lower() not in json.dumps(problems).lower()


@pytest.mark.parametrize("value", PASTED_TOKENS)
def test_token_pasted_into_a_secret_field_is_an_error(value):
    text = OKTA.replace("secret: okta_key", f"secret: '{value}'")
    assert [e["path"] for e in errors(text)] == ["auth.secret"]
    assert_not_echoed(value, validate_config(text))


@pytest.mark.parametrize(
    "path, text",
    [
        ("auth.secret", with_auth(f"{{type: bearer, secret: {TOKEN}}}")),
        ("auth.username_secret", with_auth(f"{{type: basic, username_secret: {TOKEN}, secret: jira_token}}")),
        ("auth.secret", with_auth(f"{{type: basic, username_secret: jira_email, secret: {TOKEN}}}")),
        ("auth.client_id_secret", with_auth(OAUTH.format(url=LOGIN_URL, client_id=TOKEN, secret="edr_client_secret"))),
        ("auth.client_secret_secret", with_auth(OAUTH.format(url=LOGIN_URL, client_id="edr_client_id", secret=TOKEN))),
        ("auth.username_secret", with_auth(LOGIN.format(url=LOGIN_URL, user=TOKEN, password="jira_token"))),
        ("auth.password_secret", with_auth(LOGIN.format(url=LOGIN_URL, user="jira_email", password=TOKEN))),
        ("request.secret_headers.X-Extra", with_request(f"secret_headers: {{X-Extra: {TOKEN}}}")),
    ],
)
def test_every_secret_field_refuses_a_pasted_token(path, text):
    assert [e["path"] for e in errors(text)] == [path]
    assert_not_echoed(TOKEN, validate_config(text))


def test_secret_reference_refuses_a_pasted_token():
    token = "a7d93c2a1b4e4f6a8c3d2e5f7a9b0c1d"
    text = with_auth(f"{{type: session_login, login_url: {LOGIN_URL}, body: {{key: '{{secret:{token}}}'}}}}")
    assert [e["path"] for e in errors(text)] == ["auth"]
    assert_not_echoed(token, validate_config(text))


def test_secret_field_hint_points_to_auth_or_secret_headers():
    hint = errors(OKTA.replace("secret: okta_key", f"secret: {TOKEN}"))[0]["hint"]
    assert "auth" in hint and "secret_headers" in hint


@pytest.mark.parametrize(
    "name",
    ["okta_key", "jira-token", "OKTA_KEY", "oauth2_secret", "k8s_token", "m365_client_secret", "mock_cortex_key_id", "tenant_12345_key"],
)
def test_real_secret_names_stay_valid(name):
    assert errors(OKTA.replace("secret: okta_key", f"secret: {name}")) == []


def test_pasted_token_never_reaches_an_error_message_or_the_store(store):
    text = OKTA.replace("secret: okta_key", f"secret: {TOKEN}")
    with pytest.raises(ConfigError) as refused:
        load_config(text)
    assert TOKEN not in str(refused.value)
    assert TOKEN not in run_connector(text, dry_run=True).last_error

    saved = save_and_approve(text, store=store)
    assert not saved["ok"] and store.get_connector("okta-users") is None
    assert_not_echoed(TOKEN, saved)


def test_token_in_a_config_saved_before_this_check_stays_out_of_last_error(store):
    text = OKTA.replace("secret: okta_key", f"secret: {TOKEN}")
    store.save_connector("okta-users", "user", text, "old-hash")
    r = run_connector("okta-users", store=store)
    assert r.status == "failed" and TOKEN not in r.last_error
    assert TOKEN not in json.dumps(r.to_dict())


@pytest.mark.parametrize(
    "path, text",
    [
        ("source.base_url", OKTA.replace("{base_url: https://dev-1.okta.com,", "{base_url: 'https://admin:hunter2@dev-1.okta.com',")),
        ("source.base_url", OKTA.replace("{base_url: https://dev-1.okta.com,", "{base_url: 'https://hunter2@dev-1.okta.com',")),
        ("request.path", OKTA.replace("path: /api/v1/users", "path: 'https://admin:hunter2@dev-1.okta.com/api/v1/users'")),
        ("auth.token_url", with_auth(OAUTH.format(url="'https://admin:hunter2@dev-1.okta.com/t'", client_id="edr_client_id", secret="edr_client_secret"))),
        ("auth.login_url", with_auth(LOGIN.format(url="'https://admin:hunter2@dev-1.okta.com/l'", user="jira_email", password="jira_token"))),
    ],
)
def test_credentials_inside_a_url_are_an_error(path, text):
    found = errors(text)
    assert [e["path"] for e in found] == [path] and "auth" in found[0]["hint"]
    assert_not_echoed("hunter2", validate_config(text))


@pytest.mark.parametrize(
    "path, text",
    [
        ("request.path", OKTA.replace("path: /api/v1/users", "path: '/api/v1/users?limit=5&api_key=hunter2'")),
        ("source.base_url", OKTA.replace("{base_url: https://dev-1.okta.com,", "{base_url: 'https://dev-1.okta.com?token=hunter2',")),
    ],
)
def test_credential_in_a_url_query_is_an_error(path, text):
    found = errors(text)
    assert [e["path"] for e in found] == [path] and "auth" in found[0]["hint"]
    assert_not_echoed("hunter2", validate_config(text))


@pytest.mark.parametrize(
    "path",
    ["/api/v1/users/admin@example.com", "/api/v1/users?q=admin@example.com", "https://dev-1.okta.com/users/a:b@example.com"],
)
def test_at_sign_outside_the_host_part_of_a_url_is_fine(path):
    assert errors(OKTA.replace("path: /api/v1/users", f"path: '{path}'")) == []


@pytest.mark.parametrize("header", ["Authorization", "X-API-Key", "Cookie", "X-Auth-Token", "X-Session-Id"])
def test_literal_value_under_a_sensitive_header_is_an_error(header):
    text = with_request(f"headers: {{{header}: 'pasted-value-123'}}")
    found = errors(text)
    assert [e["path"] for e in found] == [f"request.headers.{header}"]
    assert "secret_headers" in found[0]["hint"] and "auth" in found[0]["hint"]
    assert_not_echoed("pasted-value-123", validate_config(text))


@pytest.mark.parametrize("value", ["pasted-value-123", 987654321987])
@pytest.mark.parametrize("param", ["api_key", "apiKey", "token", "password", "sessionId", "client_secret"])
def test_literal_value_under_a_sensitive_param_is_an_error(param, value):
    text = with_request(f"params: {{limit: 200, {param}: {value}}}")
    found = errors(text)
    assert [e["path"] for e in found] == [f"request.params.{param}"]
    assert "auth" in found[0]["hint"]
    assert_not_echoed(str(value), validate_config(text))


@pytest.mark.parametrize(
    "line",
    [
        "headers: {Accept: application/vnd.github+json}",
        "headers: {X-GitHub-Api-Version: '2026-03-10'}",
        "headers: {X-Amz-Target: CloudTrail_20131101.LookupEvents}",
        "secret_headers: {X-Api-Key: okta_key}",
        "params: {filter: 'eventType eq \"user.session.start\"'}",
        "params: {secret_type: some_kind_of_token}",
        "params: {token_type: bearer}",
        "params: {session_timeout: 30}",
        "params: {pageToken: ''}",
        "params: {token: null}",
        "params: {include_tokens: true}",
        "params: {session_since: '{{now-1h}}'}",
        "params: {syncToken: '{{checkpoint}}'}",
    ],
)
def test_values_that_are_not_credentials_stay_valid(line):
    assert errors(with_request(line)) == []
