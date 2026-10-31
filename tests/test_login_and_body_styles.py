"""Session login, nested body paging, GraphQL errors, secret headers, custom CA files."""

import base64
import json
import shutil
from urllib.parse import quote

import certifi
import httpx
import pytest

from engine import run_connector, save_and_approve, validate_config
from engine.auth import fill_secrets
from engine.config import load_config
from engine.parse import set_path

ROWS = [{"id": str(i), "ts": f"2026-10-31T00:{i:02d}:00Z"} for i in range(5)]
BASE = """
name: src
entity: alert
source: {base_url: https://api.example.com, allow_hosts: [api.example.com]}
AUTH
REQUEST
PAGING
map: {id: id, timestamp: {path: ts, transform: to_utc}}
"""
JSON_LOGIN = """auth:
  type: session_login
  login_url: https://api.example.com/login
  body: {username: "{secret:api_user}", password: "{secret:api_pass}"}
  token_path: token
  send_header: x-session-auth
"""
LIST_REQUEST = "request: {path: /items, records_path: items}"


def config(auth="", request=LIST_REQUEST, paging=""):
    return BASE.replace("AUTH", auth).replace("REQUEST", request).replace("PAGING", paging)


@pytest.fixture(autouse=True)
def _secrets(monkeypatch):
    monkeypatch.setenv("API_USER", "svc-user")
    monkeypatch.setenv("API_PASS", "login-SECRET-value")
    monkeypatch.setenv("EXTRA_KEY", "extra-SECRET-value")


def body_login_handler(seen):
    def handler(req):
        if req.url.path == "/login":
            seen.append(json.loads(req.content))
            return httpx.Response(200, json={"token": f"session-token-{len(seen)}"})
        if req.headers.get("x-session-auth") != f"session-token-{len(seen)}":
            return httpx.Response(401)
        return httpx.Response(200, json={"items": ROWS})

    return handler


def test_login_with_a_json_body_and_a_custom_token_header(runner):
    seen = []
    r = runner(config(JSON_LOGIN), body_login_handler(seen))
    assert r.status == "success" and r.records_pulled == 5
    assert seen == [{"username": "svc-user", "password": "login-SECRET-value"}]


def test_session_token_is_reused_by_the_next_run(runner, store):
    seen = []
    handler = body_login_handler(seen)
    runner(config(JSON_LOGIN), handler)
    second = run_connector("src", store=store, transport=httpx.MockTransport(handler), resolver=lambda _: ["93.184.216.34"])
    assert second.status == "success" and len(seen) == 1


def test_expired_session_logs_in_again_once(runner):
    logins, calls = [], []

    def handler(req):
        if req.url.path == "/login":
            logins.append(1)
            return httpx.Response(200, json={"token": f"token-{len(logins)}"})
        calls.append(1)
        return httpx.Response(401) if len(calls) == 1 else httpx.Response(200, json={"items": ROWS})

    r = runner(config(JSON_LOGIN), handler)
    assert r.status == "success" and len(logins) == 2


def test_session_token_rejected_twice_is_auth_failed(runner):
    def handler(req):
        return httpx.Response(200, json={"token": "t"}) if req.url.path == "/login" else httpx.Response(401)

    assert runner(config(JSON_LOGIN), handler).status == "auth_failed"


def test_rejected_login_is_auth_failed_with_no_secret_in_the_error(runner):
    r = runner(config(JSON_LOGIN), lambda req: httpx.Response(401, json={"message": "bad login"}))
    assert r.status == "auth_failed" and "login rejected" in r.last_error
    assert "login-SECRET-value" not in r.last_error


def test_login_response_without_the_token_is_a_clear_error(runner):
    r = runner(config(JSON_LOGIN), lambda req: httpx.Response(200, json={"nope": 1}))
    assert r.status == "auth_failed" and "no token at 'token'" in r.last_error


def test_login_with_basic_and_a_token_in_a_response_header(runner):
    auth = """auth:
  type: session_login
  login_url: https://api.example.com/auth/generatetoken
  username_secret: api_user
  password_secret: api_pass
  token_header: X-Access-Token
  send_header: X-Access-Token
"""
    seen = {}

    def handler(req):
        if req.url.path == "/auth/generatetoken":
            seen["basic"] = base64.b64decode(req.headers["Authorization"].split()[1]).decode()
            return httpx.Response(204, headers={"X-Access-Token": "header-token"})
        assert req.headers["X-Access-Token"] == "header-token" and "Authorization" not in req.headers
        return httpx.Response(200, json={"items": ROWS})

    r = runner(config(auth), handler)
    assert r.status == "success" and seen["basic"] == "svc-user:login-SECRET-value"


def test_login_with_a_secret_header_and_bearer_prefix(runner):
    auth = """auth:
  type: session_login
  login_url: https://api.example.com/api/v2/access/tokens
  headers: {X-Secret-Key: "{secret:api_pass}"}
  body: {keyId: "{secret:api_user}", expiryTime: 3600}
  token_path: token
  send_header: Authorization
  prefix: "Bearer "
"""

    def handler(req):
        if req.url.path.endswith("/tokens"):
            assert req.headers["X-Secret-Key"] == "login-SECRET-value"
            assert json.loads(req.content) == {"keyId": "svc-user", "expiryTime": 3600}
            return httpx.Response(201, json={"token": "bearer-token"})
        assert req.headers["Authorization"] == "Bearer bearer-token"
        return httpx.Response(200, json={"items": ROWS})

    assert runner(config(auth), handler).status == "success"


def test_login_by_get_with_the_token_sent_as_a_query_param(runner):
    auth = """auth:
  type: session_login
  login_url: https://api.example.com/login
  method: GET
  params: {login: "{secret:api_user}", password: "{secret:api_pass}"}
  token_path: log.loginResponse.log.return
  send_param: authToken
"""

    def handler(req):
        if req.url.path == "/login":
            assert req.url.params["login"] == "svc-user"
            return httpx.Response(200, json={"log.loginResponse": {"log.return": "arc-token"}})
        assert req.url.params["authToken"] == "arc-token"
        return httpx.Response(200, json={"items": ROWS})

    assert runner(config(auth), handler).status == "success"


def test_cookie_session_logs_in_once_per_run(runner):
    auth = """auth:
  type: session_login
  login_url: https://api.example.com/auth
  username_secret: api_user
  password_secret: api_pass
"""
    logins = []

    def handler(req):
        if req.url.path == "/auth":
            logins.append(1)
            return httpx.Response(200, headers={"Set-Cookie": "SESSION=abc; Path=/"})
        assert "SESSION=abc" in req.headers.get("cookie", "")
        return httpx.Response(200, json={"items": ROWS})

    r = runner(config(auth), handler)
    assert r.status == "success" and len(logins) == 1


@pytest.mark.parametrize(
    "extra, message",
    [
        ("  token_path: a\n  token_header: b\n  send_header: c\n", "not both"),
        ("  token_path: a\n", "say where the token goes"),
        ("  send_header: c\n", "need `token_path` or `token_header`"),
        ("  username_secret: api_user\n", "needs both"),
    ],
)
def test_session_login_config_mistakes_are_explained(extra, message):
    auth = "auth:\n  type: session_login\n  login_url: https://api.example.com/login\n" + extra
    problems = validate_config(config(auth))
    assert any(message in p["message"] for p in problems), problems


def test_session_login_typo_gets_did_you_mean():
    problems = validate_config(config(JSON_LOGIN.replace("token_path", "tokn_path")))
    assert any(p["path"] == "auth.tokn_path" and "token_path" in p["hint"] for p in problems), problems


def test_token_with_url_symbols_is_masked_in_the_request_log(runner):
    token = "session+token/with=symbols"
    auth = JSON_LOGIN.replace("send_header: x-session-auth", "send_param: sid")

    def handler(req):
        if req.url.path == "/login":
            return httpx.Response(200, json={"token": token})
        assert req.url.params["sid"] == token
        return httpx.Response(200, json={"items": ROWS})

    r = runner(config(auth), handler)
    assert r.status == "success"
    logged = json.dumps(r.requests)
    assert "sid=***" in logged and token not in logged and quote(token, safe="") not in logged


def test_login_url_must_be_an_allowed_host():
    auth = JSON_LOGIN.replace("https://api.example.com/login", "https://evil.example.org/login")
    problems = validate_config(config(auth))
    assert any(p["path"] == "auth.login_url" and p["level"] == "error" for p in problems)


def test_secret_names_cover_refs_and_secret_headers():
    request = "request: {path: /items, records_path: items, secret_headers: {x-api-key: extra_key}}"
    assert load_config(config(JSON_LOGIN, request)).secret_names() == ["api_user", "api_pass", "extra_key"]


def test_fill_secrets_reaches_nested_values():
    filled = fill_secrets({"a": ["{secret:api_user}"], "b": {"c": "x-{secret:api_pass}"}, "d": 3})
    assert filled == {"a": ["svc-user"], "b": {"c": "x-login-SECRET-value"}, "d": 3}


# Nested body paging


def test_set_path_builds_nested_objects_and_prefers_a_literal_key():
    body = {"a.b": 1, "x": "not an object"}
    set_path(body, "a.b", 2)
    set_path(body, "x.y.z", 3)
    assert body == {"a.b": 2, "x": {"y": {"z": 3}}}


GRAPHQL_REQUEST = """request:
  method: POST
  read_only_post: true
  path: /graphql
  body: {query: "query Issues($first: Int, $after: String) { issues }", variables: {first: 2, after: null}}
  records_path: data.issues.nodes
  error_path: errors
"""
GRAPHQL_PAGING = """pagination:
  type: body_token
  token_path: data.issues.pageInfo.endCursor
  token_param: variables.after
  token_in: body
  has_more_path: data.issues.pageInfo.hasNextPage
"""


def graphql_handler(sent):
    def handler(req):
        variables = json.loads(req.content)["variables"]
        sent.append(variables)
        start = int(variables["after"] or 0)
        page = ROWS[start:start + variables["first"]]
        more = start + 2 < len(ROWS)
        info = {"hasNextPage": more, "endCursor": str(start + 2)}  # the cursor stays set on the last page
        return httpx.Response(200, json={"data": {"issues": {"nodes": page, "pageInfo": info}}})

    return handler


def test_graphql_cursor_goes_inside_variables_and_stops_on_has_next_page(runner):
    sent = []
    r = runner(config("", GRAPHQL_REQUEST, GRAPHQL_PAGING), graphql_handler(sent))
    assert r.status == "success" and r.records_pulled == 5 and r.pages == 3
    assert sent == [{"first": 2, "after": None}, {"first": 2, "after": "2"}, {"first": 2, "after": "4"}]


def test_graphql_error_in_a_200_fails_the_run_with_the_reason(runner):
    r = runner(config("", GRAPHQL_REQUEST, GRAPHQL_PAGING),
               lambda req: httpx.Response(200, json={"data": None, "errors": [{"message": "Field 'issues' is unknown"}]}))
    assert r.status == "failed" and "Field 'issues' is unknown" in r.last_error


def test_offset_inside_a_nested_body_with_an_end_index(runner):
    request = """request:
  method: POST
  read_only_post: true
  path: /public_api/v1/alerts
  body: {request_data: {filters: []}}
  records_path: reply.alerts
"""
    paging = """pagination:
  type: offset
  offset_param: request_data.search_from
  end_param: request_data.search_to
  limit: 2
  param_in: body
  total_path: reply.total_count
"""
    sent = []

    def handler(req):
        data = json.loads(req.content)["request_data"]
        sent.append((data["search_from"], data["search_to"]))
        assert "limit" not in data and data["filters"] == []
        return httpx.Response(200, json={"reply": {"total_count": 5, "alerts": ROWS[data["search_from"]:data["search_to"]]}})

    r = runner(config("", request, paging), handler)
    assert r.status == "success" and r.records_pulled == 5
    assert sent == [(0, 2), (2, 4), (4, 6)]


def test_incremental_value_can_go_inside_a_nested_body(runner):
    request = GRAPHQL_REQUEST + "incremental:\n  field: ts\n  param: variables.since\n  param_in: body\n  template: '{checkpoint}'\n  start: '2026-10-01T00:00:00Z'\n"
    sent = []

    r = runner(config("", request, GRAPHQL_PAGING), graphql_handler(sent))
    assert r.status == "success"
    assert sent[0]["since"] == "2026-10-01T00:00:00Z" and sent[0]["first"] == 2


# Second secret header


TOKEN_AUTH = """auth:
  type: oauth2_client_credentials
  token_url: https://api.example.com/oauth/token
  client_id_secret: api_user
  client_secret_secret: api_pass
"""


def test_secret_header_goes_out_alongside_oauth2(runner):
    request = "request: {path: /items, records_path: items, secret_headers: {x-api-key: extra_key}}"

    def handler(req):
        if req.url.path == "/oauth/token":
            assert "x-api-key" not in req.headers
            return httpx.Response(200, json={"access_token": "oauth-token", "expires_in": 3600})
        assert req.headers["x-api-key"] == "extra-SECRET-value"
        assert req.headers["Authorization"] == "Bearer oauth-token"
        return httpx.Response(200, json={"items": ROWS})

    assert runner(config(TOKEN_AUTH, request), handler).status == "success"


def test_secret_header_value_never_lives_in_the_saved_config(store):
    request = "request: {path: /items, records_path: items, secret_headers: {x-api-key: extra_key}}"
    text = config(TOKEN_AUTH, request)
    assert save_and_approve(text, store=store)["ok"]
    assert "extra-SECRET-value" not in store.connectors["src"]["config_yaml"]


def test_missing_secret_header_is_auth_failed(runner, monkeypatch):
    monkeypatch.delenv("EXTRA_KEY")
    request = "request: {path: /items, records_path: items, secret_headers: {x-api-key: extra_key}}"
    r = run_connector(config("", request), transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"items": []})),
                      resolver=lambda _: ["93.184.216.34"], dry_run=True)
    assert r.status == "auth_failed" and "EXTRA_KEY" in r.last_error


# Redirects must not carry credentials to another host


@pytest.mark.parametrize(
    "auth, request_text, header",
    [
        ('auth: {type: api_key, header: X-API-Key, secret: api_pass}', LIST_REQUEST, "x-api-key"),
        ("", "request: {path: /items, records_path: items, secret_headers: {x-extra: extra_key}}", "x-extra"),
        (JSON_LOGIN, LIST_REQUEST, "x-session-auth"),
    ],
)
def test_cross_host_redirect_drops_every_credential_header(runner, auth, request_text, header):
    text = config(auth, request_text).replace("allow_hosts: [api.example.com]", "allow_hosts: [api.example.com, cdn.example.com]")
    seen = {}

    def handler(req):
        if req.url.path == "/login":
            return httpx.Response(200, json={"token": "session-token"})
        seen[req.url.host] = header in req.headers
        if req.url.host == "api.example.com":
            return httpx.Response(302, headers={"Location": "https://cdn.example.com/items"})
        return httpx.Response(200, json={"items": ROWS})

    r = runner(text, handler)
    assert r.status == "success"
    assert seen == {"api.example.com": True, "cdn.example.com": False}


# Custom CA file


def ca_config(path):
    return BASE.replace("allow_hosts: [api.example.com]", f"allow_hosts: [api.example.com], ca_file: {path}").replace(
        "AUTH", "").replace("REQUEST", LIST_REQUEST).replace("PAGING", "")


def test_ca_file_inside_the_data_folder_is_loaded(runner, tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    shutil.copy(certifi.where(), tmp_path / "onprem-ca.crt")
    r = runner(ca_config("onprem-ca.crt"), lambda req: httpx.Response(200, json={"items": ROWS}))
    assert r.status == "success"


def test_ca_file_outside_the_data_folder_is_blocked(runner, tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    outside = tmp_path / "outside.crt"
    shutil.copy(certifi.where(), outside)
    r = runner(ca_config(outside.as_posix()), lambda req: httpx.Response(200, json={"items": ROWS}))
    assert r.status == "failed" and "outside the data folder" in r.last_error


def test_invalid_ca_file_is_a_clear_error(runner, tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    (tmp_path / "broken.crt").write_text("not a certificate", encoding="utf-8")
    r = runner(ca_config("broken.crt"), lambda req: httpx.Response(200, json={"items": ROWS}))
    assert r.status == "failed" and "not a valid certificate" in r.last_error
