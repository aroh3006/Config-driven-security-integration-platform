"""The Okta, GitHub and Jira mocks checked against vendor specs and documented behaviour."""

import re
import uuid
from datetime import datetime, timezone

import pytest
import vendor_schemas as spec
from fastapi.testclient import TestClient

from mock_server import app as mock_app
from mock_server import data, saas

NOW = datetime(2026, 10, 31, 12, tzinfo=timezone.utc)
OKTA = {"Authorization": f"SSWS {saas.OKTA_KEY}"}
GITHUB = {"Authorization": f"Bearer {saas.GITHUB_TOKEN}", "X-GitHub-Api-Version": "2026-03-10"}
JIRA = (saas.JIRA_EMAIL, saas.JIRA_TOKEN)
USERS = "/okta/api/v1/users"
LOGS = "/okta/api/v1/logs"
MEMBERS = f"/github/orgs/{saas.GITHUB_ORG}/members"
ALERTS = f"/github/repos/{saas.GITHUB_ORG}/{saas.GITHUB_REPO}/dependabot/alerts"
SEARCH = "/jira/rest/api/3/search/jql"
JQL = {"jql": "project = SEC ORDER BY created DESC"}
EXTERNAL_IP = re.compile(r"^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d+$")


@pytest.fixture
def client():
    return TestClient(mock_app.create_app(now=NOW), base_url="http://localhost:9000")


def next_link(response):
    return response.links.get("next", {}).get("url")


# Conformance to the vendor specs

def test_okta_users_match_the_spec():
    users = [u for u in data.okta_users(NOW) if "id" in u]
    assert all(set(u) <= spec.OKTA_USER_FIELDS for u in users)
    assert {u["status"] for u in users} <= spec.OKTA_USER_STATUSES
    assert all(re.fullmatch(r"00u[0-9a-f]{17}", u["id"]) for u in users)
    assert all(u["profile"]["login"].endswith("@example.com") for u in users)
    staged = [u for u in users if u["status"] in ("STAGED", "PROVISIONED")]
    assert staged and all(u["lastLogin"] is None for u in staged)


def test_okta_logs_match_the_spec():
    events = data.okta_logs(NOW)
    assert all(set(e) <= spec.OKTA_LOG_FIELDS for e in events)
    clean = [e for e in events if "uuid" in e and isinstance(e["severity"], str)]
    assert {e["severity"] for e in clean} <= spec.OKTA_SEVERITIES
    for event in clean:
        uuid.UUID(event["uuid"])
        assert set(event["actor"]) <= spec.OKTA_ACTOR_FIELDS
        assert set(event["client"]) <= spec.OKTA_CLIENT_FIELDS
        assert set(event["securityContext"]) <= spec.OKTA_SECURITY_FIELDS
        assert EXTERNAL_IP.match(event["client"]["ipAddress"])


def test_github_members_match_the_spec():
    members = [m for m in data.github_members() if "id" in m]
    assert all(spec.GITHUB_USER_REQUIRED <= set(m) <= spec.GITHUB_USER_FIELDS for m in members)
    assert sum("email" in m for m in members) < len(members) / 2


def test_github_alerts_match_the_spec():
    alerts = [a for a in data.github_dependabot(NOW, "o", "r") if "number" in a]
    for alert in alerts:
        assert spec.GITHUB_ALERT_REQUIRED <= set(alert) <= spec.GITHUB_ALERT_FIELDS
        advisory = alert["security_advisory"]
        assert spec.GITHUB_ADVISORY_REQUIRED <= set(advisory) <= spec.GITHUB_ADVISORY_FIELDS
        assert set(alert["security_vulnerability"]) == spec.GITHUB_VULNERABILITY_FIELDS
        assert advisory["severity"] in spec.GITHUB_ADVISORY_SEVERITIES
        assert re.fullmatch(r"GHSA-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}", advisory["ghsa_id"])
        assert re.fullmatch(r"CVE-\d{4}-\d{4,}", advisory["cve_id"])
        assert advisory["cvss"]["vector_string"].startswith("CVSS:3.")
        assert data.severity_band(advisory["cvss"]["score"]) == advisory["severity"]
    assert {a["state"] for a in alerts} <= spec.GITHUB_ALERT_STATES


def test_jira_results_match_the_spec(client):
    body = client.get(SEARCH, auth=JIRA, params={**JQL, "fields": "*all"}).json()
    assert set(body) <= spec.JIRA_RESULT_FIELDS
    assert all(set(issue) <= spec.JIRA_ISSUE_FIELDS for issue in body["issues"])
    created = next(i for i in body["issues"] if "key" in i)["fields"]["created"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000\+0000", created)
    assert body["issues"][0]["fields"]["description"]["type"] == "doc"


def test_error_bodies_match_the_specs(client):
    okta = client.get(USERS, headers={"Authorization": "SSWS wrong"})
    assert set(okta.json()) == spec.OKTA_ERROR_FIELDS
    jira = client.get(SEARCH, auth=JIRA, params={"jql": "order by key desc"})
    assert set(jira.json()) <= spec.JIRA_ERROR_FIELDS
    assert set(client.get(MEMBERS).json()) == {"message", "documentation_url", "status"}


def test_data_is_deterministic():
    assert data.okta_logs(NOW) == data.okta_logs(NOW)
    assert data.jira_issues(NOW, "SEC") == data.jira_issues(NOW, "SEC")


def test_messy_share_stays_about_one_percent():
    for records, key in (
        (data.okta_users(NOW), "id"),
        (data.github_members(), "id"),
        (data.github_dependabot(NOW, "o", "r"), "number"),
        (data.jira_issues(NOW, "SEC"), "key"),
    ):
        missing = sum(key not in r for r in records)
        assert 1 <= missing <= len(records) * 0.02


# Okta behaviour

@pytest.mark.parametrize(
    "headers, status, code",
    [
        ({}, 401, "E0000005"),
        ({"Authorization": "Bearer x"}, 401, "E0000005"),
        ({"Authorization": "SSWS wrong"}, 401, "E0000011"),
        ({"Authorization": f"SSWS {saas.OKTA_KEY_NO_ACCESS}"}, 403, "E0000006"),
    ],
)
def test_okta_enforces_auth(client, headers, status, code):
    response = client.get(USERS, headers=headers)
    assert (response.status_code, response.json()["errorCode"]) == (status, code)


def test_okta_users_follow_link_header_to_the_end(client):
    seen, url = [], USERS + "?limit=50"
    while url:
        response = client.get(url, headers=OKTA)
        assert "X-Rate-Limit-Remaining" in response.headers
        assert response.links["self"]["url"]
        seen.extend(response.json())
        url = next_link(response)
    assert len(seen) == 120


def test_okta_polling_next_link_never_ends(client):
    response = client.get(LOGS, headers=OKTA, params={"since": "2026-10-20T00:00:00Z", "limit": 1000})
    assert response.json()
    empty = client.get(next_link(response), headers=OKTA)
    assert empty.json() == []
    assert next_link(empty)


def test_okta_bounded_query_ends_with_no_next_link(client):
    params = {"since": "2026-10-20T00:00:00Z", "until": "2026-10-31T00:00:00Z", "limit": 1000}
    assert next_link(client.get(LOGS, headers=OKTA, params=params)) is None


def test_okta_filter_since_and_sort(client):
    params = {"filter": 'eventType eq "user.session.start"', "since": "2026-10-28T00:00:00Z", "limit": 1000}
    events = client.get(LOGS, headers=OKTA, params=params).json()
    assert events and all(e["eventType"] == "user.session.start" for e in events)
    assert all(e["published"] >= params["since"] for e in events)
    assert [e["published"] for e in events] == sorted(e["published"] for e in events)
    newest = client.get(LOGS, headers=OKTA, params={**params, "sortOrder": "DESCENDING"}).json()
    assert newest[0]["published"] == events[-1]["published"]


@pytest.mark.parametrize(
    "params",
    [
        {"since": "yesterday"},
        {"since": "2025-01-01T00:00:00Z"},
        {"filter": "published gt 1"},
        {"after": "garbage!"},
        {"sortOrder": "SIDEWAYS"},
    ],
)
def test_okta_rejects_bad_log_queries(client, params):
    response = client.get(LOGS, headers=OKTA, params=params)
    assert (response.status_code, response.json()["errorCode"]) == (400, "E0000001")


# GitHub behaviour

@pytest.mark.parametrize(
    "headers, status",
    [
        ({}, 401),
        ({"Authorization": "Bearer wrong"}, 401),
        ({"Authorization": f"Bearer {saas.GITHUB_TOKEN}", "X-GitHub-Api-Version": "1999-01-01"}, 400),
    ],
)
def test_github_auth_and_version_errors(client, headers, status):
    assert client.get(MEMBERS, headers=headers).status_code == status


def test_github_rate_headers(client):
    headers = client.get(MEMBERS, headers=GITHUB).headers
    for name in ("X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "X-RateLimit-Used", "X-RateLimit-Resource", "X-GitHub-Request-Id"):
        assert name in headers


def test_github_page_numbers_stop_on_empty_page(client):
    seen, page = [], 1
    while True:
        rows = client.get(MEMBERS, headers=GITHUB, params={"page": page, "per_page": 50}).json()
        if not rows:
            break
        seen.extend(rows)
        page += 1
    assert len(seen) == 130


def test_github_members_link_header(client):
    middle = client.get(MEMBERS, headers=GITHUB, params={"page": 2, "per_page": 50})
    assert {"next", "prev", "first", "last"} == set(middle.links)
    assert "page=3" in middle.links["last"]["url"]


def test_github_members_validation(client):
    assert client.get(MEMBERS, headers=GITHUB, params={"role": "boss"}).status_code == 422
    assert len(client.get(MEMBERS, headers=GITHUB, params={"role": "admin"}).json()) == 3
    assert client.get("/github/orgs/other/members", headers=GITHUB).status_code == 404


def test_github_per_page_is_capped_at_100(client):
    assert len(client.get(MEMBERS, headers=GITHUB, params={"per_page": 500}).json()) == 100


def test_github_alerts_cursor_and_state(client):
    seen, url = [], ALERTS + "?per_page=20&state=open"
    while url:
        response = client.get(url, headers=GITHUB)
        seen.extend(response.json())
        url = next_link(response)
    assert seen and all(a["state"] == "open" for a in seen)
    assert len(seen) < 60


def test_github_alerts_errors(client):
    denied = {"Authorization": f"Bearer {saas.GITHUB_TOKEN_NO_ALERTS}"}
    assert client.get(MEMBERS, headers=denied).status_code == 200
    assert client.get(ALERTS, headers=denied).status_code == 403
    assert client.get(ALERTS, headers=GITHUB, params={"state": "weird"}).status_code == 422
    assert client.get("/github/repos/a/b/dependabot/alerts", headers=GITHUB).status_code == 404


# Jira behaviour

def test_jira_treats_a_bad_login_as_anonymous_like_the_live_api(client):
    anonymous = client.get(SEARCH, params=JQL)
    assert (anonymous.status_code, anonymous.json()) == (200, {"issues": [], "isLast": True})
    assert "X-Seraph-LoginReason" not in anonymous.headers
    wrong = client.get(SEARCH, params=JQL, auth=(saas.JIRA_EMAIL, "wrong"))
    assert (wrong.status_code, wrong.json()["issues"]) == (200, [])
    assert wrong.headers["X-Seraph-LoginReason"] == "AUTHENTICATED_FAILED"


@pytest.mark.parametrize("jql", [None, "order by key desc", "created > -7d"])
def test_jira_rejects_unbounded_jql(client, jql):
    response = client.get(SEARCH, auth=JIRA, params={"jql": jql} if jql else {})
    assert response.status_code == 400
    assert "Unbounded" in response.json()["errorMessages"][0]


def test_jira_rejects_unknown_project(client):
    assert client.get(SEARCH, auth=JIRA, params={"jql": "project = NOPE"}).status_code == 400


def test_jira_returns_only_ids_unless_fields_are_named(client):
    bare = client.get(SEARCH, auth=JIRA, params=JQL).json()["issues"][0]
    assert set(bare) == {"id"}
    named = client.get(SEARCH, auth=JIRA, params={**JQL, "fields": "summary,priority"}).json()["issues"]
    assert set(named[0]["fields"]) == {"summary", "priority"}


def test_jira_token_paging_and_last_page(client):
    seen, token, pages = [], None, 0
    while True:
        params = {**JQL, "fields": "summary", "maxResults": 50, **({"nextPageToken": token} if token else {})}
        body = client.get(SEARCH, auth=JIRA, params=params).json()
        seen.extend(body["issues"])
        pages += 1
        token = body.get("nextPageToken")
        if not token:
            assert body["isLast"] is True
            break
        assert body["isLast"] is False
    assert (len(seen), pages) == (150, 3)


def test_jira_rejects_a_bad_token(client):
    assert client.get(SEARCH, auth=JIRA, params={**JQL, "nextPageToken": "garbage!"}).status_code == 400


# Shared behaviour

def test_large_responses_are_gzip_compressed(client):
    response = client.get(USERS, headers={**OKTA, "Accept-Encoding": "gzip"})
    assert response.headers["Content-Encoding"] == "gzip"
    assert len(response.json()) == 120


@pytest.mark.parametrize(
    "path, kwargs",
    [
        (USERS, {"headers": OKTA}),
        (MEMBERS, {"headers": GITHUB}),
        (SEARCH, {"auth": JIRA, "params": JQL}),
    ],
)
def test_fault_control_covers_the_new_mocks(client, path, kwargs):
    prefix = "/" + path.split("/")[1]
    client.post("/admin/faults", json={"path": prefix, "mode": "429:30"})
    limited = client.get(path, **kwargs)
    assert (limited.status_code, limited.headers["Retry-After"]) == (429, "30")
    assert client.get(path, **kwargs).status_code == 200


def test_real_rate_limit_on_okta(client):
    for _ in range(600):
        client.get(USERS, headers=OKTA, params={"limit": 1})
    limited = client.get(USERS, headers=OKTA, params={"limit": 1})
    assert (limited.status_code, limited.json()["errorCode"]) == (429, "E0000047")
    assert "Retry-After" in limited.headers


def test_badrecord_fault_on_jira(client):
    client.post("/admin/faults", json={"path": "/jira", "mode": "badrecord"})
    first = client.get(SEARCH, auth=JIRA, params={**JQL, "fields": "summary"}).json()["issues"][0]
    assert "key" not in first


def test_oauth_token_response_is_not_cacheable(client):
    response = client.post(
        "/edr/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": mock_app.EDR_CLIENT_ID,
            "client_secret": mock_app.EDR_CLIENT_SECRET,
        },
    )
    assert response.headers["Cache-Control"] == "no-store"
    bad = client.get("/edr/devices/combined/devices/v1", headers={"Authorization": "Bearer nope"})
    assert 'error="invalid_token"' in bad.headers["WWW-Authenticate"]


def test_cloud_event_is_a_full_cloudtrail_record():
    import json

    event = next(e for e in data.cloud_events(NOW) if "EventId" in e)
    uuid.UUID(event["EventId"])
    record = json.loads(event["CloudTrailEvent"])
    for field in ("eventVersion", "userIdentity", "eventTime", "awsRegion", "sourceIPAddress", "requestID", "eventID", "eventType", "recipientAccountId"):
        assert field in record
    assert record["eventID"] == event["EventId"]
    finding = next(e for e in data.cloud_events(NOW) if "Cve" in e)
    assert finding["EventSource"] == "securityhub.amazonaws.com"


def test_jira_uses_its_own_rate_limit_headers(client):
    response = client.get(SEARCH, params=JQL, auth=JIRA)
    assert response.headers["X-RateLimit-Limit"] == "600"
    assert "X-RateLimit-NearLimit" not in response.headers
    assert response.headers["RateLimit-Policy"] == '"jira-burst-based";q=100;w=1'
    assert "X-Rate-Limit-Remaining" not in response.headers
    assert "X-RateLimit-Reset" not in response.headers


def test_jira_429_carries_reset_reason_and_retry_after():
    headers = saas._jira_throttled_headers({"X-RateLimit-Limit": "600"}, 30)
    assert headers["Retry-After"] == "30" and headers["RateLimit-Reason"] == "jira-burst-based"
    assert headers["X-RateLimit-Reset"].endswith("Z")


def test_github_without_a_token_asks_for_authentication(client):
    response = client.get(MEMBERS)
    assert (response.status_code, response.json()["message"]) == (401, "Requires authentication")
