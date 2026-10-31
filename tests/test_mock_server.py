import re
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from mock_server import app as mock_app
from mock_server import data

NOW = datetime(2026, 10, 31, 12, tzinfo=timezone.utc)
FW = {"X-API-Key": mock_app.FIREWALL_KEY}
CLOUD = {"X-Api-Key": mock_app.CLOUD_KEY, "X-Amz-Target": "CloudTrail_20131101.LookupEvents"}
FW_PATH = "/firewall/api/v1/logs"
HOSTS_PATH = "/edr/devices/combined/devices/v1"
ALERTS_PATH = "/edr/alerts/combined/alerts/v1"


@pytest.fixture
def client():
    return TestClient(mock_app.create_app(now=NOW))


def edr_token(client, client_id=mock_app.EDR_CLIENT_ID, secret=mock_app.EDR_CLIENT_SECRET):
    response = client.post(
        "/edr/oauth2/token",
        data={"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret},
    )
    assert response.status_code == 201
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_data_is_deterministic():
    assert data.firewall_events(NOW) == data.firewall_events(NOW)
    assert data.edr_detections(NOW) == data.edr_detections(NOW)


def test_data_follows_the_mock_rules():
    events = data.firewall_events(NOW)
    external = tuple(f"{prefix}." for prefix in data.EXTERNAL_RANGES)
    inbound = [e for e in events if e["deviceDirection"] == 0]
    outbound = [e for e in events if e["deviceDirection"] == 1]
    assert inbound and outbound
    assert all(e["src"].startswith(external) and e["dst"].startswith("10.") for e in inbound)
    assert all(e["src"].startswith("10.") and e["dst"].startswith(external) for e in outbound)
    assert any(e.get("cs1") in data.KEV_CVES for e in events)

    detections = data.edr_detections(NOW)
    clean = [d for d in detections if isinstance(d["severity_name"], str)]
    assert all(d["severity_name"].lower() == data.severity_band(d["cvss_score"]) for d in clean if d["cve"])
    assert all(d["cvss_score"] is None for d in detections if not d["cve"])
    assert all(re.fullmatch(r"[0-9a-f]{64}", d["sha256"]) for d in detections)
    assert all(re.fullmatch(r"T\d{4}(\.\d{3})?", d["technique_id"]) for d in detections)
    assert any(d["cve"] in data.KEV_CVES for d in detections)
    assert all(h["last_login_user"].endswith("@example.com") for h in data.edr_hosts(NOW))


def test_timestamps_fall_in_the_last_seven_days():
    earliest = (NOW - timedelta(days=7)).timestamp() * 1000
    good = [e["rt"] for e in data.firewall_events(NOW) if isinstance(e["rt"], int)]
    assert all(earliest <= stamp <= NOW.timestamp() * 1000 for stamp in good)


def test_about_one_percent_of_records_are_messy():
    events = data.firewall_events(NOW)
    assert sum("externalId" not in e for e in events) == 1
    assert sum(not isinstance(e["rt"], int) for e in events) == 2
    assert sum(not isinstance(e["severity"], int) for e in events) == 0


@pytest.mark.parametrize(
    "severity, band",
    [(0, "none"), (3.9, "low"), (4.0, "medium"), (6.9, "medium"), (7.0, "high"), (8.9, "high"), (9.0, "critical")],
)
def test_cvss_bands(severity, band):
    assert data.severity_band(severity) == band


@pytest.mark.parametrize(
    "headers, status, error",
    [
        ({}, 401, "invalid_token"),
        ({"X-API-Key": "wrong"}, 401, "invalid_token"),
        ({"X-API-Key": mock_app.FIREWALL_KEY_NO_ACCESS}, 403, "insufficient_scope"),
    ],
)
def test_firewall_enforces_auth(client, headers, status, error):
    response = client.get(FW_PATH, headers=headers)
    assert response.status_code == status
    assert response.json()["error"] == error


def test_firewall_offset_paging_covers_everything(client):
    seen, offset = [], 0
    while True:
        body = client.get(FW_PATH, headers=FW, params={"offset": offset, "limit": 100}).json()
        if not body["events"]:
            break
        seen.extend(body["events"])
        offset += 100
    assert len(seen) == body["total"] == 300


def test_firewall_sends_rate_limit_headers_and_rejects_bad_limit(client):
    response = client.get(FW_PATH, headers=FW)
    assert response.headers["X-Rate-Limit-Remaining"] == "119"
    assert "X-Rate-Limit-Reset" in response.headers
    assert client.get(FW_PATH, headers=FW, params={"limit": 0}).status_code == 400


def test_real_rate_limit_returns_429_with_retry_after(client):
    for _ in range(120):
        assert client.get(FW_PATH, headers=FW, params={"limit": 1}).status_code == 200
    response = client.get(FW_PATH, headers=FW, params={"limit": 1})
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) >= 1


def test_token_rejects_bad_client_and_grant(client):
    bad = client.post(
        "/edr/oauth2/token",
        data={"grant_type": "client_credentials", "client_id": "x", "client_secret": "y"},
    )
    assert (bad.status_code, bad.json()["error"]) == (401, "invalid_client")
    wrong = client.post("/edr/oauth2/token", data={"grant_type": "password"})
    assert (wrong.status_code, wrong.json()["error"]) == (400, "unsupported_grant_type")


def test_token_accepts_basic_credentials(client):
    response = client.post(
        "/edr/oauth2/token",
        data={"grant_type": "client_credentials"},
        auth=(mock_app.EDR_CLIENT_ID, mock_app.EDR_CLIENT_SECRET),
    )
    assert response.status_code == 201
    assert response.json()["expires_in"] == 300


def test_edr_requires_a_token(client):
    response = client.get(HOSTS_PATH)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert client.get(HOSTS_PATH, headers={"Authorization": "Bearer nope"}).status_code == 401


def test_edr_tokens_really_expire():
    client = TestClient(mock_app.create_app(now=NOW, token_ttl_s=-1))
    response = client.get(HOSTS_PATH, headers=edr_token(client))
    assert response.status_code == 401
    assert "expired" in response.json()["error_description"]


def test_expire_tokens_control(client):
    headers = edr_token(client)
    assert client.get(HOSTS_PATH, headers=headers).status_code == 200
    assert client.post("/admin/expire-tokens").json() == {"expired": 1}
    assert client.get(HOSTS_PATH, headers=headers).status_code == 401


def test_edr_scope_is_enforced(client):
    headers = edr_token(client, mock_app.EDR_HOSTS_ONLY_CLIENT_ID, mock_app.EDR_HOSTS_ONLY_CLIENT_SECRET)
    assert client.get(HOSTS_PATH, headers=headers).status_code == 200
    denied = client.get(ALERTS_PATH, headers=headers)
    assert (denied.status_code, denied.json()["error"]) == (403, "insufficient_scope")


def test_edr_cursor_paging_covers_everything(client):
    headers = edr_token(client)
    seen, after = [], None
    while True:
        params = {"limit": 100, **({"after": after} if after else {})}
        body = client.get(ALERTS_PATH, headers=headers, params=params).json()
        seen.extend(body["resources"])
        after = body["meta"]["pagination"]["next"]
        if not after:
            break
    assert len(seen) == 300


def test_edr_rejects_a_bad_cursor(client):
    response = client.get(HOSTS_PATH, headers=edr_token(client), params={"after": "garbage!"})
    assert response.status_code == 400


def test_cloud_token_in_body_paging_covers_everything(client):
    seen, token = [], None
    while True:
        body = {"MaxResults": 50, **({"NextToken": token} if token else {})}
        result = client.post("/cloud/", headers=CLOUD, json=body).json()
        seen.extend(result["Events"])
        token = result.get("NextToken")
        if not token:
            break
    assert len(seen) == 300
    assert isinstance(seen[0]["EventTime"], float)
    assert isinstance(seen[0]["CloudTrailEvent"], str)


@pytest.mark.parametrize(
    "headers, body, status, kind",
    [
        ({}, {}, 401, "UnrecognizedClientException"),
        ({"X-Api-Key": mock_app.CLOUD_KEY}, {}, 400, "UnknownOperationException"),
        (CLOUD, {"MaxResults": 51}, 400, "InvalidMaxResultsException"),
        (CLOUD, {"NextToken": "garbage!"}, 400, "InvalidNextTokenException"),
    ],
)
def test_cloud_errors_use_aws_shape(client, headers, body, status, kind):
    response = client.post("/cloud/", headers=headers, json=body)
    assert response.status_code == status
    assert response.json()["__type"] == kind


def set_fault(client, path, mode):
    return client.post("/admin/faults", json={"path": path, "mode": mode})


def test_fault_503x3_then_recovers(client):
    set_fault(client, "/firewall", "503x3")
    statuses = [client.get(FW_PATH, headers=FW).status_code for _ in range(4)]
    assert statuses == [503, 503, 503, 200]


def test_fault_429_sends_retry_after_once(client):
    set_fault(client, "/firewall", "429:30")
    first = client.get(FW_PATH, headers=FW)
    assert (first.status_code, first.headers["Retry-After"]) == (429, "30")
    assert client.get(FW_PATH, headers=FW).status_code == 200


def test_fault_badrecord_until_off(client):
    set_fault(client, "/firewall", "badrecord")
    assert "externalId" not in client.get(FW_PATH, headers=FW).json()["events"][0]
    set_fault(client, "/firewall", "off")
    assert "externalId" in client.get(FW_PATH, headers=FW).json()["events"][0]


def test_fault_timeout_hangs(client, monkeypatch):
    monkeypatch.setattr(mock_app, "HANG_SECONDS", 0.01)
    set_fault(client, "/firewall", "timeout")
    assert client.get(FW_PATH, headers=FW).status_code == 504


def test_fault_on_one_path_leaves_others_alone(client):
    set_fault(client, "/firewall", "503x3")
    assert client.post("/cloud/", headers=CLOUD, json={}).status_code == 200


def test_unknown_fault_mode_is_rejected(client):
    assert set_fault(client, "/firewall", "explode").status_code == 400


def test_unknown_path_gives_json_404(client):
    response = client.get("/nope")
    assert response.status_code == 404
    assert response.json()["error"] == "not_found"


def test_openapi_docs_exist(client):
    assert FW_PATH in client.get("/openapi.json").json()["paths"]
