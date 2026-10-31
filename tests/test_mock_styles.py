"""The Cisco FMC, Wiz and Cortex mocks enforce the behaviour the engine has to handle."""

import base64
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from mock_server import app as mock_app
from mock_server import data, styles

NOW = datetime(2026, 10, 31, 12, tzinfo=timezone.utc)
FMC_LOGIN = "/fmc/api/fmc_platform/v1/auth/generatetoken"
FMC_DEVICES = f"/fmc/api/fmc_config/v1/domain/{data.FMC_DOMAIN}/devices/devicerecords"
WIZ_TOKEN = "/wiz/oauth/token"
WIZ_GRAPHQL = "/wiz/graphql"
WIZ_FORM = {
    "grant_type": "client_credentials",
    "client_id": styles.WIZ_CLIENT_ID,
    "client_secret": styles.WIZ_CLIENT_SECRET,
    "audience": styles.WIZ_AUDIENCE,
}
CORTEX = "/cortex/public_api/v1/alerts/get_alerts"
CORTEX_HEADERS = {"Authorization": styles.CORTEX_KEY, "x-xdr-auth-id": styles.CORTEX_KEY_ID}
QUERY = "query { issues { nodes { id } } }"


@pytest.fixture
def client():
    return TestClient(mock_app.create_app(now=NOW), base_url="http://localhost:9000")


def fmc_token(client):
    response = client.post(FMC_LOGIN, auth=(styles.FMC_USER, styles.FMC_PASSWORD))
    assert response.status_code == 204 and response.content == b""
    assert response.headers["DOMAIN_UUID"] == data.FMC_DOMAIN and response.headers["X-auth-refresh-token"]
    return {"X-auth-access-token": response.headers["X-auth-access-token"]}


def wiz_token(client):
    return {"Authorization": f"Bearer {client.post(WIZ_TOKEN, data=WIZ_FORM).json()['access_token']}"}


def test_fmc_login_rejects_bad_credentials(client):
    assert client.post(FMC_LOGIN, auth=(styles.FMC_USER, "wrong")).status_code == 401
    assert client.post(FMC_LOGIN).status_code == 401
    assert client.post(FMC_LOGIN, headers={"Authorization": f"Basic {base64.b64encode(b'x').decode()}"}).status_code == 401


def test_fmc_records_need_a_live_token(client):
    assert client.get(FMC_DEVICES).status_code == 401
    headers = fmc_token(client)
    assert client.get(FMC_DEVICES, headers=headers).status_code == 200
    client.post("/admin/expire-tokens")
    assert client.get(FMC_DEVICES, headers=headers).status_code == 401


def test_fmc_paging_defaults_and_cap(client):
    headers = fmc_token(client)
    body = client.get(FMC_DEVICES, headers=headers).json()
    assert body["paging"]["limit"] == 25 and len(body["items"]) == 25 and body["paging"]["count"] == 60
    assert body["paging"]["pages"] == 3 and body["paging"]["next"]
    assert client.get(FMC_DEVICES, headers=headers, params={"limit": 5000}).json()["paging"]["limit"] == 1000
    assert client.get(FMC_DEVICES, headers=headers, params={"offset": 60}).json()["items"] == []


def test_fmc_expanded_adds_device_detail(client):
    headers = fmc_token(client)
    assert "sw_version" not in client.get(FMC_DEVICES, headers=headers).json()["items"][0]
    item = client.get(FMC_DEVICES, headers=headers, params={"expanded": "true"}).json()["items"][0]
    assert item["sw_version"] and item["hostName"].startswith("10.")


def test_fmc_unknown_domain_is_404(client):
    url = FMC_DEVICES.replace(data.FMC_DOMAIN, "not-a-domain")
    assert client.get(url, headers=fmc_token(client)).status_code == 404


def test_wiz_token_needs_the_audience(client):
    assert client.post(WIZ_TOKEN, data={**WIZ_FORM, "audience": "other"}).status_code == 403
    assert client.post(WIZ_TOKEN, data={**WIZ_FORM, "client_secret": "wrong"}).status_code == 401
    assert client.post(WIZ_TOKEN, data=WIZ_FORM).json()["token_type"] == "Bearer"


def test_wiz_graphql_needs_a_token(client):
    assert client.post(WIZ_GRAPHQL, json={"query": QUERY}).status_code == 401


@pytest.mark.parametrize(
    "body",
    [
        {"query": "query { unknown }", "variables": {"first": 5}},
        {"query": QUERY, "variables": {}},
        {"query": QUERY, "variables": {"first": 10001}},
        {"query": QUERY, "variables": {"first": 5, "after": "!!"}},
    ],
)
def test_wiz_request_errors_arrive_in_a_200(client, body):
    response = client.post(WIZ_GRAPHQL, headers=wiz_token(client), json=body)
    assert response.status_code == 200 and response.json()["errors"] and response.json()["data"] is None


def test_wiz_cursor_walks_to_the_end_with_the_cursor_still_set(client):
    headers, seen, after = wiz_token(client), 0, None
    while True:
        issues = client.post(WIZ_GRAPHQL, headers=headers, json={"query": QUERY, "variables": {"first": 50, "after": after}}).json()
        page = issues["data"]["issues"]
        seen += len(page["nodes"])
        after = page["pageInfo"]["endCursor"]
        if not page["pageInfo"]["hasNextPage"]:
            break
    assert seen == 120 and after


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": styles.CORTEX_KEY},
        {"Authorization": "wrong", "x-xdr-auth-id": styles.CORTEX_KEY_ID},
        {"Authorization": styles.CORTEX_KEY, "x-xdr-auth-id": "99"},
    ],
)
def test_cortex_needs_both_auth_headers(client, headers):
    assert client.post(CORTEX, headers=headers, json={"request_data": {}}).status_code == 401


def test_cortex_pages_by_range_and_caps_it_at_100(client):
    reply = client.post(CORTEX, headers=CORTEX_HEADERS, json={"request_data": {"search_from": 0, "search_to": 100}}).json()["reply"]
    assert (reply["total_count"], reply["result_count"], len(reply["alerts"])) == (250, 100, 100)
    too_wide = client.post(CORTEX, headers=CORTEX_HEADERS, json={"request_data": {"search_from": 0, "search_to": 101}})
    assert too_wide.status_code == 400
    assert client.post(CORTEX, headers=CORTEX_HEADERS, json={}).status_code == 400


def test_new_mock_data_follows_the_rules():
    devices = data.fmc_devices()
    assert all(d["hostName"].startswith("10.") and d["type"] == "Device" for d in devices)
    assert data.fmc_devices() == devices
    issues = data.wiz_issues(NOW)
    assert data.wiz_issues(NOW) == issues
    assert {i["severity"] for i in issues if isinstance(i["severity"], str)} <= {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    alerts = data.cortex_alerts(NOW)
    hosts = {h["hostname"]: h["local_ip"] for h in data.edr_hosts(NOW)}
    assert all(hosts[a["host_name"]] == a["host_ip"] for a in alerts)
    assert all(a["user_name"].endswith("@example.com") for a in alerts)
