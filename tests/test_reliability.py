"""Failure tests: retries 1/2/4 (FR-7), 429 + Retry-After (FR-8), wrong key, network off, OAuth refresh."""

import httpx

from engine import faults, run_connector, save_and_approve

FW = """
name: mock-firewall
entity: alert
mock: true
source: {base_url: https://fw.example.com, allow_hosts: [fw.example.com]}
auth: {type: api_key, header: X-API-Key, secret: fw_key}
request: {path: /logs, records_path: data.logs}
pagination: {type: offset, offset_param: offset, limit_param: limit, limit: 2, total_path: total}
map:
  id: id
  type: act
  severity: { path: severity, transform: str }
  timestamp: { path: rt, transform: to_utc }
"""

LOGS = [{"id": f"e{i}", "act": "DENY", "severity": 7, "rt": f"2026-10-31T06:0{i}:00Z"} for i in range(5)]


def fw_handler(req: httpx.Request):
    assert req.headers["X-API-Key"] == "fw-SECRET-key-42"
    off, lim = int(req.url.params["offset"]), int(req.url.params["limit"])
    return httpx.Response(200, json={"data": {"logs": LOGS[off:off + lim]}, "total": len(LOGS)})


def test_happy_path(runner, store):
    r = runner(FW, fw_handler)
    assert r.status == "success" and r.records_pulled == 5 and r.pages == 3
    assert len(store.tables["alerts"]) == 5


def test_503_three_times_then_success_waits_1_2_4(runner, sleeps):
    faults.set_fault("mock-firewall", "503x3")
    r = runner(FW, fw_handler)
    assert r.status == "success"
    assert sleeps == [1, 2, 4]
    assert r.retries == 3 and r.connector_status == "degraded"


def test_503_four_times_marks_run_failed(runner, sleeps, store):
    faults.set_fault("mock-firewall", "503x4")
    r = runner(FW, fw_handler)
    assert r.status == "failed" and "503" in r.last_error
    assert sleeps == [1, 2, 4]
    assert store.get_connector("mock-firewall")["status"] == "failing"


def test_429_respects_retry_after(runner, sleeps):
    faults.set_fault("mock-firewall", "429:30")
    r = runner(FW, fw_handler)
    assert r.status == "success" and sleeps == [30]


def test_real_429_with_http_date_and_reset_header(runner, sleeps):
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "7"})
        return fw_handler(req)

    r = runner(FW, handler)
    assert r.status == "success" and sleeps[0] == 7


def test_wrong_key_is_not_retried(runner, sleeps, store):
    def handler(req):
        return httpx.Response(401, json={"errorCode": "E0000011", "errorSummary": "Invalid token provided"})

    r = runner(FW, handler)
    assert r.status == "auth_failed" and sleeps == [] and len(r.requests) == 1
    assert store.get_connector("mock-firewall")["status"] == "auth_failed"


def test_network_off_retries_then_resumes(runner, sleeps, store):
    calls = {"n": 0}

    def flaky(req):
        calls["n"] += 1
        if req.url.params["offset"] == "2" and calls["n"] < 10:
            raise httpx.ConnectError("network is down")
        return fw_handler(req)

    r1 = runner(FW, flaky)
    assert r1.status == "failed" and sleeps == [1, 2, 4] and r1.records_pulled == 2
    cp = store.get_checkpoint("mock-firewall")
    assert cp["resume_state"]["params"]["offset"] == 2  # resume point saved after page 1
    r2 = run_connector("mock-firewall", store=store, transport=httpx.MockTransport(fw_handler),
                       resolver=lambda h: ["93.184.216.34"], sleeper=sleeps.append)
    assert r2.status == "success" and r2.records_pulled == 3  # continued, not restarted
    assert len(store.tables["alerts"]) == 5
    assert store.get_checkpoint("mock-firewall")["resume_state"] is None


def test_timeout_fault(runner, sleeps):
    faults.set_fault("mock-firewall", "timeoutx2")
    r = runner(FW, fw_handler)
    assert r.status == "success" and sleeps == [1, 2]


def test_rate_limit_remaining_zero_pauses_until_reset(runner, sleeps):
    text = FW.replace("map:", "rate_limit: {remaining_header: X-Rate-Limit-Remaining, reset_header: X-Rate-Limit-Reset}\nmap:")

    def handler(req):
        resp = fw_handler(req)
        resp.headers["X-Rate-Limit-Remaining"] = "0"
        resp.headers["X-Rate-Limit-Reset"] = "12"
        return resp

    r = runner(text, handler)
    assert r.status == "success" and any(abs(s - 12) < 0.5 for s in sleeps)


OAUTH = """
name: mock-edr
entity: alert
mock: true
source: {base_url: https://edr.example.com, allow_hosts: [edr.example.com]}
auth:
  type: oauth2_client_credentials
  token_url: https://edr.example.com/oauth2/token
  client_id_secret: edr_client_id
  client_secret_secret: edr_client_secret
request: {path: /detections, records_path: resources}
map: {id: id, timestamp: ts}
"""


def test_oauth2_token_fetched_and_refreshed_on_401(runner):
    state = {"tokens": 0, "api": 0}

    def handler(req):
        if req.url.path == "/oauth2/token":
            state["tokens"] += 1
            body = dict(x.split("=") for x in req.content.decode().split("&"))
            assert body["grant_type"] == "client_credentials" and body["client_id"] == "edr-client"
            return httpx.Response(200, json={"access_token": f"tok{state['tokens']}", "expires_in": 300, "token_type": "bearer"})
        state["api"] += 1
        if req.headers["Authorization"] == "Bearer tok1":
            return httpx.Response(401, json={"error": "invalid_token"})  # token expired server-side
        assert req.headers["Authorization"] == "Bearer tok2"
        return httpx.Response(200, json={"resources": [{"id": "d1", "ts": "2026-10-31T01:00:00Z"}]})

    r = runner(OAUTH, handler)
    assert r.status == "success" and state["tokens"] == 2 and r.records_pulled == 1


def test_oauth2_bad_client_secret_is_auth_failed(runner):
    def handler(req):
        return httpx.Response(401, json={"error": "invalid_client"})

    r = runner(OAUTH, handler)
    assert r.status == "auth_failed" and "client credentials" in r.last_error


def test_secrets_never_appear_in_results(runner):
    text = FW.replace("header: X-API-Key", "query_param: api_key")

    def handler(req):
        assert req.url.params["api_key"] == "fw-SECRET-key-42"
        return httpx.Response(500, text="server error for key fw-SECRET-key-42")

    r = runner(text, handler)
    dumped = str(r.to_dict())
    assert "fw-SECRET-key-42" not in dumped and "***" in dumped


def test_circuit_opens_after_repeated_failures(store, sleeps):
    save_and_approve(FW.replace("map:", "limits: {circuit_after_failures: 2}\nmap:"), store=store)
    kw = dict(store=store, transport=httpx.MockTransport(lambda r: httpx.Response(503)),
              resolver=lambda h: ["93.184.216.34"], sleeper=sleeps.append)
    run_connector("mock-firewall", **kw)
    r = run_connector("mock-firewall", **kw)
    assert r.connector_status == "circuit_open"


def test_hook_called_with_failure_count(runner):
    from engine import on_run_finished

    seen = []
    on_run_finished.append(lambda cfg, res, row: seen.append((res.status, row["consecutive_failures"])))
    try:
        runner(FW, lambda r: httpx.Response(401))
    finally:
        on_run_finished.clear()
    assert seen == [("auth_failed", 1)]
