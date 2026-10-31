"""Mapping (FR-5), bad data (FR-9), dedup, incremental (B-1), tamper hash, kill switch, file source."""

import httpx
import pytest

from engine import faults, load_config, run_connector, save_and_approve, test_connection
from engine.errors import MappingError
from engine.mapper import map_record, to_utc

USERS = """
name: okta-users
entity: user
source: {base_url: https://dev-1.okta.com, allow_hosts: [dev-1.okta.com]}
auth: {type: api_key, header: Authorization, prefix: "SSWS ", secret: okta_key}
request: {path: /api/v1/users}
pagination: {type: link_header}
required: [id, email]
map:
  id: id
  name: { join: [profile.firstName, profile.lastName], sep: " " }
  email: profile.login
  status: { path: status, transform: lower }
  last_login: { path: lastLogin, transform: to_utc }
"""


def okta_record(i, **over):
    r = {"id": f"00u{i}", "status": "ACTIVE", "lastLogin": "2026-10-30T18:22:05.000Z",
         "profile": {"firstName": "Ann", "lastName": "Rao", "login": f"u{i}@example.com"}}
    r.update(over)
    return r


@pytest.mark.parametrize("value,expected", [
    ("2026-10-30T18:22:05.000Z", "2026-10-30T18:22:05Z"),
    ("2026-10-30T10:00:00.000+0530", "2026-10-30T04:30:00Z"),     # Jira
    ("2024-04-12T08:15:06.230", "2024-04-12T08:15:06Z"),          # NVD (naive = UTC)
    (1793420000, "2026-10-31T04:13:20Z"),                         # CloudTrail epoch seconds
    (1793420000000, "2026-10-31T04:13:20Z"),                      # epoch ms
    ("Oct 31 2026 06:42:10", "2026-10-31T06:42:10Z"),             # CEF rt
    ("2021-12-10", "2021-12-10T00:00:00Z"),                       # CISA dateAdded
    ("Sat, 31 Oct 2026 06:42:10 GMT", "2026-10-31T06:42:10Z"),    # RFC 2822
])
def test_to_utc(value, expected):
    assert to_utc(value) == expected


def test_prd_mapping_example():
    cfg = load_config(USERS)
    row = map_record(okta_record(1), cfg)
    assert row == {"id": "00u1", "name": "Ann Rao", "email": "u1@example.com", "status": "active",
                   "last_login": "2026-10-30T18:22:05Z"}


def test_missing_required_field_reason():
    cfg = load_config(USERS)
    with pytest.raises(MappingError, match="missing required field 'email' \\(path profile.login\\)"):
        map_record(okta_record(1, profile={"firstName": "A"}), cfg)


def test_bad_date_reason():
    cfg = load_config(USERS)
    with pytest.raises(MappingError, match="last_login.*to_utc"):
        map_record(okta_record(1, lastLogin="yesterday-ish"), cfg)


def test_lookup_coalesce_const_regex():
    text = """
name: nvd
entity: alert
source: {base_url: https://services.nvd.nist.gov, allow_hosts: [services.nvd.nist.gov]}
request: {records_path: vulnerabilities}
map:
  id: cve.id
  type: { const: vulnerability }
  severity: { coalesce: [cve.metrics.cvssMetricV31.0.cvssData.baseSeverity, cve.metrics.cvssMetricV2.0.baseSeverity], transform: lower }
  timestamp: { path: cve.published, transform: to_utc }
  description: cve.descriptions.0.value
  cve: { path: cve.id, regex: "(CVE-\\\\d{4}-\\\\d+)" }
"""
    cfg = load_config(text)
    rec = {"cve": {"id": "CVE-2024-3400", "published": "2024-04-12T08:15:06.230",
                   "descriptions": [{"lang": "en", "value": "Command injection"}],
                   "metrics": {"cvssMetricV2": [{"baseSeverity": "HIGH"}]}}}
    row = map_record(rec, cfg)
    assert row["severity"] == "high" and row["type"] == "vulnerability" and row["cve"] == "CVE-2024-3400"


def test_three_of_n_quarantined_run_continues(runner, store):
    recs = [okta_record(i) for i in range(10)]
    recs[2]["profile"] = {}
    recs[5]["lastLogin"] = "not a date"
    recs[8]["id"] = None
    r = runner(USERS, lambda req: httpx.Response(200, json=recs))
    assert r.status == "partial" and r.records_pulled == 10 and r.records_bad == 3
    assert r.last_error == "3 of 10 records quarantined as invalid"
    assert len(store.tables["users"]) == 7 and len(store.quarantine) == 3
    assert r.connector_status == "degraded"


def test_rerun_upserts_without_duplicates(runner, store):
    recs = [okta_record(i) for i in range(4)]
    r1 = runner(USERS, lambda req: httpx.Response(200, json=recs))
    r2 = run_connector("okta-users", store=store, transport=httpx.MockTransport(lambda req: httpx.Response(200, json=recs)),
                       resolver=lambda h: ["93.184.216.34"])
    assert (r1.inserted, r2.inserted, r2.updated) == (4, 0, 4)
    assert len(store.tables["users"]) == 4


def test_badrecord_fault(runner, store):
    faults.set_fault("okta-users", "badrecord")
    r = runner(USERS, lambda req: httpx.Response(200, json=[okta_record(1)]))
    assert r.records_bad == 1 and "missing required field 'id'" in store.quarantine[0]["reason"]


def test_object_in_a_text_field_is_quarantined(runner, store):
    bad = okta_record(2)
    bad["status"] = {"unexpected": "object"}

    r = runner(USERS, lambda req: httpx.Response(200, json=[okta_record(1), bad]))
    assert r.status == "partial" and r.records_bad == 1 and len(store.tables["users"]) == 1
    assert "field 'status': expected a single value, got an object" in store.quarantine[0]["reason"]


def test_object_inside_a_join_is_quarantined(runner, store):
    bad = okta_record(2)
    bad["profile"]["firstName"] = ["a", "list"]

    r = runner(USERS, lambda req: httpx.Response(200, json=[okta_record(1), bad]))
    assert r.records_bad == 1
    assert "field 'name': expected a single value, got a list" in store.quarantine[0]["reason"]


def test_incremental_sends_and_advances_watermark(runner, store):
    text = USERS.replace("map:", "incremental: {field: lastUpdated, param: filter, template: 'lastUpdated gt \"{checkpoint}\"', start: '2026-10-01T00:00:00Z'}\nmap:")
    filters = []

    def h(req):
        filters.append(req.url.params.get("filter"))
        return httpx.Response(200, json=[okta_record(1, lastUpdated="2026-10-29T10:00:00.000Z"),
                                         okta_record(2, lastUpdated="2026-10-30T09:00:00.000Z")])

    runner(text, h)
    run_connector("okta-users", store=store, transport=httpx.MockTransport(h), resolver=lambda x: ["93.184.216.34"])
    assert filters[0] == 'lastUpdated gt "2026-10-01T00:00:00Z"'
    assert filters[1] == 'lastUpdated gt "2026-10-30T09:00:00.000Z"'


def test_tampered_config_refuses_to_run(store):
    save_and_approve(USERS, store=store)
    store.connectors["okta-users"]["config_yaml"] = USERS.replace("dev-1.okta.com]", "dev-1.okta.com, evil.example.com]")
    r = run_connector("okta-users", store=store)
    assert r.status == "config_changed" and store.audit_log[-1]["action"] == "run_refused"


def test_paused_connector_does_not_run(store):
    save_and_approve(USERS, store=store)
    store.set_status("okta-users", "paused")
    assert run_connector("okta-users", store=store).status == "paused"


def test_test_connection_stores_nothing(store):
    r = test_connection(USERS, transport=httpx.MockTransport(lambda req: httpx.Response(200, json=[okta_record(i) for i in range(5)])),
                        resolver=lambda h: ["93.184.216.34"])
    assert r.status == "success" and len(r.sample_mapped) == 3 and r.dry_run
    assert store.tables["users"] == {}


def test_unmapped_fields_reported(store):
    rec = okta_record(1, created="2026-01-01T00:00:00Z")
    r = test_connection(USERS, transport=httpx.MockTransport(lambda req: httpx.Response(200, json=[rec])),
                        resolver=lambda h: ["93.184.216.34"])
    assert "created" in r.unmapped_fields and "profile.login" not in r.unmapped_fields


def test_file_source_csv(tmp_path, monkeypatch, store):
    (tmp_path / "devices.csv").write_text("hostname,ip,os,owner,last_seen\nLAPTOP-1,10.0.0.5,Windows 11,a@example.com,2026-10-30T10:00:00Z\n,10.0.0.6,,,\n")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    text = """
name: devices-file
entity: device
source: {type: file, path: devices.csv}
map: {id: hostname, hostname: hostname, ip: ip, os: os, owner: owner, last_seen: {path: last_seen, transform: to_utc}}
"""
    save_and_approve(text, store=store)
    r = run_connector("devices-file", store=store)
    assert r.status == "partial" and r.records_pulled == 2 and r.records_bad == 1
    assert ("devices-file", "LAPTOP-1") in store.tables["devices"]
