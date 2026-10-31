"""Onboard-from-sample on realistic response shapes: each draft must validate and map correctly."""

import pytest

from engine import load_config, profile_sample, validate_config
from tests_helpers import sample


def draft_ok(res):
    errs = [e for e in validate_config(res["draft_yaml"]) if e["level"] == "error"]
    assert errs == [], res["draft_yaml"]
    return load_config(res["draft_yaml"])


def spec(res, field):
    return res["guesses"].get(field, {}).get("spec")


def test_okta_users_with_link_header():
    text = 'HTTP/1.1 200 OK\nContent-Type: application/json\nLink: <https://dev-123456.okta.com/api/v1/users?after=00u7&limit=8>; rel="next"\n\n' + sample("okta_users.json")
    res = profile_sample(text)
    assert res["entity"] == "user" and res["records_path"] == ""
    assert res["paging_guess"]["type"] == "link_header"
    assert spec(res, "id") == {"path": "id"}
    assert spec(res, "email")["path"] in ("profile.email", "profile.login")
    assert spec(res, "status") == {"path": "status", "transform": "lower"}
    assert spec(res, "last_login") == {"path": "lastLogin", "transform": "to_utc"}
    assert "name" in res["guesses"] or "join" in res["draft_yaml"]
    cfg = draft_ok(res)
    assert cfg.source.base_url == "https://dev-123456.okta.com"
    assert res["confidence"]["level"] == "high"


def test_okta_system_log():
    res = profile_sample(sample("okta_logs.json"), "alert")
    assert spec(res, "id")["path"] == "uuid"
    assert spec(res, "timestamp")["path"] == "published"
    assert spec(res, "type")["path"] == "eventType"
    assert spec(res, "severity")["path"] == "severity"
    assert spec(res, "description")["path"] == "displayMessage"
    draft_ok(res)


def test_github_dependabot():
    res = profile_sample(sample("github_dependabot.json"), "alert")
    assert spec(res, "cve")["path"] == "security_advisory.cve_id"
    assert spec(res, "timestamp")["path"] in ("created_at", "updated_at")
    assert "severity" in spec(res, "severity")["path"]
    draft_ok(res)


def test_jira_search_body_token():
    res = profile_sample(sample("jira_search.json"))
    assert res["records_path"] == "issues" and res["entity"] == "alert"
    pg = res["paging_guess"]
    assert pg["type"] == "body_token" and pg["token_param"] == "nextPageToken" and pg.get("stop_path") == "isLast"
    assert spec(res, "timestamp")["path"] in ("fields.created", "fields.updated")
    assert spec(res, "description")["path"] == "fields.summary"
    cfg = draft_ok(res)
    assert cfg.source.base_url == "https://acme.atlassian.net"


def test_nvd_offset():
    res = profile_sample(sample("nvd_cves.json"))
    assert res["records_path"] == "vulnerabilities"
    pg = res["paging_guess"]
    assert pg["type"] == "offset" and pg["offset_param"] == "startIndex" and pg["total_path"] == "totalResults"
    assert spec(res, "cve")["path"] == "cve.id"
    assert spec(res, "timestamp")["path"] in ("cve.published", "cve.lastModified")
    draft_ok(res)


def test_cisa_kev_live_demo_source():
    res = profile_sample(sample("cisa_kev.json"))
    assert res["entity"] == "alert" and res["records_path"] == "vulnerabilities"
    assert spec(res, "id")["path"] == "cveID" and spec(res, "cve")["path"] == "cveID"
    assert spec(res, "timestamp")["path"] == "dateAdded"
    assert res["paging_guess"]["type"] == "none"
    cfg = draft_ok(res)
    assert all("_quarantined" not in m for m in res["preview_mapped"])
    assert cfg.map


def test_cloudtrail_post_next_token():
    res = profile_sample(sample("cloudtrail_lookup.json"), method="POST")
    assert res["records_path"] == "Events"
    pg = res["paging_guess"]
    assert pg["type"] == "body_token" and pg["token_param"] == "NextToken" and pg["token_in"] == "body"
    assert spec(res, "id")["path"] == "EventId"
    assert spec(res, "timestamp")["path"] == "EventTime"
    assert spec(res, "type")["path"] == "EventName"
    draft_ok(res)
    assert res["preview_mapped"][0]["timestamp"].endswith("Z")


def test_edr_nested_cursor():
    res = profile_sample(sample("edr_detections.json"), "alert")
    assert res["records_path"] == "resources"
    pg = res["paging_guess"]
    assert pg["type"] == "body_token" and pg["token_path"] == "meta.pagination.next" and pg["token_param"] == "after"
    assert spec(res, "id")["path"] == "composite_id"
    draft_ok(res)


def test_csv_devices():
    res = profile_sample(sample("devices.csv"))
    assert res["format"] == "csv" and res["entity"] == "device"
    assert spec(res, "ip")["path"] == "ip" and spec(res, "owner")["path"] == "owner"
    assert spec(res, "hostname")["path"] == "hostname"
    cfg = draft_ok(res)
    assert cfg.source.type == "file"


def test_garbage_is_a_clear_error():
    from engine.errors import ParseError

    with pytest.raises(ParseError):
        profile_sample("hello world")
