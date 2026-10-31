"""Mock data must behave like real data, not only have the right field names."""

import json
from datetime import datetime, timezone

from mock_server import data

NOW = datetime(2026, 10, 31, 8, 0, tzinfo=timezone.utc)


def when(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00").replace("+0000", "+00:00"))


def test_okta_dates_follow_the_user_lifecycle():
    users = [u for u in data.okta_users(NOW) if "id" in u]
    assert all(len(u["id"]) == 20 and len(u["type"]["id"]) == 20 for u in users)
    for user in users:
        if user["activated"]:
            assert when(user["created"]) < when(user["activated"])
        if user["passwordChanged"]:
            assert when(user["activated"]) < when(user["passwordChanged"]) < when(user["lastUpdated"])
    staged = [u for u in users if u["status"] == "STAGED"]
    assert staged and all(u["activated"] is None for u in staged)
    no_password = [u for u in users if u["status"] in ("STAGED", "PROVISIONED")]
    assert no_password and all(u["passwordChanged"] is None and "password" not in u["credentials"] for u in no_password)


def test_people_have_real_names_and_unique_emails():
    users = data.okta_users(NOW)
    assert not any(u["profile"]["firstName"].startswith("User") for u in users)
    assert len({u["profile"]["email"] for u in users}) == len(users)


def test_okta_log_actors_are_real_users_with_one_id_each():
    user_ids = {u["id"] for u in data.okta_users(NOW) if "id" in u}
    events = data.okta_logs(NOW)
    assert all(e["actor"]["id"] in user_ids for e in events)
    by_person = {}
    for event in events:
        by_person.setdefault(event["actor"]["alternateId"], set()).add(event["actor"]["id"])
    assert all(len(ids) == 1 for ids in by_person.values())


def test_okta_outcomes_use_the_values_each_event_really_has():
    events = data.okta_logs(NOW)
    outcomes = {}
    for event in events:
        outcomes.setdefault(event["eventType"], set()).add(event["outcome"]["result"])
    assert outcomes["policy.evaluate_sign_on"] == {"ALLOW", "CHALLENGE", "DENY"}
    assert outcomes["user.session.start"] == {"SUCCESS", "FAILURE"}
    assert outcomes["user.authentication.sso"] == {"SUCCESS"}
    locks = [e for e in events if e["eventType"] == "user.account.lock" and isinstance(e["severity"], str)]
    assert locks and all(e["severity"] == "WARN" for e in locks)
    assert {e["displayMessage"] for e in locks} == {"Max sign in attempts exceeded"}


def test_okta_events_carry_the_real_nested_fields():
    event = data.okta_logs(NOW)[0]
    assert "rootSessionId" in event["authenticationContext"]
    assert set(event["client"]["geographicalContext"]) == {"city", "state", "country", "postalCode", "geolocation"}
    assert {"ip", "geographicalContext", "version", "source", "ipDetails"} == set(event["request"]["ipChain"][0])


def test_github_members_have_no_name_or_email():
    assert not any("name" in m or "email" in m for m in data.github_members())


def test_github_alerts_are_newest_first_and_close_after_they_open():
    alerts = [a for a in data.github_dependabot(NOW, "o", "r") if "number" in a]
    numbers = [a["number"] for a in alerts]
    assert numbers == sorted(numbers, reverse=True)
    assert [a["created_at"] for a in alerts] == sorted((a["created_at"] for a in alerts), reverse=True)
    assert {a["state"] for a in alerts} == {"open", "fixed", "dismissed"}
    for alert in alerts:
        closed = alert["fixed_at"] or alert["dismissed_at"]
        assert (closed is None) == (alert["state"] == "open")
        if closed:
            assert when(closed) > when(alert["created_at"]) and alert["updated_at"] == closed
        if alert["state"] == "dismissed":
            assert alert["dismissed_reason"] in data.GITHUB_DISMISS_REASONS and alert["dismissed_by"]["login"]


def test_log4j_advisory_lists_all_of_its_cwes():
    log4j = next(a for a in data.GITHUB_ADVISORIES if a["cve"] == "CVE-2021-44228")
    assert set(log4j["cwes"]) == {"CWE-20", "CWE-400", "CWE-502", "CWE-917"}
    assert all(cwe in data.CWE_NAMES for a in data.GITHUB_ADVISORIES for cwe in a["cwes"])


def test_jira_issues_keep_time_order_and_resolve_when_done():
    issues = [i for i in data.jira_issues(NOW, "SEC") if "key" in i]
    numbers = [int(i["key"].split("-")[1]) for i in issues]
    assert numbers == sorted(numbers, reverse=True)
    assert len({i["fields"]["issuetype"]["id"] for i in issues}) == 3
    assert len({(i["fields"]["issuetype"]["id"], i["fields"]["issuetype"]["name"]) for i in issues}) == 3
    for issue in issues:
        fields = issue["fields"]
        assert when(fields["updated"]) >= when(fields["created"])
        assert (fields["resolution"] is not None) == (fields["status"]["statusCategory"]["key"] == "done")
    assert all({"self", "id", "key", "colorName", "name"} == set(i["fields"]["status"]["statusCategory"]) for i in issues)


def test_jira_keeps_one_account_id_per_person():
    ids = {}
    for issue in data.jira_issues(NOW, "SEC"):
        assignee = issue["fields"]["assignee"]
        ids.setdefault(assignee["emailAddress"], set()).add(assignee["accountId"])
    assert all(len(found) == 1 and len(next(iter(found))) == 24 for found in ids.values())


def test_firewall_events_make_network_sense():
    events = data.firewall_events(NOW)
    assert all(e["deviceEventClassId"] for e in events)
    assert not any(e["proto"] == "UDP" and e["dpt"] != 53 for e in events)
    limits = {name: (low, high) for name, _, _, _, (low, high), _ in data.FIREWALL_EVENTS}
    for event in events:
        if isinstance(event["severity"], int):
            low, high = limits[event["name"]]
            assert low <= event["severity"] <= high
    times = [e["rt"] for e in events if isinstance(e["rt"], int)]
    assert times == sorted(times)


def test_edr_detections_point_at_real_hosts():
    hosts = {h["hostname"]: h for h in data.edr_hosts(NOW)}
    detections = data.edr_detections(NOW)
    for detection in detections:
        host, device = hosts[detection["device"]["hostname"]], detection["device"]
        assert (device["device_id"], device["local_ip"]) == (host["device_id"], host["local_ip"])
        assert detection["user_name"] == host["last_login_user"]
        assert detection["tactic_id"].startswith("TA") and detection["technique_id"] in data.TECHNIQUE_DETAILS


def test_only_vulnerabilities_carry_a_cvss_score():
    detections = data.edr_detections(NOW)
    with_cve = [d for d in detections if d["cve"]]
    assert with_cve and all(d["cvss_score"] == data.KEV_CVES[d["cve"]] for d in with_cve)
    assert all(d["technique_id"] == "T1190" for d in with_cve)
    assert all(d["cvss_score"] is None for d in detections if not d["cve"])


def test_console_logins_look_like_console_logins():
    events = [e for e in data.cloud_events(NOW) if e["EventName"] == "ConsoleLogin"]
    assert events and not any("AccessKeyId" in e for e in events)
    for event in events:
        record = json.loads(event["CloudTrailEvent"])
        assert record["eventType"] == "AwsConsoleSignIn"
        assert record["responseElements"]["ConsoleLogin"] in ("Success", "Failure")
        assert "accessKeyId" not in record["userIdentity"] and "requestID" not in record
        assert record["userAgent"].startswith("Mozilla/")


def test_every_kind_of_damage_appears():
    sets = {
        "id": ((data.firewall_events(NOW), "externalId"),),
        "null": ((data.okta_logs(NOW), "published"), (data.cloud_events(NOW), "EventTime")),
        "text": ((data.edr_hosts(NOW), "last_seen"),),
        "type": ((data.edr_detections(NOW), "severity_name"), (data.cloud_events(NOW), "EventName")),
    }
    assert any(field not in row for rows, field in sets["id"] for row in rows)
    assert any(row.get(field, "x") is None for rows, field in sets["null"] for row in rows)
    assert any(row.get(field) == "yesterday-ish" for rows, field in sets["text"] for row in rows)
    assert any(isinstance(row.get(field), dict) for rows, field in sets["type"] for row in rows)


def test_messy_share_stays_small():
    for rows in (data.firewall_events(NOW), data.edr_detections(NOW), data.cloud_events(NOW)):
        clean = [r for r in rows if "unexpected" not in str(r) and "yesterday-ish" not in str(r)]
        assert len(rows) - len(clean) <= len(rows) * 0.02
