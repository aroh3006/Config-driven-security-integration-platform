"""Seeded fake data for the mock sources.

Follows the mock rules: documentation-range external IPs, 10.x internal hosts,
example.com identities, real CVE IDs from CISA KEV, correct CVSS v3.1 bands.
Every 100th record is messy on purpose. See mock_server/README.md.
"""

from __future__ import annotations

import hashlib
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

SEED = 42
WINDOW = timedelta(days=7)

# CVSS v3.1 base scores as listed by NVD. All nine are in the CISA KEV catalog.
KEV_CVES = {
    "CVE-2021-44228": 10.0,
    "CVE-2023-34362": 9.8,
    "CVE-2024-3400": 10.0,
    "CVE-2021-34527": 8.8,
    "CVE-2023-4966": 7.5,
    "CVE-2017-0144": 8.8,
    "CVE-2019-19781": 9.8,
    "CVE-2022-30190": 7.8,
    "CVE-2021-26855": 9.8,
}
TECHNIQUES = {
    "T1059.001": "PowerShell execution",
    "T1003.001": "LSASS memory access",
    "T1021.001": "Remote Desktop lateral movement",
    "T1566.001": "Spearphishing attachment opened",
    "T1486": "Data encrypted for impact",
    "T1190": "Exploit of a public-facing application",
    "T1078": "Use of valid accounts",
    "T1055": "Process injection",
    "T1071.001": "Web protocol command and control",
    "T1547.001": "Registry run key persistence",
}
EXTERNAL_RANGES = ("192.0.2", "198.51.100", "203.0.113")
PEOPLE = ("ann", "bob", "chitra", "dev", "esha", "farid", "gita", "hari")
FIREWALL_NAMES = (
    "Inbound connection blocked",
    "Port scan detected",
    "Exploit attempt blocked",
    "Outbound connection allowed",
)
CLOUD_EVENTS = (
    ("ConsoleLogin", "signin.amazonaws.com", "false"),
    ("AssumeRole", "sts.amazonaws.com", "true"),
    ("DescribeInstances", "ec2.amazonaws.com", "true"),
    ("PutBucketPolicy", "s3.amazonaws.com", "false"),
    ("CreateAccessKey", "iam.amazonaws.com", "false"),
    ("StopLogging", "cloudtrail.amazonaws.com", "false"),
)
CLOUD_ACCOUNT_ID = "123456789012"
CLOUD_REGION = "ap-south-1"
LAST_NAMES = ("Rao", "Iyer", "Menon", "Shah", "Nair", "Khan", "Desai", "Pillai")
OKTA_STATUSES = ("ACTIVE", "SUSPENDED", "PROVISIONED", "STAGED", "LOCKED_OUT", "PASSWORD_EXPIRED")
OKTA_EVENTS = (
    ("user.session.start", "User login to Okta"),
    ("user.authentication.sso", "User single sign on to app"),
    ("policy.evaluate_sign_on", "Evaluation of sign-on policy"),
    ("user.account.lock", "Okta user locked out"),
)
CWE_NAMES = {
    "CWE-20": "Improper Input Validation",
    "CWE-74": "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
    "CWE-77": "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-755": "Improper Handling of Exceptional Conditions",
    "CWE-1321": "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')",
}
# Facts copied from GitHub's public advisory database. Only the alerts built from them are fake.
GITHUB_ADVISORIES = (
    {
        "cve": "CVE-2021-44228",
        "ghsa": "GHSA-jfh8-c2jp-5v3q",
        "summary": "Remote code injection in Log4j",
        "severity": "critical",
        "score": 10.0,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H",
        "cwes": ("CWE-20", "CWE-400"),
        "published": "2021-12-10T00:40:56Z",
        "package": "org.apache.logging.log4j:log4j-core",
        "ecosystem": "maven",
        "range": ">= 2.13.0, < 2.15.0",
        "patched": "2.15.0",
        "installed": "2.14.1",
        "manifest": "pom.xml",
    },
    {
        "cve": "CVE-2022-22965",
        "ghsa": "GHSA-36p3-wjmg-h94x",
        "summary": "Remote Code Execution in Spring Framework",
        "severity": "critical",
        "score": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H",
        "cwes": ("CWE-74", "CWE-94"),
        "published": "2022-03-31T18:30:50Z",
        "package": "org.springframework:spring-beans",
        "ecosystem": "maven",
        "range": ">= 5.3.0, < 5.3.18",
        "patched": "5.3.18",
        "installed": "5.3.17",
        "manifest": "pom.xml",
    },
    {
        "cve": "CVE-2017-5638",
        "ghsa": "GHSA-j77q-2qqg-6989",
        "summary": "Apache Struts vulnerable to remote arbitrary command execution due to improper input validation",
        "severity": "critical",
        "score": 10.0,
        "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H",
        "cwes": ("CWE-20", "CWE-755"),
        "published": "2018-10-18T19:24:26Z",
        "package": "org.apache.struts:struts2-core",
        "ecosystem": "maven",
        "range": ">= 2.3.0, <= 2.3.31",
        "patched": "2.3.32",
        "installed": "2.3.31",
        "manifest": "pom.xml",
    },
    {
        "cve": "CVE-2022-28346",
        "ghsa": "GHSA-2gwj-7jmv-h26r",
        "summary": "SQL Injection in Django",
        "severity": "critical",
        "score": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwes": ("CWE-89",),
        "published": "2022-04-13T00:00:33Z",
        "package": "Django",
        "ecosystem": "pip",
        "range": ">= 2.2, < 2.2.28",
        "patched": "2.2.28",
        "installed": "2.2.27",
        "manifest": "requirements.txt",
    },
    {
        "cve": "CVE-2021-44906",
        "ghsa": "GHSA-xvch-5gv4-984h",
        "summary": "Prototype Pollution in minimist",
        "severity": "critical",
        "score": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwes": ("CWE-1321",),
        "published": "2022-03-18T00:01:09Z",
        "package": "minimist",
        "ecosystem": "npm",
        "range": ">= 1.0.0, < 1.2.6",
        "patched": "1.2.6",
        "installed": "1.2.5",
        "manifest": "package-lock.json",
    },
    {
        "cve": "CVE-2021-23337",
        "ghsa": "GHSA-35jh-r3h4-6jhm",
        "summary": "Command Injection in lodash",
        "severity": "high",
        "score": 7.2,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "cwes": ("CWE-77", "CWE-94"),
        "published": "2021-05-06T16:05:51Z",
        "package": "lodash",
        "ecosystem": "npm",
        "range": "< 4.17.21",
        "patched": "4.17.21",
        "installed": "4.17.20",
        "manifest": "package-lock.json",
    },
)
JIRA_PRIORITIES = (("Highest", "1"), ("High", "2"), ("Medium", "3"), ("Low", "4"), ("Lowest", "5"))
JIRA_STATUSES = (("To Do", "1", "new"), ("In Progress", "3", "indeterminate"), ("Done", "10001", "done"))
JIRA_SUMMARIES = (
    "Patch {cve} on internet-facing hosts",
    "Investigate failed logins for {user}",
    "Laptop reported stolen, owner {user}",
    "Review firewall exception request",
    "Rotate exposed service credential",
)
OS_VERSIONS = (
    ("Windows", "Windows 11 23H2"),
    ("Windows", "Windows Server 2022"),
    ("Mac", "macOS 15.0"),
    ("Linux", "Ubuntu 24.04"),
)


def severity_band(score: float) -> str:
    """Return the CVSS v3.1 qualitative rating for a base score."""
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _moment(rng: random.Random, now: datetime) -> datetime:
    return now - timedelta(seconds=rng.randrange(int(WINDOW.total_seconds())))


def _external_ip(rng: random.Random) -> str:
    return f"{rng.choice(EXTERNAL_RANGES)}.{rng.randrange(1, 255)}"


def _internal_ip(rng: random.Random) -> str:
    return f"10.{rng.randrange(0, 50)}.{rng.randrange(0, 255)}.{rng.randrange(1, 255)}"


def _digest(rng: random.Random) -> str:
    return hashlib.sha256(str(rng.random()).encode()).hexdigest()


def _email(rng: random.Random) -> str:
    return f"{rng.choice(PEOPLE)}@example.com"


def _uuid(rng: random.Random) -> str:
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


def _okta_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _person(n: int) -> tuple[str, str, str]:
    """Return (first, last, email). The first few match the other mock sources."""
    if n < len(PEOPLE):
        first = PEOPLE[n]
        return first.capitalize(), LAST_NAMES[n % len(LAST_NAMES)], f"{first}@example.com"
    return f"User{n:03d}", LAST_NAMES[n % len(LAST_NAMES)], f"user{n:03d}@example.com"


def _make_messy(records: list[dict[str, Any]], id_field: str, time_field: str, type_field: str) -> None:
    """Spoil every 100th record, cycling through the four kinds of damage."""
    for position, index in enumerate(range(50, len(records), 100)):
        record = records[index]
        kind = position % 4
        if kind == 0:
            del record[id_field]
        elif kind == 1:
            record[time_field] = None
        elif kind == 2:
            record[time_field] = "yesterday-ish"
        else:
            record[type_field] = {"unexpected": "object"}


def okta_users(now: datetime, base_url: str = "https://example.okta.example.com", count: int = 120) -> list[dict[str, Any]]:
    """Users shaped like Okta's User schema."""
    rng = random.Random(f"{SEED}-okta-users")
    users = []
    for n in range(count):
        first, last, email = _person(n)
        status = rng.choices(OKTA_STATUSES, weights=(82, 5, 5, 3, 3, 2))[0]
        moment = _moment(rng, now)
        user_id = f"00u{_digest(rng)[:17]}"
        users.append(
            {
                "id": user_id,
                "status": status,
                "created": _okta_time(moment - timedelta(days=rng.randrange(30, 400))),
                "activated": _okta_time(moment - timedelta(days=rng.randrange(10, 30))),
                "statusChanged": _okta_time(moment - timedelta(days=rng.randrange(1, 10))),
                "lastLogin": None if status in ("STAGED", "PROVISIONED") else _okta_time(moment),
                "lastUpdated": _okta_time(moment),
                "passwordChanged": _okta_time(moment - timedelta(days=rng.randrange(1, 90))),
                "type": {"id": "oty1example0000000000"},
                "profile": {
                    "firstName": first,
                    "lastName": last,
                    "login": email,
                    "email": email,
                    "mobilePhone": None,
                    "secondEmail": None,
                },
                "credentials": {
                    "password": {},
                    "provider": {"type": "OKTA", "name": "OKTA"},
                },
                "_links": {"self": {"href": f"{base_url}/api/v1/users/{user_id}"}},
            }
        )
    _make_messy(users, "id", "lastLogin", "status")
    return users


def okta_logs(now: datetime, count: int = 300) -> list[dict[str, Any]]:
    """Events shaped like Okta's LogEvent schema, oldest first."""
    rng = random.Random(f"{SEED}-okta-logs")
    events = []
    for _ in range(count):
        event_type, message = rng.choices(OKTA_EVENTS, weights=(70, 15, 10, 5))[0]
        failed = rng.random() < 0.15
        first, last, email = _person(rng.randrange(len(PEOPLE)))
        ip_address = _external_ip(rng)
        events.append(
            {
                "uuid": _uuid(rng),
                "published": _okta_time(_moment(rng, now)),
                "eventType": event_type,
                "legacyEventType": None,
                "version": "0",
                "severity": "WARN" if failed else "INFO",
                "displayMessage": message,
                "actor": {
                    "id": f"00u{_digest(rng)[:17]}",
                    "type": "User",
                    "alternateId": email,
                    "displayName": f"{first} {last}",
                    "detailEntry": None,
                },
                "client": {
                    "id": None,
                    "device": "Computer",
                    "zone": "null",
                    "ipAddress": ip_address,
                    "userAgent": {
                        "rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                        "os": "Windows 10",
                        "browser": "CHROME",
                    },
                    "geographicalContext": {"country": "India", "state": "Karnataka", "city": "Bengaluru"},
                },
                "outcome": {
                    "result": "FAILURE" if failed else "SUCCESS",
                    "reason": "VERIFICATION_ERROR" if failed else None,
                },
                "target": [],
                "transaction": {"type": "WEB", "id": _digest(rng)[:27], "detail": {}},
                "debugContext": {"debugData": {"requestId": _digest(rng)[:27]}},
                "authenticationContext": {"externalSessionId": _digest(rng)[:25]},
                "securityContext": {"asNumber": 64496, "asOrg": "example", "isp": "example", "domain": "example.com", "isProxy": False},
                "request": {"ipChain": [{"ip": ip_address, "version": "V4"}]},
            }
        )
    events.sort(key=lambda item: item["published"])
    _make_messy(events, "uuid", "published", "severity")
    events[50]["eventType"] = "user.session.start"
    return events


def github_members(count: int = 130) -> list[dict[str, Any]]:
    """Members shaped like GitHub's simple-user schema. Most have no name or email."""
    rng = random.Random(f"{SEED}-github-members")
    api = "https://api.example.com/users"
    members = []
    for n in range(count):
        first, last, email = _person(n)
        login = f"{first.lower()}-{last.lower()}"
        member: dict[str, Any] = {
            "login": login,
            "id": 5000 + n,
            "node_id": f"U_{_digest(rng)[:14]}",
            "avatar_url": f"https://avatars.example.com/u/{5000 + n}?v=4",
            "gravatar_id": "",
            "url": f"{api}/{login}",
            "html_url": f"https://git.example.com/{login}",
            "followers_url": f"{api}/{login}/followers",
            "following_url": f"{api}/{login}/following{{/other_user}}",
            "gists_url": f"{api}/{login}/gists{{/gist_id}}",
            "starred_url": f"{api}/{login}/starred{{/owner}}{{/repo}}",
            "subscriptions_url": f"{api}/{login}/subscriptions",
            "organizations_url": f"{api}/{login}/orgs",
            "repos_url": f"{api}/{login}/repos",
            "events_url": f"{api}/{login}/events{{/privacy}}",
            "received_events_url": f"{api}/{login}/received_events",
            "type": "User",
            "user_view_type": "public",
            "site_admin": False,
        }
        if n < len(PEOPLE):
            member["name"] = f"{first} {last}"
            member["email"] = email
        members.append(member)
    _make_messy(members, "id", "login", "type")
    return members


def github_dependabot(now: datetime, owner: str, repo: str, count: int = 60) -> list[dict[str, Any]]:
    """Alerts shaped like GitHub's dependabot-alert schema, built on real advisories."""
    rng = random.Random(f"{SEED}-github-dependabot")
    alerts = []
    for n in range(1, count + 1):
        item = rng.choice(GITHUB_ADVISORIES)
        moment = _moment(rng, now)
        fixed = n % 7 == 0
        package = {"ecosystem": item["ecosystem"], "name": item["package"]}
        vulnerability = {
            "package": package,
            "severity": item["severity"],
            "vulnerable_version_range": item["range"],
            "first_patched_version": {"identifier": item["patched"]},
        }
        alerts.append(
            {
                "number": n,
                "state": "fixed" if fixed else "open",
                "dependency": {
                    "package": package,
                    "manifest_path": item["manifest"],
                    "scope": "runtime",
                    "relationship": "direct",
                    "version_requirement": item["installed"],
                },
                "security_advisory": {
                    "ghsa_id": item["ghsa"],
                    "cve_id": item["cve"],
                    "summary": item["summary"],
                    "description": item["summary"],
                    "vulnerabilities": [vulnerability],
                    "severity": item["severity"],
                    "cvss": {"score": item["score"], "vector_string": item["vector"]},
                    "cwes": [{"cwe_id": cwe, "name": CWE_NAMES[cwe]} for cwe in item["cwes"]],
                    "identifiers": [
                        {"type": "GHSA", "value": item["ghsa"]},
                        {"type": "CVE", "value": item["cve"]},
                    ],
                    "references": [{"url": f"https://nvd.nist.gov/vuln/detail/{item['cve']}"}],
                    "published_at": item["published"],
                    "updated_at": item["published"],
                    "withdrawn_at": None,
                },
                "security_vulnerability": vulnerability,
                "url": f"https://api.example.com/repos/{owner}/{repo}/dependabot/alerts/{n}",
                "html_url": f"https://git.example.com/{owner}/{repo}/security/dependabot/{n}",
                "created_at": iso(moment),
                "updated_at": iso(moment),
                "dismissed_at": None,
                "dismissed_by": None,
                "dismissed_reason": None,
                "dismissed_comment": None,
                "fixed_at": iso(moment) if fixed else None,
                "auto_dismissed_at": None,
                "assignees": [],
            }
        )
    _make_messy(alerts, "number", "created_at", "state")
    return alerts


def jira_issues(now: datetime, project: str, count: int = 150) -> list[dict[str, Any]]:
    """Issues shaped like Jira Cloud search results, newest first.

    Timestamps use Jira's offset with no colon, like +0000. Descriptions use
    Atlassian Document Format, as API v3 does.
    """
    rng = random.Random(f"{SEED}-jira")
    issues = []
    for n in range(1, count + 1):
        moment = _moment(rng, now)
        first, last, email = _person(rng.randrange(len(PEOPLE)))
        summary = rng.choice(JIRA_SUMMARIES).format(cve=rng.choice(list(KEV_CVES)), user=email)
        priority, priority_id = rng.choice(JIRA_PRIORITIES)
        status, status_id, category = rng.choice(JIRA_STATUSES)
        created = moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        issues.append(
            {
                "expand": "operations,versionedRepresentations,editmeta,changelog,renderedFields",
                "id": str(10000 + n),
                "key": f"{project}-{n}",
                "fields": {
                    "summary": summary,
                    "description": {
                        "type": "doc",
                        "version": 1,
                        "content": [{"type": "paragraph", "content": [{"type": "text", "text": summary}]}],
                    },
                    "issuetype": {"id": "10001", "name": rng.choice(("Incident", "Task", "Bug")), "subtask": False},
                    "priority": {"id": priority_id, "name": priority},
                    "status": {"id": status_id, "name": status, "statusCategory": {"key": category}},
                    "project": {"id": "10000", "key": project, "name": "Security Operations", "projectTypeKey": "software"},
                    "created": created,
                    "updated": created,
                    "assignee": {
                        "accountId": f"5b10a2844c20165700ede{n:03d}",
                        "displayName": f"{first} {last}",
                        "emailAddress": email,
                        "active": True,
                    },
                    "labels": ["security"],
                },
            }
        )
    issues.sort(key=lambda item: item["fields"]["created"], reverse=True)
    _make_messy(issues, "key", "id", "expand")
    return issues


def firewall_events(now: datetime, count: int = 300) -> list[dict[str, Any]]:
    """Firewall events with CEF extension field names."""
    rng = random.Random(f"{SEED}-firewall")
    events = []
    for n in range(1, count + 1):
        name = rng.choice(FIREWALL_NAMES)
        moment = _moment(rng, now)
        event: dict[str, Any] = {
            "externalId": f"fw-{n:06d}",
            "rt": int(moment.timestamp() * 1000),
            "deviceVendor": "Example Networks",
            "deviceProduct": "ExampleFW",
            "deviceVersion": "9.1",
            "name": name,
            "severity": rng.randrange(0, 11),
            "src": _external_ip(rng),
            "spt": rng.randrange(1024, 65535),
            "dst": _internal_ip(rng),
            "dpt": rng.choice((22, 80, 443, 445, 3389, 8443)),
            "proto": rng.choice(("TCP", "UDP")),
            "act": "allowed" if name.startswith("Outbound") else "blocked",
            "msg": f"{name} on sensor fw-{rng.randrange(1, 5)}",
        }
        if name.startswith("Exploit"):
            event["cs1Label"] = "CVE"
            event["cs1"] = rng.choice(list(KEV_CVES))
        events.append(event)
    _make_messy(events, "externalId", "rt", "severity")
    return events


def edr_hosts(now: datetime, count: int = 200) -> list[dict[str, Any]]:
    rng = random.Random(f"{SEED}-hosts")
    hosts = []
    for n in range(1, count + 1):
        platform, version = rng.choice(OS_VERSIONS)
        last_seen = _moment(rng, now)
        hosts.append(
            {
                "device_id": _digest(rng)[:32],
                "hostname": f"host-{n:04d}",
                "local_ip": _internal_ip(rng),
                "external_ip": _external_ip(rng),
                "platform_name": platform,
                "os_version": version,
                "status": "normal",
                "first_seen": iso(last_seen - timedelta(days=rng.randrange(30, 400))),
                "last_seen": iso(last_seen),
                "last_login_user": _email(rng),
            }
        )
    _make_messy(hosts, "device_id", "last_seen", "os_version")
    return hosts


def edr_detections(now: datetime, count: int = 300) -> list[dict[str, Any]]:
    rng = random.Random(f"{SEED}-detections")
    detections = []
    for n in range(1, count + 1):
        technique = rng.choice(list(TECHNIQUES))
        cve = rng.choice(list(KEV_CVES)) if rng.random() < 0.2 else None
        score = KEV_CVES[cve] if cve else round(rng.uniform(2.0, 9.9), 1)
        detections.append(
            {
                "id": f"ldt:{n:06d}:{_digest(rng)[:12]}",
                "created_timestamp": iso(_moment(rng, now)),
                "technique_id": technique,
                "description": TECHNIQUES[technique],
                "severity_name": severity_band(score).capitalize(),
                "cvss_score": score,
                "cve": cve,
                "sha256": _digest(rng),
                "device": {"hostname": f"host-{rng.randrange(1, 201):04d}", "local_ip": _internal_ip(rng)},
                "user_name": _email(rng),
            }
        )
    _make_messy(detections, "id", "created_timestamp", "severity_name")
    return detections


def cloud_events(now: datetime, count: int = 300) -> list[dict[str, Any]]:
    """Events shaped like CloudTrail LookupEvents, newest first.

    `Cve` is the one field the real API does not have. It appears only on
    finding events. That gives the KEV match cloud rows to show.
    """
    rng = random.Random(f"{SEED}-cloud")
    events = []
    for _ in range(count):
        moment = _moment(rng, now)
        name, service, read_only = rng.choice(CLOUD_EVENTS)
        cve = None
        if rng.random() < 0.05:
            name, service, read_only = "BatchImportFindings", "securityhub.amazonaws.com", "false"
            cve = rng.choice(list(KEV_CVES))
        user = rng.choice(PEOPLE)
        event_id = _uuid(rng)
        event: dict[str, Any] = {
            "EventId": event_id,
            "EventName": name,
            "EventSource": service,
            "EventTime": moment.timestamp(),
            "ReadOnly": read_only,
            "Username": user,
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "Resources": [],
            "CloudTrailEvent": json.dumps(
                {
                    "eventVersion": "1.08",
                    "userIdentity": {
                        "type": "IAMUser",
                        "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                        "arn": f"arn:aws:iam::{CLOUD_ACCOUNT_ID}:user/{user}",
                        "accountId": CLOUD_ACCOUNT_ID,
                        "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
                        "userName": user,
                    },
                    "eventTime": iso(moment),
                    "eventSource": service,
                    "eventName": name,
                    "awsRegion": CLOUD_REGION,
                    "sourceIPAddress": _external_ip(rng),
                    "userAgent": "aws-cli/2.15.0",
                    "requestParameters": None,
                    "responseElements": None,
                    "requestID": _uuid(rng),
                    "eventID": event_id,
                    "readOnly": read_only == "true",
                    "eventType": "AwsApiCall",
                    "managementEvent": True,
                    "recipientAccountId": CLOUD_ACCOUNT_ID,
                    "eventCategory": "Management",
                }
            ),
        }
        if cve:
            event["Cve"] = cve
        events.append(event)
    events.sort(key=lambda item: item["EventTime"], reverse=True)
    _make_messy(events, "EventId", "EventTime", "EventName")
    return events
