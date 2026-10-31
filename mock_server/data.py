"""Seeded fake data for the mock sources.

Follows the mock rules: documentation-range external IPs, 10.x internal hosts,
example.com identities, real CVE IDs from CISA KEV, correct CVSS v3.1 bands and
real MITRE ATT&CK IDs. One person keeps the same identity across sources.
Every 100th record is messy on purpose. See mock_server/README.md.
"""

from __future__ import annotations

import base64
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
# ATT&CK name, tactic ID, tactic name, process name, command line and EDR severity.
# Names and tactics are from attack.mitre.org. The processes are illustrative.
TECHNIQUE_DETAILS = {
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "TA0002", "Execution", "powershell.exe", "powershell.exe -NoProfile -ExecutionPolicy Bypass -File update.ps1", 50),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "TA0006", "Credential Access", "procdump.exe", "procdump.exe -ma lsass.exe lsass.dmp", 90),
    "T1021.001": ("Remote Services: Remote Desktop Protocol", "TA0008", "Lateral Movement", "mstsc.exe", "mstsc.exe /v:host-0001", 50),
    "T1566.001": ("Phishing: Spearphishing Attachment", "TA0001", "Initial Access", "WINWORD.EXE", "WINWORD.EXE invoice.docm", 50),
    "T1486": ("Data Encrypted for Impact", "TA0040", "Impact", "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", 90),
    "T1190": ("Exploit Public-Facing Application", "TA0001", "Initial Access", "w3wp.exe", "w3wp.exe -ap DefaultAppPool", 70),
    "T1078": ("Valid Accounts", "TA0001", "Initial Access", "svchost.exe", "svchost.exe -k netsvcs", 30),
    "T1055": ("Process Injection", "TA0005", "Defense Evasion", "rundll32.exe", "rundll32.exe update.dll,Start", 70),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "TA0011", "Command and Control", "curl.exe", "curl.exe -s https://c2.example.com/beacon", 70),
    "T1547.001": ("Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "TA0003", "Persistence", "reg.exe", "reg.exe add HKCU Run /v updater", 50),
}
EDR_SEVERITY_NAMES = {30: "Low", 50: "Medium", 70: "High", 90: "Critical"}
EXTERNAL_RANGES = ("192.0.2", "198.51.100", "203.0.113")
PEOPLE = ("ann", "bob", "chitra", "dev", "esha", "farid", "gita", "hari")
# Name, CEF Device Event Class ID, inbound, action, severity range and destination ports.
FIREWALL_EVENTS = (
    ("Inbound connection blocked", "100", True, "blocked", (3, 5), (22, 445, 3389, 8443)),
    ("Port scan detected", "200", True, "blocked", (5, 7), (22, 80, 443, 445, 3389)),
    ("Exploit attempt blocked", "300", True, "blocked", (8, 10), (80, 443, 8443)),
    ("Outbound connection allowed", "400", False, "allowed", (1, 2), (53, 80, 443)),
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
CLOUD_SIGNIN_REGION = "us-east-1"
CLOUD_BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
FIRST_NAMES = (
    "Aarav", "Diya", "Ishaan", "Kavya", "Rohan", "Sneha", "Vikram", "Meera", "Arjun", "Nisha",
    "Karan", "Pooja", "Rahul", "Tara", "Sanjay", "Lakshmi", "Naveen", "Priya", "Imran", "Fatima",
)
LAST_NAMES = ("Rao", "Iyer", "Menon", "Shah", "Nair", "Khan", "Desai", "Pillai", "Gupta", "Reddy", "Bose", "Kulkarni")
OKTA_STATUSES = ("ACTIVE", "SUSPENDED", "PROVISIONED", "STAGED", "LOCKED_OUT", "PASSWORD_EXPIRED")
OKTA_EVENTS = (
    ("user.session.start", "User login to Okta"),
    ("user.authentication.sso", "User single sign on to app"),
    ("policy.evaluate_sign_on", "Evaluation of sign-on policy"),
    ("user.account.lock", "Max sign in attempts exceeded"),
)
OKTA_TYPE_ID = "oty1example000000000"
OKTA_APP_ID = "0oa1example000000000"
OKTA_RULE_ID = "rul1example000000000"
OKTA_GEO = {
    "city": "Bengaluru",
    "state": "Karnataka",
    "country": "India",
    "postalCode": "560001",
    "geolocation": {"lat": 12.9716, "lon": 77.5946},
}
OKTA_IP_DETAILS = {"asNumber": 64496, "asOrg": "example", "isp": "example", "domain": "example.com"}
CWE_NAMES = {
    "CWE-20": "Improper Input Validation",
    "CWE-74": "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
    "CWE-77": "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-755": "Improper Handling of Exceptional Conditions",
    "CWE-917": "Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')",
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
        "cwes": ("CWE-20", "CWE-400", "CWE-502", "CWE-917"),
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
JIRA_BASE = "https://example.atlassian.example.com"
JIRA_EXPAND = "renderedFields,names,schema,operations,editmeta,changelog,versionedRepresentations"
JIRA_STATUS_CATEGORIES = {
    "new": {"self": f"{JIRA_BASE}/rest/api/3/statuscategory/2", "id": 2, "key": "new", "colorName": "blue-gray", "name": "To Do"},
    "indeterminate": {"self": f"{JIRA_BASE}/rest/api/3/statuscategory/4", "id": 4, "key": "indeterminate", "colorName": "yellow", "name": "In Progress"},
    "done": {"self": f"{JIRA_BASE}/rest/api/3/statuscategory/3", "id": 3, "key": "done", "colorName": "green", "name": "Done"},
}
JIRA_ISSUE_TYPES = (("Incident", "10003"), ("Task", "10001"), ("Bug", "10004"))
GITHUB_DISMISS_REASONS = ("fix_started", "inaccurate", "no_bandwidth", "not_used", "tolerable_risk")
JIRA_SUMMARIES = (
    "Patch {cve} on internet-facing hosts",
    "Investigate failed logins for {user}",
    "Laptop reported stolen, owner {user}",
    "Review firewall exception request",
    "Rotate exposed service credential",
)
EDR_HOST_STATUSES = ("normal", "contained", "containment_pending")
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
        return first.capitalize(), LAST_NAMES[n], f"{first}@example.com"
    first = FIRST_NAMES[n % len(FIRST_NAMES)]
    last = LAST_NAMES[n // len(FIRST_NAMES) % len(LAST_NAMES)]
    return first, last, f"{first.lower()}.{last.lower()}@example.com"


def _okta_user_id(email: str) -> str:
    """Okta ids are 20 characters. Deriving it from the email keeps users and log actors in step."""
    return f"00u{hashlib.sha256(email.encode()).hexdigest()[:17]}"


def _atlassian_id(email: str) -> str:
    return hashlib.sha256(f"atlassian-{email}".encode()).hexdigest()[:24]


def _put(record: dict[str, Any], path: str, value: Any) -> None:
    *parents, leaf = path.split(".")
    for key in parents:
        record = record[key]
    record[leaf] = value


def _make_messy(
    records: list[dict[str, Any]], id_field: str, time_field: str, type_field: str, first_kind: int = 0
) -> None:
    """Spoil every 100th record, cycling through the four kinds of damage.

    Short lists only reach the first kind or two. `first_kind` moves the start of
    the cycle. That way every kind appears across the sources.
    """
    for position, index in enumerate(range(50, len(records), 100)):
        record = records[index]
        kind = (position + first_kind) % 4
        if kind == 0:
            del record[id_field]
        elif kind == 1:
            _put(record, time_field, None)
        elif kind == 2:
            _put(record, time_field, "yesterday-ish")
        else:
            _put(record, type_field, {"unexpected": "object"})


def okta_users(now: datetime, base_url: str = "https://example.okta.example.com", count: int = 120) -> list[dict[str, Any]]:
    """Users shaped like a real /api/v1/users response.

    Dates follow the lifecycle. STAGED users were never activated. STAGED and
    PROVISIONED users have no password and have never logged in.
    """
    rng = random.Random(f"{SEED}-okta-users")
    users = []
    for n in range(count):
        first, last, email = _person(n)
        status = rng.choices(OKTA_STATUSES, weights=(82, 5, 5, 3, 3, 2))[0]
        updated = _moment(rng, now)
        created = updated - timedelta(days=rng.randrange(200, 400))
        activated = None if status == "STAGED" else created + timedelta(days=rng.randrange(1, 6))
        has_password = status not in ("STAGED", "PROVISIONED")
        password_changed = activated + timedelta(days=rng.randrange(1, 90)) if has_password else None
        status_changed = None if status == "STAGED" else updated - timedelta(days=rng.randrange(1, 10))
        user_id = _okta_user_id(email)
        credentials: dict[str, Any] = {"provider": {"type": "OKTA", "name": "OKTA"}}
        if has_password:
            credentials = {"password": {}, **credentials}
        users.append(
            {
                "id": user_id,
                "status": status,
                "created": _okta_time(created),
                "activated": activated and _okta_time(activated),
                "statusChanged": status_changed and _okta_time(status_changed),
                "lastLogin": _okta_time(updated) if has_password else None,
                "lastUpdated": _okta_time(updated),
                "passwordChanged": password_changed and _okta_time(password_changed),
                "type": {"id": OKTA_TYPE_ID},
                "profile": {
                    "firstName": first,
                    "lastName": last,
                    "login": email,
                    "email": email,
                    "mobilePhone": None,
                    "secondEmail": None,
                },
                "credentials": credentials,
                "_links": {"self": {"href": f"{base_url}/api/v1/users/{user_id}"}},
            }
        )
    _make_messy(users, "id", "lastLogin", "status")
    return users


def _okta_outcome(rng: random.Random, event_type: str) -> tuple[str, str | None, str, str | None]:
    """Return (result, reason, severity, legacyEventType), using values seen in a real org."""
    if event_type == "policy.evaluate_sign_on":
        result, step = rng.choices(
            (("ALLOW", "AUTHENTICATED"), ("CHALLENGE", "CHALLENGE"), ("CHALLENGE", "ENROLL"), ("DENY", "DENY")),
            weights=(70, 18, 7, 5),
        )[0]
        return result, f"Sign-on policy evaluation resulted in {step}", "WARN" if result == "DENY" else "INFO", None
    if event_type == "user.account.lock":
        return "FAILURE", "LOCKED_OUT", "WARN", None
    if event_type == "user.authentication.sso":
        return "SUCCESS", None, "INFO", "app.auth.sso"
    if rng.random() < 0.15:
        reason, severity = rng.choice((("VERIFICATION_ERROR", "INFO"), ("INVALID_CREDENTIALS", "WARN")))
        return "FAILURE", reason, severity, "core.user_auth.login_failed"
    return "SUCCESS", None, "INFO", "core.user_auth.login_success"


def _okta_target(event_type: str, actor: dict[str, Any], outcome: str) -> list[dict[str, Any]]:
    """Target list by event type, matching the target types seen in a real org."""
    if event_type == "user.account.lock":
        return []
    app = {
        "id": OKTA_APP_ID,
        "type": "AppInstance",
        "alternateId": "Example Portal",
        "displayName": "Example Portal",
        "detailEntry": {"signOnModeType": "OPENID_CONNECT"},
    }
    if event_type == "policy.evaluate_sign_on":
        app["detailEntry"]["signOnModeEvaluationResult"] = outcome
        rule = {"id": OKTA_RULE_ID, "type": "Rule", "alternateId": "Catch-all Rule", "displayName": "Catch-all Rule", "detailEntry": None}
        return [app, rule]
    person_type = "AppUser" if event_type == "user.authentication.sso" else "User"
    return [app, {**actor, "type": person_type}]


def okta_logs(now: datetime, count: int = 300) -> list[dict[str, Any]]:
    """Sign-in events shaped like real /api/v1/logs records, oldest first.

    Actors are real mock users. Their `actor.id` matches okta_users.
    """
    rng = random.Random(f"{SEED}-okta-logs")
    events = []
    for _ in range(count):
        event_type, message = rng.choices(OKTA_EVENTS, weights=(70, 15, 10, 5))[0]
        result, reason, severity, legacy = _okta_outcome(rng, event_type)
        first, last, email = _person(rng.randrange(len(PEOPLE)))
        ip_address = _external_ip(rng)
        actor = {
            "id": _okta_user_id(email),
            "type": "User",
            "alternateId": email,
            "displayName": f"{first} {last}",
            "detailEntry": None,
        }
        events.append(
            {
                "uuid": _uuid(rng),
                "published": _okta_time(_moment(rng, now)),
                "eventType": event_type,
                "legacyEventType": legacy,
                "version": "0",
                "severity": severity,
                "displayMessage": message,
                "actor": actor,
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
                    "geographicalContext": OKTA_GEO,
                },
                "device": None,
                "gatewayContext": None,
                "outcome": {"result": result, "reason": reason},
                "target": _okta_target(event_type, actor, result),
                "transaction": {"type": "WEB", "id": _digest(rng)[:27], "detail": {}},
                "debugContext": {
                    "debugData": {
                        "requestId": _digest(rng)[:27],
                        "requestUri": "/idp/idx/identify",
                        "url": "/idp/idx/identify",
                    }
                },
                "authenticationContext": {
                    "authenticationProvider": None,
                    "credentialProvider": None,
                    "credentialType": None,
                    "issuer": None,
                    "interface": None,
                    "authenticationStep": 0,
                    "rootSessionId": _digest(rng)[:25],
                    "externalSessionId": _digest(rng)[:25],
                },
                "securityContext": {"asNumber": 64496, "asOrg": "example", "isp": "example", "domain": "example.com", "isProxy": False},
                "request": {
                    "ipChain": [
                        {
                            "ip": ip_address,
                            "geographicalContext": OKTA_GEO,
                            "version": "V4",
                            "source": None,
                            "ipDetails": OKTA_IP_DETAILS,
                        }
                    ]
                },
            }
        )
    events.sort(key=lambda item: item["published"])
    _make_messy(events, "uuid", "published", "severity")
    events[50]["eventType"] = "user.session.start"
    return events


def github_members(count: int = 130) -> list[dict[str, Any]]:
    """Members shaped like a real /orgs/{org}/members response.

    The real list has no name or email. All 100 rows of a live response omitted both.
    """
    api = "https://api.example.com/users"
    members = []
    for n in range(count):
        first, last, _ = _person(n)
        login = f"{first.lower()}-{last.lower()}"
        user_id = 5000 + n
        members.append(
            {
                "login": login,
                "id": user_id,
                "node_id": base64.b64encode(f"04:User{user_id}".encode()).decode(),
                "avatar_url": f"https://avatars.example.com/u/{user_id}?v=4",
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
        )
    _make_messy(members, "id", "login", "type")
    return members


def github_dependabot(now: datetime, owner: str, repo: str, count: int = 60) -> list[dict[str, Any]]:
    """Alerts shaped like GitHub's dependabot-alert schema, built on real advisories.

    Alert numbers rise with time. The newest comes first, the API's default sort.
    Fixed and dismissed alerts close after they were created.
    """
    rng = random.Random(f"{SEED}-github-dependabot")
    dismisser = github_members(1)[0]
    alerts = []
    for n, created in enumerate(sorted(_moment(rng, now) for _ in range(count)), 1):
        item = rng.choice(GITHUB_ADVISORIES)
        state = rng.choices(("open", "fixed", "dismissed"), weights=(75, 15, 10))[0]
        closed = None if state == "open" else min(created + timedelta(hours=rng.randrange(1, 72)), now)
        package = {"ecosystem": item["ecosystem"], "name": item["package"]}
        vulnerability = {
            "package": package,
            "severity": item["severity"],
            "vulnerable_version_range": item["range"],
            "first_patched_version": {"identifier": item["patched"]},
        }
        dismissed = state == "dismissed"
        alerts.append(
            {
                "number": n,
                "state": state,
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
                "created_at": iso(created),
                "updated_at": iso(closed or created),
                "dismissed_at": iso(closed) if dismissed else None,
                "dismissed_by": dismisser if dismissed else None,
                "dismissed_reason": rng.choice(GITHUB_DISMISS_REASONS) if dismissed else None,
                "dismissed_comment": "Reviewed by the security team." if dismissed else None,
                "fixed_at": iso(closed) if state == "fixed" else None,
                "auto_dismissed_at": None,
                "assignees": [],
            }
        )
    alerts.reverse()
    _make_messy(alerts, "number", "created_at", "state")
    return alerts


def _jira_time(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000")


def _jira_user(first: str, last: str, email: str) -> dict[str, Any]:
    account_id = _atlassian_id(email)
    return {
        "self": f"{JIRA_BASE}/rest/api/3/user?accountId={account_id}",
        "accountId": account_id,
        "accountType": "atlassian",
        "displayName": f"{first} {last}",
        "emailAddress": email,
        "active": True,
        "timeZone": "Asia/Calcutta",
    }


def _jira_issue_type(name: str, type_id: str) -> dict[str, Any]:
    return {
        "self": f"{JIRA_BASE}/rest/api/3/issuetype/{type_id}",
        "id": type_id,
        "description": "",
        "iconUrl": f"{JIRA_BASE}/rest/api/2/universal_avatar/view/type/issuetype/avatar/10318",
        "name": name,
        "subtask": False,
        "avatarId": 10318,
        "entityId": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{name}.example.com")),
        "hierarchyLevel": 0,
    }


def _jira_status(name: str, status_id: str, category: str) -> dict[str, Any]:
    return {
        "self": f"{JIRA_BASE}/rest/api/3/status/{status_id}",
        "description": "",
        "iconUrl": f"{JIRA_BASE}/images/icons/statuses/generic.png",
        "name": name,
        "id": status_id,
        "statusCategory": JIRA_STATUS_CATEGORIES[category],
    }


def jira_issues(now: datetime, project: str, count: int = 150) -> list[dict[str, Any]]:
    """Issues shaped like Jira Cloud search results, newest first.

    Issue keys rise with time. Timestamps use Jira's offset with no colon, like
    +0000. Descriptions use Atlassian Document Format, as API v3 does.
    """
    rng = random.Random(f"{SEED}-jira")
    issues = []
    for n, created in enumerate(sorted(_moment(rng, now) for _ in range(count)), 1):
        first, last, email = _person(rng.randrange(len(PEOPLE)))
        summary = rng.choice(JIRA_SUMMARIES).format(cve=rng.choice(list(KEV_CVES)), user=email)
        priority, priority_id = rng.choice(JIRA_PRIORITIES)
        status, status_id, category = rng.choice(JIRA_STATUSES)
        issue_type, issue_type_id = rng.choice(JIRA_ISSUE_TYPES)
        updated = min(created + timedelta(hours=rng.randrange(1, 96)), now)
        done = category == "done"
        issues.append(
            {
                "expand": JIRA_EXPAND,
                "id": str(10000 + n),
                "key": f"{project}-{n}",
                "fields": {
                    "summary": summary,
                    "description": {
                        "type": "doc",
                        "version": 1,
                        "content": [{"type": "paragraph", "content": [{"type": "text", "text": summary}]}],
                    },
                    "issuetype": _jira_issue_type(issue_type, issue_type_id),
                    "priority": {"id": priority_id, "name": priority},
                    "status": _jira_status(status, status_id, category),
                    "resolution": {"id": "10000", "name": "Done"} if done else None,
                    "resolutiondate": _jira_time(updated) if done else None,
                    "project": {
                        "self": f"{JIRA_BASE}/rest/api/3/project/10000",
                        "id": "10000",
                        "key": project,
                        "name": "Security Operations",
                        "projectTypeKey": "software",
                        "simplified": True,
                    },
                    "created": _jira_time(created),
                    "updated": _jira_time(updated),
                    "assignee": _jira_user(first, last, email),
                    "reporter": _jira_user(*_person(0)),
                    "labels": ["security"],
                },
            }
        )
    issues.reverse()
    _make_messy(issues, "key", "fields.created", "fields.priority")
    return issues


def firewall_events(now: datetime, count: int = 300) -> list[dict[str, Any]]:
    """Firewall events with CEF header and extension field names, oldest first.

    Direction, port, protocol and severity follow the event name. Outbound traffic
    runs from an internal host to an external one. Inbound traffic runs the other way.
    """
    rng = random.Random(f"{SEED}-firewall")
    events = []
    for _ in range(count):
        name, signature, inbound, action, (low, high), ports = rng.choice(FIREWALL_EVENTS)
        external, internal = _external_ip(rng), _internal_ip(rng)
        port = rng.choice(ports)
        event: dict[str, Any] = {
            "rt": int(_moment(rng, now).timestamp() * 1000),
            "deviceVendor": "Example Networks",
            "deviceProduct": "ExampleFW",
            "deviceVersion": "9.1",
            "deviceEventClassId": signature,
            "name": name,
            "severity": rng.randint(low, high),
            "src": external if inbound else internal,
            "spt": rng.randrange(1024, 65535),
            "dst": internal if inbound else external,
            "dpt": port,
            "proto": "UDP" if port == 53 else "TCP",
            "deviceDirection": 0 if inbound else 1,
            "act": action,
            "msg": f"{name} on sensor fw-{rng.randrange(1, 5)}",
        }
        if name.startswith("Exploit"):
            event["cs1Label"] = "CVE"
            event["cs1"] = rng.choice(list(KEV_CVES))
        events.append(event)
    events.sort(key=lambda item: item["rt"])
    for n, event in enumerate(events, 1):
        event["externalId"] = f"fw-{n:06d}"
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
                "status": rng.choices(EDR_HOST_STATUSES, weights=(95, 4, 1))[0],
                "first_seen": iso(last_seen - timedelta(days=rng.randrange(30, 400))),
                "last_seen": iso(last_seen),
                "last_login_user": _email(rng),
            }
        )
    _make_messy(hosts, "device_id", "last_seen", "os_version", first_kind=2)
    return hosts


def edr_detections(now: datetime, count: int = 300) -> list[dict[str, Any]]:
    """Detections on real mock hosts, newest first.

    Device fields match edr_hosts. `cve` and `cvss_score` appear only on exploit
    detections. CVSS rates vulnerabilities, not behaviour. Other detections take
    their severity from the technique.
    """
    rng = random.Random(f"{SEED}-detections")
    windows_hosts = [h for h in edr_hosts(now) if h["platform_name"] == "Windows" and "device_id" in h]
    detections = []
    for n in range(1, count + 1):
        cve = rng.choice(list(KEV_CVES)) if rng.random() < 0.2 else None
        technique = "T1190" if cve else rng.choice(list(TECHNIQUES))
        name, tactic_id, tactic, filename, cmdline, severity = TECHNIQUE_DETAILS[technique]
        score = KEV_CVES[cve] if cve else None
        host = rng.choice(windows_hosts)
        detections.append(
            {
                "id": f"ldt:{host['device_id']}:{n}",
                "created_timestamp": iso(_moment(rng, now)),
                "status": rng.choices(("new", "in_progress", "closed"), weights=(60, 25, 15))[0],
                "tactic_id": tactic_id,
                "tactic": tactic,
                "technique_id": technique,
                "technique": name,
                "description": TECHNIQUES[technique],
                "severity": int(score * 10) if score else severity,
                "severity_name": severity_band(score).capitalize() if score else EDR_SEVERITY_NAMES[severity],
                "cvss_score": score,
                "cve": cve,
                "filename": filename,
                "cmdline": cmdline,
                "sha256": _digest(rng),
                "device": {
                    "device_id": host["device_id"],
                    "hostname": host["hostname"],
                    "local_ip": host["local_ip"],
                    "platform_name": host["platform_name"],
                },
                "user_name": host["last_login_user"],
            }
        )
    detections.sort(key=lambda item: item["created_timestamp"], reverse=True)
    _make_messy(detections, "id", "created_timestamp", "severity_name", first_kind=3)
    return detections


def _cloud_record(rng: random.Random, name: str, service: str, read_only: str, user: str, moment: datetime, event_id: str) -> dict[str, Any]:
    """One CloudTrail record. Console sign-ins differ from API calls, as AWS documents."""
    identity: dict[str, Any] = {
        "type": "IAMUser",
        "principalId": "AIDACKCEVSQ6C2EXAMPLE",
        "arn": f"arn:aws:iam::{CLOUD_ACCOUNT_ID}:user/{user}",
        "accountId": CLOUD_ACCOUNT_ID,
        "userName": user,
    }
    record: dict[str, Any] = {
        "eventVersion": "1.08",
        "userIdentity": identity,
        "eventTime": iso(moment),
        "eventSource": service,
        "eventName": name,
        "awsRegion": CLOUD_REGION,
        "sourceIPAddress": _external_ip(rng),
        "userAgent": "aws-cli/2.15.0",
        "requestParameters": None,
        "responseElements": None,
        "eventID": event_id,
        "readOnly": read_only == "true",
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": CLOUD_ACCOUNT_ID,
        "eventCategory": "Management",
    }
    if name != "ConsoleLogin":
        identity["accessKeyId"] = "AKIAIOSFODNN7EXAMPLE"
        record["requestID"] = _uuid(rng)
        return record
    failed = rng.random() < 0.1
    record.update(
        {
            "awsRegion": CLOUD_SIGNIN_REGION,
            "userAgent": CLOUD_BROWSER,
            "responseElements": {"ConsoleLogin": "Failure" if failed else "Success"},
            "additionalEventData": {"MobileVersion": "No", "MFAUsed": rng.choice(("Yes", "No"))},
            "eventType": "AwsConsoleSignIn",
        }
    )
    if failed:
        record["errorMessage"] = "Failed authentication"
    return record


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
            "Resources": [],
            "CloudTrailEvent": json.dumps(_cloud_record(rng, name, service, read_only, user, moment, event_id)),
        }
        if name != "ConsoleLogin":
            event["AccessKeyId"] = "AKIAIOSFODNN7EXAMPLE"
        if cve:
            event["Cve"] = cve
        events.append(event)
    events.sort(key=lambda item: item["EventTime"], reverse=True)
    _make_messy(events, "EventId", "EventTime", "EventName", first_kind=1)
    return events
