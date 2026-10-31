"""Seeded fake data for the mock sources.

Follows the mock rules: documentation-range external IPs, 10.x internal hosts,
example.com identities, real CVE IDs from CISA KEV, correct CVSS v3.1 bands.
Every 100th record is messy on purpose. See mock_server/README.md.
"""

from __future__ import annotations

import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from typing import Any

SEED = 42
WINDOW = timedelta(days=7)

KEV_CVES = {
    "CVE-2021-44228": 10.0,
    "CVE-2023-34362": 9.8,
    "CVE-2024-3400": 10.0,
    "CVE-2021-34527": 8.8,
    "CVE-2023-4966": 7.5,
    "CVE-2017-0144": 8.1,
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
        user = rng.choice(PEOPLE)
        event_id = _digest(rng)[:36]
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
                    "eventID": event_id,
                    "eventName": name,
                    "eventSource": service,
                    "sourceIPAddress": _external_ip(rng),
                    "userIdentity": {"type": "IAMUser", "userName": user},
                }
            ),
        }
        if rng.random() < 0.05:
            event["EventName"] = "BatchImportFindings"
            event["Cve"] = rng.choice(list(KEV_CVES))
        events.append(event)
    events.sort(key=lambda item: item["EventTime"], reverse=True)
    _make_messy(events, "EventId", "EventTime", "EventName")
    return events
