"""Builds the health view (FR-10) from connector state and run history."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

import yaml

from store import db

SCHEDULE_RE = re.compile(r"^every\s+(\d+)\s*([smh])$")
UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600}
ENTITY_LABELS = {"user": "users", "device": "devices", "alert": "alerts"}
AUTH_LABELS = {
    "none": "No login",
    "api_key": "API key",
    "basic": "Basic",
    "bearer": "Bearer",
    "oauth2_client_credentials": "OAuth2",
}
PAGING_LABELS = {
    "none": "one file",
    "link_header": "link header",
    "page_number": "page number",
    "offset": "offset",
    "body_token": "page token",
    "body_next_url": "next URL",
}


def parse_schedule(text: Any) -> int | None:
    """Return the interval in seconds for `every 15m`. Unreadable text gives None."""
    match = SCHEDULE_RE.match(str(text or "").strip())
    if not match or int(match[1]) == 0:
        return None
    return int(match[1]) * UNIT_SECONDS[match[2]]


def parse_iso(text: str | None) -> datetime | None:
    if not text:
        return None
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def time_ago(moment: datetime | None, now: datetime) -> str:
    if moment is None:
        return "never"
    seconds = int((now - moment).total_seconds())
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    if seconds < 86400:
        return f"{seconds // 3600} h ago"
    return f"{seconds // 86400} d ago"


def time_until(moment: datetime | None, now: datetime) -> str:
    if moment is None:
        return "-"
    seconds = int((moment - now).total_seconds())
    if seconds <= 0:
        return "due now"
    if seconds < 60:
        return "in under 1 min"
    if seconds < 3600:
        return f"in {seconds // 60} min"
    return f"in {seconds // 3600} h"


def _read_config(connector: dict[str, Any]) -> dict[str, Any]:
    try:
        data = yaml.safe_load(connector["config_yaml"])
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def connector_row(connector: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """Return everything the health page shows for one connector."""
    now = now or datetime.now(timezone.utc)
    config = _read_config(connector)
    run = db.last_run(connector["name"])
    finished = parse_iso(run["finished_at"]) if run else None
    last_time = finished or (parse_iso(run["started_at"]) if run else None)
    label = ENTITY_LABELS.get(connector["entity"], connector["entity"])
    stored = db.count_records(connector["entity"], connector["name"])

    interval = parse_schedule(config.get("schedule"))
    next_run = None
    if connector["enabled"] and interval:
        next_run = (last_time + timedelta(seconds=interval)) if last_time else now

    auth = (config.get("auth") or {}).get("type", "none")
    paging = (config.get("pagination") or {}).get("type", "none")
    last_ago = time_ago(last_time, now)
    summary = f"{connector['name']}: {connector['status']}, {last_ago}, {stored:,} {label}"
    return {
        "name": connector["name"],
        "mock": bool(config.get("mock")),
        "entity": connector["entity"],
        "enabled": bool(connector["enabled"]),
        "status": connector["status"],
        "consecutive_failures": connector["consecutive_failures"],
        "running": bool(run and run["status"] == "running"),
        "last_run": last_ago,
        "last_run_at": last_time.strftime("%Y-%m-%dT%H:%M:%SZ") if last_time else None,
        "records_pulled": run["records_pulled"] if run else 0,
        "records_bad": run["records_bad"] if run else 0,
        "stored": stored,
        "last_error": run["last_error"] if run else None,
        "next_run": time_until(next_run, now),
        "summary": summary,
        "detail": f"{AUTH_LABELS.get(auth, auth)} · {PAGING_LABELS.get(paging, paging)}",
    }


def health_rows(now: datetime | None = None) -> list[dict[str, Any]]:
    return [connector_row(connector, now) for connector in db.list_connectors()]
