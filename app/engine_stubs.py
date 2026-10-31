"""Stand-ins for the engine interface. They fetch nothing and return fake data.

The app falls back to these when an engine module or function is missing. A
non-dry run writes fake rows and a run record through the store, the same way
the real runner will. That gives the health page something to show.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from store import db

ENTITIES = {"user", "device", "alert"}
AUTH_TYPES = {"none", "api_key", "basic", "bearer", "oauth2_client_credentials", "session_login"}
PAGINATION_TYPES = {"none", "link_header", "page_number", "offset", "body_token", "body_next_url"}
REQUIRED_KEYS = ("name", "entity", "source", "map")
FAULT_MODE_RE = re.compile(r"^(503x\d+|429:\d+|timeout(x\d+)?|401|badrecord)$")

DRAFT_YAML = """\
name: new-source
entity: alert
mock: false
source:
  type: http
  base_url: https://api.example.com
  allow_hosts: [api.example.com]
auth:
  type: none
request:
  method: GET
  path: /v1/items
  format: json
  records_path: items
pagination:
  type: none
schedule: every 15m
map:
  id: id
  type: type
  severity: { path: severity, transform: lower }
  timestamp: { path: created_at, transform: to_utc }
  description: description
"""

_FAKE_MAPPED: dict[str, dict[str, Any]] = {
    "user": {
        "name": "Ann Rao",
        "email": "ann{n}@example.com",
        "status": "active",
        "last_login": "2026-10-30T18:22:05Z",
    },
    "device": {
        "hostname": "laptop-{n}",
        "ip": "10.0.0.{n}",
        "os": "Ubuntu 24.04",
        "owner": "ann{n}@example.com",
        "last_seen": "2026-10-30T18:22:05Z",
    },
    "alert": {
        "type": "stub.event",
        "severity": "high",
        "timestamp": "2026-10-30T18:22:05Z",
        "description": "Fake alert {n} from the engine stub",
        "cve": "CVE-2021-44228",
    },
}

_faults: dict[str, str] = {}
_scheduler_started = False


@dataclass
class StubConfig:
    """The few config fields the app reads."""

    name: str
    entity: str
    mock: bool = False
    schedule: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class RunResult:
    status: str
    records_pulled: int = 0
    records_bad: int = 0
    pages: int = 0
    retries: int = 0
    last_error: str | None = None
    requests: list[dict[str, Any]] = field(default_factory=list)
    sample_raw: list[dict[str, Any]] = field(default_factory=list)
    sample_mapped: list[dict[str, Any]] = field(default_factory=list)
    unmapped_fields: list[str] = field(default_factory=list)


def validate_config(yaml_text: str) -> list[dict[str, str]]:
    """Check the basic shape only. The real validator goes much further."""
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        return [_problem("", f"not valid YAML: {exc}", "Check indentation and quotes.")]
    if not isinstance(data, dict):
        return [_problem("", "config must be a mapping", "Start with `name: my-source`.")]

    problems = [
        _problem(key, "required field is missing", f"Add `{key}:` to the config.")
        for key in REQUIRED_KEYS
        if key not in data
    ]
    if "entity" in data and data["entity"] not in ENTITIES:
        problems.append(_problem("entity", "unknown entity", f"Use one of {sorted(ENTITIES)}."))
    _check_type(problems, data, "auth", AUTH_TYPES)
    _check_type(problems, data, "pagination", PAGINATION_TYPES)
    return problems


def load_config(yaml_text: str) -> StubConfig:
    problems = validate_config(yaml_text)
    if problems:
        details = "; ".join(f"{p['path'] or 'config'}: {p['message']}" for p in problems)
        raise ValueError(f"invalid config: {details}")
    data = yaml.safe_load(yaml_text)
    return StubConfig(
        name=data["name"],
        entity=data["entity"],
        mock=bool(data.get("mock", False)),
        schedule=data.get("schedule"),
        raw=data,
    )


def run_connector(
    name_or_config: str | StubConfig, dry_run: bool = False, max_pages: int | None = None
) -> RunResult:
    """Fake a run. Fault modes change the outcome but never really wait."""
    config = _resolve_config(name_or_config)
    if config is None:
        return RunResult(status="failed", last_error=f"unknown connector {name_or_config!r}")

    result = _fake_result(config, _faults.get(config.name))
    if dry_run:
        result.sample_mapped = result.sample_mapped[:3]
        return result

    connector = db.get_connector(config.name)
    if connector and connector["approved_hash"] != connector["config_hash"]:
        return RunResult(
            status="failed", last_error="config changed since approval, approve it to run"
        )

    run_id = db.start_run(config.name)
    if result.sample_mapped:
        db.upsert(config.entity, config.name, result.sample_mapped)
    if result.records_bad:
        db.add_quarantine(
            config.name, run_id, {"name": "no id here"}, "missing required field: id"
        )
    db.finish_run(
        run_id,
        result.status,
        result.records_pulled,
        result.records_bad,
        result.pages,
        result.retries,
        result.last_error,
    )
    if db.get_connector(config.name):
        _update_status(config.name, result.status)
    return result


def test_connection(config: str | StubConfig) -> RunResult:
    return run_connector(config, dry_run=True, max_pages=1)


def profile_sample(text: str, entity: str | None = None) -> dict[str, Any]:
    """Return one fixed draft config, whatever the sample says."""
    draft = DRAFT_YAML.replace("entity: alert", f"entity: {entity}") if entity else DRAFT_YAML
    return {
        "draft_yaml": draft,
        "records_path": "items",
        "format": "json",
        "guesses": {"id": "id", "timestamp": "created_at"},
        "paging_guess": "none",
        "preview_raw": _sample_records(text)[:5],
        "preview_mapped": [],
        "unmapped_fields": [],
        "confidence": 0.5,
    }


def replay_record(connector_name: str, raw: dict[str, Any]) -> dict[str, Any]:
    """Pretend to re-map a quarantined record. It passes once it has an id."""
    if raw.get("id") in (None, ""):
        return {"ok": False, "reason": "missing required field: id"}
    return {"ok": True, "row": {"id": raw["id"], "raw": raw}}


def start_scheduler() -> None:
    global _scheduler_started
    _scheduler_started = True


def pause(name: str) -> None:
    db.set_enabled(name, False)
    db.set_status(name, "paused")


def resume(name: str) -> None:
    db.set_enabled(name, True)
    run = db.last_run(name)
    db.set_status(name, _STATUS_AFTER_RUN.get(run["status"], "never_run") if run else "never_run")


def set_fault(connector: str, mode: str) -> None:
    if not FAULT_MODE_RE.match(mode):
        raise ValueError(f"unknown fault mode {mode!r}")
    _faults[connector] = mode


def clear_fault(connector: str) -> None:
    _faults.pop(connector, None)


_STATUS_AFTER_RUN = {
    "success": "healthy",
    "partial": "degraded",
    "failed": "failing",
    "auth_failed": "auth_failed",
}


def _problem(path: str, message: str, hint: str) -> dict[str, str]:
    return {"path": path, "message": message, "hint": hint}


def _check_type(
    problems: list[dict[str, str]], data: dict[str, Any], section: str, allowed: set[str]
) -> None:
    value = data.get(section)
    if isinstance(value, dict) and value.get("type") not in allowed:
        problems.append(
            _problem(f"{section}.type", "unknown type", f"Use one of {sorted(allowed)}.")
        )


def _resolve_config(name_or_config: str | StubConfig) -> StubConfig | None:
    if isinstance(name_or_config, StubConfig):
        return name_or_config
    connector = db.get_connector(name_or_config)
    return load_config(connector["config_yaml"]) if connector else None


def _fake_result(config: StubConfig, fault: str | None) -> RunResult:
    if fault == "401":
        return RunResult(status="auth_failed", last_error="HTTP 401: the key was rejected")
    if fault and fault.startswith("timeout"):
        return RunResult(status="failed", retries=3, last_error="request timed out")
    if fault and _is_503_over_limit(fault):
        return RunResult(status="failed", retries=3, last_error="HTTP 503 after 3 retries")

    good = 4 if fault == "badrecord" else 5
    bad = 1 if fault == "badrecord" else 0
    mapped = [_fake_row(config.entity, n) for n in range(1, good + 1)]
    retries = 0
    if fault and fault.startswith("503x"):
        retries = int(fault[4:])
    elif fault and fault.startswith("429:"):
        retries = 1
    return RunResult(
        status="partial" if bad else "success",
        records_pulled=good + bad,
        records_bad=bad,
        pages=1,
        retries=retries,
        last_error="1 of 5 records logged as invalid" if bad else None,
        requests=[
            {
                "method": "GET",
                "url_masked": "https://stub.example.com/items",
                "status": 200,
                "ms": 12,
                "attempt": retries + 1,
            }
        ],
        sample_raw=[row["raw"] for row in mapped[:5]],
        sample_mapped=mapped[:5],
        unmapped_fields=["stub_only_field"],
    )


def _is_503_over_limit(fault: str) -> bool:
    return fault.startswith("503x") and int(fault[4:]) > 3


def _fake_row(entity: str, n: int) -> dict[str, Any]:
    row: dict[str, Any] = {
        key: value.format(n=n) for key, value in _FAKE_MAPPED[entity].items()
    }
    row["id"] = f"stub-{n}"
    row["raw"] = {"stub": True, "n": n, "stub_only_field": "x"}
    return row


def _update_status(name: str, run_status: str) -> None:
    connector = db.get_connector(name)
    if run_status in ("failed", "auth_failed"):
        failures = connector["consecutive_failures"] + 1
    elif run_status == "success":
        failures = 0
    else:
        failures = connector["consecutive_failures"]
    db.set_status(name, _STATUS_AFTER_RUN[run_status], failures)


def _sample_records(text: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if isinstance(data, dict):
        data = next((v for v in data.values() if isinstance(v, list)), [data])
    return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []
