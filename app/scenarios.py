"""Turns a run's saved request log into what the live page says.

Everything here is read from the log, the config and the store. A value the
system does not know, such as a total page count, is simply not shown.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import yaml

from app.theme import tone
from store import db

# Each pill maps to one fixed fault mode. The browser never sends a mode.
SCENARIOS = {
    "healthy": {"label": "Healthy", "mode": "off", "tone": "teal"},
    "rate_limit": {"label": "Too many requests (429)", "mode": "429:30", "tone": "amber", "network": True},
    "timeout": {"label": "Timeout", "mode": "timeoutx4", "tone": "red", "network": True},
    "wrong_key": {"label": "Wrong key", "mode": "401", "tone": "red", "network": True},
    "bad_record": {"label": "Bad record", "mode": "badrecord", "tone": "amber"},
}
KIND_PILL = {
    "healthy": "healthy",
    "rate_limited": "rate_limit",
    "waiting": "rate_limit",
    "timeout": "timeout",
    "auth": "wrong_key",
    "bad_record": "bad_record",
}
STATUS_TEXT = {
    200: "OK",
    201: "Created",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}
TIMELINE_LIMIT = 7
EVENT_ROW_LIMIT = 4
RECORD_ROW_LIMIT = 4
PEER_LIMIT = 5
QUARANTINE_LIMIT = 3


def _config(connector: dict[str, Any]) -> dict[str, Any]:
    try:
        data = yaml.safe_load(connector["config_yaml"])
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def is_file_source(connector: dict[str, Any]) -> bool:
    """A file source makes no web requests, so network faults have nothing to act on."""
    source = _config(connector).get("source")
    return isinstance(source, dict) and source.get("type") == "file"


def for_connector(connector: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The scenario pills for one connector, with the ones it cannot show marked."""
    on_file = is_file_source(connector)
    return {key: {**item, "blocked": on_file and item.get("network", False)} for key, item in SCENARIOS.items()}


def _time(stamp: str | None) -> str:
    return stamp[11:19] if stamp and len(stamp) >= 19 else "--:--:--"


def _seconds(value: float | None) -> str:
    if value is None:
        return "0 s"
    return f"{value:g} s" if value != int(value) else f"{int(value)} s"


def _path(url: str) -> str:
    parts = urlsplit(url)
    return parts.path + (f"?{parts.query}" if parts.query else "")


def _is_token(entry: dict[str, Any]) -> bool:
    return "token" in (entry.get("note") or "")


def _injected(entry: dict[str, Any]) -> str:
    return " · injected" if "injected" in (entry.get("note") or "") else ""


def _lookup(record: Any, path: str) -> Any:
    value = record
    for part in path.split("."):
        if isinstance(value, dict):
            value = value.get(part)
        elif isinstance(value, list) and part.isdigit() and int(part) < len(value):
            value = value[int(part)]
        else:
            return None
    return value


def classify(run: dict[str, Any] | None, requests: list[dict[str, Any]], state: dict[str, Any], status: str) -> str:
    """Work out what happened from the real data, whatever pill was pressed."""
    if state["waiting"]:
        return "waiting"
    if state["active"]:
        return "running"
    if status in ("paused", "config_changed"):
        return status
    if run is None:
        return "never"
    if run["status"] == "running":
        return "running"
    if run["status"] == "auth_failed":
        return "auth"
    if run["status"] == "failed":
        return "timeout" if any(entry["status"] is None and not _is_token(entry) for entry in requests) else "failed"
    if any(entry["status"] == 429 for entry in requests):
        return "rate_limited"
    if run["records_bad"]:
        return "bad_record"
    if run["status"] == "partial":
        return "partial"
    return "recovered" if run["retries"] else "healthy"


def _login_row(config: dict[str, Any]) -> dict[str, str]:
    auth = config.get("auth") or {}
    kind = auth.get("type", "none")
    if kind == "none":
        return {"code": "no login", "tag": "LOGIN · this source needs none", "tone": ""}
    if kind == "api_key" and auth.get("query_param"):
        code = f"?{auth['query_param']}=••••••••"
    elif kind == "api_key":
        code = f"{auth.get('header', 'header')}: {auth.get('prefix', '')}••••••••"
    elif kind == "basic":
        code = "Authorization: Basic ••••••••"
    else:
        code = "Authorization: Bearer ••••••••"
    secret = auth.get("secret") or auth.get("client_secret_secret") or "not named"
    return {"code": code, "tag": f"LOGIN · secret {secret}, masked", "tone": "teal"}


def _event_rows(requests: list[dict[str, Any]], run_status: str | None) -> list[dict[str, str]]:
    """One row per request that did not simply succeed."""
    rows = []
    calls = [entry for entry in requests if not _is_token(entry)]
    for index, entry in enumerate(calls):
        status = entry["status"]
        waited = entry.get("waited_s")
        extra = _injected(entry)
        is_last = index == len(calls) - 1
        if status == 429:
            after = entry.get("retry_after")
            code = f"429 Too Many Requests · Retry-After: {after}" if after else "429 Too Many Requests"
            rows.append({"code": code, "tag": f"RATE LIMIT · waits {_seconds(waited)}, then resumes{extra}", "tone": "amber"})
        elif status in (401, 403):
            text = STATUS_TEXT[status]
            rows.append({"code": f"{status} {text}", "tag": f"NOT RETRIED · a wrong key won't fix itself{extra}", "tone": "red"})
        elif status is None or status >= 500:
            what = "no answer" if status is None else f"{status} {STATUS_TEXT.get(status, 'error')}"
            label = "TIMEOUT" if status is None else "SERVER ERROR"
            if waited is not None:
                tag = f"{label} · retry in {_seconds(waited)}{extra}"
            elif is_last and run_status == "failed":
                tag = f"GAVE UP · as the rules say{extra}"
            else:
                tag = f"{label}{extra}"
            rows.append({"code": f"Try {entry['attempt']} · {what}", "tag": tag, "tone": "red"})
    if len(rows) > EVENT_ROW_LIMIT:
        hidden = len(rows) - EVENT_ROW_LIMIT
        rows = rows[-EVENT_ROW_LIMIT:]
        rows.insert(0, {"code": f"{hidden} earlier tries not shown", "tag": "LOG", "tone": ""})
    return rows


def _timeline(run: dict[str, Any] | None, requests: list[dict[str, Any]]) -> list[dict[str, str]]:
    lines = []
    page = 0
    for entry in requests:
        at = _time(entry.get("at"))
        status = entry["status"]
        if _is_token(entry):
            lines.append({"at": at, "text": "Fetched a login token", "tone": ""})
            continue
        if entry["attempt"] == 1:
            page += 1
            lines.append({"at": at, "text": f"Requested page {page}", "tone": ""})
        else:
            lines.append({"at": at, "text": f"Requested page {page} again (try {entry['attempt']})", "tone": ""})
        waited = entry.get("waited_s")
        if status == 429:
            lines.append({"at": at, "text": f"Got 429. Told to wait {_seconds(waited)}", "tone": "amber"})
        elif status in (401, 403):
            lines.append({"at": at, "text": f"Got {status}. Stopped, no retry", "tone": "red"})
        elif status is None or status >= 500:
            what = "Timed out" if status is None else f"Got {status}"
            after = f". Retry in {_seconds(waited)}" if waited is not None else ""
            lines.append({"at": at, "text": f"{what}{after}", "tone": "red"})
        elif status < 300:
            lines.append({"at": at, "text": f"{status} OK", "tone": "teal"})
    if run and run.get("finished_at"):
        bad = f", {run['records_bad']} set aside" if run["records_bad"] else ""
        lines.append(
            {
                "at": _time(run["finished_at"]),
                "text": f"Run {run['status']}: {run['records_pulled']:,} records{bad}",
                "tone": tone(run["status"]),
            }
        )
    return _trim_timeline(lines)


def _trim_timeline(lines: list[dict[str, str]]) -> list[dict[str, str]]:
    """Drop routine steps, oldest first. Warnings, failures and the last line stay."""
    hidden = 0
    kept = list(lines)
    index = 0
    while len(kept) > TIMELINE_LIMIT and index < len(kept) - 1:
        if kept[index]["tone"] in ("amber", "red"):
            index += 1
        else:
            del kept[index]
            hidden += 1
    if hidden:
        kept.insert(0, {"at": "", "text": f"{hidden} routine steps not shown", "tone": ""})
    return kept


def _spec_path(spec: Any) -> str | None:
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict) and isinstance(spec.get("path"), str):
        return spec["path"]
    return None


def _record_rows(config: dict[str, Any], item: dict[str, Any]) -> list[dict[str, str]]:
    """Walk one quarantined record through the mapping, field by field."""
    try:
        record = yaml.safe_load(item["raw_json"])
    except yaml.YAMLError:
        record = None
    reason = item["reason"]
    rows = []
    mapped = [(target, _spec_path(spec)) for target, spec in (config.get("map") or {}).items()]
    mapped = [(target, path) for target, path in mapped if path]
    mapped.sort(key=lambda pair: 0 if f"'{pair[0]}'" in reason else 1)
    for target, path in mapped[:RECORD_ROW_LIMIT]:
        value = _lookup(record, path)
        shown = "(missing)" if value is None else str(value)[:60]
        if f"'{target}'" in reason:
            rows.append({"code": f"{path}: {shown}", "tag": f"{target.upper()} · set aside", "tone": "amber"})
        else:
            rows.append({"code": f"{path}: {shown}", "tag": f"{target.upper()} · ok", "tone": "teal"})
    rows.append({"code": "raw record kept in quarantine", "tag": "REPLAY · after a fix", "tone": ""})
    return rows


def _name_upper(name: str) -> str:
    return name.upper()


def _copy(kind: str, name: str, run: dict[str, Any] | None, state: dict[str, Any], connector: dict[str, Any]) -> dict[str, Any]:
    """Status card, engine block, cable tag and caption for each outcome."""
    pulled = run["records_pulled"] if run else 0
    bad = run["records_bad"] if run else 0
    saved = pulled - bad
    failures = connector["consecutive_failures"]
    error = run["last_error"] if run else None
    if kind == "waiting":
        wait = _seconds(state["seconds"])
        return {
            "title": "Slowed down: rate limit" if state["reason"] == "rate limit" else "Waiting to retry",
            "tone": "amber",
            "line": f"Waiting {wait} · resumes {state['resumes_at']} UTC",
            "detail": "Nothing is lost. Scheduled sources keep running.",
            "engine": (f"Pausing {name} only", "Sources on their own schedule are not held up"),
            "tag": {"text": f"wait {wait}", "tone": "amber"},
            "caption": (
                f"{name} asked us to slow down" if state["reason"] == "rate limit" else f"{name} did not answer",
                f"Otto paused only this source. It tries again after {wait} and this page refreshes until the run ends.",
                ("Rate limiter", "Retry-After reader", "Checkpoint", "Scheduler"),
            ),
        }
    if kind == "running":
        return {
            "title": "Running",
            "tone": "amber",
            "line": "Run in progress",
            "detail": "This page refreshes every 5 seconds until the run ends.",
            "engine": (f"Reading {name}", "Run in progress"),
            "tag": None,
            "caption": ("A run is going", "The request log appears here when the run ends.", ("Scheduler", "Request log")),
        }
    if kind == "rate_limited":
        return {
            "title": "Done, after a rate limit",
            "tone": "amber",
            "line": f"{pulled:,} records · {run['pages']} pages",
            "detail": "The source returned 429. Otto waited, then carried on. Nothing was lost."
            + (f" Bad records sent to quarantine: {bad}." if bad else ""),
            "engine": (f"{name} recovered", "Waited as asked, then resumed"),
            "tag": {"text": "429 · waited", "tone": "amber"},
            "caption": (
                f"{name} asked us to slow down",
                "Otto paused only this source, waited the time it asked for, then fetched the page again.",
                ("Rate limiter", "Retry-After reader", "Checkpoint", "Scheduler"),
            ),
        }
    if kind == "timeout":
        return {
            "title": "Failed: timeout",
            "tone": "red",
            "line": f"{run['retries']} retries · {failures} failed in a row",
            "detail": f"{saved:,} records saved before the failure.",
            "engine": (f"{name} failed after {run['retries']} retries", "Progress kept"),
            "tag": {"text": "1 s 2 s 4 s", "tone": "red"},
            "caption": (
                "The source stopped answering",
                "Otto retried on the backoff schedule, then marked the run failed. Saved records stay saved and the next run resumes from the checkpoint.",
                ("Timeouts", "Backoff", "Checkpoint", "Health view"),
            ),
        }
    if kind == "auth":
        return {
            "title": "Failed: login rejected",
            "tone": "red",
            "line": f"Not retried · {failures} failed in a row",
            "detail": error or "The login was rejected.",
            "engine": (f"{name} stopped", "A wrong key won't fix itself"),
            "tag": {"text": "401 · no retry", "tone": "red"},
            "caption": (
                "The login was rejected",
                "Retrying a wrong key only risks locking the account. Otto stops at once and marks the connection auth_failed.",
                ("Auth plugin", "Health view", "Alerts"),
            ),
        }
    if kind == "failed":
        return {
            "title": "Failed",
            "tone": "red",
            "line": f"{run['retries']} retries · {failures} failed in a row",
            "detail": error or "The run failed.",
            "engine": (f"{name} failed", "Progress kept"),
            "tag": {"text": "failed", "tone": "red"},
            "caption": ("The run failed", error or "See the last error.", ("Health view", "Checkpoint")),
        }
    if kind == "bad_record":
        return {
            "title": f"Done, {bad} set aside",
            "tone": "amber",
            "line": f"{saved:,} saved · {bad} in quarantine",
            "detail": f"{bad} of {pulled:,} records logged as invalid.",
            "engine": (f"{saved:,} saved, {bad} set aside", "The run kept going"),
            "tag": None,
            "caption": (
                f"{bad} record{'s were' if bad != 1 else ' was'} broken. The run kept going.",
                "Each broken record goes to quarantine with the reason and everything valid is saved. Fix the mapping or the source, then replay.",
                ("Mapper", "Validator", "Quarantine", "Replay"),
            ),
        }
    if kind == "partial":
        return {
            "title": "Partial",
            "tone": "amber",
            "line": f"{pulled:,} records · {run['pages']} pages",
            "detail": error or "The run stopped early. The next run continues from here.",
            "engine": (f"{name} paused at the limit", "Next run continues"),
            "tag": None,
            "caption": ("Stopped at the page limit", error or "The next run continues from here.", ("Limits", "Checkpoint")),
        }
    if kind == "paused":
        return {
            "title": "Paused",
            "tone": "grey",
            "line": "Kill switch on",
            "detail": "Resume this connector to run a scenario.",
            "engine": (f"{name} is paused", "No scheduled runs"),
            "tag": None,
            "caption": ("This connector is paused", "Nothing calls the source until someone resumes it.", ("Kill switch",)),
        }
    if kind == "config_changed":
        return {
            "title": "Config changed",
            "tone": "amber",
            "line": "Needs approval",
            "detail": "The config changed since it was approved. It will not run until approved.",
            "engine": (f"{name} is held", "Waiting for approval"),
            "tag": None,
            "caption": ("The config changed", "Open the connector page to review and approve it.", ("Tamper check", "Audit log")),
        }
    if kind == "never":
        return {
            "title": "Never run",
            "tone": "grey",
            "line": "No runs yet",
            "detail": "Choose a scenario above to start a run.",
            "engine": (f"{name} is ready", "No runs yet"),
            "tag": None,
            "caption": ("Nothing has run yet", "Press Healthy to run this source with no fault.", ("Scheduler",)),
        }
    title = "Healthy" if kind == "healthy" else "Healthy, after retries"
    return {
        "title": title,
        "tone": "teal",
        "line": f"{pulled:,} records · {run['pages']} pages · {run['retries']} retries",
        "detail": "The last run finished with no problems." if kind == "healthy" else "The last run recovered by retrying.",
        "engine": (f"{name} is flowing", "Same rules for every source"),
        "tag": None,
        "caption": (
            "Every record came through" if kind == "healthy" else "Retries got the run through",
            "Login, paging, mapping and storage all ran from the config. No code knows this source.",
            ("Auth plugin", "Pagination plugin", "Mapper", "Store"),
        ),
    }


def _alert(name: str, connector: dict[str, Any], config: dict[str, Any], run: dict[str, Any] | None) -> dict[str, Any]:
    threshold = (config.get("notify") or {}).get("slack_after_failures")
    failures = connector["consecutive_failures"]
    last = db.last_alert_sent(name)
    sent = bool(last and (last["reason"] or "").startswith("failure:"))
    error = (run or {}).get("last_error") or "no error text"
    if sent:
        state = f"Sent to Slack at {_time(last['sent_at'])} UTC"
    elif threshold:
        state = f"Sends to Slack at {threshold} failures in a row. Now at {failures}."
    else:
        state = "No alert is set in this config."
    return {
        "state": state,
        "sent": sent,
        "message": f"{name} is {connector['status']}: {failures} failed runs in a row. Last error: {error}",
    }


def build(name: str, connector: dict[str, Any], rows: list[dict[str, Any]], state: dict[str, Any]) -> dict[str, Any]:
    """Return everything the live page shows for one connector."""
    config = _config(connector)
    run = db.last_run(name)
    log = db.get_run_log(run["id"]) if run else {"requests": [], "waits": [], "dropped": 0}
    requests = log["requests"]
    kind = classify(run, requests, state, connector["status"])
    copy = _copy(kind, name, run, state, connector)
    quarantined = [item for item in db.list_quarantine(name, limit=50) if run and item["run_id"] == run["id"]]

    # Mock sources always hold a few broken records. After a plain healthy run the
    # page still shows the request. The status card reports what was set aside.
    healthy_press = not state["active"] and kind == "bad_record" and state.get("scenario") == "healthy"
    heading = "[ The request, labelled ]"
    request_rows: list[dict[str, str]] = []
    if kind == "bad_record" and quarantined and not healthy_press:
        heading = "[ One broken record, labelled ]"
        request_rows = _record_rows(config, quarantined[0])
    else:
        calls = [entry for entry in requests if not _is_token(entry)]
        if calls:
            first = calls[0]
            request_rows.append(
                {"code": f"{first['method']} {_path(first['url_masked'])}", "tag": "ADDRESS · from the config", "tone": ""}
            )
        else:
            request = config.get("request") or {}
            if request.get("path"):
                request_rows.append(
                    {"code": f"{request.get('method', 'GET')} {request['path']}", "tag": "ADDRESS · from the config", "tone": ""}
                )
        request_rows.append(_login_row(config))
        if state["waiting"] and state["reason"] == "rate limit":
            request_rows.append(
                {
                    "code": f"429 Too Many Requests · waiting {_seconds(state['seconds'])}",
                    "tag": f"RATE LIMIT · resumes {state['resumes_at']} UTC",
                    "tone": "amber",
                }
            )
        request_rows.extend(_event_rows(requests, run["status"] if run else None))
        if kind == "auth" and not any(entry["status"] in (401, 403) for entry in calls) and run and run["last_error"]:
            request_rows.append({"code": run["last_error"], "tag": "LOGIN · stopped before any data", "tone": "red"})
        if connector["consecutive_failures"] and kind in ("auth", "timeout", "failed"):
            alert = _alert(name, connector, config, run)
            tag = "ALERT · message sent" if alert["sent"] else "ALERT · not sent yet"
            request_rows.append(
                {"code": f"failed runs in a row: {connector['consecutive_failures']}", "tag": tag, "tone": "red"}
            )
        checkpoint = db.get_checkpoint(name)
        if checkpoint["resume_state"] and kind in ("timeout", "failed", "partial"):
            request_rows.append({"code": "checkpoint saved", "tag": "NEXT RUN · resumes here", "tone": "teal"})
        paging = (config.get("pagination") or {}).get("type")
        if run and paging and paging != "none" and run["pages"]:
            pages = run["pages"]
            request_rows.append(
                {"code": f"pagination: {paging}", "tag": f"NEXT PAGE · {pages} page{'s' if pages != 1 else ''} fetched", "tone": ""}
            )
        first_map = next(
            ((target, path) for target, path in ((t, _spec_path(s)) for t, s in (config.get("map") or {}).items()) if path),
            None,
        )
        if first_map:
            request_rows.append(
                {"code": f"{first_map[1]} → {first_map[0]}", "tag": f"MAPPING · into {connector['entity']}s", "tone": ""}
            )

    peers = sorted((row for row in rows if row["name"] != name), key=lambda row: tone(row["status"]) == "teal")
    run_label = f"run {_time(run['started_at'])[:5]}" if run else "no runs"
    page_label = f" · page {run['pages']}" if run and run["pages"] else ""
    if state["active"]:
        pill = state.get("scenario")
    elif healthy_press:
        pill = "healthy"
    else:
        pill = KIND_PILL.get(kind)
    return {
        "kind": kind,
        "status": copy,
        "pill": pill,
        "heading": heading,
        "request_rows": request_rows,
        "timeline": _timeline(run, requests),
        "alert": _alert(name, connector, config, run) if kind in ("auth", "timeout", "failed") else None,
        "quarantine": quarantined[:QUARANTINE_LIMIT],
        "quarantine_total": len(quarantined),
        "peers": peers[:PEER_LIMIT],
        "panel_label": f"[ {_name_upper(name)} · {run_label.upper()}{page_label.upper()} ]",
        "injected": any("injected" in (entry.get("note") or "") for entry in requests),
        "dropped": log.get("dropped", 0),
        "run": run,
    }
