"""The run loop. Identical for every connector; only the config differs.

load config -> tamper check -> secrets -> first page (or resume point) -> auth -> HTTP
(retry, rate limits, faults) -> parse -> records -> map + validate -> upsert good rows,
quarantine bad ones -> save resume point after every committed page -> next page ->
save watermark -> record the run -> update connector status -> hooks (e.g. Slack).
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional, Union

from . import faults
from .auth import make_auth
from .config import Config, ConfigError, config_hash, load_config, validate_config
from .errors import AuthFailed, EngineError, MappingError, SecretMissing
from .http import HttpClient, RunStats
from .mapper import map_record, to_utc, unmapped_fields
from .memstore import default_store, now_iso
from .paginate import make_paginator
from .parse import BadLine, extract_records, get_path, parse_body
from .secrets import mask, mask_obj
from .security import safe_file_path

log = logging.getLogger("engine.runner")

# Called after every non-dry run: hook(cfg, result, connector_row). The Slack notifier plugs in here.
on_run_finished: list[Callable[[Config, "RunResult", dict], None]] = []

_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


@dataclass
class RunResult:
    connector: str
    status: str  # success | partial | failed | auth_failed | paused | skipped | config_changed
    records_pulled: int = 0
    records_bad: int = 0
    inserted: int = 0
    updated: int = 0
    pages: int = 0
    retries: int = 0
    last_error: Optional[str] = None
    more_pages: bool = False
    dry_run: bool = False
    run_id: Optional[int] = None
    started_at: str = field(default_factory=now_iso)
    finished_at: Optional[str] = None
    duration_ms: int = 0
    connector_status: Optional[str] = None
    requests: list[dict] = field(default_factory=list)
    waits: list[float] = field(default_factory=list)
    sample_raw: list[Any] = field(default_factory=list)
    sample_mapped: list[dict] = field(default_factory=list)
    quarantined: list[dict] = field(default_factory=list)  # first few {record, reason}, for the UI
    unmapped_fields: list[str] = field(default_factory=list)
    validation: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return mask_obj(asdict(self))

    @property
    def ok(self) -> bool:
        return self.status in ("success", "partial")


# ---------------------------------------------------------------- templates
_TPL = re.compile(r"\{\{\s*(now|checkpoint)\s*(?:([+-])\s*(\d+)\s*([smhd]))?\s*\}\}")


def render(obj: Any, checkpoint: Optional[str]) -> Any:
    """Replace {{now}}, {{now-24h}}, {{checkpoint}} in strings (no code, just substitution)."""
    if isinstance(obj, dict):
        return {k: render(v, checkpoint) for k, v in obj.items()}
    if isinstance(obj, list):
        return [render(v, checkpoint) for v in obj]
    if not isinstance(obj, str):
        return obj

    def sub(m: re.Match) -> str:
        if m.group(1) == "checkpoint":
            return checkpoint or ""
        t = datetime.now(timezone.utc)
        if m.group(2):
            unit = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[m.group(4)]
            delta = timedelta(**{unit: int(m.group(3))})
            t = t + delta if m.group(2) == "+" else t - delta
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")

    return _TPL.sub(sub, obj)


def _url(cfg: Config) -> str:
    path = cfg.request.path or ""
    if path.startswith(("http://", "https://")):
        return path
    base = (cfg.source.base_url or "").rstrip("/")
    return f"{base}/{path.lstrip('/')}" if path else base


def _wm_key(v: Any) -> tuple:
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return (0, float(v), "")
    try:
        return (1, 0.0, to_utc(v))
    except ValueError:
        return (2, 0.0, str(v))


def _lock_for(name: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(name, threading.Lock())


def _is_name(target) -> bool:
    return isinstance(target, str) and "\n" not in target and ":" not in target


def _resolve(target, store) -> tuple[Optional[Config], Optional[str], bool, Optional[str]]:
    """-> (cfg, yaml_text, by_name, error)."""
    if isinstance(target, Config):
        return target, None, False, None
    if isinstance(target, dict):
        return load_config(target), None, False, None
    if not _is_name(target):
        return load_config(target), target, False, None
    row = store.get_connector(target) if store else None
    if not row:
        return None, None, True, f"unknown connector '{target}'"
    return load_config(row["config_yaml"]), row["config_yaml"], True, None


# ---------------------------------------------------------------- main entry points
def run_connector(
    target: Union[str, Config, dict],
    dry_run: bool = False,
    max_pages: Optional[int] = None,
    *,
    store=None,
    transport=None,
    sleeper: Optional[Callable[[float], None]] = None,
    resolver=None,
) -> RunResult:
    """Run one connector. `target` is a connector name (from the store), YAML text or a Config."""
    t0 = time.perf_counter()
    is_name = _is_name(target)
    if store is None and (is_name or not dry_run):
        store = default_store()
    name = target if is_name else "?"
    try:
        cfg, yaml_text, by_name, err = _resolve(target, store)
    except ConfigError as e:
        return RunResult(connector=name, status="failed", last_error=str(e), dry_run=dry_run, validation=e.errors)
    if err:
        return RunResult(connector=name, status="failed", last_error=err, dry_run=dry_run)
    name = cfg.name
    result = RunResult(connector=name, status="failed", dry_run=dry_run)
    if yaml_text:
        result.validation = [p for p in validate_config(yaml_text) if p["level"] == "warning"]

    # kill switch and tamper check (real runs of stored connectors)
    if by_name and not dry_run:
        row = store.get_connector(name) or {}
        if row.get("status") == "paused" or row.get("enabled") is False:
            result.status, result.last_error = "paused", "connector is paused (kill switch)"
            return result
        approved = row.get("approved_hash")
        if approved != config_hash(yaml_text):
            result.status = "config_changed"
            result.last_error = ("config changed since it was approved; review and approve it again"
                                 if approved else "config has not been approved yet")
            store.set_status(name, "config_changed")
            store.audit("engine", "run_refused", name, {"reason": result.last_error})
            return result

    lock = _lock_for(name)
    if not lock.acquire(blocking=False):
        result.status, result.last_error = "skipped", "already running"
        return result
    try:
        _execute(cfg, result, dry_run, max_pages, store, transport, sleeper, resolver)
    finally:
        lock.release()
    result.duration_ms = int((time.perf_counter() - t0) * 1000)
    result.finished_at = now_iso()
    result.last_error = mask(result.last_error) if result.last_error else None

    if not dry_run and store is not None:
        store.finish_run(result.run_id, result.status, result.records_pulled, result.records_bad,
                         result.pages, result.retries, result.last_error)
        result.connector_status = _update_status(cfg, result, store)
        row = store.get_connector(name) or {}
        for hook in list(on_run_finished):
            try:
                hook(cfg, result, row)
            except Exception:  # a broken hook must never break a run
                log.exception("on_run_finished hook failed")
    return result


def test_connection(target: Union[str, Config, dict], **kw) -> RunResult:
    """B-3: one page, nothing stored, checkpoint untouched; 3 mapped rows to show."""
    res = run_connector(target, dry_run=True, max_pages=1, **kw)
    res.sample_mapped = res.sample_mapped[:3]
    return res


test_connection.__test__ = False  # stop pytest collecting it when imported into test modules


def _execute(cfg: Config, result: RunResult, dry_run, max_pages, store, transport, sleeper, resolver) -> None:
    name = cfg.name
    stats = RunStats()
    http = None
    try:
        if not dry_run:
            result.run_id = store.start_run(name)
            checkpoint = store.get_checkpoint(name) or {}
        else:
            checkpoint = {}
        watermark = checkpoint.get("watermark") or (cfg.incremental.start if cfg.incremental else None)
        resume = checkpoint.get("resume_state")
        if isinstance(resume, str):
            resume = json.loads(resume)
        new_wm = watermark
        limit_pages = max_pages or cfg.limits.max_pages
        sample_records: list = []

        if cfg.source.type == "file":
            pages_iter = _file_pages(cfg)
        else:
            http = HttpClient(cfg, make_auth(cfg), transport=transport, sleeper=sleeper, resolver=resolver, stats=stats)
            pages_iter = _http_pages(cfg, http, watermark, resume, limit_pages)

        for page in pages_iter:
            records, next_req = page["records"], page["next"]
            if faults.take(name, ("badrecord",)) and records:
                records = records + [{"_injected": "fault switch: record with required fields missing"}]
            result.pages += 1
            good, bad = [], []
            for rec in records:
                result.records_pulled += 1
                if isinstance(rec, BadLine):
                    bad.append((rec.raw, rec.reason))
                    continue
                try:
                    row = map_record(rec, cfg)
                except MappingError as e:
                    bad.append((rec, str(e)))
                    continue
                row.update(raw=rec, fetched_at=now_iso(), tenant_id=cfg.tenant_id)
                good.append(row)
                if cfg.incremental:
                    v = get_path(rec, cfg.incremental.field)
                    if v not in (None, "") and (new_wm is None or _wm_key(v) > _wm_key(new_wm)):
                        new_wm = str(v)
                if len(sample_records) < 20:
                    sample_records.append(rec)
                if len(result.sample_raw) < 5:
                    result.sample_raw.append(rec)
                    result.sample_mapped.append({k: v for k, v in row.items() if k != "raw"})
            result.records_bad += len(bad)
            for raw, reason in bad:
                if len(result.quarantined) < 10:
                    result.quarantined.append({"record": raw, "reason": reason})
            if not dry_run:
                if good:
                    ins, upd = store.upsert(cfg.entity, name, good)
                    result.inserted += ins
                    result.updated += upd
                for raw, reason in bad:
                    store.add_quarantine(name, result.run_id, raw, reason)
                store.set_checkpoint(name, watermark=watermark, resume_state=next_req)
            result.more_pages = next_req is not None

        result.unmapped_fields = unmapped_fields(sample_records, cfg)
        if result.more_pages and not dry_run:
            result.last_error = f"stopped after {result.pages} page(s) (limit); the next run continues from here"
        result.status = "partial" if (result.records_bad or (result.more_pages and not dry_run)) else "success"
        if result.records_bad and not result.last_error:
            result.last_error = f"{result.records_bad} of {result.records_pulled} records quarantined as invalid"
        if not dry_run:
            if result.more_pages:
                pass  # keep watermark and resume point; incremental advances only after a full pass
            else:
                store.set_checkpoint(name, watermark=new_wm, resume_state=None)
    except (AuthFailed, SecretMissing) as e:
        result.status, result.last_error = "auth_failed", str(e)
    except EngineError as e:
        result.status, result.last_error = "failed", str(e)
    except Exception as e:  # never let an unexpected bug crash the scheduler
        log.exception("unexpected error in connector %s", name)
        result.status, result.last_error = "failed", f"unexpected error: {type(e).__name__}: {e}"
    finally:
        if http is not None:
            http.close()
        result.retries = stats.retries
        result.requests = stats.requests
        result.waits = stats.waits


def _http_pages(cfg: Config, http: HttpClient, watermark, resume, limit_pages):
    paginator = make_paginator(cfg)
    base = {"url": _url(cfg), "params": render(dict(cfg.request.params), watermark),
            "body": render(cfg.request.body, watermark)}
    if cfg.incremental and watermark:
        value = cfg.incremental.template.format(checkpoint=watermark)
        if cfg.incremental.param_in == "body":
            base["body"] = {**(base["body"] or {}), cfg.incremental.param: value}
        else:
            base["params"][cfg.incremental.param] = value
    req = resume or paginator.first(base)
    pages = 0
    seen = set()
    while req and pages < limit_pages:
        key = json.dumps(req, sort_keys=True, default=str)
        if key in seen:  # a server that returns the same page forever
            break
        seen.add(key)
        resp = http.request(cfg.request.method, req["url"], params=req.get("params"), json_body=req.get("body"))
        parsed = parse_body(resp.content, cfg.request.format)
        records = extract_records(parsed, cfg.request.records_path, cfg.request.format)
        nxt = paginator.next(req, resp, parsed, records)
        pages += 1
        yield {"records": records, "next": nxt}
        req = nxt


def _file_pages(cfg: Config):
    path = safe_file_path(cfg.source.path)
    fmt = cfg.request.format
    if path.suffix.lower() == ".csv":
        fmt = "csv"
    elif path.suffix.lower() in (".ndjson", ".jsonl"):
        fmt = "ndjson"
    parsed = parse_body(path.read_bytes(), fmt)
    yield {"records": extract_records(parsed, cfg.request.records_path, fmt), "next": None}


def _update_status(cfg: Config, result: RunResult, store) -> str:
    row = store.get_connector(cfg.name) or {}
    fails = int(row.get("consecutive_failures") or 0)
    if result.status in ("success", "partial"):
        fails = 0
        status = "degraded" if (result.records_bad or result.retries) else "healthy"
    elif result.status == "auth_failed":
        fails += 1
        status = "auth_failed"
    else:
        fails += 1
        status = "circuit_open" if fails >= cfg.limits.circuit_after_failures else "failing"
    store.set_status(cfg.name, status, consecutive_failures=fails)
    return status


# ---------------------------------------------------------------- saving configs
def save_and_approve(yaml_text: str, *, store=None, actor: str = "user") -> dict:
    """Validate, save and approve a connector config (records the approved hash + audit entry).

    Returns {"ok": bool, "name": str|None, "errors": [...], "warnings": [...]}.
    """
    store = store or default_store()
    problems = validate_config(yaml_text)
    errors = [p for p in problems if p["level"] == "error"]
    warnings = [p for p in problems if p["level"] == "warning"]
    if errors:
        return {"ok": False, "name": None, "errors": errors, "warnings": warnings}
    cfg = load_config(yaml_text)
    h = config_hash(yaml_text)
    existed = store.get_connector(cfg.name) is not None
    store.save_connector(cfg.name, cfg.entity, yaml_text, h)
    store.approve_connector(cfg.name, h)
    row = store.get_connector(cfg.name) or {}
    if row.get("status") in (None, "config_changed"):
        store.set_status(cfg.name, "never_run")
    store.audit(actor, "config_updated" if existed else "config_added", cfg.name,
                {"hash": h[:12], "secrets": cfg.secret_names(), "hosts": cfg.source.allow_hosts})
    return {"ok": True, "name": cfg.name, "errors": [], "warnings": warnings, "hash": h}
