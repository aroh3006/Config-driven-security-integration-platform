"""In-memory store implementing the shared store interface.

Used by tests and as a fallback when the SQLite store (store/db.py) is not available.
It matches that interface exactly. The runner works the same against either.
"""

from __future__ import annotations

import itertools
import json
import threading
from datetime import datetime, timezone
from typing import Any, Optional


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class MemoryStore:
    def __init__(self):
        self._lock = threading.RLock()
        self.tables: dict[str, dict[tuple[str, str], dict]] = {"users": {}, "devices": {}, "alerts": {}}
        self.connectors: dict[str, dict] = {}
        self.runs: list[dict] = []
        self.checkpoints: dict[str, dict] = {}
        self.quarantine: list[dict] = []
        self.audit_log: list[dict] = []
        self._ids = itertools.count(1)

    # ---- data
    def init_db(self) -> None:
        return None

    def upsert(self, entity: str, source: str, rows: list[dict]) -> tuple[int, int]:
        table = {"user": "users", "device": "devices", "alert": "alerts"}.get(entity, entity)
        inserted = updated = 0
        with self._lock:
            t = self.tables[table]
            for row in rows:
                key = (source, str(row["id"]))
                stored = {**row, "source": source}
                if isinstance(stored.get("raw"), (dict, list)):
                    stored["raw"] = json.dumps(stored["raw"], default=str)
                if key in t:
                    updated += 1
                else:
                    inserted += 1
                t[key] = stored
        return inserted, updated

    # ---- runs
    def start_run(self, connector: str) -> int:
        with self._lock:
            run_id = next(self._ids)
            self.runs.append({"id": run_id, "connector": connector, "started_at": now_iso(), "status": "running"})
            return run_id

    def finish_run(self, run_id, status, records_pulled, records_bad, pages, retries, last_error) -> None:
        with self._lock:
            for r in self.runs:
                if r["id"] == run_id:
                    r.update(status=status, finished_at=now_iso(), records_pulled=records_pulled,
                             records_bad=records_bad, pages=pages, retries=retries, last_error=last_error)

    # ---- checkpoints: set_checkpoint overwrites BOTH fields exactly as given (None = cleared)
    def get_checkpoint(self, connector: str) -> dict:
        with self._lock:
            return dict(self.checkpoints.get(connector, {"watermark": None, "resume_state": None}))

    def set_checkpoint(self, connector: str, watermark: Optional[str] = None, resume_state: Optional[Any] = None) -> None:
        with self._lock:
            self.checkpoints[connector] = {"watermark": watermark, "resume_state": resume_state, "updated_at": now_iso()}

    # ---- quarantine / audit
    def add_quarantine(self, connector: str, run_id: Optional[int], raw: Any, reason: str) -> None:
        with self._lock:
            self.quarantine.append({"id": len(self.quarantine) + 1, "connector": connector, "run_id": run_id,
                                    "raw_json": json.dumps(raw, default=str) if not isinstance(raw, str) else raw,
                                    "reason": reason, "created_at": now_iso(), "replayed": False})

    def audit(self, actor: str, action: str, target: str, detail: Any = None) -> None:
        with self._lock:
            self.audit_log.append({"ts": now_iso(), "actor": actor, "action": action, "target": target, "detail": detail})

    # ---- connectors
    def get_connector(self, name: str) -> Optional[dict]:
        with self._lock:
            c = self.connectors.get(name)
            return dict(c) if c else None

    def save_connector(self, name: str, entity: str, yaml: str, hash: str) -> None:
        with self._lock:
            c = self.connectors.get(name, {"name": name, "status": "never_run", "enabled": True,
                                           "consecutive_failures": 0, "approved_hash": None, "created_at": now_iso()})
            c.update(entity=entity, config_yaml=yaml, config_hash=hash, updated_at=now_iso())
            self.connectors[name] = c

    def approve_connector(self, name: str, hash: str) -> None:
        with self._lock:
            self.connectors[name]["approved_hash"] = hash

    def set_status(self, name: str, status: str, consecutive_failures: Optional[int] = None) -> None:
        with self._lock:
            c = self.connectors.setdefault(name, {"name": name})
            c["status"] = status
            if consecutive_failures is not None:
                c["consecutive_failures"] = consecutive_failures
            c["updated_at"] = now_iso()

    def list_connectors(self) -> list[dict]:
        with self._lock:
            return [dict(c) for c in self.connectors.values()]


_default_store = None


def default_store():
    """SQLite store if it is importable, else a process-wide MemoryStore."""
    global _default_store
    if _default_store is None:
        try:
            from store import db as sqlite_store  # type: ignore

            sqlite_store.init_db()
            _default_store = sqlite_store
        except ImportError:
            import logging

            logging.getLogger("engine").warning("store.db not found; using the in-memory store (data is lost on exit)")
            _default_store = MemoryStore()
    return _default_store


def set_default_store(store) -> None:
    global _default_store
    _default_store = store
