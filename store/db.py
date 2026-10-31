"""SQLite store for the common schema, run history and connector state.

Each call opens and closes its own connection. That lets the scheduler and the
web app call in from different threads. WAL mode lets readers carry on while a
run is writing.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

SCHEMA_PATH = Path(__file__).with_name("schema.sql")
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "integration.db"

ENTITY_COLUMNS: dict[str, tuple[str, ...]] = {
    "users": ("name", "email", "status", "last_login"),
    "devices": ("hostname", "ip", "os", "owner", "last_seen"),
    "alerts": ("type", "severity", "timestamp", "description", "cve"),
}
ENTITY_TABLES = {"user": "users", "device": "devices", "alert": "alerts"}

RUN_STATUSES = frozenset({"success", "failed", "auth_failed", "partial"})
CONNECTOR_STATUSES = frozenset(
    {
        "healthy",
        "degraded",
        "failing",
        "auth_failed",
        "paused",
        "circuit_open",
        "config_changed",
        "never_run",
    }
)

_UNSET: Any = object()

MAX_LOGGED_REQUESTS = 200
RUN_COLUMNS = (
    "id, connector, started_at, finished_at, status, records_pulled, records_bad, pages, retries, last_error"
)

_MASK = "***"
_SECRET_ENV_SUFFIXES = ("_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_WEBHOOK")
_MIN_SECRET_LENGTH = 6
_SECRET_KEY_RE = re.compile(r"token|secret|password|passwd|api[_-]?key|authorization", re.IGNORECASE)
_AUTH_HEADER_RE = re.compile(
    r"""(authorization["']?\s*[:=]\s*)["']?(?:[A-Za-z]+\s+)?[^\s"',}]+""",
    re.IGNORECASE,
)
_AUTH_SCHEME_RE = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
_SECRET_PAIR_RE = re.compile(
    r"""(["']?[\w-]*(?:token|secret|password|passwd|api[_-]?key)[\w-]*["']?\s*[:=]\s*)["']?[^\s"'&,}]+""",
    re.IGNORECASE,
)


def now_iso() -> str:
    """Return the current time as ISO 8601 UTC with a Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def mask_text(text: str | None) -> str | None:
    """Hide secret values in free text before it is stored.

    Last line of defence for audit details and error messages. Replaces the
    values of secret-named env vars, auth headers and key=value pairs whose
    name looks secret.
    """
    if text is None:
        return None
    for name, value in os.environ.items():
        if name.upper().endswith(_SECRET_ENV_SUFFIXES) and len(value) >= _MIN_SECRET_LENGTH:
            text = text.replace(value, _MASK)
    text = _AUTH_HEADER_RE.sub(rf"\g<1>{_MASK}", text)
    text = _AUTH_SCHEME_RE.sub(rf"\g<1> {_MASK}", text)
    return _SECRET_PAIR_RE.sub(rf"\g<1>{_MASK}", text)


def _db_path() -> Path:
    return Path(os.environ.get("INTEGRATION_DB") or DEFAULT_DB_PATH)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(_db_path(), timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def _read() -> Iterator[sqlite3.Connection]:
    conn = _connect()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def _write() -> Iterator[sqlite3.Connection]:
    """Run a block in one write transaction. Any error rolls all of it back."""
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def _to_json(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, default=str)


def _table_for(entity: str) -> str:
    table = ENTITY_TABLES.get(entity, entity)
    if table not in ENTITY_COLUMNS:
        raise ValueError(f"unknown entity {entity!r}, expected one of {sorted(ENTITY_TABLES)}")
    return table


def init_db() -> None:
    """Create all tables and turn on WAL. Safe to call on every start."""
    conn = _connect()
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        _add_missing_columns(conn)
    finally:
        conn.close()


def _add_missing_columns(conn: sqlite3.Connection) -> None:
    """Bring a database made by an older version up to the current schema."""
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(runs)")}
    if "request_log" not in existing:
        conn.execute("ALTER TABLE runs ADD COLUMN request_log TEXT")


# Records

def _clean_row(table: str, source: str, row: dict[str, Any], fetched_at: str) -> dict[str, Any]:
    record_id = row.get("id")
    if record_id is None or record_id == "":
        raise ValueError(f"{source}: row has no id, it should have been quarantined")

    values = dict(row)
    if table == "users" and values.get("last_login") is None:
        values["last_login"] = values.get("last_seen")

    clean: dict[str, Any] = {"source": source, "id": str(record_id)}
    for column in ENTITY_COLUMNS[table]:
        value = values.get(column)
        clean[column] = _to_json(value) if isinstance(value, (dict, list)) else value
    clean["fetched_at"] = values.get("fetched_at") or fetched_at
    raw = values.get("raw")
    clean["raw"] = None if raw is None else _to_json(raw)
    clean["tenant_id"] = values.get("tenant_id") or "default"
    return clean


def upsert(entity: str, source: str, rows: Iterable[dict[str, Any]]) -> tuple[int, int]:
    """Insert or update rows on (source, id). Returns (inserted, updated).

    Fields outside the common schema are dropped. The whole batch is one
    transaction. A row with no id fails the batch and writes nothing.
    """
    table = _table_for(entity)
    fetched_at = now_iso()
    clean_rows = [_clean_row(table, source, row, fetched_at) for row in rows]
    if not clean_rows:
        return (0, 0)

    columns = list(clean_rows[0])
    names = ", ".join(columns)
    placeholders = ", ".join(f":{column}" for column in columns)
    updates = ", ".join(f"{c} = excluded.{c}" for c in columns if c not in ("source", "id"))
    insert_sql = (
        f"INSERT INTO {table} ({names}) VALUES ({placeholders}) "
        f"ON CONFLICT (source, id) DO UPDATE SET {updates}"
    )
    exists_sql = f"SELECT 1 FROM {table} WHERE source = ? AND id = ?"

    inserted = updated = 0
    with _write() as conn:
        for row in clean_rows:
            if conn.execute(exists_sql, (row["source"], row["id"])).fetchone():
                updated += 1
            else:
                inserted += 1
            conn.execute(insert_sql, row)
    return (inserted, updated)


def query_records(
    entity: str,
    source: str | None = None,
    q: str | None = None,
    tenant_id: str = "default",
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Return rows for one tenant, with an optional source and text filter."""
    table = _table_for(entity)
    where = ["tenant_id = ?"]
    params: list[Any] = [tenant_id]
    if source:
        where.append("source = ?")
        params.append(source)
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        searched = ("id", *ENTITY_COLUMNS[table])
        where.append(
            "(" + " OR ".join(f"{column} LIKE ? ESCAPE '\\'" for column in searched) + ")"
        )
        params.extend([f"%{escaped}%"] * len(searched))
    sql = (
        f"SELECT * FROM {table} WHERE {' AND '.join(where)} "
        "ORDER BY fetched_at DESC, source, id LIMIT ?"
    )
    with _read() as conn:
        return [dict(row) for row in conn.execute(sql, (*params, limit))]


def count_records(entity: str, source: str, tenant_id: str = "default") -> int:
    table = _table_for(entity)
    with _read() as conn:
        row = conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE source = ? AND tenant_id = ?", (source, tenant_id)
        ).fetchone()
    return int(row[0])


def list_sources(entity: str, tenant_id: str = "default") -> list[str]:
    table = _table_for(entity)
    with _read() as conn:
        rows = conn.execute(
            f"SELECT DISTINCT source FROM {table} WHERE tenant_id = ? ORDER BY source", (tenant_id,)
        )
        return [row[0] for row in rows]


def list_emails(tenant_id: str = "default") -> list[str]:
    """Return every known person email, from user rows and device owners."""
    sql = (
        "SELECT LOWER(email) FROM users WHERE tenant_id = ? AND email IS NOT NULL AND email != '' "
        "UNION SELECT LOWER(owner) FROM devices WHERE tenant_id = ? AND owner IS NOT NULL "
        "AND owner != '' ORDER BY 1"
    )
    with _read() as conn:
        return [row[0] for row in conn.execute(sql, (tenant_id, tenant_id))]


def person_records(email: str, tenant_id: str = "default") -> dict[str, list[dict[str, Any]]]:
    """Return one person's rows from all sources, matched on email."""
    needle = email.strip().lower()
    escaped = needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    with _read() as conn:
        users = conn.execute(
            "SELECT * FROM users WHERE tenant_id = ? AND LOWER(email) = ? ORDER BY source",
            (tenant_id, needle),
        )
        result = {"users": [dict(row) for row in users]}
        devices = conn.execute(
            "SELECT * FROM devices WHERE tenant_id = ? AND LOWER(owner) = ? ORDER BY source",
            (tenant_id, needle),
        )
        result["devices"] = [dict(row) for row in devices]
        alerts = conn.execute(
            "SELECT * FROM alerts WHERE tenant_id = ? AND LOWER(description) LIKE ? ESCAPE '\\' "
            "ORDER BY timestamp DESC LIMIT 100",
            (tenant_id, f"%{escaped}%"),
        )
        result["alerts"] = [dict(row) for row in alerts]
    return result


def kev_matches(kev_source: str, tenant_id: str = "default", limit: int = 200) -> list[dict[str, Any]]:
    """Return alerts from other sources whose CVE appears in the given KEV source."""
    sql = (
        "SELECT * FROM alerts WHERE tenant_id = ? AND source != ? AND cve IN "
        "(SELECT cve FROM alerts WHERE source = ? AND tenant_id = ? AND cve IS NOT NULL) "
        "ORDER BY timestamp DESC LIMIT ?"
    )
    with _read() as conn:
        rows = conn.execute(sql, (tenant_id, kev_source, kev_source, tenant_id, limit))
        return [dict(row) for row in rows]


# Runs

def start_run(connector: str) -> int:
    with _write() as conn:
        cursor = conn.execute(
            "INSERT INTO runs (connector, started_at) VALUES (?, ?)", (connector, now_iso())
        )
        return int(cursor.lastrowid)


def finish_run(
    run_id: int,
    status: str,
    records_pulled: int = 0,
    records_bad: int = 0,
    pages: int = 0,
    retries: int = 0,
    last_error: str | None = None,
) -> None:
    """Close a run. records_pulled counts every record seen, bad ones included."""
    if status not in RUN_STATUSES:
        raise ValueError(f"unknown run status {status!r}, expected one of {sorted(RUN_STATUSES)}")
    with _write() as conn:
        cursor = conn.execute(
            "UPDATE runs SET finished_at = ?, status = ?, records_pulled = ?, records_bad = ?, "
            "pages = ?, retries = ?, last_error = ? WHERE id = ?",
            (
                now_iso(),
                status,
                records_pulled,
                records_bad,
                pages,
                retries,
                mask_text(last_error),
                run_id,
            ),
        )
        if cursor.rowcount == 0:
            raise ValueError(f"unknown run id {run_id}")


def list_runs(connector: str, limit: int = 50) -> list[dict[str, Any]]:
    """Return runs for one connector, newest first. The request log is left out."""
    with _read() as conn:
        rows = conn.execute(
            f"SELECT {RUN_COLUMNS} FROM runs WHERE connector = ? ORDER BY id DESC LIMIT ?",
            (connector, limit),
        )
        return [dict(row) for row in rows]


def _mask_strings(value: Any) -> Any:
    if isinstance(value, str):
        return mask_text(value)
    if isinstance(value, list):
        return [_mask_strings(item) for item in value]
    if isinstance(value, dict):
        return {
            key: _MASK if _SECRET_KEY_RE.search(str(key)) else _mask_strings(item)
            for key, item in value.items()
        }
    return value


def save_run_log(run_id: int, requests: list[dict[str, Any]], waits: list[float]) -> None:
    """Keep a run's request log, latest entries first if it is over the cap.

    Text is masked one string at a time, so the stored JSON stays valid.
    """
    kept = requests[-MAX_LOGGED_REQUESTS:]
    payload = {"requests": kept, "waits": waits, "dropped": len(requests) - len(kept)}
    with _write() as conn:
        conn.execute(
            "UPDATE runs SET request_log = ? WHERE id = ?",
            (json.dumps(_mask_strings(payload), default=str), run_id),
        )


def get_run_log(run_id: int) -> dict[str, Any]:
    """Return {requests, waits, dropped}. Empty lists when nothing was saved."""
    with _read() as conn:
        row = conn.execute("SELECT request_log FROM runs WHERE id = ?", (run_id,)).fetchone()
    if row is None or not row["request_log"]:
        return {"requests": [], "waits": [], "dropped": 0}
    return json.loads(row["request_log"])


def last_run(connector: str) -> dict[str, Any] | None:
    runs = list_runs(connector, limit=1)
    return runs[0] if runs else None


# Checkpoints

def get_checkpoint(connector: str) -> dict[str, Any]:
    """Return {watermark, resume_state}. Both are None when nothing is saved."""
    with _read() as conn:
        row = conn.execute(
            "SELECT watermark, resume_state FROM checkpoints WHERE connector = ?", (connector,)
        ).fetchone()
    if row is None:
        return {"watermark": None, "resume_state": None}
    state = row["resume_state"]
    return {
        "watermark": row["watermark"],
        "resume_state": None if state is None else json.loads(state),
    }


def set_checkpoint(
    connector: str, watermark: str | None = None, resume_state: Any = _UNSET
) -> None:
    """Save progress for a connector.

    watermark: None keeps the saved value. An empty run cannot lose it.
    resume_state: leaving it out keeps the saved value. Passing None clears
    it, which is what a finished run should do. Any other value is stored as
    JSON and comes back unchanged from get_checkpoint.
    """
    with _write() as conn:
        row = conn.execute(
            "SELECT watermark, resume_state FROM checkpoints WHERE connector = ?", (connector,)
        ).fetchone()
        saved_watermark = row["watermark"] if row else None
        saved_state = row["resume_state"] if row else None
        if resume_state is _UNSET:
            new_state = saved_state
        elif resume_state is None:
            new_state = None
        else:
            new_state = json.dumps(resume_state, default=str)
        conn.execute(
            "INSERT INTO checkpoints (connector, watermark, resume_state, updated_at) "
            "VALUES (?, ?, ?, ?) ON CONFLICT (connector) DO UPDATE SET "
            "watermark = excluded.watermark, resume_state = excluded.resume_state, "
            "updated_at = excluded.updated_at",
            (
                connector,
                watermark if watermark is not None else saved_watermark,
                new_state,
                now_iso(),
            ),
        )


# Quarantine

def add_quarantine(connector: str, run_id: int | None, raw: Any, reason: str) -> int:
    """Park a bad record. Returns the quarantine id."""
    with _write() as conn:
        cursor = conn.execute(
            "INSERT INTO quarantine (connector, run_id, raw_json, reason, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (connector, run_id, _to_json(raw), mask_text(reason), now_iso()),
        )
        return int(cursor.lastrowid)


def list_quarantine(connector: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
    """Return quarantined records, newest first."""
    sql = "SELECT * FROM quarantine"
    params: list[Any] = []
    if connector:
        sql += " WHERE connector = ?"
        params.append(connector)
    with _read() as conn:
        rows = conn.execute(f"{sql} ORDER BY id DESC LIMIT ?", (*params, limit))
        return [dict(row) for row in rows]


def get_quarantine(quarantine_id: int) -> dict[str, Any] | None:
    with _read() as conn:
        row = conn.execute("SELECT * FROM quarantine WHERE id = ?", (quarantine_id,)).fetchone()
    return dict(row) if row else None


def mark_replayed(quarantine_id: int) -> None:
    with _write() as conn:
        conn.execute("UPDATE quarantine SET replayed = 1 WHERE id = ?", (quarantine_id,))


# Connectors

def _connector_dict(row: sqlite3.Row) -> dict[str, Any]:
    """The scheduler tests `enabled is False`, so it must be a real boolean."""
    connector = dict(row)
    connector["enabled"] = bool(connector["enabled"])
    return connector


def get_connector(name: str) -> dict[str, Any] | None:
    with _read() as conn:
        row = conn.execute("SELECT * FROM connectors WHERE name = ?", (name,)).fetchone()
    return _connector_dict(row) if row else None


def list_connectors() -> list[dict[str, Any]]:
    with _read() as conn:
        rows = conn.execute("SELECT * FROM connectors ORDER BY name")
        return [_connector_dict(row) for row in rows]


def save_connector(name: str, entity: str, yaml: str, config_hash: str) -> None:
    """Create or update a connector.

    Approval is separate. A saved config whose hash differs from the approved
    hash moves to config_changed until someone approves it.
    """
    _table_for(entity)
    now = now_iso()
    with _write() as conn:
        row = conn.execute(
            "SELECT approved_hash FROM connectors WHERE name = ?", (name,)
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO connectors (name, entity, config_yaml, config_hash, created_at, "
                "updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (name, entity, yaml, config_hash, now, now),
            )
            return
        conn.execute(
            "UPDATE connectors SET entity = ?, config_yaml = ?, config_hash = ?, updated_at = ? "
            "WHERE name = ?",
            (entity, yaml, config_hash, now, name),
        )
        if row["approved_hash"] and row["approved_hash"] != config_hash:
            conn.execute(
                "UPDATE connectors SET status = 'config_changed' WHERE name = ?", (name,)
            )


def approve_connector(name: str, config_hash: str) -> None:
    """Approve the saved config. The hash must match what is stored right now."""
    with _write() as conn:
        row = conn.execute(
            "SELECT config_hash, status FROM connectors WHERE name = ?", (name,)
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown connector {name!r}")
        if row["config_hash"] != config_hash:
            raise ValueError(f"{name}: hash does not match the saved config, refusing to approve")
        status = "never_run" if row["status"] == "config_changed" else row["status"]
        conn.execute(
            "UPDATE connectors SET approved_hash = ?, status = ?, updated_at = ? WHERE name = ?",
            (config_hash, status, now_iso(), name),
        )


def set_status(name: str, status: str, consecutive_failures: int | None = None) -> None:
    """Set connector status. consecutive_failures=None leaves the count as it is.

    `enabled` follows the status: paused means off and any other status means on.
    """
    if status not in CONNECTOR_STATUSES:
        raise ValueError(
            f"unknown connector status {status!r}, expected one of {sorted(CONNECTOR_STATUSES)}"
        )
    with _write() as conn:
        cursor = conn.execute(
            "UPDATE connectors SET status = ?, enabled = ?, "
            "consecutive_failures = COALESCE(?, consecutive_failures), updated_at = ? "
            "WHERE name = ?",
            (status, 0 if status == "paused" else 1, consecutive_failures, now_iso(), name),
        )
        if cursor.rowcount == 0:
            raise ValueError(f"unknown connector {name!r}")


def set_enabled(name: str, enabled: bool) -> None:
    """Turn scheduling on or off for a connector. Status is set separately."""
    with _write() as conn:
        cursor = conn.execute(
            "UPDATE connectors SET enabled = ?, updated_at = ? WHERE name = ?",
            (1 if enabled else 0, now_iso(), name),
        )
        if cursor.rowcount == 0:
            raise ValueError(f"unknown connector {name!r}")


# Alerts sent and audit

def record_alert_sent(connector: str, reason: str) -> None:
    with _write() as conn:
        conn.execute(
            "INSERT INTO alerts_sent (connector, sent_at, reason) VALUES (?, ?, ?)",
            (connector, now_iso(), mask_text(reason)),
        )


def last_alert_sent(connector: str) -> dict[str, Any] | None:
    with _read() as conn:
        row = conn.execute(
            "SELECT * FROM alerts_sent WHERE connector = ? ORDER BY rowid DESC LIMIT 1",
            (connector,),
        ).fetchone()
    return dict(row) if row else None


def audit(actor: str, action: str, target: str | None = None, detail: Any = None) -> None:
    """Add an audit entry. The detail is masked before it is written."""
    text = None if detail is None else mask_text(_to_json(detail))
    with _write() as conn:
        conn.execute(
            "INSERT INTO audit_log (ts, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
            (now_iso(), actor, action, target, text),
        )


def list_audit(limit: int = 200) -> list[dict[str, Any]]:
    """Return audit entries, newest first."""
    with _read() as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY rowid DESC LIMIT ?", (limit,))
        return [dict(row) for row in rows]
