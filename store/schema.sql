-- Common schema. Every row carries source, fetched_at, raw and tenant_id.
-- Re-runs upsert on (source, id). A retry can never duplicate a record.

CREATE TABLE IF NOT EXISTS users (
    source      TEXT NOT NULL,
    id          TEXT NOT NULL,
    name        TEXT,
    email       TEXT,
    status      TEXT,
    last_login  TEXT,
    fetched_at  TEXT NOT NULL,
    raw         TEXT,
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    PRIMARY KEY (source, id)
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

CREATE TABLE IF NOT EXISTS devices (
    source      TEXT NOT NULL,
    id          TEXT NOT NULL,
    hostname    TEXT,
    ip          TEXT,
    os          TEXT,
    owner       TEXT,
    last_seen   TEXT,
    fetched_at  TEXT NOT NULL,
    raw         TEXT,
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    PRIMARY KEY (source, id)
);
CREATE INDEX IF NOT EXISTS idx_devices_owner ON devices (owner);

CREATE TABLE IF NOT EXISTS alerts (
    source      TEXT NOT NULL,
    id          TEXT NOT NULL,
    type        TEXT,
    severity    TEXT,
    timestamp   TEXT,
    description TEXT,
    cve         TEXT,
    fetched_at  TEXT NOT NULL,
    raw         TEXT,
    tenant_id   TEXT NOT NULL DEFAULT 'default',
    PRIMARY KEY (source, id)
);
CREATE INDEX IF NOT EXISTS idx_alerts_cve ON alerts (cve);

CREATE TABLE IF NOT EXISTS connectors (
    name                 TEXT PRIMARY KEY,
    entity               TEXT NOT NULL,
    config_yaml          TEXT NOT NULL,
    config_hash          TEXT NOT NULL,
    approved_hash        TEXT,
    enabled              INTEGER NOT NULL DEFAULT 1,
    status               TEXT NOT NULL DEFAULT 'never_run',
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    connector      TEXT NOT NULL,
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    status         TEXT NOT NULL DEFAULT 'running',
    records_pulled INTEGER NOT NULL DEFAULT 0,
    records_bad    INTEGER NOT NULL DEFAULT 0,
    pages          INTEGER NOT NULL DEFAULT 0,
    retries        INTEGER NOT NULL DEFAULT 0,
    last_error     TEXT,
    request_log    TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_connector ON runs (connector, id);

CREATE TABLE IF NOT EXISTS checkpoints (
    connector    TEXT PRIMARY KEY,
    watermark    TEXT,
    resume_state TEXT,
    updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quarantine (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    connector  TEXT NOT NULL,
    run_id     INTEGER,
    raw_json   TEXT NOT NULL,
    reason     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    replayed   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_quarantine_connector ON quarantine (connector, id);

CREATE TABLE IF NOT EXISTS alerts_sent (
    connector TEXT NOT NULL,
    sent_at   TEXT NOT NULL,
    reason    TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_sent_connector ON alerts_sent (connector, sent_at);

CREATE TABLE IF NOT EXISTS audit_log (
    ts     TEXT NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT
);
