import json
import sqlite3
import threading

import pytest

from store import db


def test_init_db_is_repeatable_and_uses_wal(temp_db):
    db.init_db()
    conn = sqlite3.connect(temp_db)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    conn.close()


def test_upsert_counts_inserts_and_updates():
    row = {"id": "1", "email": "ann@example.com", "raw": {"id": "1"}}
    assert db.upsert("user", "okta-users", [row]) == (1, 0)
    changed = {"id": "1", "email": "ann.rao@example.com", "raw": {"id": "1"}}
    assert db.upsert("user", "okta-users", [changed, {"id": "2"}]) == (1, 1)

    rows = db.query_records("user")
    assert len(rows) == 2
    first = next(r for r in rows if r["id"] == "1")
    assert first["email"] == "ann.rao@example.com"


def test_same_id_from_two_sources_stays_separate():
    db.upsert("alert", "a", [{"id": "1"}])
    db.upsert("alert", "b", [{"id": "1"}])
    assert len(db.query_records("alert")) == 2
    assert len(db.query_records("alert", source="a")) == 1


def test_duplicate_id_inside_one_batch_counts_as_update():
    assert db.upsert("user", "s", [{"id": "1"}, {"id": "1"}]) == (1, 1)


def test_upsert_fills_common_columns():
    db.upsert("alert", "s", [{"id": 42, "severity": "high", "raw": {"x": 1}, "extra": "dropped"}])
    row = db.query_records("alert")[0]
    assert row["id"] == "42"
    assert row["source"] == "s"
    assert row["tenant_id"] == "default"
    assert row["fetched_at"].endswith("Z")
    assert row["cve"] is None
    assert json.loads(row["raw"]) == {"x": 1}
    assert "extra" not in row


def test_nested_values_are_stored_as_json():
    db.upsert("user", "s", [{"id": "1", "name": {"first": "Ann"}}])
    assert json.loads(db.query_records("user")[0]["name"]) == {"first": "Ann"}


def test_last_seen_is_an_alias_for_last_login_on_users():
    db.upsert("user", "s", [{"id": "1", "last_seen": "2026-10-30T00:00:00Z"}])
    assert db.query_records("user")[0]["last_login"] == "2026-10-30T00:00:00Z"


def test_upsert_accepts_plural_entity_and_rejects_unknown():
    assert db.upsert("devices", "s", [{"id": "1", "ip": "10.0.0.1"}]) == (1, 0)
    with pytest.raises(ValueError, match="unknown entity"):
        db.upsert("widgets; DROP TABLE users", "s", [{"id": "1"}])


def test_row_without_id_writes_nothing_from_the_batch():
    with pytest.raises(ValueError, match="no id"):
        db.upsert("user", "s", [{"id": "1"}, {"email": "x@example.com"}])
    assert db.query_records("user") == []


def test_empty_batch_is_fine():
    assert db.upsert("user", "s", []) == (0, 0)


def test_query_filters_by_text_and_tenant():
    db.upsert(
        "user",
        "s",
        [
            {"id": "1", "email": "ann@example.com"},
            {"id": "2", "email": "bob@example.com", "tenant_id": "acme"},
        ],
    )
    assert [r["id"] for r in db.query_records("user", q="ann")] == ["1"]
    assert db.query_records("user", q="bob") == []
    assert [r["id"] for r in db.query_records("user", tenant_id="acme")] == ["2"]


def test_query_treats_wildcards_as_plain_text():
    db.upsert("user", "s", [{"id": "1", "email": "ann@example.com"}])
    assert db.query_records("user", q="%") == []
    assert db.query_records("user", q="a_n") == []


def test_run_lifecycle():
    run_id = db.start_run("c")
    assert db.last_run("c")["status"] == "running"
    db.finish_run(run_id, "partial", 500, 3, 5, 1, "3 of 500 records invalid")
    run = db.last_run("c")
    assert run["status"] == "partial"
    assert (run["records_pulled"], run["records_bad"], run["pages"], run["retries"]) == (500, 3, 5, 1)
    assert run["finished_at"].endswith("Z")


def test_finish_run_rejects_bad_status_and_unknown_id():
    run_id = db.start_run("c")
    with pytest.raises(ValueError, match="unknown run status"):
        db.finish_run(run_id, "great")
    with pytest.raises(ValueError, match="unknown run id"):
        db.finish_run(9999, "success")


def test_list_runs_is_newest_first():
    first = db.start_run("c")
    second = db.start_run("c")
    assert [r["id"] for r in db.list_runs("c")] == [second, first]
    assert db.last_run("other") is None


def test_checkpoint_starts_empty():
    assert db.get_checkpoint("c") == {"watermark": None, "resume_state": None}


def test_checkpoint_round_trip_keeps_structure():
    db.set_checkpoint("c", watermark="2026-10-01T00:00:00Z", resume_state={"page": 3})
    assert db.get_checkpoint("c") == {
        "watermark": "2026-10-01T00:00:00Z",
        "resume_state": {"page": 3},
    }


def test_setting_one_checkpoint_field_keeps_the_other():
    db.set_checkpoint("c", watermark="w1", resume_state={"page": 3})
    db.set_checkpoint("c", watermark="w2")
    assert db.get_checkpoint("c") == {"watermark": "w2", "resume_state": {"page": 3}}
    db.set_checkpoint("c", resume_state={"page": 4})
    assert db.get_checkpoint("c") == {"watermark": "w2", "resume_state": {"page": 4}}


def test_finished_run_can_clear_resume_state_without_losing_watermark():
    db.set_checkpoint("c", watermark="w1", resume_state={"page": 3})
    db.set_checkpoint("c", resume_state=None)
    assert db.get_checkpoint("c") == {"watermark": "w1", "resume_state": None}
    db.set_checkpoint("c", watermark=None, resume_state={"page": 1})
    assert db.get_checkpoint("c")["watermark"] == "w1"


def test_quarantine_flow():
    run_id = db.start_run("c")
    quarantine_id = db.add_quarantine("c", run_id, {"bad": True}, "missing required field: id")
    item = db.get_quarantine(quarantine_id)
    assert json.loads(item["raw_json"]) == {"bad": True}
    assert item["replayed"] == 0
    db.mark_replayed(quarantine_id)
    assert db.get_quarantine(quarantine_id)["replayed"] == 1
    assert len(db.list_quarantine("c")) == 1
    assert db.list_quarantine("other") == []


def test_new_connector_defaults():
    db.save_connector("c", "user", "name: c", "h1")
    connector = db.get_connector("c")
    assert connector["status"] == "never_run"
    assert connector["enabled"] == 1
    assert connector["approved_hash"] is None
    assert connector["consecutive_failures"] == 0
    assert db.get_connector("missing") is None


def test_changing_an_approved_config_is_flagged():
    db.save_connector("c", "user", "v1", "h1")
    db.approve_connector("c", "h1")
    db.set_status("c", "healthy", 0)

    db.save_connector("c", "user", "v1", "h1")
    assert db.get_connector("c")["status"] == "healthy"

    db.save_connector("c", "user", "v2", "h2")
    connector = db.get_connector("c")
    assert connector["status"] == "config_changed"
    assert connector["approved_hash"] == "h1"

    db.approve_connector("c", "h2")
    connector = db.get_connector("c")
    assert connector["approved_hash"] == "h2"
    assert connector["status"] == "never_run"


def test_approve_refuses_a_hash_that_is_not_the_saved_config():
    db.save_connector("c", "user", "v1", "h1")
    with pytest.raises(ValueError, match="does not match"):
        db.approve_connector("c", "something-else")
    assert db.get_connector("c")["approved_hash"] is None
    with pytest.raises(ValueError, match="unknown connector"):
        db.approve_connector("missing", "h1")


def test_set_status_keeps_or_changes_failure_count():
    db.save_connector("c", "user", "v1", "h1")
    db.set_status("c", "failing", 3)
    assert db.get_connector("c")["consecutive_failures"] == 3
    db.set_status("c", "degraded")
    assert db.get_connector("c")["consecutive_failures"] == 3
    db.set_status("c", "healthy", 0)
    assert db.get_connector("c")["consecutive_failures"] == 0


def test_set_status_rejects_bad_values():
    db.save_connector("c", "user", "v1", "h1")
    with pytest.raises(ValueError, match="unknown connector status"):
        db.set_status("c", "fine")
    with pytest.raises(ValueError, match="unknown connector"):
        db.set_status("missing", "healthy")


def test_set_enabled_and_list_connectors():
    db.save_connector("b", "user", "v", "h")
    db.save_connector("a", "alert", "v", "h")
    db.set_enabled("a", False)
    connectors = db.list_connectors()
    assert [c["name"] for c in connectors] == ["a", "b"]
    assert connectors[0]["enabled"] == 0


def test_alerts_sent_returns_latest():
    assert db.last_alert_sent("c") is None
    db.record_alert_sent("c", "first")
    db.record_alert_sent("c", "second")
    assert db.last_alert_sent("c")["reason"] == "second"


@pytest.mark.parametrize(
    "text, leaked",
    [
        ("Authorization: Bearer abc.def-123", "abc.def-123"),
        ("Authorization: SSWS 00abcDEF", "00abcDEF"),
        ('{"Authorization": "Basic dXNlcjpwYXNz"}', "dXNlcjpwYXNz"),
        ("sent Bearer abc.def-123 to host", "abc.def-123"),
        ("GET https://x.example.com/?api_key=s3cr3tvalue&limit=5", "s3cr3tvalue"),
        ('{"client_secret": "s3cr3tvalue"}', "s3cr3tvalue"),
        ("password=hunter22", "hunter22"),
    ],
)
def test_mask_text_hides_common_secret_shapes(text, leaked):
    masked = db.mask_text(text)
    assert leaked not in masked
    assert "***" in masked


def test_mask_text_hides_values_of_secret_env_vars(monkeypatch):
    monkeypatch.setenv("OKTA_KEY", "plainvalue123")
    assert db.mask_text("failed with plainvalue123 in url") == "failed with *** in url"


def test_mask_text_leaves_normal_text_alone():
    text = "HTTP 503 from https://x.example.com/api after 3 retries"
    assert db.mask_text(text) == text
    assert db.mask_text(None) is None


def test_stored_error_text_is_masked():
    run_id = db.start_run("c")
    db.finish_run(run_id, "failed", last_error="401 with Authorization: Bearer abc123")
    assert "abc123" not in db.last_run("c")["last_error"]

    db.add_quarantine("c", run_id, {}, "bad token=abc123")
    assert "abc123" not in db.list_quarantine("c")[0]["reason"]


def test_audit_detail_is_masked_for_text_and_dicts():
    db.audit("tester", "connector.save", "c", "used password=hunter22")
    db.audit("tester", "connector.test", "c", {"api_key": "hunter22", "ok": True})
    db.audit("tester", "connector.pause", "c")
    entries = db.list_audit()
    assert entries[0]["action"] == "connector.pause"
    assert entries[0]["detail"] is None
    assert "hunter22" not in entries[1]["detail"]
    assert "hunter22" not in entries[2]["detail"]


def test_writes_from_many_threads_all_land():
    errors = []

    def worker(n):
        try:
            for i in range(10):
                db.upsert("alert", f"s{n}", [{"id": str(i)}])
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(db.query_records("alert")) == 50
