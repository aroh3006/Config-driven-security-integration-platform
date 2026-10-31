import time

import httpx

from engine import save_and_approve
from engine.scheduler import Scheduler

CFG = """
name: NAME
entity: alert
source: {base_url: https://api.example.com, allow_hosts: [api.example.com]}
request: {path: /x}
schedule: every 10s
map: {id: id, timestamp: ts}
"""


def test_scheduler_runs_due_connectors_and_respects_pause(store):
    for n in ("src-a", "src-b"):
        assert save_and_approve(CFG.replace("NAME", n), store=store)["ok"]
    store.set_status("src-b", "paused")
    transport = httpx.MockTransport(lambda r: httpx.Response(200, json=[{"id": "1", "ts": "2026-10-31T00:00:00Z"}]))
    s = Scheduler(store=store, tick_s=0.05, stagger_s=0, run_kwargs={"transport": transport, "resolver": lambda h: ["93.184.216.34"]})
    s.start()
    try:
        deadline = time.time() + 3
        while time.time() < deadline and not any(r.get("status") == "success" for r in store.runs):
            time.sleep(0.05)
    finally:
        s.stop()
    ran = {r["connector"] for r in store.runs}
    assert ran == {"src-a"}
    assert store.get_connector("src-a")["status"] == "healthy"
    assert s.next_run_at("src-a") > time.time() + 5  # next run ~10s later
    assert s.next_run_at("src-b") is None


def test_resume_clears_pause_and_audits(store):
    save_and_approve(CFG.replace("NAME", "src-a"), store=store)
    s = Scheduler(store=store)
    s.pause("src-a")
    assert store.get_connector("src-a")["status"] == "paused"
    s.resume("src-a")
    assert store.get_connector("src-a")["status"] == "never_run"
    assert [a["action"] for a in store.audit_log][-2:] == ["connector_paused", "connector_resumed"]
