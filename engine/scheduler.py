"""Scheduler (FR-4), kill switch and circuit breaker.

One background thread wakes every few seconds, asks the store for connectors and runs
each one that is due on a small thread pool. It never runs the same connector twice at
once. It skips paused connectors. It gives circuit-open connectors a cooldown before one
trial run (half-open).
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from .config import ConfigError, load_config
from .memstore import default_store
from .runner import run_connector

log = logging.getLogger("engine.scheduler")


class Scheduler:
    def __init__(self, store=None, tick_s: float = 5.0, workers: int = 4, stagger_s: float = 2.0, run_kwargs: dict | None = None):
        self.store = store
        self.run_kwargs = run_kwargs or {}  # tests pass a fake transport here
        self.tick_s = tick_s
        self.stagger_s = stagger_s
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="connector")
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._due_at: dict[str, float] = {}
        self._running: set[str] = set()
        self._lock = threading.Lock()

    # ---- lifecycle
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self.store = self.store or default_store()
        now = time.time()
        # first runs are staggered so we do not hit every API in the same second
        for i, c in enumerate(self.store.list_connectors()):
            self._due_at.setdefault(c["name"], now + i * self.stagger_s)
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="scheduler", daemon=True)
        self._thread.start()
        log.info("scheduler started")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self.tick_s + 1)

    # ---- kill switch
    def pause(self, name: str, actor: str = "user") -> None:
        store = self.store or default_store()
        store.set_status(name, "paused")
        store.audit(actor, "connector_paused", name, None)

    def resume(self, name: str, actor: str = "user") -> None:
        store = self.store or default_store()
        row = store.get_connector(name) or {}
        store.set_status(name, "never_run" if not row.get("consecutive_failures") else "failing", consecutive_failures=0)
        store.audit(actor, "connector_resumed", name, None)
        with self._lock:
            self._due_at[name] = time.time()  # run soon after resuming

    # ---- info for the health page
    def next_run_at(self, name: str) -> Optional[float]:
        row = (self.store or default_store()).get_connector(name) or {}
        if row.get("status") == "paused":
            return None
        try:
            load_config(row["config_yaml"])
        except (ConfigError, KeyError):
            return None
        return max(self._due_at.get(name, time.time()), time.time())

    def is_running(self, name: str) -> bool:
        with self._lock:
            return name in self._running

    # ---- internals
    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:  # keep the loop alive no matter what
                log.exception("scheduler tick failed")
            self._stop.wait(self.tick_s)

    def _tick(self) -> None:
        now = time.time()
        for row in self.store.list_connectors():
            name = row["name"]
            status = row.get("status")
            if status in ("paused", "config_changed") or row.get("enabled") is False:
                continue
            try:
                cfg = load_config(row["config_yaml"])
            except (ConfigError, KeyError):
                continue
            with self._lock:
                due = self._due_at.setdefault(name, now)  # new connectors run right away
                if name in self._running or now < due:
                    continue
                self._running.add(name)
                self._due_at[name] = now + cfg.interval_s
            self._pool.submit(self._run, name, cfg)

    def _run(self, name: str, cfg) -> None:
        try:
            res = run_connector(name, store=self.store, **self.run_kwargs)
            log.info("%s: %s, %d records, %d bad, %d retries", name, res.status, res.records_pulled, res.records_bad, res.retries)
            if res.connector_status == "circuit_open":  # cool down before one trial run
                with self._lock:
                    self._due_at[name] = time.time() + max(cfg.interval_s, cfg.limits.circuit_cooldown_s)
        finally:
            with self._lock:
                self._running.discard(name)


_scheduler: Optional[Scheduler] = None


def get_scheduler(store=None) -> Scheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = Scheduler(store=store)
    return _scheduler


def start(store=None) -> Scheduler:
    s = get_scheduler(store)
    s.start()
    return s


def pause(name: str, actor: str = "user") -> None:
    get_scheduler().pause(name, actor)


def resume(name: str, actor: str = "user") -> None:
    get_scheduler().resume(name, actor)
