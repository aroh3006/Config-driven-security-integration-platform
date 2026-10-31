"""In-memory state of runs in progress, for the live page.

This only tells the page what is happening right now. It is lost on restart,
which is fine: a run that died with the process must not keep the page refreshing.
"""

from __future__ import annotations

import threading
import time
from typing import Any

_lock = threading.Lock()
_state: dict[str, dict[str, Any]] = {}


def begin(name: str, scenario: str | None = None) -> bool:
    """Mark a run as started. Returns False if one is already going."""
    with _lock:
        entry = _state.setdefault(name, {})
        if entry.get("active"):
            return False
        entry.update(active=True, until=None, seconds=None, reason=None)
        if scenario:
            entry["scenario"] = scenario
        return True


def finish(name: str) -> None:
    with _lock:
        entry = _state.setdefault(name, {})
        entry.update(active=False, until=None, seconds=None, reason=None)


def note_wait(name: str, seconds: float, reason: str) -> None:
    """Called by the engine when a connector starts waiting."""
    with _lock:
        entry = _state.setdefault(name, {})
        entry.update(until=time.time() + seconds, seconds=seconds, reason=reason)


def snapshot(name: str) -> dict[str, Any]:
    """Return what the page should show. A wait counts as active until it ends."""
    now = time.time()
    with _lock:
        entry = dict(_state.get(name, {}))
    until = entry.get("until")
    waiting = bool(until and until > now)
    return {
        "active": bool(entry.get("active")) or waiting,
        "scenario": entry.get("scenario"),
        "waiting": waiting,
        "seconds": entry.get("seconds") if waiting else None,
        "reason": entry.get("reason") if waiting else None,
        "resumes_at": time.strftime("%H:%M:%S", time.gmtime(until)) if waiting else None,
        "began_at": time.strftime("%H:%M:%S", time.gmtime(until - entry["seconds"])) if waiting else None,
        "remaining": max(int(until - now), 1) if waiting else 0,
    }


def reset() -> None:
    with _lock:
        _state.clear()
