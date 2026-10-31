"""Fault switch: inject failures inside our own HTTP client so failure tests are repeatable.

Modes (per connector):
  "503x3"     next 3 requests return 503 (any of 500/502/503/504 works)
  "429:30"    next request returns 429 with Retry-After: 30   ("429:30x2" for two)
  "timeout"   next request times out ("timeoutx4" for four)
  "401"       next request returns 401 (simulates an expired key)
  "badrecord" the next page gets one record with its required fields removed
  "off"       clear

Set with set_fault() or the environment: FAULTS="okta-users=503x3,jira-tickets=429:30".
"""

from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass

_MODE = re.compile(r"^(?P<kind>500|502|503|504|429|401|403|timeout|badrecord)(?::(?P<arg>\d+))?(?:x(?P<n>\d+))?$")


@dataclass
class Fault:
    kind: str
    remaining: int
    arg: int | None = None


_lock = threading.Lock()
_faults: dict[str, Fault] = {}
_env_loaded = False


def parse_mode(mode: str) -> Fault | None:
    mode = (mode or "").strip().lower()
    if mode in ("", "off", "none", "clear"):
        return None
    m = _MODE.match(mode)
    if not m:
        raise ValueError(f"unknown fault mode '{mode}'. Examples: 503x3, 503x4, 429:30, timeout, timeoutx4, 401, badrecord, off")
    n = int(m.group("n") or 1)
    arg = int(m.group("arg")) if m.group("arg") else (30 if m.group("kind") == "429" else None)
    return Fault(kind=m.group("kind"), remaining=n, arg=arg)


def _load_env() -> None:
    global _env_loaded
    if _env_loaded:
        return
    _env_loaded = True
    for item in filter(None, (os.environ.get("FAULTS") or "").split(",")):
        if "=" in item:
            name, mode = item.split("=", 1)
            set_fault(name.strip(), mode.strip())


def set_fault(connector: str, mode: str) -> dict:
    fault = parse_mode(mode)
    with _lock:
        if fault is None:
            _faults.pop(connector, None)
        else:
            _faults[connector] = fault
    return list_faults().get(connector, {"mode": "off"})


def clear_fault(connector: str) -> None:
    with _lock:
        _faults.pop(connector, None)


def list_faults() -> dict[str, dict]:
    _load_env()
    with _lock:
        return {k: {"kind": f.kind, "remaining": f.remaining, "arg": f.arg} for k, f in _faults.items()}


def take(connector: str, kinds: tuple[str, ...]) -> Fault | None:
    """Consume one occurrence of a pending fault of the given kinds, if any."""
    _load_env()
    with _lock:
        f = _faults.get(connector)
        if not f or f.kind not in kinds:
            return None
        f.remaining -= 1
        if f.remaining <= 0:
            _faults.pop(connector, None)
        return Fault(f.kind, 1, f.arg)


HTTP_KINDS = ("500", "502", "503", "504", "429", "401", "403", "timeout")
