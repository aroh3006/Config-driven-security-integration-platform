"""Connects the engine's hooks to the store and the live state."""

from __future__ import annotations

import logging
from typing import Any

from app import live
from engine import http as engine_http
from engine import runner as engine_runner
from store import db

log = logging.getLogger(__name__)


def save_result(_config: Any, result: Any, _row: Any) -> None:
    """Keep the masked request log once a run ends."""
    if not result.run_id:
        return
    data = result.to_dict()
    db.save_run_log(result.run_id, data["requests"], data["waits"])


def install() -> None:
    """Register the hooks. Safe to call more than once."""
    if save_result not in engine_runner.on_run_finished:
        engine_runner.on_run_finished.append(save_result)
    if live.note_wait not in engine_http.on_wait:
        engine_http.on_wait.append(live.note_wait)


def uninstall() -> None:
    if save_result in engine_runner.on_run_finished:
        engine_runner.on_run_finished.remove(save_result)
    if live.note_wait in engine_http.on_wait:
        engine_http.on_wait.remove(live.note_wait)
