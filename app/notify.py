"""Slack alerts for connectors that keep failing (B-4).

The check reads connector state. That covers scheduled and manual runs alike.
It is safe to call often: it posts once when the failure count reaches the
config's threshold and once more on recovery.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

import httpx
import yaml

from store import db

log = logging.getLogger(__name__)

WEBHOOK_ENV = "SLACK_WEBHOOK"
FAILURE_PREFIX = "failure:"
RECOVERY_PREFIX = "recovery:"
SWEEP_INTERVAL_S = 15.0

_lock = threading.Lock()


def _threshold(connector: dict[str, Any]) -> int | None:
    try:
        config = yaml.safe_load(connector["config_yaml"])
        value = config["notify"]["slack_after_failures"]
    except (yaml.YAMLError, KeyError, TypeError):
        return None
    return value if isinstance(value, int) and value > 0 else None


def _post(text: str) -> bool:
    """Post to Slack. Errors are logged by type only, as they can hold the webhook URL."""
    webhook = os.environ.get(WEBHOOK_ENV)
    if not webhook:
        log.warning("%s is not set, alert not sent", WEBHOOK_ENV)
        return False
    try:
        response = httpx.post(webhook, json={"text": text}, timeout=10)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        log.warning("Slack post failed: %s", type(exc).__name__)
        return False
    return True


def check_connector(connector: dict[str, Any]) -> str | None:
    """Send an alert if one is due. Returns 'failure', 'recovery' or None."""
    threshold = _threshold(connector)
    if threshold is None:
        return None
    name = connector["name"]
    last = db.last_alert_sent(name)
    alerted = bool(last and (last["reason"] or "").startswith(FAILURE_PREFIX))
    failures = connector["consecutive_failures"]

    if failures >= threshold and not alerted:
        run = db.last_run(name)
        error = db.mask_text(run["last_error"]) if run and run["last_error"] else "no error text"
        text = f"{name} is {connector['status']}: {failures} failed runs in a row. Last error: {error}"
        if _post(text):
            db.record_alert_sent(name, f"{FAILURE_PREFIX} {failures} failed runs")
            return "failure"
    elif failures == 0 and alerted and connector["status"] == "healthy":
        if _post(f"{name} has recovered and is healthy again."):
            db.record_alert_sent(name, f"{RECOVERY_PREFIX} healthy")
            return "recovery"
    return None


def sweep() -> None:
    """Check every connector. The lock stops two callers posting the same alert."""
    with _lock:
        for connector in db.list_connectors():
            check_connector(connector)


def run_sweeper(stop: threading.Event) -> None:
    """Background loop for the serve process. Runs until stop is set."""
    while not stop.wait(SWEEP_INTERVAL_S):
        try:
            sweep()
        except Exception as exc:
            log.warning("alert sweep failed: %s", type(exc).__name__)
