"""Maps connector and run statuses to the Otto colour families."""

from __future__ import annotations

TONES = {
    "healthy": "teal",
    "success": "teal",
    "degraded": "amber",
    "partial": "amber",
    "config_changed": "amber",
    "running": "amber",
    "waiting": "amber",
    "skipped": "amber",
    "failing": "red",
    "failed": "red",
    "auth_failed": "red",
    "circuit_open": "red",
    "paused": "grey",
    "never_run": "grey",
}
RANK = {"red": 0, "amber": 1, "grey": 2, "teal": 3}


def tone(status: str | None) -> str:
    """Return teal, amber, red or grey. Unknown statuses are grey."""
    return TONES.get(status or "", "grey")
