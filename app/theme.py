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
SEVERITY_TONES = {
    "critical": "red",
    "error": "red",
    "high": "amber",
    "medium": "amber",
    "warn": "amber",
    "warning": "amber",
}
RANK = {"red": 0, "amber": 1, "grey": 2, "teal": 3}


def tone(status: str | None) -> str:
    """Return teal, amber, red or grey. Unknown statuses are grey."""
    return TONES.get(status or "", "grey")


def severity_tone(severity: str | None) -> str:
    """Return red, amber or grey for an alert severity. Low and unknown values are grey."""
    return SEVERITY_TONES.get(str(severity or "").strip().lower(), "grey")
