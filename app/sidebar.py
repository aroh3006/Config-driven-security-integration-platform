"""Builds the Sources panel shown on every page."""

from __future__ import annotations

from typing import Any

from app import health

GROUPS = (("users", "user"), ("devices", "device"), ("alerts", "alert"))
RAIL = (
    ("home", "Home", "/"),
    ("health", "Health", "/ui/health"),
    ("live", "Live panel", "/ui/live"),
    ("sources", "Sources", "/ui/add"),
    ("configs", "Configs", "/ui/configs"),
    ("data", "Data", "/ui/records/users"),
    ("quarantine", "Quarantine", "/ui/quarantine"),
    ("audit", "Audit", "/ui/audit"),
)


def build(find: str | None = None, rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Group connectors by entity, with mock sources in their own folder.

    `find` filters by connector name. The table totals ignore the filter.
    """
    all_rows = health.health_rows() if rows is None else rows
    needle = (find or "").strip().lower()
    shown = [row for row in all_rows if needle in row["name"].lower()]

    folders = []
    for label, entity in GROUPS:
        members = [row for row in shown if row["entity"] == entity and not row["mock"]]
        if members:
            folders.append({"label": label, "rows": members, "mock": False})
    mocks = [row for row in shown if row["mock"]]
    if mocks:
        folders.append({"label": "Mock tools", "rows": mocks, "mock": True})

    totals = {
        label: sum(row["stored"] for row in all_rows if row["entity"] == entity)
        for label, entity in GROUPS
    }
    return {
        "rail": RAIL,
        "folders": folders,
        "totals": totals,
        "find": find or "",
        "rows": all_rows,
    }
