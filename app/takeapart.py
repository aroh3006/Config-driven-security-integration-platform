"""Splits a stored config into the five answers it gives the engine."""

from __future__ import annotations

from typing import Any

import yaml

BLOCKS = (
    {
        "title": "How to log in",
        "keys": ("auth", "auth_failure"),
        "part": "Auth plugin",
        "does": "Reads the secret, adds the header, masks it in logs",
    },
    {
        "title": "Where to ask",
        "keys": ("source", "request"),
        "part": "Request builder",
        "does": "Builds the URL, checks the host is allowed",
    },
    {
        "title": "How to get the next page",
        "keys": ("pagination",),
        "part": "Pagination plugin",
        "does": "Follows pages until none are left",
    },
    {
        "title": "How often",
        "keys": ("schedule", "incremental"),
        "part": "Scheduler and checkpoint",
        "does": "Runs on time, fetches only what changed",
    },
    {
        "title": "How to rename the fields",
        "keys": ("entity", "map", "required"),
        "part": "Mapper and validator",
        "does": "Renames fields, converts dates, quarantines bad rows",
    },
)
TUNING_KEYS = ("retry", "rate_limit", "limits", "notify")
LABEL_KEYS = {"name", "mock", "description", "tenant_id"}


def _dump(section: dict[str, Any]) -> str:
    return yaml.safe_dump(section, sort_keys=False, default_flow_style=False, allow_unicode=True).rstrip()


def split(text: str) -> dict[str, Any]:
    """Return {blocks, tuning, other, error}. Every key of the file lands somewhere."""
    try:
        config = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return {"blocks": [], "tuning": "", "other": "", "error": f"not valid YAML: {exc}"}
    if not isinstance(config, dict):
        return {"blocks": [], "tuning": "", "other": "", "error": "config must be a mapping"}

    blocks = []
    used = set(LABEL_KEYS)
    for number, block in enumerate(BLOCKS, 1):
        section = {key: config[key] for key in block["keys"] if key in config}
        used.update(block["keys"])
        blocks.append(
            {
                "number": number,
                "title": block["title"],
                "part": block["part"],
                "does": block["does"],
                "code": _dump(section) if section else "# not set, the engine default applies",
            }
        )
    tuning = {key: config[key] for key in TUNING_KEYS if key in config}
    used.update(TUNING_KEYS)
    other = {key: value for key, value in config.items() if key not in used}
    return {
        "blocks": blocks,
        "tuning": _dump(tuning) if tuning else "",
        "other": _dump(other) if other else "",
        "error": None,
    }
