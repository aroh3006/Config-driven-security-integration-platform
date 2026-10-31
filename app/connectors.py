"""Saving connectors and importing config files into the store."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from app import engine_client as engine
from store import db

DEFAULT_CONFIG_DIR = Path(__file__).resolve().parent.parent / "configs"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
PLACEHOLDER = "YOUR-"


def config_dir() -> Path:
    return Path(os.environ.get("INTEGRATION_CONFIGS") or DEFAULT_CONFIG_DIR)


def config_hash(yaml_text: str) -> str:
    return hashlib.sha256(yaml_text.encode("utf-8")).hexdigest()


def errors_only(problems: list[dict[str, str]]) -> list[dict[str, str]]:
    """Drop warnings such as "secret not set yet". Only errors block a config."""
    return [p for p in problems if p.get("level", "error") == "error"]


def warnings_only(problems: list[dict[str, str]]) -> list[dict[str, str]]:
    return [p for p in problems if p.get("level") == "warning"]


def load_raw(item: dict[str, Any]) -> Any:
    """Return a quarantined record. Lines that never parsed come back as text."""
    try:
        return json.loads(item["raw_json"])
    except ValueError:
        return item["raw_json"]


def save_and_approve(yaml_text: str, actor: str) -> list[dict[str, str]]:
    """Validate, save and approve a config, then write its file.

    Returns validation problems. Nothing is saved when there are any. The name
    check also keeps the file inside the configs folder.
    """
    problems = errors_only(engine.validate_config(yaml_text))
    if problems:
        return problems
    config = engine.load_config(yaml_text)
    if not NAME_RE.match(config.name):
        return [
            {
                "path": "name",
                "message": "name has characters that are not allowed",
                "hint": "Use lower-case letters, digits and dashes, like my-source.",
            }
        ]
    digest = config_hash(yaml_text)
    db.save_connector(config.name, config.entity, yaml_text, digest)
    db.approve_connector(config.name, digest)
    db.audit(actor, "connector.save", config.name, f"approved hash {digest[:12]}")

    folder = config_dir()
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{config.name}.yaml").write_text(yaml_text, encoding="utf-8", newline="\n")
    return []


def approve(name: str, actor: str) -> None:
    """Approve whatever config is saved for this connector now."""
    connector = db.get_connector(name)
    if connector is None:
        raise ValueError(f"unknown connector {name!r}")
    db.approve_connector(name, connector["config_hash"])
    db.audit(actor, "connector.approve", name, f"approved hash {connector['config_hash'][:12]}")


def import_configs(actor: str = "startup") -> dict[str, list[Any]]:
    """Load the configs folder into the store.

    A new file is saved and approved. A changed file is saved but not approved.
    An edit made behind the app's back therefore moves to config_changed. Files
    that still have YOUR-... placeholders are skipped until someone fills them in.
    """
    report: dict[str, list[Any]] = {
        "added": [],
        "changed": [],
        "unchanged": [],
        "skipped": [],
        "invalid": [],
    }
    for path in sorted(config_dir().glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        if PLACEHOLDER in text:
            report["skipped"].append(path.name)
            continue
        problems = errors_only(engine.validate_config(text))
        if problems:
            report["invalid"].append({"file": path.name, "problems": problems})
            continue
        config = engine.load_config(text)
        digest = config_hash(text)
        existing = db.get_connector(config.name)
        if existing and existing["config_hash"] == digest:
            report["unchanged"].append(config.name)
        elif existing:
            db.save_connector(config.name, config.entity, text, digest)
            db.audit(actor, "connector.file_changed", config.name, f"new hash {digest[:12]}")
            report["changed"].append(config.name)
        else:
            db.save_connector(config.name, config.entity, text, digest)
            db.approve_connector(config.name, digest)
            db.audit(actor, "connector.import", config.name, f"approved hash {digest[:12]}")
            report["added"].append(config.name)
    return report
