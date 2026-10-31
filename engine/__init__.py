"""Config-driven integration engine.

Public interface (what the API, CLI and web app call):

    validate_config(yaml_text) -> [{path, message, hint, level}]
    load_config(yaml_text) -> Config
    save_and_approve(yaml_text, store=None, actor="user") -> {ok, name, errors, warnings, hash}
    run_connector(name_or_yaml_or_config, dry_run=False, max_pages=None) -> RunResult
    test_connection(name_or_yaml_or_config) -> RunResult   (1 page, nothing stored)
    profile_sample(text, entity=None) -> {draft_yaml, ...}
    scheduler.start() / scheduler.pause(name) / scheduler.resume(name)
    set_fault(connector, mode) / clear_fault(connector) / list_faults()
    on_run_finished: list of hooks called as hook(cfg, result, connector_row)

The engine knows no vendor names: every source is described by its YAML config.
"""

from . import scheduler
from .config import ENTITY_FIELDS, Config, config_hash, load_config, validate_config
from .errors import ConfigError, EngineError
from .faults import clear_fault, list_faults, set_fault
from .memstore import MemoryStore, default_store, set_default_store
from .profiler import profile_sample
from .runner import RunResult, on_run_finished, run_connector, save_and_approve, test_connection

__all__ = [
    "Config", "ConfigError", "ENTITY_FIELDS", "EngineError", "MemoryStore", "RunResult",
    "clear_fault", "config_hash", "default_store", "list_faults", "load_config", "on_run_finished",
    "profile_sample", "run_connector", "save_and_approve", "scheduler", "set_default_store",
    "set_fault", "test_connection", "validate_config",
]
