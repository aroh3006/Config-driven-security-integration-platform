"""The one place the app gets engine functions from.

Each function comes from the real engine module when that module has it. It
comes from app.engine_stubs otherwise. The app code stays the same either way. stubbed_functions() says what is still fake. The health page and CLI
should show it. A stub must never get mistaken for a real run.
"""

from __future__ import annotations

import dataclasses
import functools
import importlib
import logging
from typing import Any, Callable

from dotenv import load_dotenv

from app import engine_stubs
from store import db

load_dotenv()

log = logging.getLogger(__name__)

_stubbed: list[str] = []


def _load(module_name: str, attr: str, stub: Callable[..., Any]) -> tuple[Callable[..., Any], bool]:
    """Return (function, is_stub).

    Falls back only when the module itself or the function does not exist
    yet. An error inside a module that does exist still raises. A broken
    engine cannot quietly turn into fake data.
    """
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        missing = exc.name or ""
        if module_name == missing or module_name.startswith(missing + "."):
            return stub, True
        raise
    function = getattr(module, attr, None)
    return (function, False) if function is not None else (stub, True)


def _bind(public_name: str, module_name: str, attr: str, stub: Callable[..., Any]) -> Callable[..., Any]:
    function, is_stub = _load(module_name, attr, stub)
    if is_stub:
        _stubbed.append(public_name)
    return function


validate_config = _bind("validate_config", "engine.config", "validate_config", engine_stubs.validate_config)
load_config = _bind("load_config", "engine.config", "load_config", engine_stubs.load_config)
run_connector = _bind("run_connector", "engine.runner", "run_connector", engine_stubs.run_connector)
test_connection = _bind("test_connection", "engine.runner", "test_connection", engine_stubs.test_connection)
profile_sample = _bind("profile_sample", "engine.profiler", "profile_sample", engine_stubs.profile_sample)
start_scheduler = _bind("start_scheduler", "engine.scheduler", "start", engine_stubs.start_scheduler)
pause = _bind("pause", "engine.scheduler", "pause", engine_stubs.pause)
resume = _bind("resume", "engine.scheduler", "resume", engine_stubs.resume)
set_fault = _bind("set_fault", "engine.faults", "set_fault", engine_stubs.set_fault)
clear_fault = _bind("clear_fault", "engine.faults", "clear_fault", engine_stubs.clear_fault)


def _replay_with_mapper(map_record: Callable[..., Any], connector_name: str, raw: Any) -> dict[str, Any]:
    """Map a quarantined record again with the connector's current config."""
    from engine.errors import ConfigError, MappingError

    connector = db.get_connector(connector_name)
    if connector is None:
        return {"ok": False, "reason": f"unknown connector {connector_name!r}"}
    if not isinstance(raw, dict):
        return {"ok": False, "reason": "record is not a JSON object"}
    try:
        config = load_config(connector["config_yaml"])
        row = map_record(raw, config)
    except (ConfigError, MappingError) as exc:
        return {"ok": False, "reason": db.mask_text(str(exc))}
    row.update(raw=raw, tenant_id=config.tenant_id)
    return {"ok": True, "row": row}


_map_record, _mapper_missing = _load("engine.mapper", "map_record", engine_stubs.replay_record)
if _mapper_missing:
    replay_record = engine_stubs.replay_record
    _stubbed.append("replay_record")
else:
    replay_record = functools.partial(_replay_with_mapper, _map_record)

if _stubbed:
    log.warning("engine functions running as stubs: %s", ", ".join(_stubbed))


def to_dict(result: Any) -> dict[str, Any]:
    """Turn a RunResult into a dict, whichever class the engine uses for it."""
    if isinstance(result, dict):
        return result
    if hasattr(result, "to_dict"):
        return result.to_dict()
    if dataclasses.is_dataclass(result):
        return dataclasses.asdict(result)
    return result.model_dump()


def missing_secrets(yaml_text: str) -> list[str]:
    """Return the environment variables this config needs that have no value."""
    from engine.errors import ConfigError
    from engine.secrets import env_name, has_secret

    try:
        config = load_config(yaml_text)
    except ConfigError:
        return []
    names = config.secret_names() if hasattr(config, "secret_names") else []
    return [env_name(name) for name in names if not has_secret(name)]


def stubbed_functions() -> list[str]:
    """Return the engine functions that are still fake."""
    return list(_stubbed)
