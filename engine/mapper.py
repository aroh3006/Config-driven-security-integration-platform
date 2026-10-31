"""Mapper (FR-5) and record validation (FR-9).

Each target field has a spec: a path string or {path|const|join|coalesce, default,
regex, lookup, transform}. A record that misses a required field or fails a transform
raises MappingError with a precise reason; the runner quarantines it and carries on.
"""

from __future__ import annotations

import email.utils
import re
from datetime import datetime, timezone
from typing import Any, Optional

from .config import Config, FieldSpec
from .errors import MappingError
from .parse import flatten, get_path

_EMPTY = (None, "", [], {})


# ---------------------------------------------------------------- transforms
_DATE_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y/%m/%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%b %d %Y %H:%M:%S",   # CEF rt: Oct 31 2026 06:42:10
    "%b %d %H:%M:%S %Y",
    "%d %b %Y %H:%M:%S",
    "%Y-%m-%d",
    "%d/%m/%Y",
]


def to_utc(value: Any) -> str:
    """ISO 8601 (any offset), epoch seconds/ms or common formats -> 'YYYY-MM-DDTHH:MM:SSZ'."""
    if isinstance(value, bool) or value in _EMPTY:
        raise ValueError("empty")
    dt: Optional[datetime] = None
    if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d{9,16}(\.\d+)?", value.strip())):
        n = float(value)
        if n > 1e14:      # microseconds
            n /= 1e6
        elif n > 1e11:    # milliseconds
            n /= 1e3
        dt = datetime.fromtimestamp(n, tz=timezone.utc)
    elif isinstance(value, str):
        s = value.strip()
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00") if s.endswith("Z") else s)
        except ValueError:
            for fmt in _DATE_FORMATS:
                try:
                    dt = datetime.strptime(s, fmt)
                    break
                except ValueError:
                    continue
            if dt is None:
                try:
                    dt = email.utils.parsedate_to_datetime(s)  # RFC 2822
                except (TypeError, ValueError):
                    dt = None
        if dt is None:
            raise ValueError(f"unrecognised date '{s[:40]}'")
    else:
        raise ValueError(f"cannot read a date from {type(value).__name__}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)  # naive times are treated as UTC
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _to_int(v: Any) -> int:
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, str):
        v = v.strip()
    f = float(v)
    if f != int(f):
        raise ValueError(f"'{v}' is not a whole number")
    return int(f)


TRANSFORM_FUNCS = {
    "lower": lambda v: str(v).lower(),
    "upper": lambda v: str(v).upper(),
    "trim": lambda v: str(v).strip(),
    "int": _to_int,
    "float": lambda v: float(str(v).strip()) if isinstance(v, str) else float(v),
    "str": lambda v: v if isinstance(v, str) else str(v),
    "to_utc": to_utc,
}


# ---------------------------------------------------------------- mapping
def _source_value(spec: FieldSpec, raw: dict) -> Any:
    if spec.const is not None:
        return spec.const
    if spec.path is not None:
        return get_path(raw, spec.path)
    if spec.join is not None:
        parts = [get_path(raw, p) for p in spec.join]
        parts = [str(p) for p in parts if p not in _EMPTY]
        return spec.sep.join(parts) if parts else None
    if spec.coalesce is not None:
        for p in spec.coalesce:
            v = get_path(raw, p)
            if v not in _EMPTY:
                return v
        return None
    return None


def _describe(spec: FieldSpec) -> str:
    if spec.path is not None:
        return f"path {spec.path}"
    if spec.join is not None:
        return f"join {spec.join}"
    if spec.coalesce is not None:
        return f"coalesce {spec.coalesce}"
    return "const"


def _reject_object(target: str, value: Any, spec: FieldSpec) -> None:
    """Every schema field holds one value. An object or list here means bad data."""
    if isinstance(value, (dict, list)):
        kind = "an object" if isinstance(value, dict) else "a list"
        raise MappingError(f"field '{target}': expected a single value, got {kind} ({_describe(spec)})")


def map_value(target: str, spec: FieldSpec, raw: dict) -> Any:
    for path in spec.join or ():
        _reject_object(target, get_path(raw, path), spec)
    value = _source_value(spec, raw)
    if value not in _EMPTY:
        _reject_object(target, value, spec)
    if value in _EMPTY and spec.default is not None:
        value = spec.default
    if value in _EMPTY:
        return None
    if spec.regex:
        m = re.search(spec.regex, str(value))
        if not m:
            return spec.default
        value = m.group(1) if m.groups() else m.group(0)
    if spec.lookup:
        table = {str(k).lower(): v for k, v in spec.lookup.items()}
        value = table.get(str(value).lower(), table.get("_default", value))
    for t in spec.transforms():
        try:
            value = TRANSFORM_FUNCS[t](value)
        except (ValueError, TypeError, OverflowError) as e:
            shown = str(value)[:60]
            raise MappingError(f"field '{target}': cannot apply {t} to '{shown}' ({_describe(spec)}): {e}") from None
    if isinstance(value, (dict, list)) and target != "raw":
        # complex values are stored as JSON text so every column stays a scalar
        import json

        value = json.dumps(value, default=str)
    return value


def map_record(raw: Any, cfg: Config) -> dict:
    """Map one raw record to a common-schema row. Raises MappingError (-> quarantine)."""
    if not isinstance(raw, dict):
        raise MappingError(f"record is a {type(raw).__name__}, not an object")
    specs = cfg.field_specs()
    row: dict[str, Any] = {}
    for target, spec in specs.items():
        row[target] = map_value(target, spec, raw)
    for req in cfg.required_fields():
        if row.get(req) in _EMPTY:
            spec = specs.get(req)
            where = f" ({_describe(spec)})" if spec else ""
            raise MappingError(f"missing required field '{req}'{where}")
    if row.get("id") is not None and not isinstance(row["id"], str):
        row["id"] = str(row["id"])
    return row


def used_paths(cfg: Config) -> set[str]:
    out: set[str] = set()
    for spec in cfg.field_specs().values():
        for p in [spec.path] + list(spec.join or []) + list(spec.coalesce or []):
            if p:
                out.add(p)
    if cfg.incremental:
        out.add(cfg.incremental.field)
    return out


def unmapped_fields(samples: list[dict], cfg: Config, limit: int = 40) -> list[str]:
    """Leaf paths seen in sample records that no mapping uses (shown in the test view)."""
    used = used_paths(cfg)
    seen: dict[str, None] = {}
    for rec in samples[:20]:
        if isinstance(rec, dict):
            for p in flatten(rec):
                seen.setdefault(p, None)

    def covered(p: str) -> bool:
        return any(p == u or p.startswith(u + ".") or u.startswith(p + ".") for u in used)

    return [p for p in seen if not covered(p)][:limit]
