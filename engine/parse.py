"""Response parsers (json, ndjson, csv) and path helpers.

Paths are dotted with optional numeric indexes: `profile.login`, `items.0.name`,
`cve.metrics.cvssMetricV31.0.cvssData.baseSeverity`. A key that itself contains dots
(e.g. `@odata.nextLink`) is matched whole when present.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from .errors import ParseError

_MISSING = object()


def get_path(obj: Any, path: str, default: Any = None) -> Any:
    if path in (None, "", "."):
        return obj
    parts = path.split(".")
    cur = obj
    i = 0
    while i < len(parts):
        if isinstance(cur, dict):
            # greedy match for keys containing dots, longest first
            for j in range(len(parts), i, -1):
                key = ".".join(parts[i:j])
                if key in cur:
                    cur, i = cur[key], j
                    break
            else:
                return default
        elif isinstance(cur, list):
            try:
                cur, i = cur[int(parts[i])], i + 1
            except (ValueError, IndexError):
                return default
        else:
            return default
    return cur


def has_path(obj: Any, path: str) -> bool:
    return get_path(obj, path, _MISSING) is not _MISSING


class BadLine:
    """A line in an NDJSON/CSV body that could not be parsed. Quarantined by the runner."""

    def __init__(self, raw: str, reason: str):
        self.raw, self.reason = raw, reason


def parse_body(content: bytes, fmt: str) -> Any:
    text = content.decode("utf-8-sig", errors="replace")
    if fmt == "json":
        if not text.strip():
            return []
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            snippet = text[:120].replace("\n", " ")
            raise ParseError(f"response is not valid JSON ({e.msg} at line {e.lineno}); starts with: {snippet!r}") from None
    if fmt == "ndjson":
        out: list = []
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as e:
                out.append(BadLine(line, f"line {n} is not valid JSON ({e.msg})"))
        return out
    if fmt == "csv":
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            return []
        rows = []
        for n, row in enumerate(reader, 2):
            if None in row:  # more cells than headers
                rows.append(BadLine(json.dumps(row, default=str), f"line {n} has more cells than the header"))
                continue
            rows.append({k.strip(): (v if v not in ("",) else None) for k, v in row.items() if k is not None})
        return rows
    raise ParseError(f"unknown format '{fmt}'")


def find_list_paths(obj: Any, prefix: str = "", depth: int = 0, out: list | None = None) -> list[tuple[str, int]]:
    """All paths to lists of objects, with their lengths (used for hints and the profiler)."""
    out = [] if out is None else out
    if depth > 5:
        return out
    if isinstance(obj, list):
        # nested lists inside records are fields, not record lists. Stop here.
        if obj and all(isinstance(x, dict) for x in obj[:20]):
            out.append((prefix, len(obj)))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            find_list_paths(v, f"{prefix}.{k}" if prefix else str(k), depth + 1, out)
    return out


def extract_records(parsed: Any, records_path: str, fmt: str) -> list:
    """Return the list of records from a parsed body."""
    if fmt in ("ndjson", "csv"):
        return [r if isinstance(r, (dict, BadLine)) else {"value": r} for r in parsed]
    node = get_path(parsed, records_path, _MISSING)
    if node is _MISSING:
        candidates = find_list_paths(parsed)
        hint = ", ".join(f"'{p or '(top level)'}' ({n} items)" for p, n in candidates[:5]) or "none found"
        raise ParseError(f"records_path '{records_path}' not found in the response. Lists in the response: {hint}")
    if node is None:
        return []
    if isinstance(node, dict):
        if records_path == "":
            candidates = find_list_paths(parsed)
            if candidates:
                hint = ", ".join(f"'{p}' ({n} items)" for p, n in candidates[:5])
                raise ParseError(f"the response is an object, not a list. Set records_path to one of: {hint}")
        return [node]
    if not isinstance(node, list):
        raise ParseError(f"records_path '{records_path}' points to a {type(node).__name__}, not a list")
    return [r if isinstance(r, dict) else {"value": r} for r in node]


def flatten(obj: Any, prefix: str = "", out: dict | None = None, depth: int = 0) -> dict[str, Any]:
    """Leaf paths -> values. Lists of objects are followed through index 0."""
    out = {} if out is None else out
    if depth > 8:
        return out
    if isinstance(obj, dict):
        if not obj and prefix:
            out[prefix] = obj
        for k, v in obj.items():
            flatten(v, f"{prefix}.{k}" if prefix else str(k), out, depth + 1)
    elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
        flatten(obj[0], f"{prefix}.0" if prefix else "0", out, depth + 1)
    else:
        out[prefix] = obj
    return out
