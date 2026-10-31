"""Turns the Add Source form into a config (B-5) and a config back into the form."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

import yaml

from app.connectors import NAME_RE
from app.health import parse_schedule
from store.db import ENTITY_COLUMNS

SECRET_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")

DEFAULT_MAPS = {
    "user": "id: id\nname: name\nemail: email\nstatus: status\n",
    "device": "id: id\nhostname: hostname\nip: ip\nos: os\nowner: owner\n",
    "alert": (
        "id: id\ntype: type\nseverity: severity\n"
        "timestamp: { path: timestamp, transform: to_utc }\ndescription: description\n"
    ),
}

PAGING_FIELDS = {
    "page_number": ("page_param", "size_param", "size", "start"),
    "offset": ("offset_param", "limit_param", "limit", "total_path"),
    "body_token": ("token_path", "token_param", "token_in"),
    "body_next_url": ("next_url_path",),
}
AUTH_FIELDS = {
    "api_key": ("header", "query_param", "prefix", "secret"),
    "basic": ("username_secret", "secret"),
    "bearer": ("secret",),
    "oauth2_client_credentials": (
        "token_url",
        "client_id_secret",
        "client_secret_secret",
        "scope",
        "send_as",
    ),
}
SECRET_FIELDS = ("secret", "username_secret", "client_id_secret", "client_secret_secret")
NUMBER_FIELDS = ("size", "start", "limit")
REQUEST_OWNED = ("method", "path", "params", "format", "records_path")


def default_form() -> dict[str, str]:
    return {
        "name": "",
        "entity": "alert",
        "base_url": "",
        "auth_type": "none",
        "method": "GET",
        "path": "",
        "params": "",
        "format": "json",
        "records_path": "",
        "paging_type": "none",
        "schedule": "every 15m",
        "map": DEFAULT_MAPS["alert"],
        "yaml": "",
    }


def _problem(path: str, message: str, hint: str) -> dict[str, str]:
    return {"path": path, "message": message, "hint": hint}


def _yaml_mapping(text: str, path: str, problems: list[dict[str, str]]) -> dict[str, Any]:
    if not text.strip():
        return {}
    try:
        value = yaml.safe_load(text)
    except yaml.YAMLError:
        problems.append(_problem(path, "not valid YAML", "Write one `key: value` per line."))
        return {}
    if not isinstance(value, dict):
        problems.append(_problem(path, "must be key and value pairs", "Write `key: value`."))
        return {}
    return value


def _pick(form: dict[str, str], prefix: str, fields: tuple[str, ...]) -> dict[str, Any]:
    picked: dict[str, Any] = {}
    for field in fields:
        value = (form.get(f"{prefix}{field}") or "").strip(" " if field != "prefix" else "\n")
        if value:
            picked[field] = int(value) if field in NUMBER_FIELDS and value.isdigit() else value
    return picked


def _current_config(form: dict[str, str], problems: list[dict[str, str]]) -> dict[str, Any]:
    """Read the YAML box, so keys the form has no field for can be kept."""
    text = form.get("yaml", "")
    if not text.strip():
        return {}
    try:
        value = yaml.safe_load(text)
    except yaml.YAMLError:
        problems.append(
            _problem("yaml", "the YAML box could not be read", "Keys the form has no field for were not kept.")
        )
        return {}
    return value if isinstance(value, dict) else {}


def _section(current: dict[str, Any], key: str) -> dict[str, Any]:
    value = current.get(key)
    return dict(value) if isinstance(value, dict) else {}


def _typed_section(
    current: dict[str, Any], key: str, kind: str, picked: dict[str, Any], owned: tuple[str, ...]
) -> dict[str, Any]:
    """Merge form fields over the same section of the YAML box.

    Extra keys survive while the type stays the same. Choosing another type
    starts clean, because the old keys would not be valid for it.
    """
    old = _section(current, key)
    extras = {}
    if old.get("type", "none") == kind:
        extras = {k: v for k, v in old.items() if k != "type" and k not in owned}
    return {"type": kind, **extras, **picked}


def _source(current: dict[str, Any], base_url: str, host: str | None) -> dict[str, Any]:
    """Keep extra source keys. The allowlist resets if the host changes."""
    old = _section(current, "source")
    if old.get("type") == "file" and not base_url:
        return old
    allowed = [host] if host else []
    old_hosts = old.get("allow_hosts")
    if host and isinstance(old_hosts, list) and urlsplit(str(old.get("base_url", ""))).hostname == host:
        allowed = old_hosts if host in old_hosts else [host, *old_hosts]
    return {**old, "type": "http", "base_url": base_url, "allow_hosts": allowed}


def form_to_yaml(form: dict[str, str]) -> tuple[str, list[dict[str, str]]]:
    """Build config YAML from form fields. Returns (yaml_text, problems).

    Any key in the YAML box that the form has no field for is kept as it is.
    """
    problems: list[dict[str, str]] = []
    current = _current_config(form, problems)

    name = form.get("name", "").strip()
    if not NAME_RE.match(name):
        problems.append(_problem("name", "name is missing or has bad characters", "Use my-source."))
    base_url = form.get("base_url", "").strip()
    parts = urlsplit(base_url)
    is_file = _section(current, "source").get("type") == "file" and not base_url
    if not is_file and (parts.scheme not in ("http", "https") or not parts.hostname):
        problems.append(
            _problem("source.base_url", "must be a full URL", "Use https://api.example.com.")
        )
    schedule = form.get("schedule", "").strip()
    if parse_schedule(schedule) is None:
        problems.append(_problem("schedule", "cannot read the schedule", "Use every 15m."))

    auth_type = form.get("auth_type", "none")
    auth_owned = AUTH_FIELDS.get(auth_type, ())
    auth = _typed_section(current, "auth", auth_type, _pick(form, "auth_", auth_owned), auth_owned)
    for field in SECRET_FIELDS:
        if field in auth and not SECRET_NAME_RE.match(str(auth[field])):
            problems.append(
                _problem(
                    f"auth.{field}",
                    "this must be a secret name, not the secret itself",
                    "Use a name like okta_key and put the value in .env as OKTA_KEY.",
                )
            )

    paging_type = form.get("paging_type", "none")
    paging_owned = PAGING_FIELDS.get(paging_type, ())
    pagination = _typed_section(
        current, "pagination", paging_type, _pick(form, "paging_", paging_owned), paging_owned
    )

    params = _yaml_mapping(form.get("params", ""), "request.params", problems)
    mapping = _yaml_mapping(form.get("map", ""), "map", problems)
    if not mapping:
        problems.append(_problem("map", "map is empty", "Add at least `id: some_field`."))

    request = {k: v for k, v in _section(current, "request").items() if k not in REQUEST_OWNED}
    path = form.get("path", "").strip()
    built_request: dict[str, Any] = {"method": form.get("method") or "GET"}
    if path or not is_file:
        built_request["path"] = path or "/"
    if params:
        built_request["params"] = params
    built_request["format"] = form.get("format") or "json"
    built_request["records_path"] = form.get("records_path", "").strip()

    config: dict[str, Any] = {
        "name": name,
        "entity": form.get("entity") or "alert",
        "mock": form.get("mock") == "on",
        "source": _source(current, base_url, parts.hostname),
        "auth": auth,
        "request": {**built_request, **request},
        "pagination": pagination,
        "schedule": schedule,
        "map": mapping,
    }
    for key, value in current.items():
        config.setdefault(key, value)
    return yaml.safe_dump(config, sort_keys=False, default_flow_style=False), problems


def suggestions(profile: dict[str, Any], entity: str) -> list[dict[str, Any]]:
    """One row per schema field: what the profiler picked, or that nothing fits."""
    table = {"user": "users", "device": "devices", "alert": "alerts"}.get(entity, "alerts")
    guesses = profile.get("guesses") or {}
    rows = []
    for field in ("id", *ENTITY_COLUMNS[table]):
        guess = guesses.get(field)
        if guess is None:
            rows.append({"field": field, "code": None})
            continue
        spec = guess.get("spec") if isinstance(guess, dict) else guess
        if isinstance(spec, dict) and set(spec) == {"path"}:
            spec = spec["path"]
        if not isinstance(spec, str):
            spec = yaml.safe_dump(spec, default_flow_style=True, sort_keys=False).strip()
        rows.append({"field": field, "code": spec})
    return rows


def yaml_to_form(text: str) -> dict[str, str]:
    """Fill form fields from config YAML. Unreadable YAML gives a blank form."""
    form = default_form()
    form["yaml"] = text
    try:
        config = yaml.safe_load(text)
    except yaml.YAMLError:
        return form
    if not isinstance(config, dict):
        return form

    source = config.get("source") or {}
    auth = config.get("auth") or {}
    request = config.get("request") or {}
    pagination = config.get("pagination") or {}
    form.update(
        name=str(config.get("name", "")),
        entity=str(config.get("entity", "alert")),
        base_url=str(source.get("base_url", "")),
        auth_type=str(auth.get("type", "none")),
        method=str(request.get("method", "GET")),
        path=str(request.get("path", "")),
        format=str(request.get("format", "json")),
        records_path=str(request.get("records_path", "")),
        paging_type=str(pagination.get("type", "none")),
        schedule=str(config.get("schedule", "")),
    )
    if config.get("mock"):
        form["mock"] = "on"
    if request.get("params"):
        form["params"] = yaml.safe_dump(request["params"], sort_keys=False)
    if config.get("map"):
        form["map"] = yaml.safe_dump(config["map"], sort_keys=False)
    for key, value in auth.items():
        if key != "type":
            form[f"auth_{key}"] = str(value)
    for key, value in pagination.items():
        if key != "type":
            form[f"paging_{key}"] = str(value)
    return form
