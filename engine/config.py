"""Connector config: schema, loading and validation with clear errors (FR-1..FR-5, B-2).

A config is plain YAML read with yaml.safe_load. Nothing in it can execute code.
Every model forbids unknown keys. Errors come back as
[{path, message, hint, level}] with "did you mean ..." suggestions.
"""

from __future__ import annotations

import difflib
import hashlib
import re
from typing import Annotated, Any, Callable, Literal, Optional, Union, get_args
from urllib.parse import parse_qsl, urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Discriminator, Field, Tag, ValidationError, field_validator, model_validator

from .errors import ConfigError
from .secrets import SENSITIVE_NAME, env_name, has_secret, is_secret_name

# ---------------------------------------------------------------- common schema
ENTITY_FIELDS: dict[str, list[str]] = {
    "user": ["id", "name", "email", "status", "last_login"],
    "device": ["id", "hostname", "ip", "os", "owner", "last_seen"],
    "alert": ["id", "type", "severity", "timestamp", "description", "cve"],
}
ENTITY_TABLE = {"user": "users", "device": "devices", "alert": "alerts"}
DEFAULT_REQUIRED = {"user": ["id"], "device": ["id"], "alert": ["id", "timestamp"]}
FIELD_ALIASES = {"user": {"last_seen": "last_login"}}  # some sources call this field last_seen for users

TRANSFORMS = ["lower", "upper", "trim", "int", "float", "str", "to_utc"]
SCHEDULE_RE = re.compile(r"^\s*(?:every\s+)?(\d+)\s*(s|sec|secs|seconds?|m|min|mins|minutes?|h|hr|hrs|hours?)\s*$", re.I)
SECRET_REF = re.compile(r"\{secret:([a-z0-9_]+)\}")
TEMPLATE = re.compile(r"\{\{\s*(now|checkpoint)\s*(?:([+-])\s*(\d+)\s*([smhd]))?\s*\}\}")
URL_USERINFO = re.compile(r"[a-z][a-z0-9+.-]*://[^/?#]*@", re.I)
# These match SENSITIVE_NAME but only describe a credential. Examples: secret_type, session_timeout.
DESCRIPTIVE_NAME = re.compile(r"(type|name|status|count|limit|timeout|ttl|duration)s?$", re.I)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


# ---------------------------------------------------------------- source
class Source(Strict):
    type: Literal["http", "file"] = "http"
    base_url: Optional[str] = None
    allow_hosts: list[str] = Field(default_factory=list)
    allow_private_network: bool = False  # needed when a source lives on a LAN IP (e.g. venue server)
    path: Optional[str] = None  # file source only; must stay inside the data folder
    ca_file: Optional[str] = None  # extra trusted CA for on-prem hosts; must stay inside the data folder

    @model_validator(mode="after")
    def _check(self):
        if self.type == "http" and not self.base_url:
            raise ValueError("base_url is required for an http source")
        if self.type == "file" and not self.path:
            raise ValueError("path is required for a file source (e.g. data/devices.csv)")
        if self.base_url and urlsplit(self.base_url).scheme not in ("http", "https"):
            raise ValueError("base_url must start with https:// (or http:// for local mocks)")
        return self


# ---------------------------------------------------------------- auth (FR-1)
class NoAuth(Strict):
    type: Literal["none"] = "none"


class ApiKeyAuth(Strict):
    type: Literal["api_key"]
    header: Optional[str] = None
    query_param: Optional[str] = None
    prefix: str = ""
    secret: str

    @model_validator(mode="after")
    def _one_place(self):
        if bool(self.header) == bool(self.query_param):
            raise ValueError("api_key needs exactly one of `header` or `query_param`")
        return self


class BasicAuth(Strict):
    type: Literal["basic"]
    username_secret: Optional[str] = None
    username: Optional[str] = None  # a non-secret username may be written inline
    secret: str

    @model_validator(mode="after")
    def _user(self):
        if not (self.username_secret or self.username):
            raise ValueError("basic auth needs `username_secret` (or `username`)")
        return self


class BearerAuth(Strict):
    type: Literal["bearer"]
    secret: str
    prefix: str = "Bearer "


class OAuth2ClientCredentials(Strict):
    type: Literal["oauth2_client_credentials"]
    token_url: str
    client_id_secret: str
    client_secret_secret: str
    scope: Optional[str] = None
    audience: Optional[str] = None
    send_as: Literal["body", "basic"] = "body"
    extra_params: dict[str, str] = Field(default_factory=dict)


class SessionLogin(Strict):
    """One login call that returns a token to send on every later request.

    Credentials can go in a Basic header or in `headers`, `params` and `body`.
    There {secret:name} stands for a secret. With no token_path or token_header the server
    keeps the session in a cookie.
    """

    type: Literal["session_login"]
    login_url: str
    method: Literal["GET", "POST"] = "POST"
    username_secret: Optional[str] = None
    password_secret: Optional[str] = None
    headers: dict[str, str] = Field(default_factory=dict)
    params: dict[str, str] = Field(default_factory=dict)
    body: Optional[Any] = None
    token_path: Optional[str] = None
    token_header: Optional[str] = None
    send_header: Optional[str] = None
    send_param: Optional[str] = None
    prefix: str = ""
    ttl_s: float = 600

    @model_validator(mode="after")
    def _check(self):
        if self.token_path and self.token_header:
            raise ValueError("set token_path or token_header, not both")
        if bool(self.username_secret) != bool(self.password_secret):
            raise ValueError("Basic login needs both `username_secret` and `password_secret`")
        reads_token = bool(self.token_path or self.token_header)
        sends = [name for name in (self.send_header, self.send_param) if name]
        if reads_token and len(sends) != 1:
            raise ValueError("say where the token goes: set `send_header` or `send_param`")
        if sends and not reads_token:
            raise ValueError("`send_header` and `send_param` need `token_path` or `token_header`")
        return self


Auth = Annotated[
    Union[NoAuth, ApiKeyAuth, BasicAuth, BearerAuth, OAuth2ClientCredentials, SessionLogin],
    Field(discriminator="type"),
]


# ---------------------------------------------------------------- request (FR-2)
class Request(Strict):
    method: Literal["GET", "POST"] = "GET"
    read_only_post: bool = False
    path: str = ""
    params: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    secret_headers: dict[str, str] = Field(default_factory=dict)  # header name -> secret name
    body: Optional[Any] = None
    format: Literal["json", "ndjson", "csv"] = "json"
    records_path: str = ""
    error_path: Optional[str] = None  # a value here means failure, for APIs that report errors in a 200

    @field_validator("method", mode="before")
    @classmethod
    def _upper(cls, v):
        return v.upper() if isinstance(v, str) else v

    @model_validator(mode="after")
    def _read_only(self):
        if self.method == "POST" and not self.read_only_post:
            raise ValueError(
                "POST is only allowed for search-style reads: set `read_only_post: true` to confirm it does not change data"
            )
        return self


# ---------------------------------------------------------------- pagination (FR-3)
class NoPaging(Strict):
    type: Literal["none"] = "none"


class LinkHeaderPaging(Strict):
    type: Literal["link_header"]


class PageNumberPaging(Strict):
    type: Literal["page_number"]
    page_param: str = "page"
    size_param: Optional[str] = "per_page"
    size: int = 100
    start: int = 1
    total_pages_path: Optional[str] = None


class OffsetPaging(Strict):
    type: Literal["offset"]
    offset_param: str = "offset"
    limit_param: Optional[str] = "limit"
    limit: int = 100
    start: int = 0
    total_path: Optional[str] = None
    param_in: Literal["query", "body"] = "query"
    end_param: Optional[str] = None  # for APIs that take an end index in place of a page size


class BodyTokenPaging(Strict):
    type: Literal["body_token"]
    token_path: str
    token_param: str
    token_in: Literal["query", "body"] = "query"
    stop_path: Optional[str] = None  # e.g. isLast: stop when this field is true
    has_more_path: Optional[str] = None  # e.g. pageInfo.hasNextPage: stop when this field is false


class BodyNextUrlPaging(Strict):
    type: Literal["body_next_url"]
    next_url_path: str


Pagination = Annotated[
    Union[NoPaging, LinkHeaderPaging, PageNumberPaging, OffsetPaging, BodyTokenPaging, BodyNextUrlPaging],
    Field(discriminator="type"),
]


# ---------------------------------------------------------------- reliability
class Retry(Strict):
    delays_s: list[float] = Field(default_factory=lambda: [1, 2, 4])
    jitter: bool = False


class RateLimit(Strict):
    max_rps: Optional[float] = None
    remaining_header: Optional[str] = None
    reset_header: Optional[str] = None
    max_wait_s: float = 120
    max_429_waits: int = 5


class Incremental(Strict):
    field: str  # record path whose max value becomes the watermark
    param: str  # query param (or body key) carrying the watermark
    template: str = "{checkpoint}"
    start: Optional[str] = None
    param_in: Literal["query", "body"] = "query"


class Limits(Strict):
    max_pages: int = 50
    timeout_s: float = 30
    max_response_mb: float = 20
    circuit_after_failures: int = 5
    circuit_cooldown_s: float = 300


class Notify(Strict):
    slack_after_failures: int = 3


class AuthFailure(Strict):
    """How an API reports a rejected login when it does not answer 401 or 403.

    Some APIs answer 200 with an empty list or 404 and only say why in a header.
    Without this block a wrong key looks like a healthy run with no data.
    """

    header: str
    contains: str


# ---------------------------------------------------------------- mapping (FR-5)
class FieldSpec(Strict):
    path: Optional[str] = None
    const: Optional[Any] = None
    join: Optional[list[str]] = None
    sep: str = " "
    coalesce: Optional[list[str]] = None
    default: Optional[Any] = None
    regex: Optional[str] = None
    lookup: Optional[dict[str, Any]] = None
    transform: Optional[Union[str, list[str]]] = None

    @model_validator(mode="after")
    def _one_source(self):
        n = sum(x is not None for x in (self.path, self.const, self.join, self.coalesce))
        if n != 1 and not (n == 0 and self.default is not None):
            raise ValueError("a field needs exactly one of `path`, `const`, `join` or `coalesce`")
        for t in self.transforms():
            if t not in TRANSFORMS:
                guess = difflib.get_close_matches(t, TRANSFORMS, n=1)
                tip = f" did you mean '{guess[0]}'?" if guess else ""
                raise ValueError(f"unknown transform '{t}'.{tip} Allowed: {', '.join(TRANSFORMS)}")
        if self.regex:
            try:
                re.compile(self.regex)
            except re.error as e:
                raise ValueError(f"regex does not compile: {e}") from e
        return self

    def transforms(self) -> list[str]:
        if self.transform is None:
            return []
        return [self.transform] if isinstance(self.transform, str) else list(self.transform)


MapValue = Annotated[
    Union[Annotated[str, Tag("path")], Annotated[FieldSpec, Tag("spec")]],
    Discriminator(lambda v: "path" if isinstance(v, str) else "spec"),
]


# ---------------------------------------------------------------- the whole connector
class Config(Strict):
    name: str
    entity: Literal["user", "device", "alert"]
    description: Optional[str] = None
    mock: bool = False
    tenant_id: str = "default"
    source: Source
    auth: Auth = Field(default_factory=NoAuth)
    auth_failure: Optional[AuthFailure] = None
    request: Request = Field(default_factory=Request)
    pagination: Pagination = Field(default_factory=NoPaging)
    schedule: str = "every 15m"
    retry: Retry = Field(default_factory=Retry)
    rate_limit: RateLimit = Field(default_factory=RateLimit)
    incremental: Optional[Incremental] = None
    limits: Limits = Field(default_factory=Limits)
    map: dict[str, MapValue]
    required: Optional[list[str]] = None
    notify: Notify = Field(default_factory=Notify)

    @field_validator("name")
    @classmethod
    def _name(cls, v):
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,63}", v):
            raise ValueError("name must be lowercase letters, digits, '-' or '_' (e.g. okta-users)")
        return v

    @field_validator("schedule")
    @classmethod
    def _schedule(cls, v):
        schedule_seconds(v)
        return v

    @field_validator("map", mode="before")
    @classmethod
    def _map_nonempty(cls, v):
        if not v:
            raise ValueError("map must list at least one field, e.g. `id: id`")
        return v

    # convenience
    @property
    def table(self) -> str:
        return ENTITY_TABLE[self.entity]

    @property
    def interval_s(self) -> int:
        return schedule_seconds(self.schedule)

    def required_fields(self) -> list[str]:
        return self.required if self.required is not None else DEFAULT_REQUIRED[self.entity]

    def field_specs(self) -> dict[str, FieldSpec]:
        aliases = FIELD_ALIASES.get(self.entity, {})
        out = {}
        for target, spec in self.map.items():
            target = aliases.get(target, target)
            out[target] = FieldSpec(path=spec) if isinstance(spec, str) else spec
        return out

    def secret_fields(self) -> list[tuple[str, str]]:
        """Every place that names a secret, as (config path, secret name)."""
        a = self.auth
        fields = [(f"auth.{key}", getattr(a, key)) for key in type(a).model_fields
                  if key.endswith("secret") and getattr(a, key) is not None]
        if isinstance(a, SessionLogin):
            fields += [("auth", name) for name in secret_refs([a.headers, a.params, a.body])]
        fields += [(f"request.secret_headers.{header}", name) for header, name in self.request.secret_headers.items()]
        return fields

    def secret_names(self) -> list[str]:
        return list(dict.fromkeys(name for _, name in self.secret_fields()))


def secret_refs(value: Any) -> list[str]:
    """Names used as {secret:name} anywhere inside strings, dicts and lists."""
    if isinstance(value, str):
        return SECRET_REF.findall(value)
    if isinstance(value, dict):
        value = list(value.values())
    if isinstance(value, list):
        return [name for item in value for name in secret_refs(item)]
    return []


def schedule_seconds(text: str) -> int:
    m = SCHEDULE_RE.match(str(text))
    if not m:
        raise ValueError(f"schedule '{text}' not understood; use e.g. 'every 15m', 'every 30s', 'every 1h'")
    n, unit = int(m.group(1)), m.group(2).lower()
    secs = n * (1 if unit.startswith("s") else 60 if unit.startswith("m") else 3600)
    if secs < 10:
        raise ValueError("schedule must be at least 10 seconds")
    return secs


def config_hash(yaml_text: str) -> str:
    return hashlib.sha256(yaml_text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- validation helpers
_SECTION_MODELS: dict[str, type[BaseModel]] = {
    "": Config,
    "source": Source,
    "request": Request,
    "retry": Retry,
    "rate_limit": RateLimit,
    "incremental": Incremental,
    "limits": Limits,
    "notify": Notify,
    "auth_failure": AuthFailure,
}
_AUTH_MODELS = {get_args(m.model_fields["type"].annotation)[0]: m
                for m in (NoAuth, ApiKeyAuth, BasicAuth, BearerAuth, OAuth2ClientCredentials, SessionLogin)}
_PAGING_MODELS = {get_args(m.model_fields["type"].annotation)[0]: m
                  for m in (NoPaging, LinkHeaderPaging, PageNumberPaging, OffsetPaging, BodyTokenPaging, BodyNextUrlPaging)}


def _suggest(word: str, options) -> Optional[str]:
    hit = difflib.get_close_matches(str(word), list(options), n=1, cutoff=0.6)
    return hit[0] if hit else None


def _allowed_keys(loc: tuple, raw: dict) -> list[str]:
    """Which keys are allowed at the parent of `loc` (for did-you-mean hints)."""
    parent = [p for p in loc[:-1] if isinstance(p, str)]
    # strip pydantic's union-branch labels, e.g. ('auth', 'api_key', 'heder')
    if parent and parent[0] in ("auth", "pagination"):
        section = raw.get(parent[0]) or {}
        models = _AUTH_MODELS if parent[0] == "auth" else _PAGING_MODELS
        model = models.get(section.get("type", "none"))
        return list(model.model_fields) if model else []
    if parent and parent[0] == "map":
        return list(FieldSpec.model_fields)
    model = _SECTION_MODELS.get(".".join(parent))
    return list(model.model_fields) if model else []


def _friendly(err: dict, raw: dict) -> dict:
    loc = tuple(err.get("loc", ()))
    # drop union branch tags pydantic inserts (e.g. 'api_key', 'FieldSpec', 'str')
    clean = []
    for i, p in enumerate(loc):
        if i > 0 and loc[i - 1] in ("auth", "pagination") and isinstance(p, str) and p in {**_AUTH_MODELS, **_PAGING_MODELS}:
            continue
        if p in ("path", "spec") and i > 0 and i == 2 and loc[0] == "map":
            continue
        if isinstance(p, str) and ("[" in p or p.startswith("function-")):
            continue
        clean.append(str(p))
    path = ".".join(clean)
    etype = err.get("type", "")
    msg = err.get("msg", "invalid value").removeprefix("Value error, ")
    hint = ""
    if etype == "extra_forbidden":
        bad = clean[-1] if clean else ""
        guess = _suggest(bad, _allowed_keys(tuple(clean), raw))
        msg = f"unknown key '{bad}'"
        hint = f"did you mean '{guess}'?" if guess else f"allowed keys: {', '.join(_allowed_keys(tuple(clean), raw))}"
    elif etype == "union_tag_invalid":
        ctx = err.get("ctx", {})
        tags = [t.strip(" '") for t in str(ctx.get("expected_tags", "")).split(",")]
        given = ctx.get("tag")
        guess = _suggest(given, tags)
        path = path or clean[0]
        msg = f"unknown type '{given}'"
        hint = (f"did you mean '{guess}'? " if guess else "") + f"allowed: {', '.join(tags)}"
    elif etype == "missing":
        msg = f"'{clean[-1] if clean else path}' is required"
    elif etype == "literal_error":
        hint = f"allowed: {err.get('ctx', {}).get('expected', '')}"
    return {"path": path, "message": msg, "hint": hint, "level": "error"}


def parse_yaml(yaml_text: str) -> dict:
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        where = f"line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise ConfigError([{"path": "", "message": f"YAML syntax error {where}".strip(), "hint": str(getattr(e, 'problem', '')), "level": "error"}])
    if not isinstance(data, dict):
        raise ConfigError([{"path": "", "message": "config must be a YAML mapping (key: value lines)", "hint": "", "level": "error"}])
    return data


def _holds_credential(name: str, value: Any) -> bool:
    """True when a sensitive name such as api_key carries a value typed into the config."""
    if not SENSITIVE_NAME.search(name) or DESCRIPTIVE_NAME.search(name):
        return False
    if isinstance(value, bool) or value in (None, "", [], {}):
        return False
    return not (isinstance(value, str) and TEMPLATE.fullmatch(value.strip()))


def _param_hint(param: str) -> str:
    return f"use auth: {{ type: api_key, query_param: {param}, secret: my_secret_name }}"


def _credential_checks(cfg: Config, err: Callable[..., None]) -> None:
    """Configs hold names only. These errors never repeat a value. It may be a real credential."""
    for path, name in cfg.secret_fields():
        if not is_secret_name(name):
            err(path, "this field must hold a secret name and not the credential itself",
                "use a name like okta_key in auth or secret_headers and put the value in .env as OKTA_KEY")

    auth_urls = {f"auth.{key}": getattr(cfg.auth, key) for key in type(cfg.auth).model_fields if key.endswith("_url")}
    for path, url in {"source.base_url": cfg.source.base_url, "request.path": cfg.request.path, **auth_urls}.items():
        if URL_USERINFO.match(url or ""):
            err(path, "this URL must not hold credentials",
                "remove them and set auth: { type: basic, username_secret: my_user, secret: my_password }")
        for param, value in parse_qsl((url or "").partition("?")[2].partition("#")[0]):
            if _holds_credential(param, value):
                err(path, f"query parameter '{param}' in this URL must not hold a credential", _param_hint(param))

    for header, value in cfg.request.headers.items():
        if _holds_credential(header, value):
            err(f"request.headers.{header}", f"header '{header}' must not hold a literal value",
                f"use request.secret_headers: {{ {header}: my_secret_name }} or set auth")
    for param, value in cfg.request.params.items():
        if _holds_credential(param, value):
            err(f"request.params.{param}", f"parameter '{param}' must not hold a literal value", _param_hint(param))


def _semantic_checks(cfg: Config) -> list[dict]:
    """Checks that need the whole config: hosts, entity fields, paging vs format, secrets."""
    out: list[dict] = []
    err = lambda p, m, h="": out.append({"path": p, "message": m, "hint": h, "level": "error"})  # noqa: E731
    warn = lambda p, m, h="": out.append({"path": p, "message": m, "hint": h, "level": "warning"})  # noqa: E731

    if cfg.source.type == "http":
        host = (urlsplit(cfg.source.base_url).hostname or "").lower()
        if not cfg.source.allow_hosts:
            err("source.allow_hosts", "allow_hosts must list the hosts this connector may call", f"add: allow_hosts: [{host}]")
        elif not host_allowed(host, cfg.source.allow_hosts):
            err("source.allow_hosts", f"base_url host '{host}' is not in allow_hosts", f"add '{host}' to allow_hosts")
        if isinstance(cfg.auth, OAuth2ClientCredentials):
            th = (urlsplit(cfg.auth.token_url).hostname or "").lower()
            if not host_allowed(th, cfg.source.allow_hosts):
                err("auth.token_url", f"token_url host '{th}' is not in allow_hosts", f"add '{th}' to allow_hosts")
        if isinstance(cfg.auth, SessionLogin):
            lh = (urlsplit(cfg.auth.login_url).hostname or "").lower()
            if not host_allowed(lh, cfg.source.allow_hosts):
                err("auth.login_url", f"login_url host '{lh}' is not in allow_hosts", f"add '{lh}' to allow_hosts")
        if cfg.source.allow_private_network:
            warn("source.allow_private_network", "private network addresses are allowed for this connector",
                 "only use this for sources on your own LAN; cloud metadata addresses stay blocked")
    if cfg.source.type == "file" and cfg.pagination.type != "none":
        err("pagination.type", "file sources cannot be paginated", "use pagination: { type: none }")

    if cfg.pagination.type in ("body_token", "body_next_url") and cfg.request.format != "json":
        err("pagination.type", f"{cfg.pagination.type} paging needs request.format: json")
    if isinstance(cfg.pagination, BodyTokenPaging) and cfg.pagination.token_in == "body" and cfg.request.method != "POST":
        err("pagination.token_in", "token_in: body needs request.method: POST", "use token_in: query for GET requests")
    if cfg.incremental and cfg.incremental.param_in == "body" and cfg.request.method != "POST":
        err("incremental.param_in", "param_in: body needs request.method: POST")
    if cfg.incremental and "{checkpoint}" not in cfg.incremental.template:
        err("incremental.template", "template must contain {checkpoint}", "e.g. template: 'lastUpdated gt \"{checkpoint}\"'")

    fields = ENTITY_FIELDS[cfg.entity]
    aliases = FIELD_ALIASES.get(cfg.entity, {})
    for target in cfg.map:
        if target not in fields and target not in aliases:
            guess = _suggest(target, fields + list(aliases))
            err(f"map.{target}", f"'{target}' is not a field of {cfg.table}",
                (f"did you mean '{guess}'? " if guess else "") + f"fields: {', '.join(fields)}")
    mapped = set(cfg.field_specs())
    for r in cfg.required_fields():
        if r not in fields:
            err("required", f"'{r}' is not a field of {cfg.table}", f"fields: {', '.join(fields)}")
        elif r not in mapped:
            err(f"map.{r}", f"required field '{r}' has no mapping", f"add e.g. `{r}: <path in the record>`")

    _credential_checks(cfg, err)
    for name in cfg.secret_names():
        if is_secret_name(name) and not has_secret(name):
            warn("auth", f"secret '{name}' is not set yet", f"add {env_name(name)}=... to your .env file")
    if cfg.retry.delays_s and any(d < 0 for d in cfg.retry.delays_s):
        err("retry.delays_s", "delays must be positive numbers of seconds")
    return out


def host_allowed(host: str, allow_hosts: list[str]) -> bool:
    host = (host or "").lower().rstrip(".")
    for pattern in allow_hosts:
        p = pattern.lower().strip().rstrip(".")
        if p.startswith("*."):
            if host.endswith(p[1:]) and host != p[2:]:
                return True
        elif host == p:
            return True
    return False


def validate_config(yaml_text: str) -> list[dict]:
    """B-2: return every problem as {path, message, hint, level}. Empty list = valid."""
    try:
        raw = parse_yaml(yaml_text)
    except ConfigError as e:
        return e.errors
    try:
        cfg = Config.model_validate(raw)
    except ValidationError as e:
        seen, out = set(), []
        items = [_friendly(x, raw) for x in e.errors()]
        entity = raw.get("entity")
        if entity in ENTITY_FIELDS and isinstance(raw.get("map"), dict):
            fields = ENTITY_FIELDS[entity] + list(FIELD_ALIASES.get(entity, {}))
            for target in raw["map"]:
                if target not in fields:
                    guess = _suggest(target, fields)
                    items.append({"path": f"map.{target}", "message": f"'{target}' is not a field of {ENTITY_TABLE[entity]}",
                                  "hint": (f"did you mean '{guess}'? " if guess else "") + f"fields: {', '.join(ENTITY_FIELDS[entity])}",
                                  "level": "error"})
        for item in items:
            key = (item["path"], item["message"])
            if key not in seen:
                seen.add(key)
                out.append(item)
        return out
    return _semantic_checks(cfg)


def load_config(source: Union[str, dict, Config]) -> Config:
    """Parse and validate; raise ConfigError if there is any error-level problem."""
    if isinstance(source, Config):
        return source
    text = source if isinstance(source, str) else yaml.safe_dump(source, sort_keys=False)
    problems = validate_config(text)
    errors = [p for p in problems if p["level"] == "error"]
    if errors:
        raise ConfigError(errors)
    return Config.model_validate(parse_yaml(text))
