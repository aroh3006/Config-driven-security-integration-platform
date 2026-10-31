"""Auth plugins (FR-1). One small registered class per login style.

Each plugin adds headers/query params to an outgoing request. OAuth2 client credentials
also fetches and caches a token. It refreshes the token once when the source answers 401.
To add a new login style: write a class with apply()/refresh() and @register it.
"""

from __future__ import annotations

import base64
import time
from typing import TYPE_CHECKING, Callable

from . import secrets
from .config import ApiKeyAuth, BasicAuth, BearerAuth, Config, NoAuth, OAuth2ClientCredentials
from .errors import AuthFailed, EngineError

if TYPE_CHECKING:
    from .http import HttpClient

AUTH_REGISTRY: dict[str, type["AuthPlugin"]] = {}


def register(type_name: str) -> Callable:
    def wrap(cls):
        AUTH_REGISTRY[type_name] = cls
        return cls

    return wrap


class AuthPlugin:
    can_refresh = False

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.auth = cfg.auth
        self.client: "HttpClient | None" = None

    def bind(self, client: "HttpClient") -> None:
        self.client = client

    def apply(self, headers: dict, params: dict) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def refresh(self) -> bool:
        """Get fresh credentials after a 401. Return True if a retry makes sense."""
        return False


@register("none")
class NoAuthPlugin(AuthPlugin):
    def apply(self, headers, params):
        return None


@register("api_key")
class ApiKeyPlugin(AuthPlugin):
    auth: ApiKeyAuth

    def apply(self, headers, params):
        value = self.auth.prefix + secrets.get_secret(self.auth.secret)
        if self.auth.header:
            headers[self.auth.header] = value
        else:
            params[self.auth.query_param] = value


@register("basic")
class BasicPlugin(AuthPlugin):
    auth: BasicAuth

    def apply(self, headers, params):
        user = secrets.get_secret(self.auth.username_secret) if self.auth.username_secret else self.auth.username
        password = secrets.get_secret(self.auth.secret)
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        secrets.register(token)
        headers["Authorization"] = f"Basic {token}"


@register("bearer")
class BearerPlugin(AuthPlugin):
    auth: BearerAuth

    def apply(self, headers, params):
        headers["Authorization"] = self.auth.prefix + secrets.get_secret(self.auth.secret)


@register("oauth2_client_credentials")
class OAuth2ClientCredentialsPlugin(AuthPlugin):
    """RFC 6749 section 4.4. Token cached until 30s before expiry; refreshed once on 401."""

    auth: OAuth2ClientCredentials
    can_refresh = True
    # tokens are cached per connector so scheduled runs reuse them
    _cache: dict[str, tuple[str, float, str]] = {}

    def _fetch(self) -> tuple[str, float, str]:
        if self.client is None:
            raise EngineError("oauth2 plugin is not bound to an HTTP client")
        client_id = secrets.get_secret(self.auth.client_id_secret)
        client_secret = secrets.get_secret(self.auth.client_secret_secret)
        data = {"grant_type": "client_credentials", **self.auth.extra_params}
        if self.auth.scope:
            data["scope"] = self.auth.scope
        if self.auth.audience:
            data["audience"] = self.auth.audience
        headers = {"Accept": "application/json"}
        if self.auth.send_as == "basic":
            basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
            secrets.register(basic)
            headers["Authorization"] = f"Basic {basic}"
        else:
            data["client_id"], data["client_secret"] = client_id, client_secret
        resp = self.client.raw_post_form(self.auth.token_url, data, headers)
        if resp.status_code in (400, 401, 403):
            raise AuthFailed(f"token endpoint rejected the client credentials (HTTP {resp.status_code})")
        if resp.status_code >= 300:
            raise EngineError(f"token endpoint returned HTTP {resp.status_code}")
        try:
            body = resp.json()
            token = body["access_token"]
        except (ValueError, KeyError) as e:
            raise AuthFailed("token endpoint response has no access_token") from e
        secrets.register(token)
        expires_in = float(body.get("expires_in") or 3600)
        token_type = str(body.get("token_type") or "Bearer")
        if token_type.lower() == "bearer":
            token_type = "Bearer"
        return token, time.time() + max(expires_in - 30, 5), token_type

    def _token(self, force: bool = False) -> tuple[str, str]:
        cached = self._cache.get(self.cfg.name)
        if force or not cached or cached[1] <= time.time():
            cached = self._fetch()
            self._cache[self.cfg.name] = cached
        return cached[0], cached[2]

    def apply(self, headers, params):
        token, token_type = self._token()
        headers["Authorization"] = f"{token_type} {token}"

    def refresh(self) -> bool:
        self._cache.pop(self.cfg.name, None)
        return True


def make_auth(cfg: Config) -> AuthPlugin:
    auth = cfg.auth if cfg.auth is not None else NoAuth()
    try:
        return AUTH_REGISTRY[auth.type](cfg)
    except KeyError as e:  # pragma: no cover - config validation prevents this
        raise EngineError(f"no auth plugin registered for '{auth.type}'") from e
