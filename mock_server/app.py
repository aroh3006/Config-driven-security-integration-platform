"""Mock security tools on one HTTP server: firewall, EDR, cloud audit, Okta, GitHub and Jira.

Each one really enforces auth, paging and rate limits. The engine meets them
exactly as it meets a real API. Only base_url differs.
"""

from __future__ import annotations

import asyncio
import base64
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from mock_server import data, saas
from mock_server.common import RateLimiter, same_secret
from mock_server.common import bad_copy as _bad_copy
from mock_server.common import decode_cursor as _decode_cursor
from mock_server.common import encode_cursor as _encode_cursor

FIREWALL_KEY = "mock-fw-key-7f3a91c2"
FIREWALL_KEY_NO_ACCESS = "mock-fw-key-no-log-access"
CLOUD_KEY = "mock-cloud-key-4be810d6"
EDR_CLIENT_ID = "mock-edr-client"
EDR_CLIENT_SECRET = "mock-edr-secret-c15e7702"
EDR_HOSTS_ONLY_CLIENT_ID = "mock-edr-hosts-only"
EDR_HOSTS_ONLY_CLIENT_SECRET = "mock-edr-secret-hosts-only"

ALL_SCOPES = frozenset({"hosts:read", "detections:read"})
FAULT_MODE_RE = re.compile(r"^(?:(?P<code>500|503)x(?P<count>\d+)|429:(?P<wait>\d+)|timeout|badrecord)$")
HANG_SECONDS = 120.0
CONTROL_PREFIXES = ("/admin", "/docs", "/openapi.json", "/redoc")


@dataclass
class Fault:
    kind: str
    remaining: int = 0
    retry_after: int = 0


class FaultRequest(BaseModel):
    path: str
    mode: str


def _oauth_error(status: int, error: str, description: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"error": error, "error_description": description}, status, headers)


def create_app(now: datetime | None = None, token_ttl_s: int = 300) -> FastAPI:
    """Build the mock app. Data is the same on every start for a given hour."""
    start = now or datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    firewall = data.firewall_events(start)
    hosts = data.edr_hosts(start)
    detections = data.edr_detections(start)
    cloud = data.cloud_events(start)

    faults: dict[str, Fault] = {}
    tokens: dict[str, tuple[float, frozenset[str]]] = {}
    clients = {
        EDR_CLIENT_ID: (EDR_CLIENT_SECRET, ALL_SCOPES),
        EDR_HOSTS_ONLY_CLIENT_ID: (EDR_HOSTS_ONLY_CLIENT_SECRET, frozenset({"hosts:read"})),
    }
    firewall_limit = RateLimiter(120, 60)
    edr_limit = RateLimiter(120, 60)
    cloud_limit = RateLimiter(20, 10)

    app = FastAPI(
        title="Mock security tools",
        description="Firewall, EDR, cloud audit, Okta, GitHub and Jira mocks. All data is fake.",
    )

    # Real APIs compress large responses. Clients must handle gzip here too.
    app.add_middleware(GZipMiddleware, minimum_size=500)

    def bad_record_active(path: str) -> bool:
        return any(
            path.startswith(prefix) and fault.kind == "badrecord"
            for prefix, fault in faults.items()
        )

    @app.exception_handler(StarletteHTTPException)
    async def json_errors(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "error")
        return JSONResponse(
            {"error": code, "error_description": str(exc.detail)}, exc.status_code
        )

    @app.middleware("http")
    async def inject_faults(request: Request, call_next: Any) -> Response:
        path = request.url.path
        if path.startswith(CONTROL_PREFIXES):
            return await call_next(request)
        for prefix, fault in list(faults.items()):
            if not path.startswith(prefix):
                continue
            if fault.kind == "timeout":
                await asyncio.sleep(HANG_SECONDS)
                return _oauth_error(504, "gateway_timeout", "Injected timeout.")
            if fault.kind == "429":
                del faults[prefix]
                return _oauth_error(
                    429,
                    "rate_limited",
                    "Injected rate limit.",
                    {"Retry-After": str(fault.retry_after)},
                )
            if fault.kind in ("500", "503"):
                fault.remaining -= 1
                if fault.remaining <= 0:
                    del faults[prefix]
                return _oauth_error(int(fault.kind), "server_error", "Injected server error.")
        return await call_next(request)

    # Admin

    @app.post("/admin/faults", tags=["admin"])
    def set_fault(body: FaultRequest) -> JSONResponse:
        """Set a fault on a path prefix: 503x3, 503x4, 500x1, 429:30, timeout, badrecord, off."""
        if body.mode == "off":
            faults.pop(body.path, None)
            return JSONResponse({"path": body.path, "mode": "off"})
        match = FAULT_MODE_RE.match(body.mode)
        if not match:
            return _oauth_error(400, "invalid_request", f"Unknown fault mode {body.mode!r}.")
        if match["code"]:
            faults[body.path] = Fault(match["code"], remaining=int(match["count"]))
        elif match["wait"]:
            faults[body.path] = Fault("429", retry_after=int(match["wait"]))
        else:
            faults[body.path] = Fault(body.mode)
        return JSONResponse({"path": body.path, "mode": body.mode})

    @app.get("/admin/faults", tags=["admin"])
    def list_faults() -> dict[str, str]:
        return {path: fault.kind for path, fault in faults.items()}

    @app.post("/admin/expire-tokens", tags=["admin"])
    def expire_tokens() -> dict[str, int]:
        """Expire every OAuth token now, without waiting five minutes."""
        count = len(tokens)
        tokens.clear()
        return {"expired": count}

    # Firewall: API key in a header, offset paging

    @app.get("/firewall/api/v1/logs", tags=["firewall"])
    def firewall_logs(request: Request, offset: int = 0, limit: int = 100) -> Response:
        key = request.headers.get("x-api-key")
        if key is None:
            return _oauth_error(401, "invalid_token", "Missing X-API-Key header.")
        if same_secret(key, FIREWALL_KEY_NO_ACCESS):
            return _oauth_error(403, "insufficient_scope", "This key cannot read logs.")
        if not same_secret(key, FIREWALL_KEY):
            return _oauth_error(401, "invalid_token", "The API key is not valid.")
        allowed, headers, wait = firewall_limit.hit(key)
        if not allowed:
            return _oauth_error(
                429, "rate_limited", "Too many requests.", {**headers, "Retry-After": str(wait)}
            )
        if offset < 0 or not 1 <= limit <= 500:
            return _oauth_error(400, "invalid_request", "Need offset >= 0 and limit from 1 to 500.")
        events = list(firewall[offset : offset + limit])
        if events and bad_record_active(request.url.path):
            events[0] = _bad_copy(events[0], "externalId")
        return JSONResponse(
            {"total": len(firewall), "offset": offset, "limit": limit, "events": events},
            headers=headers,
        )

    # EDR: OAuth2 client credentials, cursor paging

    @app.post("/edr/oauth2/token", tags=["edr"], status_code=201)
    async def edr_token(request: Request) -> JSONResponse:
        form = await request.form()
        client_id = form.get("client_id")
        client_secret = form.get("client_secret")
        authorization = request.headers.get("authorization", "")
        if authorization.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(authorization[6:]).decode()
                client_id, client_secret = decoded.split(":", 1)
            except ValueError:
                return _oauth_error(401, "invalid_client", "Malformed Basic credentials.")
        if form.get("grant_type") != "client_credentials":
            return _oauth_error(400, "unsupported_grant_type", "Use client_credentials.")
        client = clients.get(str(client_id))
        if client is None or not same_secret(str(client_secret), client[0]):
            return _oauth_error(401, "invalid_client", "Client authentication failed.")
        token = secrets.token_urlsafe(32)
        tokens[token] = (time.time() + token_ttl_s, client[1])
        return JSONResponse(
            {"access_token": token, "token_type": "bearer", "expires_in": token_ttl_s},
            201,
            {"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    def edr_page(
        request: Request, records: list[dict[str, Any]], scope: str, id_field: str, limit: int, after: str | None
    ) -> JSONResponse:
        authorization = request.headers.get("authorization", "")
        challenge = {"WWW-Authenticate": 'Bearer error="invalid_token"'}
        if not authorization.lower().startswith("bearer "):
            return _oauth_error(401, "invalid_token", "Missing bearer token.", {"WWW-Authenticate": "Bearer"})
        token = authorization[7:]
        entry = tokens.get(token)
        if entry is None:
            return _oauth_error(401, "invalid_token", "The token is not valid.", challenge)
        expires_at, scopes = entry
        if time.time() >= expires_at:
            del tokens[token]
            return _oauth_error(401, "invalid_token", "The token has expired.", challenge)
        if scope not in scopes:
            return _oauth_error(
                403,
                "insufficient_scope",
                f"Token lacks {scope}.",
                {"WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{scope}"'},
            )
        allowed, headers, wait = edr_limit.hit(token)
        if not allowed:
            return _oauth_error(
                429, "rate_limited", "Too many requests.", {**headers, "Retry-After": str(wait)}
            )
        if not 1 <= limit <= 500:
            return _oauth_error(400, "invalid_request", "Need limit from 1 to 500.")
        offset = 0
        if after:
            decoded = _decode_cursor(after)
            if decoded is None:
                return _oauth_error(400, "invalid_request", "The after cursor is not valid.")
            offset = decoded
        page = list(records[offset : offset + limit])
        if page and bad_record_active(request.url.path):
            page[0] = _bad_copy(page[0], id_field)
        following = offset + limit
        pagination = {
            "total": len(records),
            "limit": limit,
            "next": _encode_cursor(following) if following < len(records) else "",
        }
        return JSONResponse(
            {
                "meta": {"query_time": 0.01, "pagination": pagination, "powered_by": "mock-edr"},
                "resources": page,
                "errors": [],
            },
            headers=headers,
        )

    @app.get("/edr/devices/combined/devices/v1", tags=["edr"])
    def edr_devices(request: Request, limit: int = 100, after: str | None = None) -> JSONResponse:
        return edr_page(request, hosts, "hosts:read", "device_id", limit, after)

    @app.get("/edr/alerts/combined/alerts/v1", tags=["edr"])
    def edr_alerts(request: Request, limit: int = 100, after: str | None = None) -> JSONResponse:
        return edr_page(request, detections, "detections:read", "id", limit, after)

    # Cloud audit: CloudTrail LookupEvents shape, token in the POST body

    def aws_error(status: int, kind: str, message: str, headers: dict[str, str] | None = None) -> JSONResponse:
        return JSONResponse({"__type": kind, "message": message}, status, headers)

    @app.post("/cloud/", tags=["cloud"])
    async def cloud_lookup(request: Request) -> JSONResponse:
        key = request.headers.get("x-api-key")
        if not same_secret(key, CLOUD_KEY):
            return aws_error(401, "UnrecognizedClientException", "The security token is not valid.")
        if request.headers.get("x-amz-target") != "CloudTrail_20131101.LookupEvents":
            return aws_error(400, "UnknownOperationException", "Unknown X-Amz-Target.")
        allowed, headers, wait = cloud_limit.hit(key)
        if not allowed:
            return aws_error(
                429, "ThrottlingException", "Rate exceeded.", {**headers, "Retry-After": str(wait)}
            )
        try:
            body = await request.json()
        except ValueError:
            return aws_error(400, "SerializationException", "Body is not valid JSON.")
        limit = body.get("MaxResults", 50)
        if not isinstance(limit, int) or not 1 <= limit <= 50:
            return aws_error(400, "InvalidMaxResultsException", "MaxResults must be 1 to 50.")
        offset = 0
        if body.get("NextToken"):
            decoded = _decode_cursor(str(body["NextToken"]))
            if decoded is None:
                return aws_error(400, "InvalidNextTokenException", "NextToken is not valid.")
            offset = decoded
        events = list(cloud[offset : offset + limit])
        if events and bad_record_active(request.url.path):
            events[0] = _bad_copy(events[0], "EventId")
        result: dict[str, Any] = {"Events": events}
        if offset + limit < len(cloud):
            result["NextToken"] = _encode_cursor(offset + limit)
        return JSONResponse(result, headers=headers)

    app.include_router(saas.build_router(start, bad_record_active))
    return app
