"""Mocks for login and paging styles that the core sources do not cover.

Cisco FMC: Basic login that returns its token in a response header.
Wiz: OAuth2 with an audience. Requests are GraphQL with the cursor inside `variables`.
Cortex XSIAM: an API key plus a key ID header, with paging inside `request_data`.
"""

from __future__ import annotations

import base64
import secrets
import time
from datetime import datetime
from typing import Any, Callable

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from mock_server import data
from mock_server.common import RateLimiter, bad_copy, decode_cursor, encode_cursor, same_secret

FMC_USER = "mock-fmc-api"
FMC_PASSWORD = "mock-fmc-password-6d1f"
FMC_TOKEN_TTL_S = 1800
FMC_DEFAULT_LIMIT = 25
FMC_MAX_LIMIT = 1000
WIZ_CLIENT_ID = "mock-wiz-client"
WIZ_CLIENT_SECRET = "mock-wiz-secret-93ab17e4"
WIZ_AUDIENCE = "wiz-api"
WIZ_TOKEN_TTL_S = 3600
WIZ_MAX_FIRST = 10000
CORTEX_KEY = "mock-cortex-key-2f8a90c1"
CORTEX_KEY_ID = "17"
CORTEX_MAX_PAGE = 100

Tokens = dict[str, tuple[float, frozenset[str]]]


def _fmc_error(status: int, message: str) -> JSONResponse:
    body = {"error": {"category": "FRAMEWORK", "severity": "ERROR", "messages": [{"description": message}]}}
    return JSONResponse(body, status)


def _cortex_error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"reply": {"err_code": status, "err_msg": message, "err_extra": ""}}, status)


def _graphql_error(message: str) -> JSONResponse:
    """GraphQL reports request errors in a 200 response."""
    return JSONResponse({"data": None, "errors": [{"message": message}]})


def build_router(now: datetime, bad_record_active: Callable[[str], bool], tokens: Tokens) -> APIRouter:
    devices = data.fmc_devices()
    issues = data.wiz_issues(now)
    alerts = data.cortex_alerts(now)
    fmc_limit = RateLimiter(120, 60)
    wiz_limit = RateLimiter(300, 60)
    cortex_limit = RateLimiter(300, 60)
    router = APIRouter()

    def issue_token(ttl_s: int) -> str:
        token = secrets.token_urlsafe(32)
        tokens[token] = (time.time() + ttl_s, frozenset())
        return token

    def token_is_live(token: str | None) -> bool:
        entry = tokens.get(token or "")
        if entry is None:
            return False
        if time.time() >= entry[0]:
            del tokens[token]
            return False
        return True

    # Cisco FMC: the token comes back in response headers with an empty 204 body

    @router.post("/fmc/api/fmc_platform/v1/auth/generatetoken", tags=["cisco-fmc"])
    def fmc_login(request: Request) -> Response:
        authorization = request.headers.get("authorization", "")
        try:
            decoded = base64.b64decode(authorization.partition(" ")[2]).decode()
        except ValueError:
            decoded = ""
        if not authorization.lower().startswith("basic ") or not same_secret(decoded, f"{FMC_USER}:{FMC_PASSWORD}"):
            return _fmc_error(401, "Invalid username or password.")
        headers = {
            "X-auth-access-token": issue_token(FMC_TOKEN_TTL_S),
            "X-auth-refresh-token": secrets.token_urlsafe(32),
            "DOMAIN_UUID": data.FMC_DOMAIN,
        }
        return Response(status_code=204, headers=headers)

    @router.get("/fmc/api/fmc_config/v1/domain/{domain}/devices/devicerecords", tags=["cisco-fmc"])
    def fmc_device_records(
        request: Request, domain: str, offset: int = 0, limit: int = FMC_DEFAULT_LIMIT, expanded: bool = False
    ) -> JSONResponse:
        if not token_is_live(request.headers.get("x-auth-access-token")):
            return _fmc_error(401, "Access token invalid.")
        allowed, headers, wait = fmc_limit.hit(FMC_USER)
        if not allowed:
            return JSONResponse({"error": {"messages": [{"description": "Rate limit exceeded."}]}}, 429, {**headers, "Retry-After": str(wait)})
        if domain != data.FMC_DOMAIN:
            return _fmc_error(404, "Domain not found.")
        size = min(max(limit, 1), FMC_MAX_LIMIT)
        page = [dict(d) if expanded else {k: d[k] for k in ("id", "type", "name", "links") if k in d} for d in devices[offset : offset + size]]
        if page and bad_record_active(request.url.path):
            page[0] = bad_copy(page[0], "id")
        paging: dict[str, Any] = {
            "offset": offset,
            "limit": size,
            "count": len(devices),
            "pages": (len(devices) + size - 1) // size,
        }
        if offset + size < len(devices):
            paging["next"] = [str(request.url.include_query_params(offset=offset + size, limit=size))]
        return JSONResponse({"links": {"self": str(request.url)}, "items": page, "paging": paging}, headers=headers)

    # Wiz: OAuth2 token with an audience and one GraphQL endpoint

    @router.post("/wiz/oauth/token", tags=["wiz"])
    async def wiz_token(request: Request) -> JSONResponse:
        form = await request.form()
        if form.get("grant_type") != "client_credentials":
            return JSONResponse({"error": "unsupported_grant_type", "error_description": "Use client_credentials."}, 400)
        if not same_secret(str(form.get("client_id")), WIZ_CLIENT_ID) or not same_secret(str(form.get("client_secret")), WIZ_CLIENT_SECRET):
            return JSONResponse({"error": "invalid_client", "error_description": "Client authentication failed."}, 401)
        if form.get("audience") != WIZ_AUDIENCE:
            return JSONResponse({"error": "access_denied", "error_description": "Service not enabled within domain."}, 403)
        token = issue_token(WIZ_TOKEN_TTL_S)
        return JSONResponse({"access_token": token, "token_type": "Bearer", "expires_in": WIZ_TOKEN_TTL_S})

    @router.post("/wiz/graphql", tags=["wiz"])
    async def wiz_graphql(request: Request) -> JSONResponse:
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token_is_live(token):
            return JSONResponse({"error": "unauthorized", "error_description": "The token is not valid."}, 401)
        allowed, headers, wait = wiz_limit.hit(WIZ_CLIENT_ID)
        if not allowed:
            return JSONResponse({"error": "rate_limited", "error_description": "Too many requests."}, 429, {**headers, "Retry-After": str(wait)})
        try:
            body = await request.json()
        except ValueError:
            return _graphql_error("Body is not valid JSON.")
        if "issues" not in str(body.get("query", "")):
            return _graphql_error("Cannot query the requested field.")
        variables = body.get("variables") or {}
        first = variables.get("first")
        if not isinstance(first, int) or not 0 < first <= WIZ_MAX_FIRST:
            return _graphql_error(f"Variable $first must be from 1 to {WIZ_MAX_FIRST}.")
        offset = 0
        if variables.get("after"):
            decoded = decode_cursor(str(variables["after"]))
            if decoded is None:
                return _graphql_error("Variable $after is not a valid cursor.")
            offset = decoded
        nodes = list(issues[offset : offset + first])
        if nodes and bad_record_active(request.url.path):
            nodes[0] = bad_copy(nodes[0], "id")
        following = offset + len(nodes)
        info = {"hasNextPage": following < len(issues), "endCursor": encode_cursor(following)}
        return JSONResponse({"data": {"issues": {"nodes": nodes, "pageInfo": info}}}, headers=headers)

    # Cortex XSIAM: two auth headers, every read is a POST with request_data

    @router.post("/cortex/public_api/v1/alerts/get_alerts", tags=["cortex"])
    async def cortex_get_alerts(request: Request) -> JSONResponse:
        key_ok = same_secret(request.headers.get("authorization"), CORTEX_KEY)
        if not key_ok or not same_secret(request.headers.get("x-xdr-auth-id"), CORTEX_KEY_ID):
            return _cortex_error(401, "Public API request unauthorized")
        allowed, headers, wait = cortex_limit.hit(CORTEX_KEY_ID)
        if not allowed:
            return JSONResponse({"reply": {"err_code": 429, "err_msg": "Too many requests"}}, 429, {**headers, "Retry-After": str(wait)})
        try:
            body = await request.json()
        except ValueError:
            return _cortex_error(400, "Body is not valid JSON.")
        request_data = body.get("request_data") if isinstance(body, dict) else None
        if not isinstance(request_data, dict):
            return _cortex_error(400, "request_data is required.")
        start, end = request_data.get("search_from", 0), request_data.get("search_to", CORTEX_MAX_PAGE)
        if not isinstance(start, int) or not isinstance(end, int) or not 0 < end - start <= CORTEX_MAX_PAGE:
            return _cortex_error(400, f"search_to minus search_from must be from 1 to {CORTEX_MAX_PAGE}.")
        page = list(alerts[start:end])
        if page and bad_record_active(request.url.path):
            page[0] = bad_copy(page[0], "alert_id")
        reply = {"total_count": len(alerts), "result_count": len(page), "alerts": page}
        return JSONResponse({"reply": reply}, headers=headers)

    return router
