"""Mocks of Okta, GitHub and Jira Cloud, built from each vendor's published OpenAPI spec.

Each copies its vendor's login, paging, field names and error format, including
the awkward parts. Okta's log `next` link never ends while polling. GitHub
members usually have no email. Jira returns only ids unless fields are named
and it rejects unbounded JQL.
"""

from __future__ import annotations

import base64
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from mock_server import data
from mock_server.common import RateLimiter, bad_copy, decode_cursor, encode_cursor, same_secret

OKTA_KEY = "mock-okta-key-a84d21f9"
OKTA_KEY_NO_ACCESS = "mock-okta-key-no-access"
GITHUB_TOKEN = "mock-github-token-52c7e1b0"
GITHUB_TOKEN_NO_ALERTS = "mock-github-token-no-alerts"
GITHUB_ORG = "example-org"
GITHUB_REPO = "demo-service"
GITHUB_API_VERSIONS = {"2022-11-28", "2026-03-10"}
JIRA_EMAIL = "sec-bot@example.com"
JIRA_TOKEN = "mock-jira-token-9e03b7d4"
JIRA_PROJECT = "SEC"

OKTA_MAX_SINCE_DAYS = 180
OKTA_FILTER_RE = re.compile(r'^eventType eq "([^"]+)"$')
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
JQL_RE = re.compile(
    r'^project\s*=\s*"?([A-Za-z0-9_-]+)"?(\s+and\s+.+?)?(\s+order\s+by\s+.+)?$', re.IGNORECASE
)
GITHUB_DOCS = "https://docs.example.com/rest"
DEPENDABOT_STATES = {"auto_dismissed", "dismissed", "fixed", "open"}
JIRA_ALL_FIELDS = {"*all", "*navigable"}
GITHUB_ADMIN_COUNT = 3


def _okta_error(status: int, code: str, summary: str, headers: dict[str, str] | None = None) -> JSONResponse:
    body = {"errorCode": code, "errorSummary": summary, "errorLink": code, "errorId": "oaeMockError", "errorCauses": []}
    return JSONResponse(body, status, headers)


def _github_error(status: int, message: str, headers: dict[str, str] | None = None) -> JSONResponse:
    body = {"message": message, "documentation_url": GITHUB_DOCS, "status": str(status)}
    return JSONResponse(body, status, headers)


def _jira_error(status: int, message: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"errorMessages": [message], "errors": {}}, status, headers)


def _link_header(links: dict[str, str]) -> str:
    return ", ".join(f'<{url}>; rel="{rel}"' for rel, url in links.items())


def _is_valid_time(value: Any) -> bool:
    return isinstance(value, str) and bool(ISO_RE.match(value))


def _github_rate_headers(headers: dict[str, str], request: Request) -> dict[str, str]:
    renamed = {name.replace("X-Rate-Limit-", "X-RateLimit-"): value for name, value in headers.items()}
    used = int(renamed["X-RateLimit-Limit"]) - int(renamed["X-RateLimit-Remaining"])
    return {
        **renamed,
        "X-RateLimit-Used": str(used),
        "X-RateLimit-Resource": "core",
        "X-GitHub-Request-Id": f"MOCK:{used:08X}",
        "X-GitHub-Api-Version-Selected": request.headers.get("x-github-api-version", "2022-11-28"),
    }


def _jira_rate_headers(headers: dict[str, str]) -> dict[str, str]:
    """Jira spells these X-RateLimit-*. Reset and reason come only with a 429."""
    limit, remaining = int(headers["X-Rate-Limit-Limit"]), int(headers["X-Rate-Limit-Remaining"])
    renamed = {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(remaining),
        "RateLimit": f'"jira-burst-based";r={remaining};t=1',
        "RateLimit-Policy": '"jira-burst-based";q=100;w=1',
    }
    if remaining < limit * 0.2:
        renamed["X-RateLimit-NearLimit"] = "true"
    return renamed


def _jira_throttled_headers(headers: dict[str, str], wait: int) -> dict[str, str]:
    reset = datetime.now(timezone.utc) + timedelta(seconds=wait)
    return {
        **headers,
        "X-RateLimit-Reset": data.iso(reset),
        "RateLimit-Reason": "jira-burst-based",
        "Retry-After": str(wait),
    }


def build_router(now: datetime, bad_record_active: Callable[[str], bool]) -> APIRouter:
    users = data.okta_users(now)
    logs = data.okta_logs(now)
    members = data.github_members()
    alerts = data.github_dependabot(now, GITHUB_ORG, GITHUB_REPO)
    issues = data.jira_issues(now, JIRA_PROJECT)
    okta_limit = RateLimiter(600, 60)
    github_limit = RateLimiter(600, 60)
    jira_limit = RateLimiter(600, 60)
    router = APIRouter()

    # Okta: `Authorization: SSWS <token>`, cursor in an RFC 8288 Link header

    def okta_guard(request: Request) -> tuple[JSONResponse | None, dict[str, str]]:
        authorization = request.headers.get("authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme != "SSWS":
            return _okta_error(401, "E0000005", "Invalid session"), {}
        if same_secret(token, OKTA_KEY_NO_ACCESS):
            return _okta_error(403, "E0000006", "You do not have permission to perform the requested action"), {}
        if not same_secret(token, OKTA_KEY):
            return _okta_error(401, "E0000011", "Invalid token provided"), {}
        allowed, headers, wait = okta_limit.hit(OKTA_KEY)
        if not allowed:
            limited = {**headers, "Retry-After": str(wait)}
            return _okta_error(429, "E0000047", "API call exceeded rate limit due to too many requests.", limited), {}
        return None, headers

    @router.get("/okta/api/v1/users", tags=["okta"])
    def okta_list_users(request: Request, limit: int = 200, after: str | None = None) -> JSONResponse:
        refused, headers = okta_guard(request)
        if refused:
            return refused
        offset = 0 if not after else decode_cursor(after)
        if offset is None:
            return _okta_error(400, "E0000001", "Api validation failed: after", headers)
        size = min(max(limit, 1), 200)
        page = list(users[offset : offset + size])
        if page and bad_record_active(request.url.path):
            page[0] = bad_copy(page[0], "id")
        links = {"self": str(request.url)}
        if offset + size < len(users):
            links["next"] = str(request.url.include_query_params(after=encode_cursor(offset + size)))
        return JSONResponse(page, headers={**headers, "Link": _link_header(links)})

    @router.get("/okta/api/v1/logs", tags=["okta"])
    def okta_list_logs(
        request: Request,
        since: str | None = None,
        until: str | None = None,
        filter: str | None = None,
        limit: int = 100,
        after: str | None = None,
        sortOrder: str = "ASCENDING",
    ) -> JSONResponse:
        """A request with no `until` is polling. It always gets a next link."""
        refused, headers = okta_guard(request)
        if refused:
            return refused
        for name, value in (("since", since), ("until", until)):
            if value is not None and not _is_valid_time(value):
                return _okta_error(400, "E0000001", f"Api validation failed: {name}", headers)
        if since:
            oldest = now - timedelta(days=OKTA_MAX_SINCE_DAYS)
            moment = datetime.strptime(since[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
            if moment < oldest:
                return _okta_error(
                    400, "E0000001", "Api validation failed: 'since' is over 180 days prior to the current day", headers
                )
        if sortOrder not in ("ASCENDING", "DESCENDING"):
            return _okta_error(400, "E0000001", "Api validation failed: sortOrder", headers)
        selected = logs
        if filter:
            match = OKTA_FILTER_RE.match(filter)
            if not match:
                return _okta_error(400, "E0000001", "Api validation failed: filter", headers)
            selected = [event for event in selected if event["eventType"] == match[1]]
        if since:
            selected = [e for e in selected if _is_valid_time(e["published"]) and e["published"] >= since]
        if until:
            selected = [e for e in selected if _is_valid_time(e["published"]) and e["published"] <= until]
        if sortOrder == "DESCENDING":
            selected = list(reversed(selected))
        offset = 0 if not after else decode_cursor(after)
        if offset is None:
            return _okta_error(400, "E0000001", "Api validation failed: after", headers)
        size = min(max(limit, 1), 1000)
        page = list(selected[offset : offset + size])
        if page and bad_record_active(request.url.path):
            page[0] = bad_copy(page[0], "uuid")
        following = min(offset + size, len(selected))
        links = {"self": str(request.url)}
        if until is None or following < len(selected):
            links["next"] = str(request.url.include_query_params(after=encode_cursor(following)))
        return JSONResponse(page, headers={**headers, "Link": _link_header(links)})

    # GitHub: bearer token, X-RateLimit-* headers, API version header

    def github_guard(request: Request) -> tuple[JSONResponse | None, dict[str, str], str]:
        version = request.headers.get("x-github-api-version")
        if version is not None and version not in GITHUB_API_VERSIONS:
            return _github_error(400, f"Invalid API version provided: {version}"), {}, ""
        if "authorization" not in request.headers:
            return _github_error(401, "Requires authentication"), {}, ""
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        known = same_secret(token, GITHUB_TOKEN) or same_secret(token, GITHUB_TOKEN_NO_ALERTS)
        if scheme.lower() not in ("bearer", "token") or not known:
            return _github_error(401, "Bad credentials"), {}, ""
        allowed, headers, wait = github_limit.hit(token)
        headers = _github_rate_headers(headers, request)
        if not allowed:
            limited = {**headers, "Retry-After": str(wait)}
            return _github_error(429, "API rate limit exceeded", limited), {}, ""
        return None, headers, token

    @router.get("/github/orgs/{org}/members", tags=["github"])
    def github_org_members(
        request: Request, org: str, per_page: int = 30, page: int = 1, filter: str = "all", role: str = "all"
    ) -> JSONResponse:
        refused, headers, _ = github_guard(request)
        if refused:
            return refused
        if org != GITHUB_ORG:
            return _github_error(404, "Not Found", headers)
        if filter not in ("all", "2fa_disabled", "2fa_insecure") or role not in ("all", "admin", "member"):
            return _github_error(422, "Validation failed", headers)
        selected = {"admin": members[:GITHUB_ADMIN_COUNT], "member": members[GITHUB_ADMIN_COUNT:]}.get(role, members)
        size = min(max(per_page, 1), 100)
        number = max(page, 1)
        start = (number - 1) * size
        rows = list(selected[start : start + size])
        if rows and bad_record_active(request.url.path):
            rows[0] = bad_copy(rows[0], "id")
        last = max((len(selected) + size - 1) // size, 1)
        links = {}
        if number < last:
            links["next"] = str(request.url.include_query_params(page=number + 1, per_page=size))
            links["last"] = str(request.url.include_query_params(page=last, per_page=size))
        if number > 1:
            links["prev"] = str(request.url.include_query_params(page=number - 1, per_page=size))
            links["first"] = str(request.url.include_query_params(page=1, per_page=size))
        if links:
            headers = {**headers, "Link": _link_header(links)}
        return JSONResponse(rows, headers=headers)

    @router.get("/github/repos/{owner}/{repo}/dependabot/alerts", tags=["github"])
    def github_alerts(
        request: Request,
        owner: str,
        repo: str,
        per_page: int = 30,
        after: str | None = None,
        state: str | None = None,
        severity: str | None = None,
    ) -> JSONResponse:
        refused, headers, token = github_guard(request)
        if refused:
            return refused
        if same_secret(token, GITHUB_TOKEN_NO_ALERTS):
            return _github_error(403, "Resource not accessible by personal access token", headers)
        if owner != GITHUB_ORG or repo != GITHUB_REPO:
            return _github_error(404, "Not Found", headers)
        selected = alerts
        if state:
            wanted = set(state.split(","))
            if not wanted <= DEPENDABOT_STATES:
                return _github_error(422, "Validation failed: state", headers)
            selected = [alert for alert in selected if alert["state"] in wanted]
        if severity:
            levels = set(severity.split(","))
            selected = [alert for alert in selected if alert["security_advisory"]["severity"] in levels]
        offset = 0 if not after else decode_cursor(after)
        if offset is None:
            return _github_error(400, "Bad Request: after", headers)
        size = min(max(per_page, 1), 100)
        rows = list(selected[offset : offset + size])
        if rows and bad_record_active(request.url.path):
            rows[0] = bad_copy(rows[0], "number")
        if offset + size < len(selected):
            next_url = str(request.url.include_query_params(after=encode_cursor(offset + size)))
            headers = {**headers, "Link": _link_header({"next": next_url})}
        return JSONResponse(rows, headers=headers)

    # Jira Cloud: basic auth with email and API token, nextPageToken in the body

    def jira_authorized(request: Request) -> bool:
        authorization = request.headers.get("authorization", "")
        if not authorization.lower().startswith("basic "):
            return False
        try:
            decoded = base64.b64decode(authorization[6:]).decode()
        except ValueError:
            return False
        return same_secret(decoded, f"{JIRA_EMAIL}:{JIRA_TOKEN}")

    def jira_row(issue: dict[str, Any], names: list[str], base: str) -> dict[str, Any]:
        if not names or names == ["id"]:
            return {"id": issue["id"]}
        fields = issue["fields"]
        chosen = fields if JIRA_ALL_FIELDS & set(names) else {n: fields[n] for n in names if n in fields}
        return {**issue, "self": f"{base}jira/rest/api/3/issue/{issue['id']}", "fields": dict(chosen)}

    @router.get("/jira/rest/api/3/search/jql", tags=["jira"])
    def jira_search(
        request: Request,
        jql: str | None = None,
        maxResults: int = 50,
        fields: str | None = None,
        nextPageToken: str | None = None,
    ) -> JSONResponse:
        """The last page has no nextPageToken, as Atlassian documents.

        A bad login is not an error here. Live Jira treats the caller as anonymous
        and answers 200 with no issues. Only a wrong token gets a telling header.
        """
        if not jira_authorized(request):
            signal = {"X-Seraph-LoginReason": "AUTHENTICATED_FAILED"} if "authorization" in request.headers else {}
            return JSONResponse({"issues": [], "isLast": True}, headers=signal)
        allowed, limits, wait = jira_limit.hit(JIRA_EMAIL)
        headers = _jira_rate_headers(limits)
        if not allowed:
            return _jira_error(429, "Rate limit exceeded.", _jira_throttled_headers(headers, wait))
        match = JQL_RE.match((jql or "").strip())
        if not match:
            return _jira_error(
                400,
                "Unbounded JQL queries are not allowed here. Please add a search restriction to your query.",
                headers,
            )
        if match[1].upper() != JIRA_PROJECT:
            return _jira_error(400, f"The value '{match[1]}' does not exist for the field 'project'.", headers)
        offset = 0 if not nextPageToken else decode_cursor(nextPageToken)
        if offset is None:
            return _jira_error(400, "The nextPageToken is not valid.", headers)
        size = min(max(maxResults, 1), 100)
        names = [name.strip() for name in fields.split(",")] if fields else []
        base = str(request.base_url)
        page = [jira_row(issue, names, base) for issue in issues[offset : offset + size]]
        if page and bad_record_active(request.url.path):
            page[0] = bad_copy(page[0], "key")
        following = offset + size
        body: dict[str, Any] = {"issues": page, "isLast": following >= len(issues)}
        if following < len(issues):
            body["nextPageToken"] = encode_cursor(following)
        return JSONResponse(body, headers=headers)

    return router
