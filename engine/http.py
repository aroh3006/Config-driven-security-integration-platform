"""The one HTTP client every connector uses. Reliability and safety live here, once.

FR-7  timeouts, connection errors and 5xx are retried after exactly delays_s (default
      1s, 2s, 4s). After that the run is marked failed. 401/403 and other 4xx are never retried.
FR-8  429: wait for Retry-After (seconds or HTTP date), else the configured reset header,
      else the next retry delay. Waits are capped. Requests are paced to max_rps. When
      the remaining-calls header reaches 0 we sleep until the reset time.
Also: SSRF guard on every URL and redirect, response size limit, masked request log,
OAuth refresh on 401 and the fault switch for repeatable demos.
"""

from __future__ import annotations

import email.utils
import logging
import random
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urljoin, urlsplit

import httpx

from . import faults
from .auth import AuthPlugin
from .config import Config
from .errors import AuthFailed, HttpError, RetryExhausted, SecurityError
from .secrets import get_secret, mask, mask_url
from .security import Resolver, check_url, safe_file_path

log = logging.getLogger("engine.http")
USER_AGENT = "mitigata-config-connector/0.1"


@dataclass
class RunStats:
    retries: int = 0
    requests: list[dict] = field(default_factory=list)
    waits: list[float] = field(default_factory=list)  # every retry / rate-limit wait, in seconds


def parse_reset(value: str, now: float) -> Optional[float]:
    """Reset header -> seconds to wait. Epoch seconds (Okta, GitHub) or plain seconds."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if v > 1e12:  # epoch milliseconds
        v = v / 1000
    return max(v - now, 0.0) if v > 1e9 else max(v, 0.0)


def parse_retry_after(value: Optional[str], now: float) -> Optional[float]:
    if not value:
        return None
    value = value.strip()
    try:
        return max(float(value), 0.0)
    except ValueError:
        pass
    try:
        dt = email.utils.parsedate_to_datetime(value)
        return max(dt.timestamp() - now, 0.0)
    except (TypeError, ValueError):
        return None


class HttpClient:
    def __init__(
        self,
        cfg: Config,
        auth: AuthPlugin,
        *,
        transport: Optional[httpx.BaseTransport] = None,
        sleeper: Optional[Callable[[float], None]] = None,
        resolver: Optional[Resolver] = None,
        stats: Optional[RunStats] = None,
        clock: Callable[[], float] = time.time,
    ):
        self.cfg = cfg
        self.auth = auth
        self.sleep = sleeper or time.sleep
        self.resolver = resolver
        self.stats = stats or RunStats()
        self.clock = clock
        self._last_request = 0.0
        self._blocked_until = 0.0
        self._client = httpx.Client(
            transport=transport,
            timeout=httpx.Timeout(cfg.limits.timeout_s),
            verify=self._tls_verify(),
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/csv, */*"},
        )
        auth.bind(self)

    # ------------------------------------------------------------------ public
    def close(self) -> None:
        self._client.close()

    def request(
        self,
        method: str,
        url: str,
        params: Optional[dict] = None,
        json_body: Any = None,
        extra_headers: Optional[dict] = None,
    ) -> httpx.Response:
        cfg = self.cfg
        delays = list(cfg.retry.delays_s)
        error_retries = 0
        waits_429 = 0
        refreshed = False
        attempt = 0
        if method not in ("GET", "POST") or (method == "POST" and not cfg.request.read_only_post):
            raise SecurityError(f"blocked: method {method} is not allowed (read-only connectors)")

        while True:
            attempt += 1
            self._pace()
            plain_headers = {**cfg.request.headers, **(extra_headers or {})}
            headers = dict(plain_headers)
            query = {k: v for k, v in (params or {}).items() if v is not None}
            self.auth.apply(headers, query)
            headers.update({name: get_secret(secret) for name, secret in cfg.request.secret_headers.items()})
            credentials = set(headers) - set(plain_headers)
            fault = faults.take(cfg.name, faults.HTTP_KINDS)
            started = time.perf_counter()
            try:
                if fault:
                    resp = self._fake_response(fault, method, url)
                else:
                    resp = self._send(method, url, query, json_body, headers, credentials)
            except (httpx.TimeoutException, httpx.TransportError) as e:
                kind = "timeout" if isinstance(e, httpx.TimeoutException) else "connection error"
                self._log(method, url, query, None, started, attempt, kind + (" (injected)" if fault else ""))
                if error_retries < len(delays):
                    self._wait(self._delay(delays[error_retries]))
                    error_retries += 1
                    continue
                raise RetryExhausted(f"{kind} on {self._host(url)} after {attempt} attempts") from None

            self._log(method, str(resp.request.url) if resp.request else url, None, resp.status_code, started, attempt,
                      "injected" if fault else "")
            self._note_rate_headers(resp)
            self._check_auth_failure(resp, url)
            status = resp.status_code
            if 200 <= status < 300:
                return resp
            if status in (401, 403):
                if status == 401 and self.auth.can_refresh and not refreshed:
                    refreshed = True
                    self.auth.refresh()
                    continue
                reason = "credentials rejected (wrong or expired key)" if status == 401 else "permission denied (token lacks a scope)"
                raise AuthFailed(f"HTTP {status} from {self._host(url)}: {reason}")
            if status == 429:
                waits_429 += 1
                if waits_429 > cfg.rate_limit.max_429_waits:
                    raise RetryExhausted(f"still rate limited (HTTP 429) after {cfg.rate_limit.max_429_waits} waits")
                wait = self._rate_limit_wait(resp)
                if wait is None:
                    wait = delays[min(error_retries, len(delays) - 1)] if delays else 1.0
                self._wait(min(wait, cfg.rate_limit.max_wait_s))
                continue
            if status >= 500:
                if error_retries < len(delays):
                    self._wait(self._delay(delays[error_retries]))
                    error_retries += 1
                    continue
                raise RetryExhausted(f"HTTP {status} from {self._host(url)} after {attempt} attempts")
            raise HttpError(f"HTTP {status} from {self._host(url)}: {mask(resp.text[:300])}")

    def raw_post_form(self, url: str, data: dict, headers: dict) -> httpx.Response:
        """Token requests for OAuth2."""
        return self.raw_request("POST", url, label="token", headers=headers, data=data)

    def raw_request(
        self,
        method: str,
        url: str,
        *,
        label: str,
        headers: dict,
        data: Optional[dict] = None,
        json_body: Any = None,
        params: Optional[dict] = None,
    ) -> httpx.Response:
        """Login and token calls. Same guard and retry rules, no auth plugin."""
        delays = list(self.cfg.retry.delays_s)
        for attempt in range(len(delays) + 1):
            started = time.perf_counter()
            try:
                check_url(url, self.cfg, self.resolver)
                resp = self._client.request(method, url, headers=headers, data=data, json=json_body, params=params or None)
            except (httpx.TimeoutException, httpx.TransportError):
                self._log(method, url, None, None, started, attempt + 1, f"{label} request failed")
                if attempt < len(delays):
                    self._wait(delays[attempt])
                    continue
                raise RetryExhausted(f"{label} endpoint {self._host(url)} unreachable") from None
            self._log(method, url, None, resp.status_code, started, attempt + 1, f"{label} request")
            if resp.status_code >= 500 and attempt < len(delays):
                self._wait(delays[attempt])
                continue
            return resp
        raise RetryExhausted(f"{label} endpoint kept failing")  # pragma: no cover

    # ------------------------------------------------------------------ internals
    def _tls_verify(self) -> Any:
        """Trust the public CAs plus the connector's own CA file. Verification stays on."""
        if not self.cfg.source.ca_file:
            return True
        path = safe_file_path(self.cfg.source.ca_file)
        context = ssl.create_default_context()
        try:
            context.load_verify_locations(cafile=str(path))
        except ssl.SSLError as e:
            raise SecurityError(f"ca_file {path.name} is not a valid certificate file") from e
        return context

    def _check_auth_failure(self, resp: httpx.Response, url: str) -> None:
        """Raise when the config's header says the login was rejected, whatever the status."""
        rule = self.cfg.auth_failure
        value = resp.headers.get(rule.header, "") if rule else ""
        if rule and rule.contains.lower() in value.lower():
            raise AuthFailed(f"HTTP {resp.status_code} from {self._host(url)}: credentials rejected ({rule.header}: {mask(value)})")

    def _send(self, method, url, params, json_body, headers, credentials) -> httpx.Response:
        max_bytes = int(self.cfg.limits.max_response_mb * 1024 * 1024)
        if params:  # httpx would replace the URL's own query string. Merge explicitly.
            url = str(httpx.URL(url).copy_merge_params(params))
        current, first_host = url, self._host(url)
        for hop in range(6):
            check_url(current, self.cfg, self.resolver)
            hop_headers = dict(headers)
            if self._host(current) != first_host:  # never leak credentials to another host
                for name in credentials:
                    hop_headers.pop(name, None)
            req = self._client.build_request(
                method, current, json=json_body if method == "POST" else None, headers=hop_headers,
            )
            resp = self._client.send(req, stream=True)
            try:
                if resp.is_redirect and "location" in resp.headers:
                    current = urljoin(str(resp.url), resp.headers["location"])
                    if resp.status_code == 303:
                        method, json_body = "GET", None
                    continue
                chunks, size = [], 0
                for chunk in resp.iter_bytes():
                    size += len(chunk)
                    if size > max_bytes:
                        raise HttpError(f"response larger than {self.cfg.limits.max_response_mb} MB limit")
                    chunks.append(chunk)
            finally:
                resp.close()
            # iter_bytes() already decoded the body. Drop the encoding header or httpx decodes it again.
            headers = httpx.Headers(resp.headers)
            headers.pop("content-encoding", None)
            return httpx.Response(resp.status_code, headers=headers, content=b"".join(chunks), request=req)
        raise SecurityError("blocked: too many redirects")

    def _fake_response(self, fault: faults.Fault, method: str, url: str) -> httpx.Response:
        check_url(url, self.cfg, self.resolver)  # faults never bypass the guard
        req = httpx.Request(method, url)
        if fault.kind == "timeout":
            raise httpx.ReadTimeout("injected timeout", request=req)
        status = int(fault.kind)
        headers = {"Retry-After": str(fault.arg)} if status == 429 else {}
        body = {"error": "injected_fault", "error_description": f"fault switch returned HTTP {status}"}
        return httpx.Response(status, headers=headers, json=body, request=req)

    def _rate_limit_wait(self, resp: httpx.Response) -> Optional[float]:
        now = self.clock()
        wait = parse_retry_after(resp.headers.get("Retry-After"), now)
        if wait is not None:
            return wait
        for name in filter(None, [self.cfg.rate_limit.reset_header, "X-Rate-Limit-Reset", "X-RateLimit-Reset", "RateLimit-Reset"]):
            if name in resp.headers:
                w = parse_reset(resp.headers[name], now)
                if w is not None:
                    return w
        return None

    def _note_rate_headers(self, resp: httpx.Response) -> None:
        rl = self.cfg.rate_limit
        if not (rl.remaining_header and rl.remaining_header in resp.headers):
            return
        try:
            remaining = int(float(resp.headers[rl.remaining_header]))
        except ValueError:
            return
        if remaining <= 0 and rl.reset_header and rl.reset_header in resp.headers:
            wait = parse_reset(resp.headers[rl.reset_header], self.clock())
            if wait:
                self._blocked_until = self.clock() + min(wait, rl.max_wait_s)

    def _pace(self) -> None:
        now = self.clock()
        if self._blocked_until > now:
            self._wait(self._blocked_until - now, kind="rate-limit reset")
            self._blocked_until = 0.0
        rps = self.cfg.rate_limit.max_rps
        if rps:
            gap = 1.0 / rps - (self.clock() - self._last_request)
            if gap > 0:
                self.sleep(gap)  # pacing is not a retry. It is not counted.
        self._last_request = self.clock()

    def _delay(self, base: float) -> float:
        return base * random.uniform(0.5, 1.5) if self.cfg.retry.jitter else base

    def _wait(self, seconds: float, kind: str = "retry") -> None:
        self.stats.retries += 1 if kind == "retry" else 0
        self.stats.waits.append(round(seconds, 3))
        log.info("%s: waiting %.1fs (%s)", self.cfg.name, seconds, kind)
        self.sleep(seconds)

    def _log(self, method, url, params, status, started, attempt, note="") -> None:
        if params:
            url = str(httpx.URL(url).copy_merge_params(params))
        entry = {
            "method": method,
            "url_masked": mask_url(url),
            "status": status,
            "ms": int((time.perf_counter() - started) * 1000),
            "attempt": attempt,
        }
        if note:
            entry["note"] = note
        self.stats.requests.append(entry)
        log.info("%s %s %s -> %s %s", self.cfg.name, method, entry["url_masked"], status, note)

    @staticmethod
    def _host(url: str) -> str:
        return (urlsplit(url).hostname or "").lower()
