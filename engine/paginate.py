"""Pagination plugins (FR-3). One small registered class per paging style.

A page request is a plain dict {url, params, body}. That makes resume trivial: after
each committed page the runner saves the NEXT page request as the checkpoint's
resume_state. A crashed run continues from exactly there, for every style.
"""

from __future__ import annotations

import copy
from typing import Any, Callable, Optional
from urllib.parse import urljoin

import httpx

from .config import (
    BodyNextUrlPaging,
    BodyTokenPaging,
    Config,
    OffsetPaging,
    PageNumberPaging,
)
from .parse import get_path

PageReq = dict  # {"url": str, "params": dict|None, "body": Any}
PAGINATION_REGISTRY: dict[str, type["Paginator"]] = {}


def register(type_name: str) -> Callable:
    def wrap(cls):
        PAGINATION_REGISTRY[type_name] = cls
        return cls

    return wrap


class Paginator:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.p = cfg.pagination

    def first(self, base: PageReq) -> PageReq:
        return base

    def next(self, current: PageReq, resp: httpx.Response, parsed: Any, records: list) -> Optional[PageReq]:
        return None


def _with_param(req: PageReq, name: str, value: Any, where: str = "query") -> PageReq:
    new = copy.deepcopy(req)
    if where == "body":
        body = new.get("body") or {}
        if not isinstance(body, dict):
            body = {}
        body[name] = value
        new["body"] = body
    else:
        params = new.get("params") or {}
        params[name] = value
        new["params"] = params
    return new


@register("none")
class NoPaginator(Paginator):
    pass


@register("link_header")
class LinkHeaderPaginator(Paginator):
    """Follow the RFC 8288 Link header rel="next" until it is absent or a page is empty.

    Polling APIs send a next link on every response. For those an empty page is the end.
    """

    def next(self, current, resp, parsed, records):
        if not records:
            return None
        nxt = resp.links.get("next", {}).get("url")
        if not nxt:
            return None
        # the next URL already carries every query param; keep the body for POST APIs
        return {"url": urljoin(str(resp.url), nxt), "params": None, "body": current.get("body")}


@register("page_number")
class PageNumberPaginator(Paginator):
    p: PageNumberPaging

    def first(self, base):
        req = _with_param(base, self.p.page_param, self.p.start)
        if self.p.size_param:
            req = _with_param(req, self.p.size_param, self.p.size)
        return req

    def next(self, current, resp, parsed, records):
        if not records:
            return None
        page = int((current.get("params") or {}).get(self.p.page_param, self.p.start))
        if self.p.total_pages_path:
            total = get_path(parsed, self.p.total_pages_path)
            if total is not None and page >= int(total):
                return None
        return _with_param(current, self.p.page_param, page + 1)


@register("offset")
class OffsetPaginator(Paginator):
    p: OffsetPaging

    def _get(self, req: PageReq, name: str, default: Any) -> Any:
        holder = req.get("body") if self.p.param_in == "body" else req.get("params")
        return (holder or {}).get(name, default)

    def first(self, base):
        req = _with_param(base, self.p.offset_param, self.p.start, self.p.param_in)
        if self.p.limit_param:
            req = _with_param(req, self.p.limit_param, self.p.limit, self.p.param_in)
        return req

    def next(self, current, resp, parsed, records):
        if not records:
            return None
        offset = int(self._get(current, self.p.offset_param, self.p.start)) + len(records)
        if self.p.total_path:
            total = get_path(parsed, self.p.total_path)
            if total is not None and offset >= int(total):
                return None
        elif len(records) < self.p.limit:
            return None
        return _with_param(current, self.p.offset_param, offset, self.p.param_in)


@register("body_token")
class BodyTokenPaginator(Paginator):
    """A token in the response body is sent back as a param (Jira nextPageToken, AWS NextToken)."""

    p: BodyTokenPaging

    def next(self, current, resp, parsed, records):
        if self.p.stop_path and get_path(parsed, self.p.stop_path) is True:
            return None
        token = get_path(parsed, self.p.token_path)
        if token in (None, "", [], {}):
            return None
        return _with_param(current, self.p.token_param, token, self.p.token_in)


@register("body_next_url")
class BodyNextUrlPaginator(Paginator):
    """A full next-page URL in the body, e.g. {"next": "https://..."} (checked by the SSRF guard)."""

    p: BodyNextUrlPaging

    def next(self, current, resp, parsed, records):
        nxt = get_path(parsed, self.p.next_url_path)
        if not nxt or not isinstance(nxt, str):
            return None
        return {"url": urljoin(str(resp.url), nxt), "params": None, "body": current.get("body")}


def make_paginator(cfg: Config) -> Paginator:
    return PAGINATION_REGISTRY[cfg.pagination.type](cfg)
