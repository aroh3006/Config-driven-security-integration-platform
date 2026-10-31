"""Helpers shared by every mock source."""

from __future__ import annotations

import base64
import hmac
import time
from typing import Any


class RateLimiter:
    """Fixed window request counter per caller."""

    def __init__(self, limit: int, window_s: int) -> None:
        self.limit = limit
        self.window_s = window_s
        self._windows: dict[str, tuple[float, int]] = {}

    def hit(self, caller: str) -> tuple[bool, dict[str, str], int]:
        """Count a request. Returns (allowed, headers, seconds until reset)."""
        now = time.time()
        start, used = self._windows.get(caller, (now, 0))
        if now - start >= self.window_s:
            start, used = now, 0
        used += 1
        self._windows[caller] = (start, used)
        reset_at = start + self.window_s
        headers = {
            "X-Rate-Limit-Limit": str(self.limit),
            "X-Rate-Limit-Remaining": str(max(self.limit - used, 0)),
            "X-Rate-Limit-Reset": str(int(reset_at)),
        }
        return used <= self.limit, headers, max(int(reset_at - now) + 1, 1)


def same_secret(given: str | None, expected: str) -> bool:
    """Compare credentials in constant time."""
    return given is not None and hmac.compare_digest(given.encode(), expected.encode())


def encode_cursor(offset: int) -> str:
    return base64.urlsafe_b64encode(f"offset:{offset}".encode()).decode()


def decode_cursor(cursor: str) -> int | None:
    try:
        prefix, value = base64.urlsafe_b64decode(cursor.encode()).decode().split(":")
        return int(value) if prefix == "offset" else None
    except ValueError:
        return None


def bad_copy(record: dict[str, Any], id_field: str) -> dict[str, Any]:
    copy = dict(record)
    copy.pop(id_field, None)
    return copy
