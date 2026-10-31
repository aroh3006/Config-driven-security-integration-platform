"""Secrets: resolve secret NAMES from config to values from the environment and mask them.

FR-6: a config only ever contains a name such as `okta_key`. The value lives in the
environment variable OKTA_KEY (loaded from a gitignored .env file). Every value we hand
out is registered for masking. A global log-record factory replaces those values
with *** in every log line and traceback, from every logger.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from urllib.parse import parse_qsl, quote, quote_plus, urlencode, urlsplit, urlunsplit

from .errors import SecretMissing

MASK = "***"
_lock = threading.Lock()
_known_values: set[str] = set()
_dotenv_loaded = False

# Header and query parameter names whose values are always hidden in request logs.
# Config validation refuses literal values under these names.
SENSITIVE_NAME = re.compile(
    r"(authorization|api[-_]?key|apikey|token|secret|password|passwd|signature|x-api-key|cookie|session)",
    re.IGNORECASE,
)

# A secret name is short words joined by _ or -. Examples: okta_key, edr-client-id.
_NAME_SHAPE = re.compile(r"[a-z][a-z0-9_-]{0,63}")
# A word holds at most one short run of digits. Examples: oauth2, k8s. Hex and UUID parts hold several.
_NAME_WORD = re.compile(r"(?=.{0,16}$)[a-z]*[0-9]{0,6}[a-z]*")


def env_name(secret_name: str) -> str:
    """okta_key -> OKTA_KEY; jira-token -> JIRA_TOKEN."""
    return re.sub(r"[^A-Za-z0-9]", "_", secret_name).upper()


def is_secret_name(value: str) -> bool:
    """True for okta_key or OKTA_KEY. False for a credential pasted in place of a name.

    Credentials are long, mix cases, hold symbols or scatter digits. A short plain word
    cannot be told apart from a name.
    """
    name = value.lower() if value.isupper() else value
    return bool(_NAME_SHAPE.fullmatch(name)) and all(_NAME_WORD.fullmatch(word) for word in re.split("[_-]", name))


def _load_dotenv_once() -> None:
    global _dotenv_loaded
    if _dotenv_loaded:
        return
    try:
        from dotenv import find_dotenv, load_dotenv

        load_dotenv(find_dotenv(usecwd=True), override=False)
    except ImportError:  # python-dotenv is optional; plain env vars still work
        pass
    _dotenv_loaded = True


def has_secret(secret_name: str) -> bool:
    _load_dotenv_once()
    return bool(os.environ.get(env_name(secret_name)))


def get_secret(secret_name: str) -> str:
    """Return the value for a secret name and register it for masking."""
    _load_dotenv_once()
    value = os.environ.get(env_name(secret_name))
    if not value:
        raise SecretMissing(
            f"secret '{secret_name}' is not set (expected environment variable {env_name(secret_name)})"
        )
    register(value)
    return value


def register(value: str) -> None:
    """Register a sensitive value (e.g. an OAuth access token) so it is masked everywhere.

    URLs carry values percent-encoded. The encoded forms are stored too.
    """
    if value and len(value) >= 4:
        with _lock:
            _known_values.update((value, quote(value, safe=""), quote_plus(value)))


def mask(text: object) -> str:
    """Replace every known secret value in text with ***."""
    s = "" if text is None else str(text)
    with _lock:
        values = sorted(_known_values, key=len, reverse=True)
    for v in values:
        if v in s:
            s = s.replace(v, MASK)
    return s


def mask_url(url: str) -> str:
    """Mask sensitive query parameters (api_key=..., token=...) and known values in a URL."""
    try:
        parts = urlsplit(url)
        # mask the decoded value: re-encoding keeps * so it can differ from the registered forms
        query = [
            (k, MASK if SENSITIVE_NAME.search(k) else mask(v))
            for k, v in parse_qsl(parts.query, keep_blank_values=True)
        ]
        url = urlunsplit(parts._replace(query=urlencode(query, safe="*")))
    except ValueError:
        pass
    return mask(url)


def mask_headers(headers: dict) -> dict:
    return {k: (MASK if SENSITIVE_NAME.search(k) else mask(v)) for k, v in headers.items()}


def mask_obj(obj):
    """Recursively mask a JSON-like structure (used for audit details and errors)."""
    if isinstance(obj, dict):
        return {k: (MASK if SENSITIVE_NAME.search(str(k)) and isinstance(v, str) else mask_obj(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_obj(v) for v in obj]
    if isinstance(obj, str):
        return mask(obj)
    return obj


_factory_installed = False
_traceback_formatter = logging.Formatter()


def _mask_message(record: logging.LogRecord) -> None:
    try:
        msg = record.getMessage()
    except Exception:  # malformed format args: leave the message alone
        return
    masked = mask(msg)
    if masked != msg:  # keep args when clean, access formatters read them
        record.msg, record.args = masked, ()


def _mask_exception(record: logging.LogRecord) -> None:
    """Hide secrets in a traceback. Every standard formatter prints exc_text as it stands.

    exc_info goes too. Some formatters read it directly and would rebuild the raw text.
    """
    if not record.exc_info:
        return
    try:
        text = _traceback_formatter.formatException(record.exc_info)
    except Exception:  # a log call must never raise into its caller
        return
    masked = mask(text)
    if masked != text:  # keep exc_info when clean, custom formatters may use it
        record.exc_text, record.exc_info = masked, None


def install_log_masking() -> None:
    """Mask secrets in every log record from every logger (idempotent)."""
    global _factory_installed
    if _factory_installed:
        return
    old_factory = logging.getLogRecordFactory()

    def factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        _mask_message(record)
        _mask_exception(record)
        return record

    logging.setLogRecordFactory(factory)
    _factory_installed = True


install_log_masking()
