"""Exception types shared across the engine.

Every error message raised here is safe to show to a user: callers pass
messages through secrets.mask() before they reach logs, the API or the UI.
"""


class EngineError(Exception):
    """Base class for all engine errors."""


class ConfigError(EngineError):
    """The connector config is invalid. `errors` holds [{path, message, hint, level}]."""

    def __init__(self, errors: list[dict]):
        self.errors = errors
        first = errors[0] if errors else {"path": "", "message": "invalid config"}
        super().__init__(f"config invalid at '{first['path']}': {first['message']}")


class SecretMissing(EngineError):
    """A secret named in the config has no value in the environment."""


class SecurityError(EngineError):
    """A request was blocked by a security control (SSRF guard, method rule, sandbox)."""


class AuthFailed(EngineError):
    """The source rejected our credentials (401/403). Never retried."""


class RetryExhausted(EngineError):
    """Timeouts, connection errors, 5xx or 429 persisted after every retry."""


class HttpError(EngineError):
    """A non-retryable HTTP error such as 400 or 404."""


class ParseError(EngineError):
    """The response body could not be parsed or the records were not found."""


class MappingError(EngineError):
    """One record could not be mapped. The record is quarantined; the run continues."""
