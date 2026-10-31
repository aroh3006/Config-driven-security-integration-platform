"""Log masking must hide secrets without breaking formatters that read record.args."""

import io
import logging
import sys
from urllib.parse import quote, quote_plus

import httpx
import pytest
from uvicorn.logging import AccessFormatter

from engine import secrets

ACCESS_FORMAT = '%s - "%s %s HTTP/%s" %d'
ACCESS_ARGS = ("127.0.0.1:5000", "GET", "/health", "1.1", 200)
URL_SECRETS = ["log-test+key/with=symbols", "log test key with spaces", "log*test+key*with*stars"]


def make_record(msg, args, exc_info=None):
    return logging.getLogRecordFactory()("uvicorn.access", logging.INFO, __file__, 1, msg, args, exc_info)


def logger_writing_to(*formatters):
    """A private logger with one handler per formatter, plus the buffers they write to."""
    logger = logging.getLogger("test.log_masking")
    logger.propagate = False
    streams = [io.StringIO() for _ in formatters]
    logger.handlers[:] = [logging.StreamHandler(stream) for stream in streams]
    for handler, formatter in zip(logger.handlers, formatters):
        handler.setFormatter(formatter)
    return logger, streams


class ReadsExcInfo(logging.Formatter):
    """Builds its text from exc_info directly. JSON log formatters do this."""

    def format(self, record):
        return self.formatException(record.exc_info) if record.exc_info else (record.exc_text or "")


def test_args_are_kept_when_there_is_nothing_to_mask():
    record = make_record(ACCESS_FORMAT, ACCESS_ARGS)
    assert record.args == ACCESS_ARGS


def test_uvicorn_access_formatter_can_read_the_record():
    formatter = AccessFormatter('%(client_addr)s - "%(request_line)s" %(status_code)s', use_colors=False)
    assert "GET /health HTTP/1.1" in formatter.format(make_record(ACCESS_FORMAT, ACCESS_ARGS))


def test_secret_in_args_is_masked():
    secrets.register("log-test-secret-in-args")
    record = make_record("token is %s", ("log-test-secret-in-args",))
    assert record.args == ()
    assert record.getMessage() == "token is ***"


def test_secret_in_message_is_masked():
    secrets.register("log-test-secret-in-message")
    assert make_record("token is log-test-secret-in-message", ()).getMessage() == "token is ***"


# URL-encoded secrets


@pytest.mark.parametrize("value", URL_SECRETS)
def test_url_encoded_forms_of_a_secret_are_masked(value):
    secrets.register(value)
    assert secrets.mask(f"key={quote(value, safe='')}") == "key=***"
    assert secrets.mask(f"key={quote_plus(value)}") == "key=***"


@pytest.mark.parametrize("value", URL_SECRETS)
def test_mask_url_hides_a_secret_under_a_plain_parameter_name(value):
    secrets.register(value)
    url = httpx.URL("https://api.example.com/items").copy_merge_params({"sid": value, "page": "2"})
    assert secrets.mask_url(str(url)) == "https://api.example.com/items?sid=***&page=2"


# Tracebacks


def test_secret_in_an_exception_is_masked_in_every_handler():
    secrets.register("log-test-secret-in-exception")
    logger, streams = logger_writing_to(logging.Formatter(), logging.Formatter("%(levelname)s %(message)s"), ReadsExcInfo())
    try:
        raise ValueError("rejected log-test-secret-in-exception")
    except ValueError:
        logger.exception("call failed")
    for stream in streams:
        assert "ValueError: rejected ***" in stream.getvalue()
        assert "log-test-secret-in-exception" not in stream.getvalue()


def test_secret_in_a_chained_exception_is_masked():
    secrets.register("log-test-secret-in-cause")
    logger, [stream] = logger_writing_to(logging.Formatter())
    try:
        try:
            raise KeyError("log-test-secret-in-cause")
        except KeyError as e:
            raise RuntimeError("call failed") from e
    except RuntimeError:
        logger.exception("run failed")
    text = stream.getvalue()
    assert "KeyError" in text and "RuntimeError" in text and "log-test-secret-in-cause" not in text


def test_exception_is_masked_when_the_message_args_are_malformed():
    secrets.register("log-test-secret-with-bad-args")
    try:
        raise ValueError("log-test-secret-with-bad-args")
    except ValueError:
        record = make_record("%d items", ("many",), sys.exc_info())
    assert record.exc_info is None and record.exc_text.endswith("ValueError: ***")


def test_clean_exception_keeps_exc_info_for_custom_formatters():
    try:
        raise ValueError("nothing sensitive here")
    except ValueError:
        info = sys.exc_info()
    record = make_record("call failed", (), info)
    assert record.exc_info == info and record.exc_text is None


def test_exc_info_that_cannot_be_formatted_does_not_raise():
    assert make_record("call failed", (), True).exc_info is True
