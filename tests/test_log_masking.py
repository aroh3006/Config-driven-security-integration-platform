"""Log masking must hide secrets without breaking formatters that read record.args."""

import logging

from uvicorn.logging import AccessFormatter

from engine import secrets

ACCESS_FORMAT = '%s - "%s %s HTTP/%s" %d'
ACCESS_ARGS = ("127.0.0.1:5000", "GET", "/health", "1.1", 200)


def make_record(msg, args):
    return logging.getLogRecordFactory()("uvicorn.access", logging.INFO, __file__, 1, msg, args, None)


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
