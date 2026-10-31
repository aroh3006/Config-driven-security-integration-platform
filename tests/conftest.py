import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine import MemoryStore, faults, run_connector, save_and_approve  # noqa: E402

SAMPLES = Path(__file__).parent / "samples"

FAKE_DNS = {
    "internal.example.com": ["10.0.0.5"],
    "meta.example.com": ["169.254.169.254"],
    "localhost": ["127.0.0.1"],
}


def fake_resolver(host: str) -> list[str]:
    return FAKE_DNS.get(host, ["93.184.216.34"])  # a public address for every other test host


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k, v in {
        "OKTA_KEY": "okta-SECRET-0123456789",
        "GITHUB_TOKEN": "ghp_SECRETtoken0123456789",
        "JIRA_EMAIL": "sec@example.com",
        "JIRA_TOKEN": "jira-SECRET-abcdef",
        "EDR_CLIENT_ID": "edr-client",
        "EDR_CLIENT_SECRET": "edr-SECRET-xyz987",
        "FW_KEY": "fw-SECRET-key-42",
    }.items():
        monkeypatch.setenv(k, v)
    faults._faults.clear()
    from engine.auth import OAuth2ClientCredentialsPlugin

    OAuth2ClientCredentialsPlugin._cache.clear()
    yield
    faults._faults.clear()


@pytest.fixture
def store():
    return MemoryStore()


@pytest.fixture
def sleeps():
    return []


@pytest.fixture
def runner(store, sleeps):
    """runner(yaml, handler, name=True) -> RunResult, against a fake HTTP server."""

    def go(yaml_text, handler, by_name=True, **kw):
        transport = httpx.MockTransport(handler)
        opts = dict(store=store, transport=transport, resolver=fake_resolver, sleeper=sleeps.append)
        opts.update(kw)
        if by_name:
            res = save_and_approve(yaml_text, store=store)
            assert res["ok"], res
            return run_connector(res["name"], **opts)
        return run_connector(yaml_text, **opts)

    return go
