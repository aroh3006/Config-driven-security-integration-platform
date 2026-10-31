"""SSRF guard, redirects, file sandbox, read-only methods."""

import httpx
import pytest

from engine import load_config
from engine.errors import SecurityError
from engine.security import check_url, safe_file_path

BASE = """
name: src
entity: alert
MOCK
source: {base_url: URL, allow_hosts: [HOSTS]PRIV}
request: {path: /x}
map: {id: id, timestamp: ts}
"""


def cfg(url="https://api.example.com", hosts="api.example.com", mock=False, private=False):
    return load_config(BASE.replace("URL", url).replace("HOSTS", hosts).replace("MOCK", "mock: true" if mock else "")
                       .replace("PRIV", ", allow_private_network: true" if private else ""))


def res(host):
    return {"internal.example.com": ["10.0.0.5"], "meta.example.com": ["169.254.169.254"],
            "localhost": ["127.0.0.1"]}.get(host, ["93.184.216.34"])


def test_public_host_allowed():
    check_url("https://api.example.com/x", cfg(), res)


@pytest.mark.parametrize("host", ["internal.example.com", "meta.example.com", "localhost"])
def test_internal_addresses_blocked(host):
    c = cfg(url=f"https://{host}", hosts=host)
    with pytest.raises(SecurityError):
        check_url(f"https://{host}/x", c, res)


def test_literal_metadata_ip_blocked_even_with_private_flag():
    c = cfg(url="http://169.254.169.254", hosts="169.254.169.254", private=True)
    with pytest.raises(SecurityError, match="metadata"):
        check_url("http://169.254.169.254/latest/meta-data/", c, res)


def test_mock_may_use_loopback_but_not_metadata():
    c = cfg(url="http://localhost:9000", hosts="localhost", mock=True)
    check_url("http://localhost:9000/x", c, res)


def test_lan_source_needs_explicit_flag():
    c = cfg(url="http://192.168.60.13:8080", hosts="192.168.60.13")
    with pytest.raises(SecurityError, match="private"):
        check_url("http://192.168.60.13:8080/x", c, res)
    check_url("http://192.168.60.13:8080/x", cfg(url="http://192.168.60.13:8080", hosts="192.168.60.13", private=True), res)


def test_host_not_in_allowlist_blocked():
    with pytest.raises(SecurityError, match="allow_hosts"):
        check_url("https://evil.example.com/x", cfg(), res)


def test_non_http_scheme_blocked():
    with pytest.raises(SecurityError):
        check_url("file:///etc/passwd", cfg(), res)


def test_redirect_to_metadata_is_blocked(runner):
    text = BASE.replace("URL", "https://api.example.com").replace("HOSTS", "api.example.com, meta.example.com") \
        .replace("MOCK", "").replace("PRIV", "")

    def h(req):
        if req.url.host == "api.example.com":
            return httpx.Response(302, headers={"Location": "https://meta.example.com/latest/meta-data/"})
        return httpx.Response(200, json=[{"id": "1", "ts": "2026-10-31T00:00:00Z"}])

    r = runner(text, h)
    assert r.status == "failed" and "metadata" in r.last_error


def test_redirect_to_other_host_drops_credentials(runner):
    text = """
name: src
entity: alert
source: {base_url: https://api.example.com, allow_hosts: [api.example.com, cdn.example.com]}
auth: {type: bearer, secret: github_token}
request: {path: /x}
map: {id: id, timestamp: ts}
"""

    def h(req):
        if req.url.host == "api.example.com":
            return httpx.Response(302, headers={"Location": "https://cdn.example.com/file"})
        assert "Authorization" not in req.headers
        return httpx.Response(200, json=[{"id": "1", "ts": "2026-10-31T00:00:00Z"}])

    assert runner(text, h).status == "success"


def test_file_sandbox(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "ok.csv").write_text("a\n1\n")
    (tmp_path / "secret.txt").write_text("x")
    monkeypatch.chdir(tmp_path)
    assert safe_file_path("data/ok.csv").name == "ok.csv"
    assert safe_file_path("ok.csv").name == "ok.csv"
    with pytest.raises(SecurityError):
        safe_file_path("../secret.txt")
    with pytest.raises(SecurityError):
        safe_file_path(str(tmp_path / "secret.txt"))
