"""Security controls applied to every connector at the same point.

- SSRF guard: only http/https, only hosts in allow_hosts. After resolving DNS the IP
  must not be loopback, private, link-local, reserved or the cloud metadata address.
  Checked again on every redirect and every next-page URL.
  Exceptions: `mock: true` connectors may call loopback (our local mock server).
  `source.allow_private_network: true` permits LAN addresses (e.g. a venue server).
  Link-local and metadata addresses are never allowed.
- File sandbox: file sources can only read inside the data folder.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from .config import Config, host_allowed
from .errors import SecurityError

METADATA_IPS = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("fd00:ec2::254")}

# A resolver returns the list of IP strings for a host. Tests inject a fake one.
Resolver = Callable[[str], list[str]]


def default_resolver(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise SecurityError(f"cannot resolve host '{host}': {e}") from e
    return sorted({info[4][0] for info in infos})


def check_ip(ip_text: str, cfg: Config) -> None:
    ip = ipaddress.ip_address(ip_text.split("%")[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip in METADATA_IPS or ip.is_link_local:
        raise SecurityError(f"blocked: {ip} is a link-local / cloud metadata address")
    if ip.is_loopback:
        if cfg.mock:
            return
        raise SecurityError(f"blocked: {ip} is a loopback address (only allowed for mock: true connectors)")
    if ip.is_private or ip.is_reserved or ip.is_unspecified or ip.is_multicast:
        if cfg.source.allow_private_network and ip.is_private:
            return
        raise SecurityError(
            f"blocked: {ip} is a private/internal address (set source.allow_private_network: true only for your own LAN)"
        )


def _proxy_configured() -> bool:
    return any(os.environ.get(k) for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"))


def check_url(url: str, cfg: Config, resolver: Resolver | None = None) -> None:
    """Raise SecurityError unless this URL is safe for this connector to call."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise SecurityError(f"blocked: scheme '{parts.scheme}' is not allowed (http/https only)")
    host = (parts.hostname or "").lower()
    if not host:
        raise SecurityError("blocked: URL has no host")
    if not host_allowed(host, cfg.source.allow_hosts):
        raise SecurityError(f"blocked: host '{host}' is not in allow_hosts {cfg.source.allow_hosts}")
    if parts.scheme == "http" and not (cfg.mock or cfg.source.allow_private_network):
        raise SecurityError("blocked: plain http is only allowed for mock or private-network connectors; use https")
    try:  # literal IP in the URL
        check_ip(str(ipaddress.ip_address(host)), cfg)
        return
    except ValueError:
        pass
    try:
        ips = (resolver or default_resolver)(host)
    except SecurityError:
        # Behind an HTTP proxy the proxy resolves names, not us. The host allowlist above
        # still applies; the IP check is done by the proxy's network instead.
        if resolver is None and _proxy_configured():
            return
        raise
    if not ips:
        raise SecurityError(f"cannot resolve host '{host}'")
    for ip in ips:
        check_ip(ip, cfg)


def data_dir() -> Path:
    """The only folder file sources may read. DATA_DIR env var, else ./data."""
    return Path(os.environ.get("DATA_DIR", "data")).resolve()


def safe_file_path(path_text: str) -> Path:
    base = data_dir()
    p = Path(path_text)
    candidate = (p if p.is_absolute() else Path.cwd() / p).resolve()
    if not candidate.is_relative_to(base):
        # allow 'devices.csv' meaning data/devices.csv
        alt = (base / p).resolve()
        if alt.is_relative_to(base) and not p.is_absolute():
            candidate = alt
        else:
            raise SecurityError(f"blocked: file '{path_text}' is outside the data folder {base}")
    if not candidate.is_file():
        raise SecurityError(f"file not found: {candidate}")
    return candidate
