import ipaddress
import socket
from urllib.parse import urlsplit

from fastapi import HTTPException

from app.core.config import settings


class ScopeViolation(ValueError):
    """Raised when a URL is outside the explicitly configured audit scope."""


def validate_target_url(url: str) -> str:
    """Require an exact allowlisted hostname and reject unsafe URL forms/IPs."""
    try:
        parsed = urlsplit(url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise ScopeViolation("Malformed target URL") from exc

    if parsed.scheme not in {"http", "https"} or not hostname:
        raise ScopeViolation("Target must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise ScopeViolation("Credentials and URL fragments are not permitted")
    if hostname not in settings.allowed_hosts:
        raise ScopeViolation("Hostname is not in AUTHORIZED_HOSTS")
    if port not in (None, 80, 443, 8080, 8443):
        raise ScopeViolation("Port is not permitted")
    if parsed.scheme == "http" and hostname != settings.demo_host.lower():
        raise ScopeViolation("HTTP is permitted only for the internal demo target")
    if parsed.query:
        raise ScopeViolation("Register a path without query parameters")

    # The demo service is intentionally internal to the isolated compose network.
    if hostname != settings.demo_host.lower():
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(hostname, port or 443, type=socket.SOCK_STREAM)}
        except socket.gaierror as exc:
            raise ScopeViolation("Allowlisted host did not resolve") from exc
        if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
            raise ScopeViolation("Target resolved to a non-public address")

    return url


def require_scope(url: str) -> str:
    try:
        return validate_target_url(url)
    except ScopeViolation as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
