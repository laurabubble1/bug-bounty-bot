import socket

import pytest

from app.core import security
from app.core.config import settings
from app.core.security import ScopeViolation, validate_target_url


def test_scope_requires_exact_allowlisted_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "authorized_hosts", "demo-target,example.org")
    monkeypatch.setattr(settings, "demo_host", "demo-target")

    assert validate_target_url("http://demo-target:8080/search") == "http://demo-target:8080/search"
    with pytest.raises(ScopeViolation, match="AUTHORIZED_HOSTS"):
        validate_target_url("https://not-allowed.example/search")
    with pytest.raises(ScopeViolation, match="HTTP is permitted"):
        validate_target_url("http://example.org/search")
    with pytest.raises(ScopeViolation, match="query parameters"):
        validate_target_url("https://example.org/search?q=hello")


def test_public_allowlisted_hostname_must_resolve_publicly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "authorized_hosts", "example.org")
    monkeypatch.setattr(settings, "demo_host", "demo-target")
    monkeypatch.setattr(
        security.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))],
    )
    assert validate_target_url("https://example.org/health") == "https://example.org/health"

    monkeypatch.setattr(
        security.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))],
    )
    with pytest.raises(ScopeViolation, match="non-public"):
        validate_target_url("https://example.org/health")
