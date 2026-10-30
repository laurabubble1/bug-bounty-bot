import httpx
import pytest

from app.plugins import security_headers
from app.plugins.security_headers import SecurityHeadersPlugin


class _Response:
    status_code = 200

    def __init__(self) -> None:
        self.headers = httpx.Headers([
            ("set-cookie", "session=not-stored; Path=/"),
            ("access-control-allow-origin", SecurityHeadersPlugin.CORS_PROBE_ORIGIN),
            ("access-control-allow-credentials", "true"),
        ])

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args) -> None:
        return None


class _Client:
    def __init__(self, **_kwargs) -> None:
        self.request: tuple[str, str, dict] | None = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args) -> None:
        return None

    def stream(self, method: str, url: str, *, headers: dict):
        self.request = (method, url, headers)
        return _Response()


async def test_security_header_plugin_reports_bounded_header_and_cookie_observations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_client = _Client()
    monkeypatch.setattr(security_headers, "validate_target_url", lambda *_args, **_kwargs: "https://example.test/")
    monkeypatch.setattr(security_headers.httpx, "AsyncClient", lambda **kwargs: fake_client)
    messages: list[str] = []

    async def log(_level: str, message: str) -> None:
        messages.append(message)

    findings = await SecurityHeadersPlugin().scan(
        base_url="https://example.test/account?ignored=1",
        options={"approved_hosts": ["example.test"]},
        log=log,
    )

    titles = {item.title for item in findings}
    assert "Response is missing HTTP Strict Transport Security" in titles
    assert "Cookie may be missing Secure (session)" in titles
    assert "Cookie may be accessible to scripts (session)" in titles
    assert "Cookie may be missing SameSite (session)" in titles
    assert "CORS allows the probe origin (reflected arbitrary origin)" in titles
    assert len(findings) == 9
    assert all("not-stored" not in item.evidence for item in findings)
    assert fake_client.request is not None
    assert fake_client.request[0] == "GET"
    assert fake_client.request[2]["Origin"] == SecurityHeadersPlugin.CORS_PROBE_ORIGIN
    assert messages[0].startswith("Checking common response security headers")
    assert messages[-1] == f"Received HTTP 200; review {len(findings)} header observation(s)"


async def test_security_header_plugin_does_not_report_hsts_for_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(security_headers, "validate_target_url", lambda *_args, **_kwargs: "http://demo-target/")
    monkeypatch.setattr(security_headers.httpx, "AsyncClient", lambda **kwargs: _Client(**kwargs))

    async def log(_level: str, _message: str) -> None:
        return None

    findings = await SecurityHeadersPlugin().scan(
        base_url="http://demo-target/path", options={}, log=log
    )
    assert not any("Strict Transport Security" in item.title for item in findings)
