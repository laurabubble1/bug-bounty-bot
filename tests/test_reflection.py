from collections.abc import AsyncIterator

import httpx
import pytest

from app.core.config import settings
from app.plugins.reflection import ParameterReflectionPlugin


class FakeResponse:
    status_code = 200
    encoding = "utf-8"

    def __init__(self, marker: str):
        self.marker = marker

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def aiter_bytes(self) -> AsyncIterator[bytes]:
        yield f"Demo response: {self.marker}".encode()


class FakeClient:
    def __init__(self, *, fail_once: bool = False, **_kwargs):
        self.fail_once = fail_once
        self.calls = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    def stream(self, _method: str, _url: str, *, params: dict[str, str], **_kwargs):
        self.calls += 1
        if self.fail_once and self.calls == 1:
            request = httpx.Request("GET", "http://demo-target/search")
            raise httpx.ConnectError("temporary test failure", request=request)
        return FakeResponse(params[next(iter(params))])


@pytest.mark.parametrize("fail_once", [False, True])
async def test_reflection_plugin_detects_inert_marker_and_retries_once(
    monkeypatch: pytest.MonkeyPatch, fail_once: bool
) -> None:
    clients: list[FakeClient] = []

    def fake_client(**kwargs):
        client = FakeClient(fail_once=fail_once, **kwargs)
        clients.append(client)
        return client

    monkeypatch.setattr("app.plugins.reflection.httpx.AsyncClient", fake_client)
    monkeypatch.setattr(settings, "request_interval_seconds", 0)
    logs: list[tuple[str, str]] = []

    async def log(level: str, message: str) -> None:
        logs.append((level, message))

    plugin = ParameterReflectionPlugin()
    findings = await plugin.scan(
        base_url="http://demo-target:8080/search",
        options={"parameters": ["q"]},
        log=log,
    )

    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].title == "Input marker reflected in response (q)"
    assert "inert unique marker" in findings[0].evidence
    assert clients[0].calls == (2 if fail_once else 1)
    if fail_once:
        assert any(level == "WARNING" for level, _message in logs)


async def test_reflection_plugin_rejects_unbounded_parameter_lists() -> None:
    async def log(_level: str, _message: str) -> None:
        return None

    plugin = ParameterReflectionPlugin()
    with pytest.raises(ValueError, match="Provide between"):
        await plugin.scan(
            base_url="http://demo-target:8080/search",
            options={"parameters": []},
            log=log,
        )
