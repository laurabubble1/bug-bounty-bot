import json
from typing import Any

import httpx
import pytest

from app import discovery
from app.core.config import settings


class _Response:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args) -> None:
        return None

    def raise_for_status(self) -> None:
        return None

    async def aiter_bytes(self):
        yield json.dumps(self.payload).encode()


class _Client:
    def __init__(self, responder) -> None:
        self.responder = responder
        self.calls: list[tuple[str, dict | None]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args) -> None:
        return None

    def stream(self, method: str, url: str, params: dict | None = None):
        assert method == "GET"
        self.calls.append((url, params))
        return _Response(self.responder(url, params))


async def test_hackerone_discovery_filters_programs_and_follows_safe_scope_pages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "hackerone_api_username", "researcher")
    monkeypatch.setattr(settings, "hackerone_api_token", "test-token")
    scopes_url = "https://api.hackerone.com/v1/hackers/programs/example/structured_scopes"

    def responder(url: str, _params: dict | None) -> dict[str, Any]:
        if url.endswith("/programs"):
            return {
                "data": [
                    {"attributes": {
                        "handle": "example", "name": "Example", "state": "public_mode",
                        "submission_state": "open", "offers_bounties": True,
                        "policy": "Rules for this program", "open_scope": True,
                    }},
                    {"attributes": {
                        "handle": "private", "name": "Private", "state": "soft_launched",
                        "submission_state": "open", "offers_bounties": True,
                    }},
                ],
                "links": {"next": "?page[number]=2"},
            }
        if url == scopes_url:
            return {
                "data": [
                    {"attributes": {
                        "eligible_for_submission": True,
                        "asset_identifier": "https://example.test", "asset_type": "URL",
                        "eligible_for_bounty": True, "instruction": "Check the public API.",
                    }},
                    {"attributes": {
                        "eligible_for_submission": False,
                        "asset_identifier": "excluded.example.test", "asset_type": "URL",
                    }},
                ],
                "links": {"next": "?page[number]=2"},
            }
        if url == f"{scopes_url}?page[number]=2":
            return {"data": [{"attributes": {
                "eligible_for_submission": True,
                "asset_identifier": "second.example.test", "asset_type": "WILDCARD",
                "eligible_for_bounty": False,
            }}]}
        raise AssertionError(f"Unexpected discovery URL: {url}")

    fake_client = _Client(responder)
    monkeypatch.setattr(discovery.httpx, "AsyncClient", lambda **_kwargs: fake_client)
    result = await discovery.discover_hackerone("second.example")

    assert result["ok"] is True
    assert result["program_list_limited_to_first_100"] is True
    program = result["programs"][0]
    assert program["policy_text"] == "Rules for this program"
    assert program["open_scope"] is True
    assert [asset["identifier"] for asset in program["assets"]] == [
        "https://example.test", "second.example.test",
    ]
    assert program["assets_complete_in_response"] is True
    assert len(fake_client.calls) == 3


async def test_discovery_reports_missing_credentials_without_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "hackerone_api_username", "")
    monkeypatch.setattr(settings, "hackerone_api_token", "")
    result = await discovery.discover_hackerone()
    assert result == {
        "provider": "HackerOne", "configured": False, "ok": False, "programs": [],
    }


async def test_json_response_rejects_non_object_and_oversized_body() -> None:
    client = _Client(lambda _url, _params: ["not", "an", "object"])
    with pytest.raises(ValueError, match="unexpected response"):
        await discovery._json_response(client, "https://example.test/")

    class LargeResponse(_Response):
        async def aiter_bytes(self):
            yield b"x" * (discovery._MAX_BODY_BYTES + 1)

    class LargeClient(_Client):
        def stream(self, method: str, url: str, params: dict | None = None):
            return LargeResponse({})

    with pytest.raises(ValueError, match="2 MB safety limit"):
        await discovery._json_response(LargeClient(lambda *_args: {}), "https://example.test/")


async def test_hackerone_discovery_sanitizes_connection_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "hackerone_api_username", "researcher")
    monkeypatch.setattr(settings, "hackerone_api_token", "test-token")
    client = _Client(lambda *_args: {})
    monkeypatch.setattr(discovery.httpx, "AsyncClient", lambda **_kwargs: client)

    async def timeout(*_args, **_kwargs):
        raise httpx.ConnectTimeout("private connection detail")

    monkeypatch.setattr(discovery, "_json_response", timeout)
    result = await discovery.discover_hackerone()

    assert result["ok"] is False
    assert result["error"] == "HackerOne discovery failed (ConnectTimeout). Check the API credentials and retry."
    assert "private connection detail" not in result["error"]


async def test_bugcrowd_discovery_maps_relationships_and_marks_partial_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "bugcrowd_api_username", "researcher")
    monkeypatch.setattr(settings, "bugcrowd_api_token", "test-token")
    payload = {
        "data": [{
            "type": "program", "id": "1", "attributes": {"code": "example", "name": "Example"},
            "relationships": {"current_brief": {"data": {"type": "program_brief", "id": "brief"}}},
        }],
        "included": [
            {"type": "program_brief", "id": "brief", "relationships": {
                "target_groups": {"data": [{"type": "target_group", "id": "group"}]},
            }},
            {"type": "target_group", "id": "group", "attributes": {"name": "Web"}, "relationships": {
                "targets": {"data": [{"type": "target", "id": "target"}],
                            "links": {"related": {"meta": {"total_hits": 2}}}},
                "reward_range": {"data": {"type": "reward_range", "id": "reward"}},
            }},
            {"type": "target", "id": "target", "attributes": {"name": "app.example.test"}},
            {"type": "reward_range", "id": "reward", "attributes": {"p1_max_cents": 120000}},
        ],
        "links": {"next": "https://api.bugcrowd.com/programs?page[offset]=100"},
    }
    fake_client = _Client(lambda _url, _params: payload)
    monkeypatch.setattr(discovery.httpx, "AsyncClient", lambda **_kwargs: fake_client)

    result = await discovery.discover_bugcrowd("Example")

    assert result["ok"] is True
    assert result["program_list_limited_to_first_100"] is True
    program = result["programs"][0]
    assert program["platform_url"] == "https://bugcrowd.com/engagements/example"
    assert program["maximum_reward_cents"] == 120000
    assert program["assets_complete_in_response"] is False
    assert program["assets"][0]["identifier"] == "app.example.test"
