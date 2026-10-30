import pytest

from app import campaign_agents, tasks
from app.core.config import settings
from app.core.database import SessionLocal
from app.models import Campaign, CampaignAgentRun, CampaignWebRun


async def test_structured_openai_request_uses_json_schema_without_environment_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "openai_api_key", "test-key")
    captured: dict = {}

    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return {"output_text": '{"result":"ok"}'}

    class Client:
        def __init__(self, **kwargs) -> None:
            captured["client_options"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def post(self, url: str, **kwargs) -> Response:
            captured["url"] = url
            captured["request"] = kwargs
            return Response()

    monkeypatch.setattr(campaign_agents.httpx, "AsyncClient", Client)
    result = await campaign_agents._structured_response(
        "test_result",
        {"type": "object", "properties": {"result": {"type": "string"}}, "required": ["result"]},
        "Return JSON.",
        {"text": "safe test"},
    )

    assert result == {"result": "ok"}
    assert captured["url"] == "https://api.openai.com/v1/responses"
    assert captured["client_options"]["trust_env"] is False
    assert captured["request"]["headers"]["Authorization"] == "Bearer test-key"
    request_body = captured["request"]["json"]
    assert request_body["store"] is False
    assert request_body["text"]["format"]["type"] == "json_schema"


async def test_campaign_agent_run_pins_source_and_queues_only_approved_app_checks(
    client, monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = "Review the in-scope source: https://github.com/example/agent-repo"
    assets = [
        {"identifier": "https://example.com/", "type": "URL"},
        {"identifier": "github.com/example/agent-repo", "type": "SOURCE_CODE"},
    ]
    async with SessionLocal() as session:
        campaign = Campaign(
            provider="HackerOne",
            external_id="agent-task-test",
            name="Agent Task Test",
            program_url="https://hackerone.com/agent-task-test",
            scope_assets=assets,
            policy_text=policy,
            scope_complete=True,
            scope_approved=True,
        )
        session.add(campaign)
        await session.flush()
        agent_run = CampaignAgentRun(
            campaign_id=campaign.id,
            policy_text=policy,
            scope_assets=assets,
        )
        session.add(agent_run)
        await session.commit()
        await session.refresh(agent_run)
        run_id = agent_run.id

    async def fake_plan(**_kwargs):
        return {
            "summary": "Review both approved asset types.",
            "app_action": "run",
            "app_reason": "The policy allows bounded app checks.",
            "target_url": "https://example.com/",
            "plugins": ["security-headers"],
            "parameters": [],
            "source_action": "run",
            "source_reason": "The policy names this repository.",
            "repository_url": "https://github.com/example/agent-repo",
        }

    async def fake_source_review(**_kwargs):
        return {
            "summary": "One code path needs manual review.",
            "reviews": [{
                "path": "src/app.py",
                "line": 8,
                "title": "Review input validation",
                "confidence": "low",
                "reasoning": "The supplied excerpt contains a relevant validation path.",
                "potential_impact": "A reachable flaw could affect request handling.",
                "validation_needed": "Trace the caller and reproduce with a local test.",
            }],
        }

    app_queue: list[int] = []
    monkeypatch.setattr(tasks, "plan_campaign_agents", fake_plan)
    monkeypatch.setattr(tasks, "review_source_candidates", fake_source_review)
    monkeypatch.setattr(tasks, "resolve_default_commit", lambda _url: "a" * 40)
    monkeypatch.setattr(
        tasks,
        "run_source_programs_with_context",
        lambda _url, _sha: (
            ["python-risk-pattern-review"],
            [{"program": "python-risk-pattern-review", "path": "src/app.py", "line": 8, "title": "Review input", "evidence": "Review this call."}],
            4,
            [{"path": "src/app.py", "lines": "8: request = parse(input)"}],
        ),
    )
    monkeypatch.setattr(tasks.run_campaign_web_scan, "delay", lambda web_id: app_queue.append(web_id))

    await tasks._run_campaign_agents(run_id)

    async with SessionLocal() as session:
        result = await session.get(CampaignAgentRun, run_id)
        assert result is not None
        web_run = await session.get(CampaignWebRun, result.web_run_id)
        assert result.status == "completed"
        assert result.campaign_agent_status == "queued"
        assert result.source_agent_status == "completed"
        assert result.commit_sha == "a" * 40
        assert result.repository_url == "https://github.com/example/agent-repo.git"
        assert result.ai_source_reviews[0]["path"] == "src/app.py"
        assert result.ai_source_reviews[0]["line"] == 8
        assert web_run is not None and web_run.target_url == "https://example.com/"
        assert web_run.selected_plugins == ["security-headers"]
        assert app_queue == [web_run.id]
