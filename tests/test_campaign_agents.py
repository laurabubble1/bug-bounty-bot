import pytest

from app import campaign_agents, tasks
from app.core.config import settings
from app.core.database import SessionLocal
from app.models import Campaign, CampaignAgentRun, CampaignWebRun, JobStatus, SourceRun


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


async def test_campaign_agents_require_a_local_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "openai_api_key", "")
    with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
        await campaign_agents._structured_response("test", {}, "instructions", {})


async def test_campaign_planner_bounds_policy_and_asset_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    async def fake_response(name, schema, instructions, payload):
        captured.update({
            "name": name, "schema": schema, "instructions": instructions, "payload": payload,
        })
        return {"app_action": "skip", "source_action": "skip"}

    monkeypatch.setattr(campaign_agents, "_structured_response", fake_response)
    result = await campaign_agents.plan_campaign_agents(
        campaign_name="N" * 250,
        program_url="https://hackerone.com/" + "x" * 2100,
        policy_text="P" * 31000,
        scope_assets=[{"identifier": str(index)} for index in range(510)],
        plugin_catalog=[{"key": "security-headers"}],
    )

    assert result["app_action"] == "skip"
    assert captured["name"] == "campaign_agents_plan"
    assert len(captured["payload"]["campaign_name"]) == 200
    assert len(captured["payload"]["program_url"]) == 2048
    assert len(captured["payload"]["policy_text"]) == 30000
    assert len(captured["payload"]["approved_scope_assets"]) == 500
    assert "never invent a host" in captured["instructions"]


async def test_source_review_payload_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    async def fake_response(name, schema, instructions, payload):
        captured.update({"name": name, "schema": schema, "instructions": instructions, "payload": payload})
        return {"summary": "reviewed", "reviews": []}

    monkeypatch.setattr(campaign_agents, "_structured_response", fake_response)
    result = await campaign_agents.review_source_candidates(
        campaign_name="Example",
        policy_text="current rules",
        repository_url="https://github.com/example/project.git",
        commit_sha="a" * 40,
        selected_programs=["python-risk-pattern-review"],
        findings=[{"line": index} for index in range(120)],
        excerpts=[{"path": str(index)} for index in range(12)],
    )

    assert result["summary"] == "reviewed"
    assert captured["name"] == "source_review_candidates"
    assert len(captured["payload"]["static_findings"]) == 100
    assert len(captured["payload"]["secret_redacted_source_excerpts"]) == 10
    assert "untrusted data" in captured["instructions"]


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


async def test_campaign_web_worker_runs_approved_plugins_and_records_findings(
    client, monkeypatch: pytest.MonkeyPatch,
) -> None:
    async with SessionLocal() as session:
        campaign = Campaign(
            provider="HackerOne", external_id="web-task-test", name="Web Task Test",
            program_url="https://hackerone.com/web-task-test",
            scope_assets=[{"identifier": "https://example.test/", "type": "URL"}],
            policy_text="Approved GET checks.", scope_complete=True, scope_approved=True,
        )
        session.add(campaign)
        await session.flush()
        web_run = CampaignWebRun(
            campaign_id=campaign.id,
            target_url="https://example.test/",
            selected_plugins=["security-headers", "parameter-reflection"],
            parameters=["q"],
        )
        session.add(web_run)
        await session.commit()
        await session.refresh(web_run)
        run_id = web_run.id

    seen: list[tuple[str, dict]] = []

    class FakePlugin:
        def __init__(self, key: str) -> None:
            self.key = key

        async def scan(self, *, base_url, options, log):
            seen.append((base_url, options))
            await log("INFO", "checked")
            return []

    monkeypatch.setattr(tasks, "get_plugin", lambda key: FakePlugin(key))
    await tasks._run_campaign_web_scan(run_id)

    async with SessionLocal() as session:
        result = await session.get(CampaignWebRun, run_id)
        assert result is not None
        assert result.status == JobStatus.completed.value
        assert result.findings == []
    assert len(seen) == 2
    assert seen[0][1]["approved_hosts"] == ["example.test"]
    assert seen[1][1]["parameters"] == ["q"]


async def test_source_worker_rejects_withdrawn_scope_and_records_failure(client) -> None:
    async with SessionLocal() as session:
        campaign = Campaign(
            provider="HackerOne", external_id="source-task-test", name="Source Task Test",
            program_url="https://hackerone.com/source-task-test",
            scope_assets=[], policy_text="", scope_complete=True, scope_approved=False,
        )
        session.add(campaign)
        await session.flush()
        source_run = SourceRun(
            campaign_id=campaign.id,
            repository_url="https://github.com/example/project.git",
            commit_sha="a" * 40,
        )
        session.add(source_run)
        await session.commit()
        await session.refresh(source_run)
        run_id = source_run.id

    await tasks._run_source_scan(run_id)

    async with SessionLocal() as session:
        result = await session.get(SourceRun, run_id)
        assert result is not None
        assert result.status == JobStatus.failed.value
        assert "approval" in result.error
