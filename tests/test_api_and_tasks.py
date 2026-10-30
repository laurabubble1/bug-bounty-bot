from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app import api, tasks
from app.core.config import settings
from app.core.database import SessionLocal
from app.models import Endpoint, Finding, JobStatus, LogEntry, ScanJob, Target
from app.plugins.base import PluginFinding


async def test_api_scope_jobs_findings_and_sse(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(api.run_scan, "delay", lambda _job_id: None)
    pending_response = await client.post("/api/targets", json={
        "name": "Pending scope",
        "base_url": "http://demo-target:8080/pending",
        "scope_authorized": False,
    })
    assert pending_response.status_code == 201
    pending_id = pending_response.json()["id"]
    blocked = await client.post("/api/jobs", json={"target_id": pending_id, "parameters": ["q"]})
    assert blocked.status_code == 403

    target_response = await client.post("/api/targets", json={
        "name": "Demo target",
        "base_url": "http://demo-target:8080/search",
        "scope_authorized": True,
    })
    assert target_response.status_code == 201
    target_id = target_response.json()["id"]
    duplicate = await client.post("/api/targets", json={
        "name": "Duplicate",
        "base_url": "http://demo-target:8080/search",
        "scope_authorized": True,
    })
    assert duplicate.status_code == 409
    invalid_scope = await client.post("/api/targets", json={
        "name": "Out of scope",
        "base_url": "https://not-allowed.example/search",
        "scope_authorized": True,
    })
    assert invalid_scope.status_code == 422

    queued = await client.post("/api/jobs", json={"target_id": target_id, "parameters": ["q"]})
    assert queued.status_code == 202
    job_id = queued.json()["id"]
    assert (await client.get(f"/api/jobs/{job_id}")).json()["status"] == "queued"
    assert len((await client.get("/api/jobs")).json()) == 1
    assert len((await client.get("/api/targets")).json()) == 2
    assert (await client.get("/api/plugins")).json()[0]["key"] == "parameter-reflection"

    async with SessionLocal() as session:
        job = await session.get(ScanJob, job_id)
        assert job is not None
        job.status = JobStatus.completed.value
        session.add(LogEntry(job_id=job_id, level="INFO", message="test log"))
        session.add(Finding(
            target_id=target_id,
            job_id=job_id,
            title="Reflected marker",
            severity="info",
            fingerprint="a" * 64,
            evidence="manual review required",
        ))
        await session.commit()

    logs = await client.get(f"/api/jobs/{job_id}/logs")
    findings = await client.get("/api/findings")
    events = await client.get(f"/api/jobs/{job_id}/events")
    report = await client.get(f"/api/findings/{findings.json()[0]['id']}/report")
    assert logs.status_code == 200 and logs.json()[0]["message"] == "test log"
    assert findings.status_code == 200 and findings.json()[0]["title"] == "Reflected marker"
    assert "test log" in events.text and "event: done" in events.text
    assert report.status_code == 200 and "Unconfirmed security finding" in report.text


async def test_worker_persists_plugin_finding_and_deduplicates(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_response = await client.post("/api/targets", json={
        "name": "Task demo",
        "base_url": "http://demo-target:8080/worker-test",
        "scope_authorized": True,
    })
    target_id = target_response.json()["id"]
    async with SessionLocal() as session:
        job = ScanJob(target_id=target_id, plugin="test-plugin", options={"parameters": ["q"]})
        session.add(job)
        await session.commit()
        await session.refresh(job)
        job_id = job.id

    class FakePlugin:
        key = "test-plugin"

        async def scan(self, *, base_url, options, log):
            await log("INFO", f"fake scan {options['parameters'][0]}")
            return [PluginFinding(
                title="Expected finding",
                severity="info",
                fingerprint="b" * 64,
                evidence="test evidence",
                endpoint_url=base_url,
            )]

    monkeypatch.setattr(tasks, "get_plugin", lambda _key: FakePlugin())
    await tasks._run_scan(job_id)
    await tasks._run_scan(job_id)

    async with SessionLocal() as session:
        job = await session.get(ScanJob, job_id)
        findings = list((await session.scalars(select(Finding))).all())
        endpoints = list((await session.scalars(select(Endpoint))).all())
        assert job is not None and job.status == JobStatus.completed.value
        assert len(findings) == 1
        assert len(endpoints) == 1


async def test_retention_deletes_expired_logs_and_finished_jobs(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = datetime.now(timezone.utc) - timedelta(days=2)
    async with SessionLocal() as session:
        target = Target(name="Retention", base_url="http://demo-target:8080/retention", scope_authorized=True)
        session.add(target)
        await session.flush()
        job = ScanJob(
            target_id=target.id,
            plugin="parameter-reflection",
            status=JobStatus.completed.value,
            options={},
            created_at=old,
            finished_at=old,
        )
        session.add(job)
        await session.flush()
        session.add(LogEntry(job_id=job.id, level="INFO", message="expired", created_at=old))
        await session.commit()

    monkeypatch.setattr(settings, "log_retention_days", 1)
    monkeypatch.setattr(settings, "job_retention_days", 1)
    result = await tasks._cleanup_retained_data()
    assert result["logs_deleted"] == 1
    assert result["jobs_deleted"] == 1


async def test_campaign_scope_approval_and_pinned_source_dispatch(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[list, dict]] = []
    monkeypatch.setattr(api.run_source_scan, "apply_async", lambda *args, **kwargs: calls.append((args, kwargs)))
    payload = {
        "provider": "HackerOne",
        "external_id": "example-program",
        "name": "Example Program",
        "program_url": "https://hackerone.com/example-program",
        "scope_assets": [{"identifier": "github.com/example/repository", "type": "SOURCE_CODE"}],
        "scope_complete": True,
    }
    created = await client.post("/api/campaigns", json=payload)
    assert created.status_code == 201
    campaign_id = created.json()["id"]

    sha = "a" * 40
    blocked = await client.post(f"/api/campaigns/{campaign_id}/source-runs", json={
        "repository_url": "https://github.com/example/repository",
        "commit_sha": sha,
    })
    assert blocked.status_code == 403

    approved = await client.post(f"/api/campaigns/{campaign_id}/approve-scope")
    assert approved.status_code == 200 and approved.json()["scope_approved"] is True
    out_of_scope = await client.post(f"/api/campaigns/{campaign_id}/source-runs", json={
        "repository_url": "https://github.com/other/repository",
        "commit_sha": sha,
    })
    assert out_of_scope.status_code == 403

    queued = await client.post(f"/api/campaigns/{campaign_id}/source-runs", json={
        "repository_url": "https://github.com/example/repository",
        "commit_sha": sha,
    })
    assert queued.status_code == 202
    assert queued.json()["status"] == "queued"
    assert calls and calls[0][1]["queue"] == "source"
    assert (await client.get("/api/source-runs")).json()[0]["id"] == queued.json()["id"]
    source_report = await client.get(f"/api/source-runs/{queued.json()['id']}/report")
    assert source_report.status_code == 200 and "manual review required" in source_report.text


async def test_campaign_web_dispatch_requires_approved_exact_web_scope(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[int] = []
    monkeypatch.setattr(api.run_campaign_web_scan, "delay", lambda run_id: calls.append(run_id))
    created = await client.post("/api/campaigns", json={
        "provider": "HackerOne",
        "external_id": "web-example",
        "name": "Web Example",
        "program_url": "https://hackerone.com/web-example",
        "scope_assets": [{"identifier": "https://example.com/", "type": "URL"}],
        "scope_complete": True,
    })
    campaign_id = created.json()["id"]
    await client.post(f"/api/campaigns/{campaign_id}/approve-scope")

    blocked = await client.post(f"/api/campaigns/{campaign_id}/web-runs", json={
        "target_url": "https://outside.example/",
    })
    assert blocked.status_code == 403

    queued = await client.post(f"/api/campaigns/{campaign_id}/web-runs", json={
        "target_url": "https://example.com/",
        "parameters": ["q"],
    })
    assert queued.status_code == 202
    assert queued.json()["selected_plugins"] == ["security-headers", "parameter-reflection"]
    assert calls == [queued.json()["id"]]
    assert (await client.get("/api/campaign-web-runs")).json()[0]["id"] == queued.json()["id"]
    web_report = await client.get(f"/api/campaign-web-runs/{queued.json()['id']}/report")
    assert web_report.status_code == 200 and "manual review required" in web_report.text


async def test_campaign_agents_require_approved_policy_and_queue_both_reviewers(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(
        api.run_campaign_agents,
        "apply_async",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    created = await client.post("/api/campaigns", json={
        "provider": "HackerOne",
        "external_id": "agent-example",
        "name": "Agent Example",
        "program_url": "https://hackerone.com/agent-example",
        "scope_assets": [{"identifier": "github.com/example/agent-example", "type": "SOURCE_CODE"}],
        "policy_text": "Review this explicitly scoped source repository.",
        "scope_complete": True,
    })
    assert created.status_code == 201
    campaign_id = created.json()["id"]

    blocked = await client.post(f"/api/campaigns/{campaign_id}/agents")
    assert blocked.status_code == 403

    await client.post(f"/api/campaigns/{campaign_id}/approve-scope")
    queued = await client.post(f"/api/campaigns/{campaign_id}/agents")
    assert queued.status_code == 202
    assert queued.json()["status"] == "queued"
    assert calls == [((), {"args": [queued.json()["id"]], "queue": "agent"})]

    report = await client.get(f"/api/campaign-agent-runs/{queued.json()['id']}/report")
    assert report.status_code == 200
    assert "Unconfirmed campaign review candidates" in report.text
    assert "submit manually" in report.text

    refreshed = await client.put(f"/api/campaigns/{campaign_id}/scope", json={
        "scope_assets": created.json()["scope_assets"],
        "policy_text": "Updated policy requires another review.",
        "scope_complete": True,
    })
    assert refreshed.status_code == 200
    assert refreshed.json()["scope_approved"] is False


async def test_program_catalog_opportunity_lookup_and_worker_queue_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_discover(search: str):
        return [{"provider": "HackerOne", "search": search}]

    class Inspector:
        def ping(self):
            return {"worker@example": {"ok": "pong"}}

        def active_queues(self):
            return {"worker@example": [{"name": "agent"}, {"name": "source"}]}

    monkeypatch.setattr(api, "discover_opportunities", fake_discover)
    monkeypatch.setattr(api, "celery_app", SimpleNamespace(
        control=SimpleNamespace(inspect=lambda **_kwargs: Inspector())
    ))

    async def inline_to_thread(function, *args, **kwargs):
        return function(*args, **kwargs)

    monkeypatch.setattr(api.asyncio, "to_thread", inline_to_thread)

    assert (await api.test_programs())["source"]
    assert (await api.plugins())
    assert await api.opportunities("needle") == {"sources": [{"provider": "HackerOne", "search": "needle"}]}
    workers = await api.worker_status()
    assert workers["online"] is True
    assert workers["source_queue_online"] is True
    assert workers["agent_queue_online"] is True
