from datetime import datetime, timedelta, timezone

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
    assert logs.status_code == 200 and logs.json()[0]["message"] == "test log"
    assert findings.status_code == 200 and findings.json()[0]["title"] == "Reflected marker"
    assert "test log" in events.text and "event: done" in events.text


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
