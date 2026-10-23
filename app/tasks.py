import asyncio
from datetime import datetime, timedelta, timezone
import hashlib

from sqlalchemy import delete, select

from app.core.celery_app import celery_app
from app.core.config import settings
from app.core.database import SessionLocal
from app.models import Endpoint, Finding, JobStatus, LogEntry, ScanJob, Target
from app.plugins.registry import get_plugin


async def _run_scan(job_id: int) -> None:
    async with SessionLocal() as session:
        job = await session.get(ScanJob, job_id)
        if job is None:
            return
        job.status = JobStatus.running.value
        await session.commit()

        async def log(level: str, message: str) -> None:
            session.add(LogEntry(job_id=job_id, level=level, message=message[:1000]))
            await session.commit()

        try:
            target = await session.get(Target, job.target_id)
            if target is None or not target.scope_authorized:
                raise ValueError("Target is missing or not marked as authorized")
            plugin = get_plugin(job.plugin)
            await log("INFO", f"Starting plugin '{plugin.key}' for target #{target.id}")
            findings = await plugin.scan(base_url=target.base_url, options=job.options, log=log)
            for item in findings:
                url_hash = hashlib.sha256(item.endpoint_url.encode()).hexdigest()
                existing_endpoint = await session.scalar(select(Endpoint).where(
                    Endpoint.target_id == target.id,
                    Endpoint.url_fingerprint == url_hash,
                ))
                if existing_endpoint is None:
                    session.add(Endpoint(target_id=target.id, url=item.endpoint_url, url_fingerprint=url_hash))
                existing_finding = await session.scalar(select(Finding).where(
                    Finding.target_id == target.id,
                    Finding.fingerprint == item.fingerprint,
                ))
                if existing_finding is None:
                    session.add(Finding(
                        target_id=target.id,
                        job_id=job.id,
                        title=item.title,
                        severity=item.severity,
                        fingerprint=item.fingerprint,
                        evidence=item.evidence,
                    ))
            job.status = JobStatus.completed.value
            job.finished_at = datetime.now(timezone.utc)
            await session.commit()
            await log("INFO", f"Completed. New findings: {len(findings)}")
        except Exception as exc:
            job.status = JobStatus.failed.value
            job.finished_at = datetime.now(timezone.utc)
            await session.commit()
            await log("ERROR", f"Job failed: {type(exc).__name__}: {str(exc)[:300]}")


@celery_app.task(name="app.tasks.run_scan")
def run_scan(job_id: int) -> None:
    asyncio.run(_run_scan(job_id))


@celery_app.task(name="app.tasks.cleanup_retained_data")
def cleanup_retained_data() -> dict[str, int]:
    return asyncio.run(_cleanup_retained_data())


async def _cleanup_retained_data() -> dict[str, int]:
    now = datetime.now(timezone.utc)
    async with SessionLocal() as session:
        logs_result = await session.execute(delete(LogEntry).where(
            LogEntry.created_at < now - timedelta(days=settings.log_retention_days)
        ))
        jobs_result = await session.execute(delete(ScanJob).where(
            ScanJob.status.in_([JobStatus.completed.value, JobStatus.failed.value]),
            ScanJob.finished_at < now - timedelta(days=settings.job_retention_days),
        ))
        await session.commit()
        return {"logs_deleted": logs_result.rowcount or 0, "jobs_deleted": jobs_result.rowcount or 0}
