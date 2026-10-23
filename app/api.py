import asyncio
import json
from typing import AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.celery_app import celery_app
from app.core.database import SessionLocal, get_db
from app.core.security import require_scope
from app.models import Finding, LogEntry, ScanJob, Target
from app.plugins.registry import get_plugin, list_plugins
from app.schemas import FindingRead, JobCreate, JobRead, LogRead, TargetCreate, TargetRead
from app.tasks import run_scan

router = APIRouter(prefix="/api")


@router.get("/plugins")
async def plugins() -> list[dict[str, str]]:
    return list_plugins()


@router.post("/targets", response_model=TargetRead, status_code=201)
async def create_target(payload: TargetCreate, db: AsyncSession = Depends(get_db)):
    url = require_scope(str(payload.base_url))
    existing = await db.scalar(select(Target).where(Target.base_url == url))
    if existing:
        raise HTTPException(status_code=409, detail="Target URL is already registered")
    target = Target(name=payload.name, base_url=url, scope_authorized=payload.scope_authorized)
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return target


@router.get("/targets", response_model=list[TargetRead])
async def list_targets(db: AsyncSession = Depends(get_db)):
    return list((await db.scalars(select(Target).order_by(Target.id.desc()))).all())


@router.post("/jobs", response_model=JobRead, status_code=202)
async def create_job(payload: JobCreate, db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, payload.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    if not target.scope_authorized:
        raise HTTPException(status_code=403, detail="Target must be explicitly marked as authorized")
    try:
        get_plugin(payload.plugin)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    require_scope(target.base_url)
    job = ScanJob(target_id=target.id, plugin=payload.plugin, options={"parameters": payload.parameters})
    db.add(job)
    await db.commit()
    await db.refresh(job)
    run_scan.delay(job.id)
    return job


@router.get("/jobs", response_model=list[JobRead])
async def list_jobs(db: AsyncSession = Depends(get_db)):
    return list((await db.scalars(select(ScanJob).order_by(ScanJob.id.desc()).limit(100))).all())


@router.get("/jobs/{job_id}", response_model=JobRead)
async def get_job(job_id: int, db: AsyncSession = Depends(get_db)):
    job = await db.get(ScanJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.get("/findings", response_model=list[FindingRead])
async def list_findings(db: AsyncSession = Depends(get_db)):
    return list((await db.scalars(select(Finding).order_by(Finding.created_at.desc()).limit(500))).all())


@router.get("/jobs/{job_id}/logs", response_model=list[LogRead])
async def list_logs(job_id: int, after_id: int = Query(default=0, ge=0), db: AsyncSession = Depends(get_db)):
    if await db.get(ScanJob, job_id) is None:
        raise HTTPException(status_code=404, detail="Job not found")
    rows = await db.scalars(select(LogEntry).where(
        LogEntry.job_id == job_id, LogEntry.id > after_id
    ).order_by(LogEntry.id).limit(500))
    return list(rows.all())


@router.get("/jobs/{job_id}/events")
async def stream_logs(job_id: int, request: Request, after_id: int = Query(default=0, ge=0)):
    async with SessionLocal() as session:
        if await session.get(ScanJob, job_id) is None:
            raise HTTPException(status_code=404, detail="Job not found")

    async def event_stream() -> AsyncIterator[str]:
        try:
            cursor = max(after_id, int(request.headers.get("last-event-id", "0")))
        except ValueError:
            cursor = after_id
        while not await request.is_disconnected():
            async with SessionLocal() as session:
                rows = await session.scalars(select(LogEntry).where(
                    LogEntry.job_id == job_id, LogEntry.id > cursor
                ).order_by(LogEntry.id).limit(100))
                entries = rows.all()
                for entry in entries:
                    cursor = entry.id
                    data = {"id": entry.id, "level": entry.level, "message": entry.message, "created_at": entry.created_at.isoformat()}
                    yield f"id: {entry.id}\ndata: {json.dumps(data)}\n\n"
                job = await session.get(ScanJob, job_id)
                if job is None or (job.status in {"completed", "failed"} and not entries):
                    yield "event: done\ndata: {}\n\n"
                    break
            await asyncio.sleep(1)

    return StreamingResponse(event_stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/workers")
async def worker_status():
    try:
        inspector = celery_app.control.inspect(timeout=1.5)
        workers = await asyncio.to_thread(inspector.ping)
        return {"online": bool(workers), "workers": workers or {}}
    except Exception:
        return {"online": False, "workers": {}}
