import asyncio
import json
from typing import AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.celery_app import celery_app
from app.core.database import SessionLocal, get_db
from app.core.security import require_scope
from app.campaign_scope import validate_campaign_web_url
from app.discovery import discover_opportunities
from app.models import Campaign, CampaignAgentRun, CampaignWebRun, Finding, LogEntry, ScanJob, SourceRun, Target
from app.plugins.registry import get_plugin, list_plugins
from app.schemas import (
    CampaignCreate,
    CampaignRead,
    CampaignWebRunCreate,
    CampaignWebRunRead,
    CampaignScopeRefresh,
    CampaignAgentRunRead,
    FindingRead,
    JobCreate,
    JobRead,
    LogRead,
    SourceRunCreate,
    SourceRunRead,
    TargetCreate,
    TargetRead,
)
from app.source_analysis import SOURCE_PROGRAMS, repository_matches_scope, validate_repository_url
from app.tasks import run_campaign_agents, run_campaign_web_scan, run_scan, run_source_scan

router = APIRouter(prefix="/api")


@router.get("/test-programs")
async def test_programs():
    """List reusable checks that the dispatcher can select."""
    return {
        "source": list(SOURCE_PROGRAMS),
        "web": list_plugins(),
        "dispatch_policy": "Source checks are selected from repository file types; approved campaign web runs use the passive check and optionally reflection for declared parameters.",
    }


@router.post("/campaigns", response_model=CampaignRead, status_code=201)
async def create_campaign(payload: CampaignCreate, db: AsyncSession = Depends(get_db)):
    existing = await db.scalar(select(Campaign).where(
        Campaign.provider == payload.provider,
        Campaign.external_id == payload.external_id,
    ))
    if existing:
        raise HTTPException(status_code=409, detail="This campaign is already in your campaign list")
    campaign = Campaign(
        provider=payload.provider,
        external_id=payload.external_id,
        name=payload.name,
        program_url=str(payload.program_url),
        scope_assets=payload.scope_assets,
        policy_text=payload.policy_text,
        scope_complete=payload.scope_complete,
    )
    db.add(campaign)
    await db.commit()
    await db.refresh(campaign)
    return campaign


@router.get("/campaigns", response_model=list[CampaignRead])
async def list_campaigns(db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(Campaign).order_by(Campaign.created_at.desc()).limit(100))
    return list(rows.all())


@router.put("/campaigns/{campaign_id}/scope", response_model=CampaignRead)
async def refresh_campaign_scope(
    campaign_id: int,
    payload: CampaignScopeRefresh,
    db: AsyncSession = Depends(get_db),
):
    campaign = await db.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    campaign.scope_assets = payload.scope_assets
    campaign.policy_text = payload.policy_text
    campaign.scope_complete = payload.scope_complete
    campaign.scope_approved = False
    await db.commit()
    await db.refresh(campaign)
    return campaign


@router.post("/campaigns/{campaign_id}/agents", response_model=CampaignAgentRunRead, status_code=202)
async def create_campaign_agent_run(campaign_id: int, db: AsyncSession = Depends(get_db)):
    campaign = await db.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if not campaign.scope_approved or not campaign.scope_complete:
        raise HTTPException(status_code=403, detail="Review and approve this campaign's complete current scope first")
    if not campaign.policy_text.strip():
        raise HTTPException(status_code=409, detail="Save the current campaign policy before starting its AI agents")
    run = CampaignAgentRun(
        campaign_id=campaign.id,
        policy_text=campaign.policy_text[:30000],
        scope_assets=campaign.scope_assets,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    run_campaign_agents.apply_async(args=[run.id], queue="agent")
    return run


@router.get("/campaign-agent-runs", response_model=list[CampaignAgentRunRead])
async def list_campaign_agent_runs(db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(CampaignAgentRun).order_by(CampaignAgentRun.created_at.desc()).limit(100))
    return list(rows.all())


@router.get("/campaign-agent-runs/{run_id}", response_model=CampaignAgentRunRead)
async def get_campaign_agent_run(run_id: int, db: AsyncSession = Depends(get_db)):
    run = await db.get(CampaignAgentRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Campaign agent run not found")
    return run


@router.get("/campaign-agent-runs/{run_id}/report", response_class=PlainTextResponse)
async def campaign_agent_report_draft(run_id: int, db: AsyncSession = Depends(get_db)):
    run = await db.get(CampaignAgentRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Campaign agent run not found")
    campaign = await db.get(Campaign, run.campaign_id)
    web_run = await db.get(CampaignWebRun, run.web_run_id) if run.web_run_id else None
    lines = [
        "# Unconfirmed campaign review candidates — manual validation required",
        "",
        f"- Campaign: {campaign.name if campaign else 'Unknown'}",
        f"- Program: {campaign.program_url if campaign else 'Unknown'}",
        f"- Agent run: {run.status}",
        f"- Scope assets snapshot: {len(run.scope_assets)} asset(s)",
        f"- App agent: {run.campaign_agent_status} — {run.campaign_plan.get('reason', '')}",
        f"- Source agent: {run.source_agent_status} — {run.source_plan.get('reason', '')}",
        "",
        run.summary,
        "",
    ]
    if web_run is not None:
        lines.extend([f"## App review: {web_run.target_url}", "", f"- Status: {web_run.status}", ""])
        for index, finding in enumerate(web_run.findings, start=1):
            lines.extend([
                f"### {index}. {finding.get('title', 'Review candidate')}",
                f"- Check: {finding.get('program', 'unknown')}",
                f"- Observation: {finding.get('evidence', '')}",
                "",
            ])
    if run.repository_url:
        lines.extend([
            "## Source review",
            "",
            f"- Repository: {run.repository_url}",
            f"- Pinned commit: `{run.commit_sha}`",
            f"- Files scanned: {run.files_scanned}",
            f"- Checks: {', '.join(run.selected_programs)}",
            "",
        ])
        for index, finding in enumerate(run.source_findings, start=1):
            lines.extend([
                f"### Static lead {index}: {finding.get('title', 'Review candidate')}",
                f"- Location: `{finding.get('path', '')}:{finding.get('line', '')}`",
                f"- Observation: {finding.get('evidence', '')}",
                "",
            ])
        for index, review in enumerate(run.ai_source_reviews, start=1):
            lines.extend([
                f"### AI source review {index}: {review.get('title', 'Review candidate')}",
                f"- Location: `{review.get('path', '')}:{review.get('line', '')}`",
                f"- Confidence: {review.get('confidence', 'unknown')}",
                f"- Reasoning: {review.get('reasoning', '')}",
                f"- Potential impact: {review.get('potential_impact', '')}",
                f"- Validation needed: {review.get('validation_needed', '')}",
                "",
            ])
    lines.extend([
        "## Manual validation",
        "These findings are hypotheses, not verified vulnerabilities or bounty-eligibility decisions. Confirm current scope and policy, reproduce safely, assess realistic impact, check for duplicates, remove sensitive data, and submit manually through the program's official channel if appropriate.",
    ])
    return PlainTextResponse(
        "\n".join(lines),
        headers={"Content-Disposition": f'attachment; filename="scopeguard-campaign-run-{run.id}.md"'},
    )


@router.post("/campaigns/{campaign_id}/approve-scope", response_model=CampaignRead)
async def approve_campaign_scope(campaign_id: int, db: AsyncSession = Depends(get_db)):
    campaign = await db.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if not campaign.scope_complete:
        raise HTTPException(status_code=409, detail="The provider returned an incomplete scope list; review the official brief and refresh the campaign before approving it")
    campaign.scope_approved = True
    await db.commit()
    await db.refresh(campaign)
    return campaign


@router.post("/campaigns/{campaign_id}/source-runs", response_model=SourceRunRead, status_code=202)
async def create_source_run(
    campaign_id: int,
    payload: SourceRunCreate,
    db: AsyncSession = Depends(get_db),
):
    campaign = await db.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if not campaign.scope_approved:
        raise HTTPException(status_code=403, detail="Review and approve this campaign's current scope first")
    try:
        repository_url = validate_repository_url(str(payload.repository_url))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not repository_matches_scope(repository_url, campaign.scope_assets):
        raise HTTPException(status_code=403, detail="That exact GitHub repository is not listed as a source-code asset in the approved scope snapshot")
    run = SourceRun(
        campaign_id=campaign.id,
        repository_url=repository_url,
        commit_sha=payload.commit_sha.lower(),
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    run_source_scan.apply_async(args=[run.id], queue="source")
    return run


@router.get("/source-runs", response_model=list[SourceRunRead])
async def list_source_runs(db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(SourceRun).order_by(SourceRun.created_at.desc()).limit(100))
    return list(rows.all())


@router.get("/source-runs/{run_id}/report", response_class=PlainTextResponse)
async def source_report_draft(run_id: int, db: AsyncSession = Depends(get_db)):
    run = await db.get(SourceRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Source run not found")
    campaign = await db.get(Campaign, run.campaign_id)
    lines = [
        "# Unconfirmed source review candidates — manual review required",
        "",
        f"- Campaign: {campaign.name if campaign else 'Unknown'}",
        f"- Program: {campaign.program_url if campaign else 'Unknown'}",
        f"- Repository: {run.repository_url}",
        f"- Pinned commit: `{run.commit_sha}`",
        f"- Run status: {run.status}",
        f"- Files reviewed: {run.files_scanned}",
        "",
        "These automated patterns are leads, not verified vulnerabilities. Reproduce and confirm impact before reporting.",
        "",
    ]
    for index, finding in enumerate(run.findings, start=1):
        lines.extend([
            f"## {index}. {finding.get('title', 'Review candidate')}",
            f"- Severity estimate: {finding.get('severity', 'info')}",
            f"- Test program: {finding.get('program', 'unknown')}",
            f"- Location: `{finding.get('path', '')}:{finding.get('line', '')}`",
            f"- Observation: {finding.get('evidence', '')}",
            "",
        ])
    lines.extend([
        "## Manual validation",
        "Confirm the pinned revision is in scope, reproduce safely, check for duplicates, and remove any sensitive data before submitting through the official program channel.",
    ])
    return PlainTextResponse(
        "\n".join(lines),
        headers={"Content-Disposition": f'attachment; filename="scopeguard-source-run-{run.id}.md"'},
    )


@router.post("/campaigns/{campaign_id}/web-runs", response_model=CampaignWebRunRead, status_code=202)
async def create_campaign_web_run(
    campaign_id: int,
    payload: CampaignWebRunCreate,
    db: AsyncSession = Depends(get_db),
):
    campaign = await db.get(Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if not campaign.scope_approved:
        raise HTTPException(status_code=403, detail="Review and approve this campaign's current scope first")
    try:
        target_url = validate_campaign_web_url(str(payload.target_url), campaign.scope_assets)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    selected_plugins = ["security-headers"]
    if payload.parameters:
        selected_plugins.append("parameter-reflection")
    run = CampaignWebRun(
        campaign_id=campaign.id,
        target_url=target_url,
        parameters=payload.parameters,
        selected_plugins=selected_plugins,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    run_campaign_web_scan.delay(run.id)
    return run


@router.get("/campaign-web-runs", response_model=list[CampaignWebRunRead])
async def list_campaign_web_runs(db: AsyncSession = Depends(get_db)):
    rows = await db.scalars(select(CampaignWebRun).order_by(CampaignWebRun.created_at.desc()).limit(100))
    return list(rows.all())


@router.get("/campaign-web-runs/{run_id}/report", response_class=PlainTextResponse)
async def campaign_web_report_draft(run_id: int, db: AsyncSession = Depends(get_db)):
    run = await db.get(CampaignWebRun, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Campaign web run not found")
    campaign = await db.get(Campaign, run.campaign_id)
    lines = [
        "# Unconfirmed app review candidates — manual review required",
        "",
        f"- Campaign: {campaign.name if campaign else 'Unknown'}",
        f"- Program: {campaign.program_url if campaign else 'Unknown'}",
        f"- Target URL: {run.target_url}",
        f"- Checks selected: {', '.join(run.selected_plugins)}",
        f"- Run status: {run.status}",
        "",
        "The checks are bounded observations, not verified vulnerabilities. Confirm current scope, reproduce safely, and validate impact before reporting.",
        "",
    ]
    for index, finding in enumerate(run.findings, start=1):
        lines.extend([
            f"## {index}. {finding.get('title', 'Review candidate')}",
            f"- Severity estimate: {finding.get('severity', 'info')}",
            f"- Check: {finding.get('program', 'unknown')}",
            f"- URL: `{finding.get('endpoint_url', run.target_url)}`",
            f"- Observation: {finding.get('evidence', '')}",
            "",
        ])
    lines.extend([
        "## Manual validation",
        "Confirm this exact asset and check are allowed by the current brief, reproduce safely, check for duplicate reports, and remove sensitive data before submitting through the official channel.",
    ])
    return PlainTextResponse(
        "\n".join(lines),
        headers={"Content-Disposition": f'attachment; filename="scopeguard-web-run-{run.id}.md"'},
    )


@router.get("/opportunities")
async def opportunities(search: str = Query(default="", max_length=100)):
    """Read provider listings only; candidate assets are never scanned automatically."""
    return {"sources": await discover_opportunities(search.strip())}


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
    if payload.plugin == "parameter-reflection" and not payload.parameters:
        raise HTTPException(status_code=422, detail="Parameter reflection requires at least one declared query parameter")
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
    query = select(Finding).options(selectinload(Finding.target)).order_by(Finding.created_at.desc()).limit(500)
    return list((await db.scalars(query)).all())


@router.get("/findings/{finding_id}/report", response_class=PlainTextResponse)
async def download_report_draft(finding_id: int, db: AsyncSession = Depends(get_db)):
    finding = await db.scalar(
        select(Finding).where(Finding.id == finding_id).options(selectinload(Finding.target))
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    body = f"""# Unconfirmed security finding — manual review required

## Summary
{finding.title}

## Affected project / target
- Program or target: {finding.target.name}
- URL: {finding.target.base_url}
- Finding recorded: {finding.created_at.isoformat()}
- Automated severity estimate: {finding.severity}

## Observation
{finding.evidence}

## Reproduction steps
Write the exact safe steps you used to reproduce this behavior. Include relevant request and response details, with secrets and personal data removed.

## Security impact
Explain the concrete impact you confirmed. Do not infer impact from the automated observation alone.

## Validation before submission
- Confirm this exact asset and test are allowed by the current program policy.
- Reproduce the issue manually and check for duplicate reports.
- Remove credentials, tokens, personal information, and unrelated data.
- Submit through the program's official reporting channel.

This is an unconfirmed draft generated by Scopeguard. It is not a verified vulnerability report.
"""
    return PlainTextResponse(
        body,
        headers={"Content-Disposition": f'attachment; filename="scopeguard-finding-{finding.id}.md"'},
    )


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
        queues = await asyncio.to_thread(inspector.active_queues)
        source_online = any(
            queue.get("name") == "source"
            for worker_queues in (queues or {}).values()
            for queue in worker_queues
        )
        agent_online = any(
            queue.get("name") == "agent"
            for worker_queues in (queues or {}).values()
            for queue in worker_queues
        )
        return {"online": bool(workers), "workers": workers or {}, "source_queue_online": source_online, "agent_queue_online": agent_online}
    except Exception:
        return {"online": False, "workers": {}, "source_queue_online": False, "agent_queue_online": False}
