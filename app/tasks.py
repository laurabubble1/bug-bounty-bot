import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import re
from urllib.parse import urlsplit

from sqlalchemy import delete, select

from app.core.celery_app import celery_app
from app.core.config import settings
from app.core.database import SessionLocal
from app.campaign_agents import plan_campaign_agents, review_source_candidates
from app.campaign_scope import policy_forbids_remote_app_testing, repository_matches_policy, validate_campaign_web_url
from app.models import Campaign, CampaignWebRun, Endpoint, Finding, JobStatus, LogEntry, ScanJob, SourceRun, Target
from app.models import CampaignAgentRun
from app.plugins.registry import get_plugin, list_plugins
from app.source_analysis import repository_matches_scope, run_source_programs, run_source_programs_with_context, resolve_default_commit, validate_repository_url


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


async def _run_source_scan(run_id: int) -> None:
    async with SessionLocal() as session:
        run = await session.get(SourceRun, run_id)
        if run is None:
            return
        run.status = JobStatus.running.value
        await session.commit()
        try:
            campaign = await session.get(Campaign, run.campaign_id)
            if campaign is None or not campaign.scope_approved:
                raise ValueError("Campaign scope approval is missing or has been withdrawn")
            repository_url = validate_repository_url(run.repository_url)
            if not repository_matches_scope(repository_url, campaign.scope_assets):
                raise ValueError("Repository is no longer present in the approved source-code scope")
            selected, findings, file_count = await asyncio.to_thread(
                run_source_programs, repository_url, run.commit_sha
            )
            run.selected_programs = selected
            run.files_scanned = file_count
            run.findings = findings
            run.status = JobStatus.completed.value
            run.error = None
            run.finished_at = datetime.now(timezone.utc)
            await session.commit()
        except Exception as exc:
            run.status = JobStatus.failed.value
            run.error = f"{type(exc).__name__}: {str(exc)[:500]}"
            run.finished_at = datetime.now(timezone.utc)
            await session.commit()


@celery_app.task(name="app.tasks.run_source_scan", queue="source")
def run_source_scan(run_id: int) -> None:
    asyncio.run(_run_source_scan(run_id))


async def _run_campaign_web_scan(run_id: int) -> None:
    async with SessionLocal() as session:
        run = await session.get(CampaignWebRun, run_id)
        if run is None:
            return
        run.status = JobStatus.running.value
        agent_run = await session.scalar(select(CampaignAgentRun).where(CampaignAgentRun.web_run_id == run_id))
        if agent_run is not None:
            agent_run.campaign_agent_status = JobStatus.running.value
        await session.commit()
        try:
            campaign = await session.get(Campaign, run.campaign_id)
            if campaign is None or not campaign.scope_approved:
                raise ValueError("Campaign scope approval is missing or has been withdrawn")
            target_url = validate_campaign_web_url(run.target_url, campaign.scope_assets)
            approved_host = urlsplit(target_url).hostname
            if not approved_host:
                raise ValueError("Target host is missing")

            async def log(_level: str, _message: str) -> None:
                return None

            findings: list[dict] = []
            for key in run.selected_plugins:
                plugin = get_plugin(key)
                options = {"approved_hosts": [approved_host]}
                if key == "parameter-reflection":
                    options["parameters"] = run.parameters
                results = await plugin.scan(base_url=target_url, options=options, log=log)
                findings.extend({
                    "program": key,
                    "title": item.title,
                    "severity": item.severity,
                    "evidence": item.evidence,
                    "endpoint_url": item.endpoint_url,
                } for item in results)
            run.findings = findings
            run.error = None
            run.status = JobStatus.completed.value
            run.finished_at = datetime.now(timezone.utc)
            if agent_run is not None:
                agent_run.campaign_agent_status = JobStatus.completed.value
            await session.commit()
        except Exception as exc:
            run.error = f"{type(exc).__name__}: {str(exc)[:500]}"
            run.status = JobStatus.failed.value
            run.finished_at = datetime.now(timezone.utc)
            if agent_run is not None:
                agent_run.campaign_agent_status = JobStatus.failed.value
                agent_run.error = (agent_run.error + " | " if agent_run.error else "") + f"App checks: {type(exc).__name__}: {str(exc)[:300]}"
            await session.commit()


@celery_app.task(name="app.tasks.run_campaign_web_scan")
def run_campaign_web_scan(run_id: int) -> None:
    asyncio.run(_run_campaign_web_scan(run_id))


async def _run_campaign_agents(agent_run_id: int) -> None:
    async with SessionLocal() as session:
        run = await session.get(CampaignAgentRun, agent_run_id)
        if run is None:
            return
        run.status = JobStatus.running.value
        await session.commit()

        try:
            campaign = await session.get(Campaign, run.campaign_id)
            if campaign is None or not campaign.scope_approved or not campaign.scope_complete:
                raise ValueError("Campaign scope approval is missing or has been withdrawn")
            if campaign.scope_assets != run.scope_assets or campaign.policy_text != run.policy_text:
                raise ValueError("Campaign scope or policy changed after this agent run was queued")
            plan = await plan_campaign_agents(
                campaign_name=campaign.name,
                program_url=campaign.program_url,
                policy_text=run.policy_text,
                scope_assets=run.scope_assets,
                plugin_catalog=list_plugins(),
            )
            run.summary = str(plan.get("summary", ""))[:2000]
            run.campaign_plan = {
                "action": plan.get("app_action", "skip"),
                "reason": str(plan.get("app_reason", ""))[:2000],
                "target_url": plan.get("target_url"),
                "plugins": plan.get("plugins", []),
                "parameters": plan.get("parameters", []),
            }
            run.source_plan = {
                "action": plan.get("source_action", "skip"),
                "reason": str(plan.get("source_reason", ""))[:2000],
                "repository_url": plan.get("repository_url"),
            }
            await session.commit()

            if plan.get("app_action") == "run" and not policy_forbids_remote_app_testing(run.policy_text):
                try:
                    # Check current approval again immediately before dispatching any network checks.
                    await session.refresh(campaign)
                    if not campaign.scope_approved or campaign.scope_assets != run.scope_assets or campaign.policy_text != run.policy_text:
                        raise ValueError("Campaign approval or scope changed before app checks could be queued")
                    target_url = validate_campaign_web_url(str(plan.get("target_url") or ""), run.scope_assets)
                    available = {item["key"] for item in list_plugins()}
                    requested = plan.get("plugins")
                    if not isinstance(requested, list):
                        requested = []
                    selected_plugins = [key for key in dict.fromkeys(requested) if key in available][:2]
                    if not selected_plugins:
                        raise ValueError("The campaign agent did not select an available bounded check")
                    parameters = plan.get("parameters")
                    if not isinstance(parameters, list):
                        parameters = []
                    # Parameterized checks require explicit names in the approved policy or asset instructions.
                    approved_text = " ".join([
                        run.policy_text,
                        *(str(asset.get("instruction", "")) for asset in run.scope_assets),
                    ])
                    safe_parameters = [
                        value for value in dict.fromkeys(parameters)
                        if isinstance(value, str)
                        and len(value) <= 64
                        and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value)
                        and re.search(rf"(?<![A-Za-z0-9_.-]){re.escape(value)}(?![A-Za-z0-9_.-])", approved_text)
                    ][:3]
                    if "parameter-reflection" in selected_plugins and not safe_parameters:
                        selected_plugins.remove("parameter-reflection")
                    if "security-headers" not in selected_plugins and "parameter-reflection" not in selected_plugins:
                        selected_plugins = ["security-headers"]
                    web_run = CampaignWebRun(
                        campaign_id=campaign.id,
                        target_url=target_url,
                        parameters=safe_parameters,
                        selected_plugins=selected_plugins,
                    )
                    session.add(web_run)
                    await session.flush()
                    run.web_run_id = web_run.id
                    run.campaign_agent_status = "queued"
                    await session.commit()
                    run_campaign_web_scan.delay(web_run.id)
                except Exception as exc:
                    run.campaign_agent_status = JobStatus.failed.value
                    run.error = f"App agent: {type(exc).__name__}: {str(exc)[:300]}"
                    await session.commit()
            else:
                run.campaign_agent_status = "skipped"
                if policy_forbids_remote_app_testing(run.policy_text):
                    run.campaign_plan = {
                        **run.campaign_plan,
                        "reason": "Skipped: campaign policy requires testing only on an installation you own.",
                    }
                await session.commit()

            if plan.get("source_action") == "run":
                run.source_agent_status = JobStatus.running.value
                await session.commit()
                try:
                    # Revalidate the approved snapshot before fetching source.
                    await session.refresh(campaign)
                    if not campaign.scope_approved or campaign.scope_assets != run.scope_assets or campaign.policy_text != run.policy_text:
                        raise ValueError("Campaign approval or scope changed before source review")
                    repository_url = validate_repository_url(str(plan.get("repository_url") or ""))
                    if not repository_matches_scope(repository_url, run.scope_assets) and not repository_matches_policy(repository_url, run.policy_text):
                        raise ValueError("Repository is not explicitly listed in the approved source scope or program policy")
                    commit_sha = await asyncio.to_thread(resolve_default_commit, repository_url)
                    selected, findings, file_count, excerpts = await asyncio.to_thread(
                        run_source_programs_with_context, repository_url, commit_sha
                    )
                    # Do not send source excerpts to the provider after scope approval has been withdrawn.
                    await session.refresh(campaign)
                    if not campaign.scope_approved or campaign.scope_assets != run.scope_assets or campaign.policy_text != run.policy_text:
                        raise ValueError("Campaign approval or scope changed before source excerpts could be reviewed")
                    review = await review_source_candidates(
                        campaign_name=campaign.name,
                        policy_text=run.policy_text,
                        repository_url=repository_url,
                        commit_sha=commit_sha,
                        selected_programs=selected,
                        findings=findings,
                        excerpts=excerpts,
                    )
                    allowed_lines: dict[str, set[int]] = {}
                    for excerpt in excerpts:
                        allowed_lines[str(excerpt.get("path", ""))] = {
                            int(match) for match in re.findall(r"(?m)^(\d+):", str(excerpt.get("lines", "")))
                        }
                    reviews = []
                    for item in review.get("reviews", [])[:20]:
                        path = str(item.get("path", ""))
                        line = item.get("line")
                        if path in allowed_lines and isinstance(line, int) and line in allowed_lines[path]:
                            reviews.append({key: str(value)[:1500] if isinstance(value, str) else value for key, value in item.items()})
                    run.repository_url = repository_url
                    run.commit_sha = commit_sha
                    run.selected_programs = selected
                    run.files_scanned = file_count
                    run.source_findings = findings[:200]
                    run.ai_source_reviews = reviews
                    run.source_plan = {**run.source_plan, "summary": str(review.get("summary", ""))[:2000]}
                    run.source_agent_status = JobStatus.completed.value
                except Exception as exc:
                    run.source_agent_status = JobStatus.failed.value
                    run.error = (run.error + " | " if run.error else "") + f"Source agent: {type(exc).__name__}: {str(exc)[:300]}"
                await session.commit()
            else:
                run.source_agent_status = "skipped"
                await session.commit()

            run.status = "completed_with_errors" if run.error else JobStatus.completed.value
            run.finished_at = datetime.now(timezone.utc)
            await session.commit()
        except Exception as exc:
            run.status = JobStatus.failed.value
            run.campaign_agent_status = JobStatus.failed.value
            run.source_agent_status = JobStatus.failed.value
            run.error = f"{type(exc).__name__}: {str(exc)[:500]}"
            run.finished_at = datetime.now(timezone.utc)
            await session.commit()


@celery_app.task(name="app.tasks.run_campaign_agents", queue="agent")
def run_campaign_agents(agent_run_id: int) -> None:
    asyncio.run(_run_campaign_agents(agent_run_id))
