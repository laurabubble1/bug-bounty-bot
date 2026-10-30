from datetime import datetime
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    base_url: HttpUrl
    scope_authorized: bool = False


class TargetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    base_url: str
    scope_authorized: bool
    created_at: datetime


class JobCreate(BaseModel):
    target_id: int
    plugin: str = "parameter-reflection"
    parameters: list[str] = Field(default_factory=list, max_length=3)


class JobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int
    plugin: str
    status: str
    options: dict
    created_at: datetime
    finished_at: datetime | None


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_id: int
    job_id: int
    title: str
    severity: str
    fingerprint: str
    evidence: str
    created_at: datetime
    target_name: str
    target_url: str


class LogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    job_id: int
    level: str
    message: str
    created_at: datetime


class CampaignCreate(BaseModel):
    provider: str = Field(pattern=r"^HackerOne$")
    external_id: str = Field(min_length=1, max_length=200)
    name: str = Field(min_length=1, max_length=200)
    program_url: HttpUrl
    scope_assets: list[dict[str, Any]] = Field(max_length=500)
    policy_text: str = Field(default="", max_length=30000)
    scope_complete: bool = False


class CampaignRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    provider: str
    external_id: str
    name: str
    program_url: str
    scope_assets: list[dict[str, Any]]
    policy_text: str
    scope_complete: bool
    scope_approved: bool
    created_at: datetime


class CampaignScopeRefresh(BaseModel):
    scope_assets: list[dict[str, Any]] = Field(max_length=500)
    policy_text: str = Field(default="", max_length=30000)
    scope_complete: bool = False


class CampaignAgentRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    campaign_id: int
    status: str
    campaign_agent_status: str
    source_agent_status: str
    campaign_plan: dict[str, Any]
    source_plan: dict[str, Any]
    web_run_id: int | None
    repository_url: str | None
    commit_sha: str | None
    selected_programs: list[str]
    files_scanned: int
    source_findings: list[dict[str, Any]]
    ai_source_reviews: list[dict[str, Any]]
    summary: str
    error: str | None
    created_at: datetime
    finished_at: datetime | None


class SourceRunCreate(BaseModel):
    repository_url: HttpUrl
    commit_sha: str = Field(pattern=r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")


class SourceRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    campaign_id: int
    repository_url: str
    commit_sha: str
    status: str
    selected_programs: list[str]
    files_scanned: int
    findings: list[dict[str, Any]]
    error: str | None
    created_at: datetime
    finished_at: datetime | None


class CampaignWebRunCreate(BaseModel):
    target_url: HttpUrl
    parameters: list[str] = Field(default_factory=list, max_length=3)

    @field_validator("parameters")
    @classmethod
    def check_parameter_names(cls, value: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name) for name in value):
            raise ValueError("Parameter names must match [A-Za-z0-9_.-], max 64 characters")
        return list(dict.fromkeys(value))


class CampaignWebRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    campaign_id: int
    target_url: str
    parameters: list[str]
    selected_plugins: list[str]
    status: str
    findings: list[dict[str, Any]]
    error: str | None
    created_at: datetime
    finished_at: datetime | None
