from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


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
    parameters: list[str] = Field(min_length=1, max_length=3)


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


class LogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    job_id: int
    level: str
    message: str
    created_at: datetime
