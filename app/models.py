import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class JobStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False, unique=True)
    scope_authorized: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    endpoints: Mapped[list["Endpoint"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    jobs: Mapped[list["ScanJob"]] = relationship(back_populates="target", cascade="all, delete-orphan")


class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (UniqueConstraint("target_id", "url_fingerprint", name="uq_endpoint_target_fingerprint"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    url_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    target: Mapped[Target] = relationship(back_populates="endpoints")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    plugin: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default=JobStatus.queued.value, index=True)
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    target: Mapped[Target] = relationship(back_populates="jobs")
    findings: Mapped[list["Finding"]] = relationship(back_populates="job", cascade="all, delete-orphan")
    logs: Mapped[list["LogEntry"]] = relationship(back_populates="job", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("target_id", "fingerprint", name="uq_finding_target_fingerprint"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="info")
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    job: Mapped[ScanJob] = relationship(back_populates="findings")
    target: Mapped[Target] = relationship()

    @property
    def target_name(self) -> str:
        return self.target.name

    @property
    def target_url(self) -> str:
        return self.target.base_url


class LogEntry(Base):
    __tablename__ = "log_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("scan_jobs.id", ondelete="CASCADE"), index=True)
    level: Mapped[str] = mapped_column(String(12), default="INFO")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    job: Mapped[ScanJob] = relationship(back_populates="logs")


class Campaign(Base):
    """A researcher-selected bounty campaign with a snapshot of its published scope."""

    __tablename__ = "campaigns"
    __table_args__ = (UniqueConstraint("provider", "external_id", name="uq_campaign_provider_external_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    external_id: Mapped[str] = mapped_column(String(200), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    program_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    scope_assets: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    policy_text: Mapped[str] = mapped_column(Text, default="", nullable=False)
    scope_complete: Mapped[bool] = mapped_column(default=False, nullable=False)
    scope_approved: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SourceRun(Base):
    """Static analysis run against one in-scope repository commit."""

    __tablename__ = "source_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), index=True)
    repository_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    commit_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default=JobStatus.queued.value, index=True)
    selected_programs: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    files_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CampaignWebRun(Base):
    """Bounded HTTP checks dispatched from one approved campaign asset."""

    __tablename__ = "campaign_web_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), index=True)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    parameters: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    selected_plugins: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default=JobStatus.queued.value, index=True)
    findings: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CampaignAgentRun(Base):
    """Two bounded AI agents planned for one approved campaign."""

    __tablename__ = "campaign_agent_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("campaigns.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(24), default=JobStatus.queued.value, index=True)
    campaign_agent_status: Mapped[str] = mapped_column(String(24), default=JobStatus.queued.value)
    source_agent_status: Mapped[str] = mapped_column(String(24), default=JobStatus.queued.value)
    policy_text: Mapped[str] = mapped_column(Text, nullable=False)
    scope_assets: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    campaign_plan: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    source_plan: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    web_run_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    repository_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    selected_programs: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    files_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    source_findings: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    ai_source_reviews: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
