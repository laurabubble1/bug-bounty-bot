from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql+asyncpg://audit:change-this-local-password@db:5432/audit"
    redis_url: str = "redis://redis:6379/0"
    authorized_hosts: str = "demo-target"
    demo_host: str = "demo-target"
    log_retention_days: int = 14
    job_retention_days: int = 30
    max_requests_per_job: int = 3
    request_timeout_seconds: float = 5.0
    request_interval_seconds: float = 1.0

    @property
    def allowed_hosts(self) -> set[str]:
        return {host.strip().lower().rstrip(".") for host in self.authorized_hosts.split(",") if host.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
