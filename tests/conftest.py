import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete

from app.core.database import SessionLocal
from app.main import app
from app.models import Endpoint, Finding, LogEntry, ScanJob, Target


@pytest_asyncio.fixture
async def client():
    async with app.router.lifespan_context(app):
        async with SessionLocal() as session:
            for model in (LogEntry, Finding, Endpoint, ScanJob, Target):
                await session.execute(delete(model))
            await session.commit()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as test_client:
            yield test_client
