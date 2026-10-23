from httpx import AsyncClient
from sqlalchemy import text

from app.core.database import engine


async def test_health_and_database_connection(client: AsyncClient) -> None:
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

    # The app lifespan created the schema; also verify a live PostgreSQL connection.
    async with engine.connect() as connection:
        result = await connection.execute(text("SELECT to_regclass('public.targets')"))
        assert result.scalar_one() == "targets"
        assert (await connection.execute(text("SELECT 1"))).scalar_one() == 1
