from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api import router
from app.core.database import engine
from app.models import Base


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Starter-only schema bootstrap. Use Alembic migrations for production.
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(title="Authorized Audit Dashboard", version="0.1.0", lifespan=lifespan)
app.include_router(router)
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", include_in_schema=False)
async def dashboard():
    return FileResponse(static_dir / "index.html")


@app.get("/health")
async def health():
    return {"status": "ok"}
