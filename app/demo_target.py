from html import escape

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse

app = FastAPI(title="Isolated Demo Target")


@app.get("/search", response_class=HTMLResponse)
async def search(q: str = Query(default="")):
    # Deliberately reflects input for the local training/demo plugin only.
    return f"<!doctype html><html><body><p>Demo result: {escape(q)}</p></body></html>"
