"""Vercel serverless entry for the Prism Mail backend (FastAPI app).

Vercel has no persistent local Postgres. If no external DATABASE_URL is set in
the dashboard, fall back to a SQLite file in /tmp (ephemeral — data resets on
cold start). For real persistence set DATABASE_URL (e.g. a Neon Postgres URL).
"""
import os

_on_vercel = bool(os.environ.get("VERCEL"))
_db_url = os.environ.get("DATABASE_URL", "")
if _on_vercel and (not _db_url or "localhost" in _db_url):
    os.environ["DATABASE_URL"] = "sqlite+aiosqlite:////tmp/prism.db"

import asyncio
import sys
from pathlib import Path

from fastapi import HTTPException
from fastapi.responses import FileResponse
from mangum import Mangum

from app import Base, app, engine

# Vercel does not run FastAPI lifespan events, so tables are created here at
# cold start instead of in the lifespan handler. A DB failure must NOT crash
# the function: the API stays up and /healthz reports db:false.
async def _create_tables() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

try:
    asyncio.run(_create_tables())
    print("[prism] cold start: tables ready", file=sys.stderr)
except Exception as exc:
    print(f"[prism] cold start: table creation FAILED — {exc!r}", file=sys.stderr)

print(f"[prism] cold start: vercel={os.environ.get('VERCEL')!r} db={_db_url[:60]!r}", file=sys.stderr)

# Serve the frontend and its assets from the function. Only whitelisted files
# are exposed — never the whole project root (.env etc. stays private).
ROOT = Path(__file__).resolve().parent
_ALLOWED_STATIC = {
    "prism.html",
    "boot-splash.png",
    "boot-logo.jpg",
    "splash.mp4",
    "app icon neon.jpg",
    "Screenshot 2026-08-02 213509 borderless.png",
    "Screenshot 2026-08-02 213509.png",
}


@app.get("/{path:path}", include_in_schema=False)
async def _serve_static(path: str) -> FileResponse:
    if path in _ALLOWED_STATIC and (ROOT / path).is_file():
        return FileResponse(ROOT / path)
    raise HTTPException(status_code=404, detail="Not found")


handler = Mangum(app)
