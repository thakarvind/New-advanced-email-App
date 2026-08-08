"""Vercel serverless entry for the Prism Mail backend (FastAPI app).

Vercel has no persistent local Postgres. If no external DATABASE_URL is set in
the dashboard, fall back to a SQLite file in /tmp (ephemeral — data resets on
cold start). For real persistence set DATABASE_URL (e.g. a Neon Postgres URL).
"""
import os

_on_vercel = bool(os.environ.get("VERCEL"))

# Guard 1: DATABASE_URL must be a real DB URL. A bare string (e.g. the app's
# own URL pasted into the dashboard) would crash create_async_engine at import.
_db_url = os.environ.get("DATABASE_URL", "")
if _on_vercel:
    if _db_url.startswith(("postgres://", "postgresql://")):
        _db_url = _db_url.replace("postgresql://", "postgresql+asyncpg://", 1).replace("postgres://", "postgresql+asyncpg://", 1)
        os.environ["DATABASE_URL"] = _db_url
    elif not _db_url.startswith("postgres"):
        os.environ["DATABASE_URL"] = "sqlite+aiosqlite:////tmp/prism.db"

# Guard 2: FRONTEND_ORIGINS must be a JSON list. A plain string (a common
# dashboard mistake) would make pydantic-settings raise at import.
_origins = os.environ.get("FRONTEND_ORIGINS", "")
if _origins and not _origins.strip().startswith("["):
    os.environ["FRONTEND_ORIGINS"] = '["' + _origins.replace('"', '\\"') + '"]'

import asyncio
import sys
from pathlib import Path

try:
    from fastapi import HTTPException
    from fastapi.responses import FileResponse
    from mangum import Mangum
    from app import Base, app as _fastapi, engine
except Exception as exc:
    import traceback
    print(traceback.format_exc(), file=sys.stderr)
    print(f"[prism] FATAL import failure: {exc!r}", file=sys.stderr)

    def handler(event, context):
        """Fallback: surface the import traceback in the HTTP response body."""
        body = "PRISM IMPORT FAILURE\n" + traceback.format_exc()
        return {
            "statusCode": 500,
            "body": body,
            "headers": {"Content-Type": "text/plain; charset=utf-8"},
        }

else:
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
        "vendor/openpgp.min.js",
        "vendor/purify.min.js",
    }

    @_fastapi.get("/{path:path}", include_in_schema=False)
    async def _serve_static(path: str) -> FileResponse:
        if path in _ALLOWED_STATIC and (ROOT / path).is_file():
            return FileResponse(ROOT / path)
        raise HTTPException(status_code=404, detail="Not found")

    handler = Mangum(_fastapi)
