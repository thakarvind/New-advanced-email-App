# Prism Mail

A single-file FastAPI backend with a static HTML/JS frontend for a Gmail-integrated email client with AI-powered classification and clustering.

## Quick Start

### Option A: Docker (recommended)

1. Copy `.env.example` to `.env` and fill in your credentials:
   ```bash
   cp .env.example .env
   ```

2. Build and start all services (backend + Postgres + frontend):
   ```bash
   docker-compose up -d
   ```

3. Open the Control Deck at `http://localhost:8000` and the mail client at `http://localhost:8001/prism.html`.

### Option B: Local dev (no Python install)

1. Copy `.env.example` to `.env` and fill in your credentials.

2. Start the bundled PostgreSQL (2.2 GB portable install):
   ```bash
   pgsql\pgsql\bin\postgres.exe -D pgsql\data
   ```

3. Start the backend (creates tables automatically):
   ```bash
   venv\Scripts\python.exe app.py
   ```

4. Run the frontend server (starts backend + serves prism.html on :8001):
   ```bash
   node server.js
   ```

5. Open `http://localhost:8001/prism.html` and connect Gmail.

## Project Structure

```
new email app/
├── app.py                 # FastAPI backend (all routers, models, sync, Gmail, LLM, auth)
├── prism.html             # Mail client UI (static, self-contained)
├── server.js              # Dev launcher — starts FastAPI backend + static frontend on :8001
├── requirements.txt       # Python dependencies
├── .env.example           # Template for environment variables (copy to .env)
├── .gitignore             # Git ignore rules
├── Dockerfile             # Backend container build
├── docker-compose.yml     # Multi-service orchestration (Postgres + backend + frontend)
├── README.md              # This file
├── tests/
│   └── test_oauth.py      # OAuth regression tests
└── venv/                  # Local Python virtualenv (gitignored)
```

## Note: Legacy PostgreSQL runtime

The `pgsql/` folder (1.15 GB) contains a portable PostgreSQL 15 installation
used during local development. It's intentionally kept so you can run the app
without Docker. If you're using docker-compose for the database or connecting
to a remote Postgres, you can delete `pgsql/` entirely — nothing else depends
on it.



## Local Setup

1. Copy `.env.example` to `.env` and fill in your credentials:
   ```bash
   cp .env.example .env
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Start PostgreSQL and ensure the `prism` database exists:
   ```bash
   createdb prism
   ```

4. Run the backend:
   ```bash
   python app.py
   ```

5. Serve the frontend on port 8001 (separate from the backend on 8000):
   ```bash
   # Using Python's built-in server for testing:
   cd /path/to/prism.html
   python -m http.server 8001
   ```

6. Open the Control Deck at `http://localhost:8000` to connect Gmail and manage sync.

## Docker Deployment

1. Build and start all services:
   ```bash
   docker-compose up -d
   ```

2. The backend runs on `http://localhost:8000` and the frontend on `http://localhost:8001`.

3. View logs:
   ```bash
   docker-compose logs -f backend
   ```

4. Stop:
   ```bash
   docker-compose down
   ```

## Configuration

Key environment variables in `.env`:

| Variable | Description | Default |
|---|---|---|
| `APP_BASE_URL` | Backend URL | `http://localhost:8000` |
| `FRONTEND_ORIGINS` | Allowed CORS origins | `["http://localhost:8000","http://localhost:8001"]` |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+asyncpg://prism:prism@localhost:5432/prism` |
| `AUTH_JWT_SECRET` | JWT signing key | `change-me-to-a-long-random-string` |
| `GMAIL_CLIENT_ID` | Gmail OAuth client ID | *(empty)* |
| `GMAIL_CLIENT_SECRET` | Gmail OAuth client secret | *(empty)* |
| `LLM_API_KEY` | LLM API key (Anthropic or OpenAI) | *(empty)* |
| `LLM_PROVIDER` | LLM provider (`anthropic` or `openai`) | `anthropic` |
| `TOKEN_ENCRYPTION_KEY` | Fernet key for token encryption | *(empty — no encryption)* |

## API Endpoints

- `GET /` — Control Deck UI
- `GET /healthz` — Health check
- `GET /api/me` — Current account info
- `GET /api/sync` — Sync status
- `POST /api/sync` — Trigger sync
- `GET /api/mail` — List messages
- `GET /api/mail/{id}` — Get message detail
- `POST /api/mail/{id}/archive` — Archive message
- `POST /api/mail/{id}/snooze` — Snooze message
- `POST /api/mail/{id}/star` — Star/unstar message
- `PATCH /api/mail/{id}` — Update message state
- `POST /api/mail/{id}/draft` — Save draft
- `POST /api/mail/send` — Send message
- `POST /api/mail/{id}/reply` — Reply to message
- `POST /api/mail/{id}/ai-reply` — AI-generate reply
- `POST /api/mail/bulk-archive` — Bulk archive
- `POST /api/mail/ai/compose-draft` — AI compose draft
- `GET /api/clusters` — List clusters
- `GET /auth/gmail/start` — Start Gmail OAuth
- `GET /auth/gmail/callback` — Gmail OAuth callback
- `POST /auth/gmail/revoke` — Revoke access

## Known Issues

The following issues exist in the original source files and cannot be resolved without modifying them:

1. **Preview build banner** — `prism.html` contains `PREVIEW BUILD — NO REAL MAIL` text (line 328). Remove before production deployment.
2. **Hardcoded demo data** — The frozen HTML includes 15 demo messages and 5 clusters. Replace with real backend data via the bridge script.
3. **Bridge JS `silent` option** — The bridge script passes `silent: true` to API calls but the `api()` function does not handle this option. It is functionally harmless (all calls have `.catch()` handlers) but is dead code.
4. **`FRONTEND_ORIGINS` with `"null"`** — The original `.env.example` includes `"null"` in origins, which allows `file://` origins. The project `.env` excludes this.
5. **Destructive `recluster`** — The `recluster()` function deletes all clusters before recreating them. Concurrent syncs could cause data loss.
6. **No rate limiting** — The `/api/sync` endpoint has no rate limiting.
7. **No DB health check** — The `/healthz` endpoint does not verify database connectivity.
8. **No email validation** — The `mail_send` endpoint does not validate the `to` field as an email address.
9. **Recursive MIME parsing** — `_body_text()` uses recursion which could hit Python's recursion limit for deeply nested MIME structures.
10. **Fragile JSON extraction** — `classify()` uses regex to extract JSON from LLM responses, which can fail if the LLM output contains braces in other contexts.
11. **Demo-specific fallback drafts** — Fallback reply drafts contain hardcoded "Tuesday at 2pm" references.

## Security Notes

- Replace `AUTH_JWT_SECRET` with a long random string before deployment.
- Replace the database password in `DATABASE_URL` before deployment.
- Set `TOKEN_ENCRYPTION_KEY` to a valid Fernet key for encrypted token storage at rest.
- Remove `"null"` from `FRONTEND_ORIGINS` in production.
- Set `CORS_ALLOW_ALL=false` in production and explicitly list allowed origins.
- Never commit `.env` with real credentials to version control.