-- Prism Security Detective - status log + honeypot tables
-- Run once against the prism database before the first scan.

CREATE TABLE IF NOT EXISTS security_runs (
    run_id          TEXT PRIMARY KEY,
    status          TEXT NOT NULL DEFAULT 'RUNNING',  -- RUNNING | COMPLETED | LEAKS_PERSIST | ESCALATED | STALE
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    emails_scanned  INT DEFAULT 0,
    emails_flagged  INT DEFAULT 0,
    accounts_checked INT DEFAULT 0,
    leaks_found     INT DEFAULT 0,
    leaks_persist   INT DEFAULT 0,
    report          TEXT
);

CREATE TABLE IF NOT EXISTS honeypot_credentials (
    id          SERIAL PRIMARY KEY,
    email       TEXT UNIQUE NOT NULL,
    password    TEXT NOT NULL,
    tag         TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Latest status only (refreshes every new scanner run):
-- SELECT status, started_at, finished_at FROM security_runs ORDER BY started_at DESC LIMIT 1;
