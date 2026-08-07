"""Prism Mail backend — single-file build.
All routers, models, sync, Gmail, LLM and auth live in this one module.
Tables are auto-created on startup (no Alembic step). Run with: python app.py
"""
from __future__ import annotations
import os
if not os.environ.get("VERCEL"):
    os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")  # local dev: allow OAuth over HTTP
# Vercel-only hardening: a bad DATABASE_URL (e.g. the app's own URL pasted into
# the dashboard) or a plain-string FRONTEND_ORIGINS would crash Settings/engine
# construction at import. This runs no matter which entrypoint Vercel boots.
if os.environ.get("VERCEL"):
    _db = os.environ.get("DATABASE_URL", "")
    if _db.startswith(("postgres://", "postgresql://")):
        _db = _db.replace("postgresql://", "postgresql+asyncpg://", 1).replace("postgres://", "postgresql+asyncpg://", 1)
        os.environ["DATABASE_URL"] = _db
    elif not _db.startswith("postgres"):
        os.environ["DATABASE_URL"] = "sqlite+aiosqlite:////tmp/prism.db"
    _orig = os.environ.get("FRONTEND_ORIGINS", "")
    if _orig and not _orig.strip().startswith("["):
        os.environ["FRONTEND_ORIGINS"] = '["' + _orig.replace('"', '\\"') + '"]'
import asyncio, base64, json, logging, re, time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.utils import formataddr, parseaddr
from typing import List
from urllib.parse import urlparse

import httpx
import jwt
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import (BigInteger, Boolean, Column, DateTime, Float, ForeignKey,
                        Integer, String, Text, UniqueConstraint, delete, func, or_, select, text, update)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base, relationship, selectinload

from google.auth.transport.requests import Request as _GAuthRequest
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

log = logging.getLogger("prism")

# ============================ CONFIG ============================
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")
    app_base_url: str = "http://localhost:8000"
    client_url: str = "http://localhost:8001/prism.html"
    frontend_origins: List[str] = Field(default_factory=lambda: ["http://localhost:8000", "http://localhost:8001"])
    cors_allow_all: bool = False
    latest_version: str = ""          # e.g. "1.4" — leave empty when no update exists
    update_url: str = ""              # where the "Update now" button goes
    database_url: str = "postgresql+asyncpg://prism:prism@localhost:5432/prism"
    auth_jwt_secret: str = "dev-secret-change-me"
    token_encryption_key: str = ""
    gmail_client_id: str = ""
    gmail_client_secret: str = ""
    gmail_redirect_uri: str = ""
    llm_provider: str = "anthropic"
    llm_api_key: str = ""
    llm_model: str = "claude-3-5-sonnet-20240620"
    hibp_api_key: str = ""   # HaveIBeenPwned v3 key — enables real dark-web breach monitoring

    @property
    def parsed_frontend_origins(self) -> List[str]:
        return [o.strip() for o in self.frontend_origins if o.strip()]

    def resolve_gmail_redirect_uri(self, request: Request | None = None) -> str:
        configured = (self.gmail_redirect_uri or "").strip()
        if configured:
            return configured
        if request is not None:
            return str(request.base_url).rstrip("/") + "/auth/gmail/callback"
        return f"{self.app_base_url.rstrip('/')}/auth/gmail/callback"

    def google_client_config(self, request: Request | None = None) -> dict:
        return {"web": {"client_id": self.gmail_client_id, "client_secret": self.gmail_client_secret,
                "redirect_uris": [self.resolve_gmail_redirect_uri(request)],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"}}

settings = Settings()

# ============================ DB ============================
_is_sqlite = settings.database_url.startswith("sqlite")
_connect_args: dict = {"timeout": 30} if _is_sqlite else {}
_db_url = settings.database_url
if not _is_sqlite and "sslmode" in _db_url:
    # asyncpg <0.30 rejects ?sslmode= in the URL (SQLAlchemy passes it as a
    # connect kwarg). Strip it and pass SSL explicitly instead.
    _db_url = _db_url.replace("?sslmode=require", "").replace("&sslmode=require", "").replace("?sslmode=disable", "").replace("&sslmode=disable", "")
    _connect_args["ssl"] = "require"
engine = create_async_engine(_db_url, pool_pre_ping=True, future=True, connect_args=_connect_args)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
Base = declarative_base()

async def get_session() -> AsyncSession:  # type: ignore[misc]
    async with SessionLocal() as session:
        yield session

# ============================ MODELS ============================
class Account(Base):
    __tablename__ = "accounts"
    id = Column(Integer, primary_key=True, autoincrement=True)
    provider = Column(String(16), nullable=False, default="gmail")
    email = Column(String(255), nullable=False, unique=True)
    display_name = Column(String(255), nullable=True)   # for email/password accounts
    password_hash = Column(String(255), nullable=True)  # for email/password accounts
    access_token = Column(Text)
    refresh_token = Column(Text)
    token_expiry = Column(DateTime, nullable=True)
    scopes = Column(String(512))
    created_at = Column(DateTime, server_default=func.now())
    last_sync_at = Column(DateTime, nullable=True)

class Message(Base):
    __tablename__ = "messages"
    __table_args__ = (UniqueConstraint("account_id", "gmail_id", name="uq_message_gmail"),)
    id = Column(Integer, primary_key=True, autoincrement=True)
    account_id = Column(Integer, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    gmail_id = Column(String(64), nullable=False)
    thread_id = Column(String(64))
    message_id_header = Column(String(255))
    from_name = Column(String(255))
    from_addr = Column(String(255))
    to_addr = Column(String(255))
    subject = Column(Text)
    snippet = Column(Text)
    body = Column(Text)
    received_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    folder = Column(String(16), nullable=False, default="inbox", index=True)
    is_read = Column(Boolean, default=False)
    is_starred = Column(Boolean, default=False)
    snoozed_until = Column(DateTime, nullable=True)
    raw_labels = Column(String(255))
    att_count = Column(Integer, default=0)
    att_names = Column(Text)
    list_unsub = Column(String(512), nullable=True)
    classification = relationship("Classification", uselist=False, back_populates="message",
                                  cascade="all, delete-orphan", passive_deletes=True)

class Classification(Base):
    __tablename__ = "classifications"
    message_id = Column(Integer, ForeignKey("messages.id", ondelete="CASCADE"), primary_key=True)
    priority = Column(String(16))
    intent = Column(String(64))
    summary = Column(Text)
    draft_body = Column(Text)
    model = Column(String(64))
    classified_at = Column(DateTime, server_default=func.now())
    message = relationship("Message", back_populates="classification")

class Cluster(Base):
    __tablename__ = "clusters"
    id = Column(Integer, primary_key=True, autoincrement=True)
    account_id = Column(Integer, ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    signature = Column(String(128), index=True)
    summary = Column(Text)
    priority = Column(String(16))
    member_count = Column(Integer, default=0)
    latest_at = Column(DateTime)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

class ClusterMember(Base):
    __tablename__ = "cluster_members"
    cluster_id = Column(Integer, ForeignKey("clusters.id", ondelete="CASCADE"), primary_key=True)
    message_id = Column(BigInteger, ForeignKey("messages.id", ondelete="CASCADE"), primary_key=True)
    score = Column(Float, default=1.0)

class SyncState(Base):
    __tablename__ = "sync_state"
    account_id = Column(Integer, ForeignKey("accounts.id", ondelete="CASCADE"), primary_key=True)
    last_history_id = Column(String(64))
    page_token = Column(String(255))
    mode = Column(String(16))
    status = Column(String(16), default="idle")
    full_sync_completed = Column(Boolean, default=False)
    started_at = Column(DateTime, nullable=True)
    heartbeat_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    fetched = Column(Integer, default=0)
    inserted = Column(Integer, default=0)
    updated = Column(Integer, default=0)
    skipped = Column(Integer, default=0)
    last_error = Column(Text)

class HoneypotState(Base):
    __tablename__ = "honeypot_state"
    id = Column(Integer, primary_key=True, autoincrement=True)
    armed = Column(Boolean, default=False)
    engaged = Column(Boolean, default=False)
    engaged_at = Column(DateTime, nullable=True)
    source = Column(String(32), nullable=True)   # 'manual' | 'bruteforce' | 'auth'
    served = Column(Integer, default=0)

# ============================ CRYPTO ============================
_fernet = None
if settings.token_encryption_key:
    try:
        from cryptography.fernet import Fernet
        _fernet = Fernet(settings.token_encryption_key.encode())
    except Exception:
        _fernet = None

def encrypt(plain):
    if plain is None: return None
    return plain if _fernet is None else _fernet.encrypt(plain.encode()).decode()

def decrypt(token):
    if token is None: return None
    if _fernet is None: return token
    try: return _fernet.decrypt(token.encode()).decode()
    except Exception: return token

# ============================ SERIALIZERS ============================
_BOT_ADDR = re.compile(r"(noreply|no-reply|notifications|alerts|digest|updates|mailer|bounce)", re.I)
_BOT_DOMAINS = {"github.com","vercel.com","aws.amazon.com","linear.app","figma.com","stripe.com","producthunt.com","substack.com","medium.com"}
_WEEKDAYS = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]
_PR_TO_TAG = {"needs_reply":"reply","waiting":"waiting","fyi":"fyi","noise":None}
_CATEGORY = {"CATEGORY_PROMOTIONS":"promotions","CATEGORY_UPDATES":"updates","CATEGORY_SOCIAL":"social","CATEGORY_FORUMS":"updates","CATEGORY_PERSONAL":"primary"}

def _hash_hue(s):
    h = 0
    for ch in (s or "x"): h = (h*31 + ord(ch)) & 0xFFFFFFFF
    return h % 360

def _initials(name, addr):
    base = (name or "").strip()
    if not base and addr: base = addr.split("@")[0]
    parts = [p for p in re.split(r"[\s._-]+", base) if p]
    if not parts: return "?"
    return parts[0][:2].upper() if len(parts) == 1 else (parts[0][0]+parts[1][0]).upper()

def _is_neu(addr, name):
    addr = (addr or "").lower()
    if _BOT_ADDR.search(addr): return True
    domain = addr.split("@")[-1] if "@" in addr else ""
    if domain in _BOT_DOMAINS: return True
    return (name or "").lower() in {"github","vercel","linear","figma","aws","stripe"}

def pretty_domain(addr):
    domain = (addr or "").split("@")[-1].lower() if "@" in (addr or "") else ""
    if not domain: return ""
    parts = domain.split(".")
    name = parts[0] if parts[0] not in {"mail","notifications","team","hello","updates"} else (parts[1] if len(parts) > 1 else parts[0])
    return name.replace("-"," ").title()

def _rel_compact(dt):
    if not dt: return ""
    mins = int((datetime.utcnow()-dt).total_seconds()//60)
    if mins < 1: return "now"
    if mins < 60: return f"{mins}m"
    hrs = mins//60
    if hrs < 24: return f"{hrs}h"
    days = hrs//24
    return f"{days}d" if days < 30 else f"{days//30}mo"

def _time_and_day(dt):
    now = datetime.utcnow(); today = now.date(); d = dt.date()
    if d == today: return dt.strftime("%H:%M"), "Today"
    if d == today - timedelta(days=1): return "Yesterday", "Yesterday"
    wd = _WEEKDAYS[d.weekday()]; return wd, wd

def _depth(m):
    cp = m.classification.priority if m.classification else None
    age = datetime.utcnow() - (m.received_at or datetime.utcnow())
    if not m.is_read and cp == "needs_reply": return 0
    if not m.is_read: return 1
    return 2 if age.total_seconds() < 2*86400 else 3

def _topic(m):
    intent = m.classification.intent if m.classification else None
    nice = {"recruiter":"Interview logistics","interview":"Interview logistics","design":"Design sign-off",
            "invoice":"Billing","receipt":"Billing","newsletter":"Newsletter","github":"Repo activity","personal":"Personal"}
    if intent and intent in nice: return nice[intent]
    head = re.split(r"[—·:]", (m.subject or "").strip())[0].strip().split()[:3]
    return " ".join(head) or "Thread"

def mail_to_frontend(m):
    cls = m.classification
    priority = cls.priority if cls else "fyi"
    pr = _PR_TO_TAG.get(priority, "fyi") or "fyi"
    if priority == "noise": pr = "noise"
    time_s, day_s = _time_and_day(m.received_at or datetime.utcnow())
    name = m.from_name or (m.from_addr.split("@")[0] if m.from_addr else "Unknown")
    cats = [_CATEGORY[l] for l in (m.raw_labels or "").split(",") if l in _CATEGORY]
    return {"id": m.id, "folder": m.folder,
            "from": {"n": name, "ini": _initials(m.from_name, m.from_addr), "h": _hash_hue(m.from_addr or name), "neu": 1 if _is_neu(m.from_addr, name) else 0},
            "co": pretty_domain(m.from_addr), "dom": _host_of(m.from_addr), "tag": _PR_TO_TAG.get(priority),
            "subj": m.subject or "(no subject)", "snip": m.snippet or "", "time": time_s, "day": day_s,
            "unread": 0 if m.is_read else 1, "star": 1 if m.is_starred else 0, "pr": pr, "cluster": None,
            "d": _depth(m), "to": m.to_addr,
            "body": m.body or "",
            "topic": _topic(m), "draft": cls.draft_body if cls else None, "tsum": cls.summary if cls else None,
            "cat": cats[0] if cats else None,
            "ts": int(m.received_at.timestamp() * 1000) if m.received_at else 0,
            "att": m.att_count or 0, "attl": (m.att_names or "").split(",") if m.att_names else None,
            "unsub": bool(m.list_unsub)}

def cluster_to_frontend(c, stack):
    return {"key": f"c{c.id}", "name": c.name, "tag": _PR_TO_TAG.get(c.priority), "count": c.member_count,
            "time": _rel_compact(c.latest_at), "sum": c.summary or f"{c.name} · {c.member_count} messages",
            "stack": [[s["ini"], s["h"], s["neu"], s.get("dom","")] for s in stack[:3]]}

# ============================ LLM ============================
_PRIO = ("needs_reply","waiting","fyi","noise")
_PRIO_HIGH = "needs_reply"; _PRIO_WAIT = "waiting"; _PRIO_LOW = "noise"

def _llm_client():
    if not settings.llm_api_key: return None
    if settings.llm_provider == "openai":
        from openai import OpenAI; return OpenAI(api_key=settings.llm_api_key)
    from anthropic import Anthropic; return Anthropic(api_key=settings.llm_api_key)

def _chat(system, user):
    c = _llm_client()
    if c is None and settings.llm_provider != "gemini": return None
    try:
        if settings.llm_provider == "openai":
            r = c.chat.completions.create(model=settings.llm_model,
                messages=[{"role":"system","content":system},{"role":"user","content":user}], temperature=0.3)
            return r.choices[0].message.content or ""
        if settings.llm_provider == "gemini":
            model = settings.llm_model or "gemini-1.5-flash"
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={settings.llm_api_key}"
            with httpx.Client(timeout=30) as client:
                resp = client.post(url, json={
                    "contents": [{"role": "user", "parts": [{"text": user}]}],
                    "system_instruction": {"parts": [{"text": system}]},
                    "generationConfig": {"temperature": 0.3, "maxOutputTokens": 600}
                })
                resp.raise_for_status()
                data = resp.json()
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                return "".join(p.get("text", "") for p in parts if p.get("text"))
            return None
        r = c.messages.create(model=settings.llm_model, max_tokens=600, system=system,
            messages=[{"role":"user","content":user}], temperature=0.3)
        return "".join(b.text for b in r.content if getattr(b,"type","") == "text")
    except Exception:
        return None

def _clip(s, n=1800):
    s = s or ""; return s if len(s) <= n else s[:n]+" …"

def _try_parse_json(raw):
    """Extract JSON object from raw LLM response using bracket matching, not greedy regex.
    Handles braces inside string literals and escape sequences."""
    if not raw:
        return None
    first = raw.find("{")
    if first == -1:
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(first, len(raw)):
        ch = raw[i]
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(raw[first:i+1])
                except (json.JSONDecodeError, ValueError):
                    return None
    return None

def classify(from_name, from_addr, subject, body):
    # Use heuristic fallback when LLM key is missing; use LLM when available
    if not settings.llm_api_key:
        return _heuristic_classify(from_name, from_addr, subject, body)
    text = _clip(f"From: {from_name} <{from_addr}>\nSubject: {subject}\n\n{body}")
    raw = _chat("You triage email for a busy engineer. Reply with ONLY compact JSON: "
                '{"priority":"needs_reply|waiting|fyi|noise","intent":"short_slug",'
                '"summary":"one plain sentence","draft":"a reply ONLY if priority is needs_reply or waiting, else empty"}',
                text)
    if raw:
        d = _try_parse_json(raw)
        if d and isinstance(d, dict):
            try:
                pr = d.get("priority") if d.get("priority") in _PRIO else _heuristic_priority(from_addr, subject)
                return (pr, d.get("intent") or "", _clip(d.get("summary") or "", 400), d.get("draft") or None)
            except Exception:
                pass
    return _heuristic_classify(from_name, from_addr, subject, body)


def _heuristic_classify(from_name, from_addr, subject, body):
    """Deterministic triage for when LLM API key is not configured."""
    from_addr = (from_addr or "").lower()
    subject = (subject or "").lower()
    body = _clip(body or "", 3000)

    # Priority: recruiter / job offer outreach
    if any(x in from_addr for x in ("linkedin.com", "indeed.", "glassdoor.", "lever.", "greenhouse.")) or \
       any(x in subject for x in ("interview", "role", "offer", "recruiter", "talent", "position available")) or \
       any(x in body for x in ("would you be interested", "are you open", "your profile looks")):
        return _PRIO_HIGH, "recruiter", "Recruiter outreach — likely interview or job opportunity", \
               _recruiter_draft(from_name, subject)

    # Priority: important actionable message
    if any(x in subject for x in ("action required", "action required:", "attention required", "please review",
                                  "urgent", "asap", "deadline", "overdue")) or \
       any(x in body for x in ("action required", "please review", "respond by", "deadline is")):
        return _PRIO_HIGH, "action", "Requires action or review", _generic_draft(from_name, subject)

    # Waiting: expected response from others
    if any(x in from_addr for x in ("mailer-daemon", "bounce", "postmaster", "noreply")) or \
       any(x in subject for x in ("undeliverable", "delivery failed", "bounced", "failed delivery")):
        return _PRIO_WAIT, "bounce", "Delivery failure notification", None

    # Noise: newsletters, marketing, digests
    if any(x in from_addr for x in ("newsletter", "digest", "marketing", "promo", "hubspot", "mailchimp",
                                  "substack", "broadcast", "campaign", "coach", "tracking", "stats")) or \
       any(x in subject for x in ("unsubscribe", "newsletter", "weekly digest", "open it later", "your personalized")):
        return _PRIO_LOW, "newsletter", "Newsletter or marketing email", None

    # FYI: notifications from GitHub, Slack, Vercel, etc.
    if any(x in from_addr for x in ("notifications@", "noreply@", "no-reply@", "support@", "security@")) or \
       any(x in subject for x in ("[github]", "[linear]", "[linear]", "[slack]", "notification", "alert")):
        return _PRIO_LOW, "notification", "Service notification", None

    # Default: FYI
    return _PRIO_LOW, "general", f"Message from {from_name or from_addr}", None


def _heuristic_priority(from_addr, subject):
    """Quick priority heuristic when the LLM classify() fails or key missing."""
    from_addr = (from_addr or "").lower()
    subject = (subject or "").lower()
    if any(x in from_addr for x in ("linkedin", "indeed", "glassdoor", "lever", "greenhouse")) or \
       any(x in subject for x in ("interview", "role", "offer", "recruiter", "onsite", "available", "follow-up", "sign-off", "thoughts?")):
        return "needs_reply"
    if any(x in subject for x in ("waiting", "update", "blocked on")):
        return "waiting"
    if any(x in from_addr for x in ("newsletter", "digest", "marketing", "promo", "noreply", "notifications", "updates@")):
        return "noise"
    return "fyi"


def _recruiter_draft(from_name, subject):
    first = (from_name or "").split()[0] if from_name else "there"
    return f"Hi {first},\n\nThank you for reaching out! I'd be interested in learning more. Could you share the role details and compensation range?\n\nBest regards"


def _generic_draft(from_name, subject):
    first = (from_name or "").split()[0] if from_name else "there"
    return f"Hi {first},\n\nThanks for this. I've noted it down and will action it shortly.\n\nBest regards"

def draft_reply(from_name, subject, body):
    raw = _chat("You write concise warm professional replies in first person as Alex. Return ONLY the reply body.",
                _clip(f"From: {from_name}\nSubject: {subject}\n\n{body}"))
    if raw and raw.strip(): return raw.strip()
    first = (from_name or "there").split()[0]
    return f"Hi {first},\n\nThanks for the note — let me know a couple of time windows that work and I'll confirm.\n\nLooking forward to it,\nAlex"

def draft_compose(to, subject, hint):
    raw = _chat("You draft a new outbound email in first person as Alex. Return ONLY the body, no Subject line.",
                _clip(f"To: {to}\nSubject: {subject}\nUser's intent: {hint}"))
    if raw and raw.strip(): return raw.strip()
    name = (to or "there").split("@")[0].split()[0] or "there"
    return f"Hi {name},\n\nThanks for reaching out — this landed at a good time. Let me take a proper look and get back to you by tomorrow morning.\n\nBest,\nAlex"

def _heuristic_intent(addr, subject):
    s = (subject or "").lower(); a = (addr or "").lower()
    if any(k in s for k in ("interview","onsite","role","recruit")) or "recruit" in a: return "recruiter"
    if any(k in s for k in ("invoice","receipt","paid","statement")): return "invoice"
    if any(k in s for k in ("design","figma","spec","mock")): return "design"
    if "github" in a or "pr #" in s or "merged" in s: return "github"
    if any(k in s for k in ("newsletter","digest","issue #","changelog")): return "newsletter"
    return "general"

def _heuristic_summary(subject, pr):
    if pr == "needs_reply": return f"Action needed on: {(subject or 'this thread').split('—')[0].strip()[:80]}."
    if pr == "waiting": return "Thread is paused on someone else; safe to leave for now."
    if pr == "noise": return "Low-signal broadcast — safe to skim or archive."
    return "Informational — no action required."

def _heuristic_draft(name, pr):
    first = (name or "there").split()[0]
    if pr == "waiting": return f"Hi {first},\n\nJust following up — any update on your end? Happy to jump on a quick call if that's easier.\n\nThanks,\nAlex"
    return f"Hi {first},\n\nThanks for reaching out — let me know a couple of time windows that work and I'll confirm.\n\nLooking forward to it,\nAlex"

# ============================ GMAIL ============================
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.modify","https://www.googleapis.com/auth/gmail.send"]

def _creds(account):
    return Credentials(token=decrypt(account.access_token), refresh_token=decrypt(account.refresh_token),
                       token_uri="https://oauth2.googleapis.com/token",
                       client_id=settings.gmail_client_id, client_secret=settings.gmail_client_secret,
                       scopes=GMAIL_SCOPES)

def _service(account):
    creds = _creds(account)
    if creds.expired and creds.refresh_token:
        try: creds.refresh(_GAuthRequest())
        except Exception as e: log.warning("token refresh failed: %s", e)
    return build("gmail","v1",credentials=creds,cache_discovery=False), creds

async def persist_refreshed(account, creds, db):
    if creds.token: account.access_token = encrypt(creds.token)
    if creds.expiry: account.token_expiry = creds.expiry.replace(tzinfo=None)
    await db.commit()

def _header(msg, name):
    for h in msg.get("payload",{}).get("headers",[]):
        if h["name"].lower() == name.lower(): return h["value"]
    return ""

def _body_extract(payload):
    # Walk MIME parts; prefer text/html, fall back to text/plain; decode base64url
    stack = [payload]
    plain = None
    html = None
    while stack:
        p = stack.pop()
        if not isinstance(p, dict):
            continue
        body = p.get("body", {}) or {}
        data = body.get("data")
        mt = (p.get("mimeType") or "").lower()
        if data:
            decoded = base64.urlsafe_b64decode(data).decode("utf-8", "ignore")
            if mt == "text/plain" and plain is None:
                plain = decoded
            elif mt == "text/html" and html is None:
                html = decoded
        for part in reversed(p.get("parts", []) or []):
            stack.append(part)
    # Prefer html; fall back to plain; return empty string if neither
    html = html or ""
    if html:
        html = _process_email_html(html, payload)
        html = _rewrite_remote_images(html)
    return html or plain or ""


def _process_email_html(html, payload):
    """Strip srcset; rewrite cid: to cid-token URL pattern for the proxy endpoint."""
    if not html:
        return html

    # Extract CID mapping from MIME parts (Content-ID -> attachmentId)
    cid_map = {}
    stack = [payload]
    while stack:
        p = stack.pop()
        if not isinstance(p, dict):
            continue
        headers = p.get("headers", []) or []
        for h in headers:
            if (h.get("name") or "").lower() == "content-id":
                cid = (h.get("value") or "").strip("<>").strip()
                body = p.get("body", {}) or {}
                att_id = body.get("attachmentId")
                if cid and att_id:
                    cid_map[cid] = {"attachmentId": att_id, "mime": (p.get("mimeType") or "image/jpeg").lower()}
        for part in reversed(p.get("parts", []) or []):
            stack.append(part)

    if cid_map:
        # payload['id'] is the Gmail message ID
        gmail_msg_id = str(payload.get('id',''))
        thread_id = str(payload.get('threadId',''))
        def replace_cid(m):
            cid = m.group(1).strip()
            if cid in cid_map:
                att = cid_map[cid]
                return f'/api/mail/proxy-image/{gmail_msg_id}/{att["attachmentId"]}?mime={att["mime"]}'
            return m.group(0)
        html = re.sub(r'src=["\']cid:([^"\']+)["\']', replace_cid, html, flags=re.IGNORECASE)

    # Strip srcset attributes (they often point to tracking proxies that break layout)
    html = re.sub(r'\s+srcset=["\'][^"\']*["\']', '', html, flags=re.IGNORECASE)
    # Strip sizes attribute
    html = re.sub(r'\s+sizes=["\'][^"\']*["\']', '', html, flags=re.IGNORECASE)

    return html


def _rewrite_remote_images(html):
    """Leave remote image URLs untouched — let the browser load them directly (Gmail does the same).
    Only tracking beacons get blocked (the proxy endpoint would return HTML, broken image)."""
    if not html:
        return html
    # Only intercept obvious tracking pixels — they return HTML, not images, so <img> breaks.
    # Everything else (Pinterest, Amazon, newsletters) loads directly from the source.
    _BEACON = re.compile(
        r'src=["\']([^"\']*(?:beacon\.|/track/|/open\?|/click\?|pixel\.|tracker\.|'
        r'mailtrack\.|sidekick\.|bananatag\.)[^"\']*)["\']',
        re.IGNORECASE)
    # 1x1 transparent GIF data URI — replaces tracking pixels so layout is preserved
    _TRANSPARENT = "data:image/gif;base64,R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw=="
    html = _BEACON.sub('src="' + _TRANSPARENT + '"', html)
    return html


def fetch_attachment_data(service, gmail_id, attachment_id):
    """Fetch a single attachment from Gmail API and return base64 data."""
    try:
        att = service.users().messages().attachments().get(
            userId="me", messageId=gmail_id, id=attachment_id
        ).execute()
        data = att.get("data", "")
        if data:
            return base64.urlsafe_b64decode(data)
    except Exception:
        log.warning("Failed to fetch attachment %s for message %s", attachment_id, gmail_id, exc_info=True)
    return None

def _att_count(payload):
    """Count real attachments (skips inline CID images)."""
    n = 0
    stack = [payload]
    while stack:
        p = stack.pop()
        if not isinstance(p, dict): continue
        body = p.get("body", {}) or {}
        if body.get("attachmentId"):
            disp = ""
            for h in (p.get("headers") or []):
                if (h.get("name") or "").lower() == "content-disposition": disp = h.get("value") or ""
            if "inline" not in disp.lower(): n += 1
        stack.extend(p.get("parts") or [])
    return n

def _att_names(payload):
    """Extract non-inline attachment filenames (comma-joined) for payload scanning."""
    names = []
    stack = [payload]
    while stack:
        p = stack.pop()
        if not isinstance(p, dict):
            continue
        body = p.get("body", {}) or {}
        if body.get("attachmentId"):
            disp = ""
            for h in (p.get("headers") or []):
                if (h.get("name") or "").lower() == "content-disposition":
                    disp = h.get("value") or ""
            if "inline" not in disp.lower():
                nm = (p.get("filename") or "").strip()
                if not nm:
                    m = re.search(r'filename="?([^";]+)', disp)
                    if m:
                        nm = m.group(1).strip()
                if nm:
                    names.append(nm)
        stack.extend(p.get("parts") or [])
    return ",".join(names) or None

def parse_message(msg):
    payload = msg.get("payload",{}); frm = _header(msg,"From"); name, addr = parseaddr(frm)
    internal = msg.get("internalDate")
    received = datetime.utcfromtimestamp(int(internal)/1000) if internal else datetime.utcnow()
    return {"gmail_id": msg["id"], "thread_id": msg.get("threadId"), "message_id_header": _header(msg,"Message-ID"),
            "from_name": name or addr.split("@")[0], "from_addr": addr or frm, "to_addr": _header(msg,"To"),
            "subject": _header(msg,"Subject"), "snippet": msg.get("snippet",""), "body": _body_extract(payload),
            "received_at": received, "labels": msg.get("labelIds", []),
            "att_count": _att_count(payload), "att_names": _att_names(payload), "list_unsub": _header(msg, "List-Unsubscribe")}

def folder_from_labels(labels):
    s = set(labels); starred = "STARRED" in s; read = "UNREAD" not in s
    if "TRASH" in s: return "trash", read, starred
    if "SPAM" in s: return "spam", read, starred
    if "SENT" in s: return "sent", read, starred
    if "DRAFT" in s: return "drafts", read, starred
    if "PRISM/Snoozed" in s: return "snoozed", read, starred
    if "INBOX" in s: return "inbox", read, starred
    return "archive", read, starred

def build_service(account): return _service(account)

def get_full_by_service(service, gmail_id):
    return parse_message(service.users().messages().get(userId="me", id=gmail_id, format="full").execute())

def list_messages_page(service, page_token, page_size, q=None):
    kw = {"userId":"me","maxResults":page_size}
    if page_token: kw["pageToken"] = page_token
    if q: kw["q"] = q
    r = service.users().messages().list(**kw).execute(); return r.get("messages",[]) or [], r.get("nextPageToken")

def list_history_page(service, start_history_id, page_token, page_size):
    kw = {"userId":"me","startHistoryId":start_history_id,"historyTypes":["messageAdded","labelAdded","labelRemoved"],"maxResults":page_size}
    if page_token: kw["pageToken"] = page_token
    return service.users().history().list(**kw).execute()

def profile_history_id(service): return service.users().getProfile(userId="me").execute().get("historyId")

async def modify(account, gmail_id, add, remove, db):
    service, creds = _service(account)
    try: await bcall(lambda: service.users().messages().modify(userId="me", id=gmail_id, body={"addLabelIds":add,"removeLabelIds":remove}).execute())
    except Exception as e: log.warning("modify failed for %s: %s", gmail_id, e)
    await persist_refreshed(account, creds, db)

def _ensure_label(service, name):
    try:
        for l in service.users().labels().list(userId="me").execute().get("labels",[]):
            if l["name"].lower() == name.lower(): return l["id"]
        return service.users().labels().create(userId="me", body={"name":name,"labelListVisibility":"labelShow","messageListVisibility":"show"}).execute()["id"]
    except Exception: return None

async def apply_archive(account, gmail_id, db): await modify(account, gmail_id, [], ["INBOX"], db)
async def apply_star(account, gmail_id, starred, db): await modify(account, gmail_id, ["STARRED"] if starred else [], [] if starred else ["STARRED"], db)
async def apply_snooze(account, gmail_id, db):
    service, creds = _service(account); lid = _ensure_label(service, "PRISM/Snoozed")
    try: await bcall(lambda: service.users().messages().modify(userId="me", id=gmail_id, body={"addLabelIds":[lid] if lid else [], "removeLabelIds":["INBOX"]}).execute())
    except Exception as e: log.warning("snooze modify failed: %s", e)
    await persist_refreshed(account, creds, db)

async def send_raw(account, to, subject, body, db, in_reply_to=None, references=None, from_addr=None, sender_name=None, bcc=None):
    msg = MIMEText(body,"plain","utf-8"); msg["To"] = to; msg["Subject"] = subject
    if bcc:
        msg["Bcc"] = bcc.strip()
    disp = (sender_name or "").strip() or account.display_name or ""
    if from_addr:
        disp = disp or from_addr.split("@")[0]
        msg["From"] = formataddr((disp, from_addr))
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = " ".join(filter(None, [references, in_reply_to]))
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    service, creds = _service(account); sent = await bcall(lambda: service.users().messages().send(userId="me", body={"raw":raw}).execute())
    await persist_refreshed(account, creds, db); return sent["id"]

# ============================ AUTH DEPS ============================
_bearer = HTTPBearer(auto_error=False); _ALG = "HS256"

def create_token(account_id):
    return jwt.encode({"sub": str(account_id), "exp": datetime.now(timezone.utc)+timedelta(days=30)}, settings.auth_jwt_secret, algorithm=_ALG)

def _decode(token):
    try: return int(jwt.decode(token, settings.auth_jwt_secret, algorithms=[_ALG])["sub"])
    except Exception: raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")

async def get_current_account(creds: HTTPAuthorizationCredentials | None = Depends(_bearer), db: AsyncSession = Depends(get_session),
                              request: Request = None) -> Account:
    if creds is None: raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing token")
    try:
        uid = _decode(creds.credentials)
    except Exception:
        await _maybe_serve_decoy(db, request)
        raise
    acc = (await db.execute(select(Account).where(Account.id == uid))).scalar_one_or_none()
    if acc is None:
        await _maybe_serve_decoy(db, request)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account not found")
    return acc

# ============================ HONEYPOT / DATA RETENTION ============================
# When armed, suspicious or brute-forcing callers are served a DECOY dataset (fake tokens,
# credentials, files and mail) instead of the real one. Real data is never exposed.
class HoneypotServed(Exception):
    """Raised when an unauthenticated requester must be handed the decoy dataset."""

_HP_AUTH_FAILS: dict[str, list[float]] = {}
_HP_MEM = {"engaged": False}

def _hp_note_fail(ip: str) -> int:
    if not ip: return 0
    now = time.time()
    q = _HP_AUTH_FAILS.setdefault(ip, [])
    q.append(now)
    while q and now - q[0] > 300: q.pop(0)
    return len(q)

_HP_DECOYS = [
    {"name": "access_token.bin", "type": "OAuth token", "size": "1.8 KB",
     "sha256": "decoy-7f81a9c2…", "note": "looks like a live Gmail token — it is a trap"},
    {"name": "credentials_dump.csv", "type": "Credentials", "size": "42 KB",
     "sha256": "decoy-b4d01e77…", "note": "11 fake logins with plausible passwords"},
    {"name": "billing_invoice_2841.pdf", "type": "Invoice", "size": "118 KB",
     "sha256": "decoy-e3fa18d5…", "note": "fake paid invoice to lure data brokers"},
    {"name": "contacts_backup.vcf", "type": "Contacts/PII", "size": "9 KB",
     "sha256": "decoy-90cb55f1…", "note": "synthetic contact list — no real person"},
    {"name": "recovery_keys.txt", "type": "Secrets", "size": "2 KB",
     "sha256": "decoy-5d2e8843…", "note": "decoy 2FA backup keys"},
    {"name": "bank_statement_04.pdf", "type": "Financial", "size": "204 KB",
     "sha256": "decoy-c0ffee00…", "note": "fake statement, zero-balance decoy account"},
]

def _hp_decoy_payload() -> dict:
    return {
        "prism_honeypot_decoy": True,
        "marker": "PRISM-HONEYPOT-DECOY-7f81",
        "account": {"email": "admin@prismmail.io", "alt_email": "billing@prismmail.io",
                    "password": "P@ssw0rd!DECOY-9", "phone": "+1-555-0199", "bank": "0000 1234 5678 9010"},
        "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJERUNPWS1RVUVOWSJ9.7f81decoy",
        "mail": [{"id": 9999001, "from": "payroll@acme-corrupt.local", "subject": "Payroll summary — Q2",
                  "body": "Attached: salaries_decoy.csv (synthetic)"},
                 {"id": 9999002, "from": "security@prismmail.io", "subject": "Session export (decoy)",
                  "body": "This mailbox snapshot is a decoy. Real data was never exposed."}],
        "credentials": [{"service": "amazon", "login": "decoy.admin@prismmail.io", "password": "Dec0y-Az#77"},
                        {"service": "aws", "login": "decoy-root", "password": "Aws#Dec0y-2024"},
                        {"service": "bank", "login": "decoy.user", "password": "B@nk-Dec0y-77"}],
        "files": _HP_DECOYS,
    }

async def _hp_row(db: AsyncSession) -> HoneypotState:
    row = (await db.execute(select(HoneypotState).limit(1))).scalar_one_or_none()
    if row is None:
        row = HoneypotState(armed=False, engaged=False, served=0)
        db.add(row)
        await db.commit()
        await db.refresh(row)
    return row

async def _maybe_serve_decoy(db: AsyncSession, request: Request | None) -> None:
    """On failed auth: record the attempt. If the honeypot is armed and the caller is
    brute-forcing (5+ failed attempts from the same IP in 5 min) or it is already
    engaged, serve the DECOY dataset instead of an error."""
    try:
        row = await _hp_row(db)
        if not row.armed:
            return
        ip = (request.client.host if request and request.client else "")
        fails = _hp_note_fail(ip)
        if not row.engaged and fails < 5:
            return
        if not row.engaged:
            row.engaged = True
            row.engaged_at = datetime.utcnow()
            row.source = "bruteforce" if fails >= 5 else "auth"
        row.served = (row.served or 0) + 1
        _HP_MEM["engaged"] = True
        await db.commit()
        raise HoneypotServed()
    except HoneypotServed:
        raise
    except Exception:
        log.warning("honeypot check failed", exc_info=True)

# ============================ CLUSTERER ============================
def _signature(m):
    if _is_neu(m.from_addr, m.from_name): return ("d:"+pretty_domain(m.from_addr)).lower()
    return ("n:"+(m.from_name or m.from_addr or "unknown")).lower()

_RANK = {"needs_reply":3,"waiting":2,"fyi":1,"noise":0,None:1}
def _max_priority(prios): return (max(prios, key=lambda p: _RANK.get(p,1)) if prios else "fyi") or "fyi"

async def recluster(account_id, db):
    rows = (await db.execute(select(Message).options(selectinload(Message.classification))
            .where(Message.account_id == account_id, Message.folder.in_(["inbox"])))).scalars().all()
    if not rows: return
    groups = {}
    for m in rows: groups.setdefault(_signature(m), []).append(m)
    
    for sig, members in groups.items():
        rep = max(members, key=lambda m: m.received_at or datetime.min)
        name = rep.from_name if not _is_neu(rep.from_addr, rep.from_name) else pretty_domain(rep.from_addr)
        prios = [m.classification.priority for m in members if m.classification and m.classification.priority]
        priority = "needs_reply" if "needs_reply" in prios else ("waiting" if "waiting" in prios else ("noise" if prios and all(p=="noise" for p in prios) else "fyi"))
        latest_at = max((m.received_at for m in members), default=datetime.utcnow())
        member_ids = set(m.id for m in members)
        
        existing = (await db.execute(select(Cluster).where(
            Cluster.account_id == account_id, Cluster.signature == sig))).scalar_one_or_none()
        
        if existing:
            # Update existing cluster
            existing.member_count = len(members)
            existing.latest_at = latest_at
            existing.priority = priority
            existing.name = name or "Conversations"
            if settings.llm_api_key and not existing.summary:
                raw = _chat("Summarize this email cluster in one plain sentence (<=18 words).",
                           f"From: {rep.from_name}\nSubject: {rep.subject}\n{(rep.body or '')[:400]}")
                if raw: existing.summary = raw.strip().strip('"')[:160]
            if not existing.summary:
                existing.summary = f"{name} · {len(members)} message{'s' if len(members)!=1 else ''}"
            # Remove stale members that are no longer in this group
            await db.execute(delete(ClusterMember).where(
                ClusterMember.cluster_id == existing.id,
                ~ClusterMember.message_id.in_(member_ids)))
            await db.flush()
            c = existing
        else:
            # Create new cluster
            summary = None
            if settings.llm_api_key:
                raw = _chat("Summarize this email cluster in one plain sentence (<=18 words).",
                           f"From: {rep.from_name}\nSubject: {rep.subject}\n{(rep.body or '')[:400]}")
                if raw: summary = raw.strip().strip('"')[:160]
            if not summary: summary = f"{name} · {len(members)} message{'s' if len(members)!=1 else ''}"
            c = Cluster(account_id=account_id, name=name or "Conversations", signature=sig,
                        summary=summary, priority=priority, member_count=len(members), latest_at=latest_at)
            db.add(c); await db.flush()
        
        # Add new members
        existing_member_ids = set((await db.execute(select(ClusterMember.message_id).where(
            ClusterMember.cluster_id == c.id))).scalars().all())
        for m in members:
            if m.id not in existing_member_ids:
                db.add(ClusterMember(cluster_id=c.id, message_id=m.id, score=1.0))
    
    # Delete orphaned clusters (no longer match any inbox messages)
    all_sigs = set(groups.keys())
    orphaned = (await db.execute(select(Cluster).where(
        Cluster.account_id == account_id, ~Cluster.signature.in_(all_sigs)))).scalars().all()
    for o in orphaned:
        await db.execute(delete(ClusterMember).where(ClusterMember.cluster_id == o.id))
        await db.delete(o)
    
    await db.commit()

async def cluster_messages(account_id, message_ids, db):
    if not message_ids: return
    msgs = (await db.execute(select(Message).options(selectinload(Message.classification)).where(Message.id.in_(message_ids)))).scalars().all()
    if not msgs: return
    groups = {}
    for m in msgs: groups.setdefault(_signature(m), []).append(m)
    for sig, members in groups.items():
        rep = max(members, key=lambda m: m.received_at or datetime.min)
        name = rep.from_name if not _is_neu(rep.from_addr, rep.from_name) else (pretty_domain(rep.from_addr) or "Conversations")
        cluster = (await db.execute(select(Cluster).where(Cluster.account_id == account_id, Cluster.signature == sig))).scalar_one_or_none()
        if cluster is None:
            cluster = (await db.execute(select(Cluster).where(Cluster.account_id == account_id, Cluster.name == name))).scalar_one_or_none()
            if cluster is not None: cluster.signature = sig
        new_prio = _max_priority([m.classification.priority for m in members if m.classification])
        latest = max((m.received_at for m in members), default=datetime.utcnow())
        if cluster is None:
            summary = (rep.classification.summary if rep.classification and rep.classification.summary else f"{name} · {len(members)} message{'s' if len(members)!=1 else ''}")
            cluster = Cluster(account_id=account_id, name=name, signature=sig, summary=summary, priority=new_prio, member_count=len(members), latest_at=latest)
            db.add(cluster); await db.flush()
        else:
            new_count = 0
            for m in members:
                existing_member = await db.execute(select(ClusterMember).where(
                    ClusterMember.cluster_id == cluster.id, ClusterMember.message_id == m.id))
                if existing_member.scalar_one_or_none() is None:
                    new_count += 1
            cluster.member_count = (cluster.member_count or 0) + new_count
            cluster.latest_at = max(cluster.latest_at or datetime.min, latest)
            if _RANK.get(new_prio,1) > _RANK.get(cluster.priority,1): cluster.priority = new_prio
        for m in members:
            if (await db.execute(select(ClusterMember).where(ClusterMember.cluster_id == cluster.id, ClusterMember.message_id == m.id))).scalar_one_or_none() is None:
                db.add(ClusterMember(cluster_id=cluster.id, message_id=m.id, score=1.0))
    await db.commit()

# ============================ SYNC ============================
PAGE_SIZE = 50; MAX_PAGES = 4; SYNC_LOCK_NS = 0x5052_4953

# In-process asyncio locks for SQLite (one per account_id)
_sync_locks: dict[int, asyncio.Lock] = {}

class GmailAuthError(Exception): pass
class SyncInProgress(Exception):
    def __init__(self, progress): self.progress = progress; super().__init__("sync_in_progress")

def _is_auth_error(e):
    try:
        from google.auth.exceptions import RefreshError, UserRefreshError
        if isinstance(e,(RefreshError,UserRefreshError)): return True
    except Exception: pass
    try:
        from googleapiclient.errors import HttpError
        if isinstance(e,HttpError) and getattr(e,"resp",None) is not None and e.resp.status in (401,403): return True
    except Exception: pass
    return type(e).__name__ in {"InvalidGrantError","RefreshError","UserRefreshError"}

async def bcall(fn, *args, **kwargs):
    try: return await asyncio_to_thread(fn, *args, **kwargs)
    except GmailAuthError: raise
    except Exception as e:
        if _is_auth_error(e): raise GmailAuthError(str(e)) from e
        raise

async def asyncio_to_thread(fn, *args, **kwargs):
    import asyncio
    return await asyncio.to_thread(fn, *args, **kwargs)

async def _get_or_create_ss(db, account_id):
    row = (await db.execute(select(SyncState).where(SyncState.account_id == account_id))).scalar_one_or_none()
    if row is None: row = SyncState(account_id=account_id); db.add(row); await db.flush()
    return row

async def read_status(db, account_id):
    row = (await db.execute(select(SyncState).where(SyncState.account_id == account_id))).scalar_one_or_none()
    if row is None:
        return {"status":"idle","running":False,"mode":None,"fetched":0,"inserted":0,"updated":0,"skipped":0,
                "full_sync_completed":False,"last_history_id":None,"started_at":None,"heartbeat_at":None,"finished_at":None,"last_error":None}
    return {"status":row.status,"running":row.status=="running","mode":row.mode,"fetched":row.fetched,"inserted":row.inserted,
            "updated":row.updated,"skipped":row.skipped,"full_sync_completed":bool(row.full_sync_completed),"last_history_id":row.last_history_id,
            "started_at":row.started_at.isoformat() if row.started_at else None,"heartbeat_at":row.heartbeat_at.isoformat() if row.heartbeat_at else None,
            "finished_at":row.finished_at.isoformat() if row.finished_at else None,"last_error":row.last_error}

@asynccontextmanager
async def acquire_sync_lock(db, account_id):
    """Dialect-aware sync lock: PostgreSQL advisory locks in prod, asyncio.Lock for SQLite dev."""
    if engine.dialect.name == "postgresql":
        got = (await db.execute(
            text("SELECT pg_try_advisory_lock(:ns, :id) AS ok"),
            {"ns": SYNC_LOCK_NS, "id": int(account_id)}
        )).scalar()
        if not got:
            raise SyncInProgress(await read_status(db, account_id))
        try:
            yield
        finally:
            try:
                await db.execute(
                    text("SELECT pg_advisory_unlock(:ns, :id)"),
                    {"ns": SYNC_LOCK_NS, "id": int(account_id)}
                )
            except Exception:
                log.warning("advisory unlock failed for account %s", account_id, exc_info=True)
    else:
        # SQLite / any non-Postgres dialect: use a per-account in-process asyncio.Lock
        lock = _sync_locks.setdefault(int(account_id), asyncio.Lock())
        if lock.locked():
            raise SyncInProgress(await read_status(db, account_id))
        async with lock:
            yield

async def _process_page(db, account, service, events):
    events = [e for e in events if e.get("gmail_id")]
    ids = [e["gmail_id"] for e in events]
    if not ids: return 0,0,0,0,[],False
    existing_rows = (await db.execute(select(Message.id, Message.gmail_id, Message.snippet, Message.body,
                                             Message.folder, Message.is_read, Message.is_starred, Message.att_count)
                     .where(Message.account_id == account.id, Message.gmail_id.in_(ids)))).all()
    existing = {r.gmail_id: r for r in existing_rows}
    new_events = [e for e in events if e["gmail_id"] not in existing]
    exist_events = [e for e in events if e["gmail_id"] in existing]
    fulls = []
    for e in new_events:
        try: fulls.append(await bcall(get_full_by_service, service, e["gmail_id"]))
        except GmailAuthError: raise
        except Exception:
            log.warning("get_full failed for %s; skipping message", e["gmail_id"], exc_info=True)
    classes = [await bcall(classify, f["from_name"], f["from_addr"], f["subject"], f["body"]) for f in fulls]
    new_ids = []
    for f,(pr,intent,summary,draft) in zip(fulls, classes):
        folder,read,star = folder_from_labels(f["labels"])
        m = Message(account_id=account.id, gmail_id=f["gmail_id"], thread_id=f["thread_id"], message_id_header=f["message_id_header"],
                    from_name=f["from_name"], from_addr=f["from_addr"], to_addr=f["to_addr"], subject=f["subject"], snippet=f["snippet"],
                    body=f["body"], received_at=f["received_at"], folder=folder, is_read=read, is_starred=star, raw_labels=",".join(f["labels"] or []),
                    att_count=f.get("att_count", 0), att_names=f.get("att_names"), list_unsub=f.get("list_unsub") or None)
        db.add(m); await db.flush()
        db.add(Classification(message_id=m.id, priority=pr, intent=intent, summary=summary, draft_body=(draft or None), model=settings.llm_model))
        new_ids.append(m.id)
    pg_updated = pg_skipped = 0
    for e in exist_events:
        r = existing[e["gmail_id"]]
        # History events carry labels — re-fetch the full message so folder/read/star stay in sync
        if e.get("labels") is not None or e.get("state_refresh"):
            try:
                full = await bcall(get_full_by_service, service, e["gmail_id"])
                folder, read, star = folder_from_labels(full["labels"])
                updates = {}
                if folder != r.folder or read != r.is_read or star != r.is_starred:
                    updates.update(folder=folder, is_read=read, is_starred=star)
                if full.get("snippet") and full["snippet"] != r.snippet: updates["snippet"] = full["snippet"]
                if full.get("body") and "<" in full["body"] and (r.body is None or "<" not in r.body): updates["body"] = full["body"]
                if full.get("att_count") is not None and full["att_count"] != r.att_count: updates["att_count"] = full["att_count"]
                if full.get("att_names") and full["att_names"] != r.att_names: updates["att_names"] = full["att_names"]
                if full.get("list_unsub"): updates["list_unsub"] = full["list_unsub"]
                if updates:
                    await db.execute(update(Message).where(Message.id == r.id).values(**updates))
                    pg_updated += 1
            except Exception:
                log.warning("label refresh failed for %s", e["gmail_id"], exc_info=True)
            continue
        snip = e.get("snippet")
        # Re-fetch body if it's missing HTML content (stale plain-text sync from before the HTML fix)
        needs_refresh = (not r.snippet or (snip and snip != r.snippet)) or (r.body is None or "<" not in r.body)
        if needs_refresh:
            updates = {}
            if snip and snip != r.snippet: updates["snippet"] = snip
            if r.body is None or "<" not in r.body:
                # Live re-fetch the full body so HTML is extracted
                try:
                    full = await bcall(get_full_by_service, service, e["gmail_id"])
                    if full.get("body") and "<" in full["body"]: updates["body"] = full["body"]
                except Exception: pass
            if updates:
                await db.execute(update(Message).where(Message.id == r.id).values(**updates))
                pg_updated += 1
        else:
            pg_skipped += 1
    await db.commit(); return len(ids), len(new_ids), pg_updated, pg_skipped, new_ids, False

def _history_to_events(resp):
    events = []
    for h in resp.get("history",[]) or []:
        for ma in h.get("messagesAdded",[]) or []:
            m = ma.get("message") or {}; events.append({"gmail_id":m.get("id"),"kind":"add","snippet":m.get("snippet"),"labels":m.get("labelIds")})
        for la in h.get("labelsAdded",[]) or []: events.append({"gmail_id":la.get("messageId"),"kind":"label","snippet":None,"labels":la.get("labelIds")})
        for lr in h.get("labelsRemoved",[]) or []: events.append({"gmail_id":lr.get("messageId"),"kind":"label","snippet":None,"labels":None,"state_refresh":True})
    return events, resp.get("historyId"), resp.get("nextPageToken")

async def _run_incremental(db, account, service, ss):
    f=i=u=s=0; new_ids=[]; hpt=None; head=ss.last_history_id; partial=False
    for _ in range(MAX_PAGES):
        resp = await bcall(list_history_page, service, ss.last_history_id, hpt, PAGE_SIZE)
        events, head, nxt = _history_to_events(resp)
        df,di,du,ds,dn,failed = await _process_page(db, account, service, events)
        f+=df; i+=di; u+=du; s+=ds; new_ids.extend(dn); ss.fetched,ss.inserted,ss.updated,ss.skipped = f,i,u,s; ss.heartbeat_at = datetime.utcnow()
        if failed: await db.commit(); return f,i,u,s,new_ids,None,True
        hpt = nxt; await db.commit()
        if not nxt: break
    return f,i,u,s,new_ids,head,False


async def _run_full(db, account, service, ss):
    f=i=u=s=0; new_ids=[]; page_token=ss.page_token; full_done=False
    for _ in range(MAX_PAGES):
        items, nxt = await bcall(list_messages_page, service, page_token, PAGE_SIZE, q="-in:trash -in:spam")
        events = [{"gmail_id":it["id"],"kind":"add","snippet":None,"labels":None} for it in (items or [])]
        df,di,du,ds,dn,failed = await _process_page(db, account, service, events)
        f+=df; i+=di; u+=du; s+=ds; new_ids.extend(dn); ss.fetched,ss.inserted,ss.updated,ss.skipped = f,i,u,s; ss.heartbeat_at = datetime.utcnow()
        if failed: await db.commit(); return f,i,u,s,new_ids,False,True
        page_token = nxt; ss.page_token = nxt; await db.commit()
        if not nxt: full_done = True; break
    return f,i,u,s,new_ids,full_done,False

async def run_sync(account, db):
    t0 = time.perf_counter(); ss = await _get_or_create_ss(db, account.id)
    ss.status="running"; ss.started_at=ss.heartbeat_at=datetime.utcnow(); ss.finished_at=None
    ss.fetched=ss.inserted=ss.updated=ss.skipped=0; ss.last_error=None; await db.commit()
    do_full = not (ss.full_sync_completed and ss.last_history_id); ss.mode = "full" if do_full else "incremental"; await db.commit()
    fetched=inserted=updated=skipped=0; new_ids=[]; partial=False; err=None; last_head=None; service=None; creds=None
    try:
        service, creds = await bcall(build_service, account)
        if not do_full:
            try:
                f,i,u,s,dn,last_head,p = await _run_incremental(db, account, service, ss)
                fetched+=f; inserted+=i; updated+=u; skipped+=s; new_ids.extend(dn); partial=p
            except GmailAuthError: raise
            except Exception as e:
                from googleapiclient.errors import HttpError
                if isinstance(e,HttpError) and getattr(e,"resp",None) is not None and e.resp.status in (400,404):
                    log.info("historyId stale (%s); falling back to full sync", e.resp.status); do_full=True
                else: partial=True; err=str(e)[:500]
        if do_full and not partial:
            ss.mode="full"; await db.commit()
            f,i,u,s,dn,full_done,p = await _run_full(db, account, service, ss)
            fetched+=f; inserted+=i; updated+=u; skipped+=s; new_ids.extend(dn); partial = partial or p
            if full_done and not partial:
                seed = await bcall(profile_history_id, service)
                if seed: ss.last_history_id = seed
                ss.full_sync_completed = True; ss.page_token = None
        if not partial and last_head and not do_full: ss.last_history_id = last_head
        if new_ids: await cluster_messages(account.id, new_ids, db)
        ss.status = "partial" if partial else "done"
        if partial and err: ss.last_error = err
    except asyncio.CancelledError:
        ss.status = "partial"; ss.last_error = "sync timed out or was cancelled"; await db.commit(); raise
    except GmailAuthError:
        ss.status="failed"; ss.last_error="gmail_auth_expired"; await db.commit(); raise
    except Exception as e:
        log.exception("sync failed"); ss.status="failed"; ss.last_error=str(e)[:500]; partial=True
    finally:
        try: await persist_refreshed(account, creds, db)
        except Exception: log.warning("persist_refreshed failed", exc_info=True)
        ss.heartbeat_at=ss.finished_at=datetime.utcnow(); ss.fetched,ss.inserted,ss.updated,ss.skipped = fetched,inserted,updated,skipped; await db.commit()
    return {"fetched":fetched,"inserted":inserted,"updated":updated,"skipped":skipped,"historyId":ss.last_history_id,
            "duration_ms":int((time.perf_counter()-t0)*1000),"status":ss.status,"mode":ss.mode,"partial":partial,"error":ss.last_error}

# ============================ REQUEST BODIES ============================
class SendIn(BaseModel):
    to: EmailStr; subject: str = ""; body: str = ""; name: str = ""; bcc: str = ""
class ReplyIn(BaseModel):
    body: str
class DraftIn(BaseModel):
    body: str
class StatePatch(BaseModel):
    folder: str | None = None; is_read: bool | None = None; is_starred: bool | None = None
class BulkIn(BaseModel):
    ids: List[int]
class BulkActionIn(BaseModel):
    ids: List[int]; action: str; until: datetime | None = None
class SnoozeIn(BaseModel):
    until: datetime | None = None
class HoneypotArmIn(BaseModel):
    armed: bool = True
class ComposeDraftIn(BaseModel):
    to: str = ""; subject: str = ""; hint: str = ""
class RegisterIn(BaseModel):
    email: EmailStr; password: str; name: str = ""
class LoginIn(BaseModel):
    email: EmailStr; password: str

# ============================ PASSWORD HASHING ============================
import hashlib, secrets as _secrets
_PBKDF2_ITERS = 200_000
def _hash_pw(password: str, salt: str = "") -> str:
    if not salt: salt = _secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _PBKDF2_ITERS).hex()
    return f"pbkdf2${_PBKDF2_ITERS}${salt}${h}"
def _verify_pw(password: str, stored: str) -> bool:
    try:
        method, iters, salt, h = stored.split("$", 3)
        if method == "pbkdf2":
            return h == hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iters)).hex()
        return False
    except Exception:
        pass
    # Backward compatibility: old format was salt$hash (sha256(salt + password))
    try:
        salt, h = stored.split("$", 1)
        return h == hashlib.sha256((salt + password).encode()).hexdigest()
    except Exception:
        return False

# ============================ ROUTER: AUTH ============================
auth_router = APIRouter(prefix="/auth/gmail", tags=["auth"])
account_auth_router = APIRouter(prefix="/auth", tags=["account-auth"])

@account_auth_router.post("/register")
async def register(body: RegisterIn, db: AsyncSession = Depends(get_session)):
    existing = (await db.execute(select(Account).where(Account.email == body.email))).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "An account with this email already exists.")
    if len(body.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters.")
    acc = Account(
        email=body.email,
        provider="email",
        display_name=body.name or body.email.split("@")[0],
        password_hash=_hash_pw(body.password)
    )
    db.add(acc); await db.flush(); await db.commit()
    token = create_token(acc.id)
    return {"token": token, "email": acc.email, "name": acc.display_name, "gmail_connected": False}

@account_auth_router.post("/login")
async def login(body: LoginIn, db: AsyncSession = Depends(get_session)):
    acc = (await db.execute(select(Account).where(Account.email == body.email))).scalar_one_or_none()
    if not acc or not acc.password_hash:
        raise HTTPException(401, "Invalid email or password.")
    if not _verify_pw(body.password, acc.password_hash):
        raise HTTPException(401, "Invalid email or password.")
    # Migrate old-format password hashes (salt$sha256) to pbkdf2 on successful login
    if not acc.password_hash.startswith("pbkdf2$"):
        acc.password_hash = _hash_pw(body.password)
        await db.commit()
    token = create_token(acc.id)
    return {"token": token, "email": acc.email, "name": acc.display_name or acc.email.split("@")[0], "gmail_connected": bool(acc.refresh_token or acc.access_token)}
OAUTH_SCOPES = ["openid","https://www.googleapis.com/auth/gmail.modify","https://www.googleapis.com/auth/gmail.send","https://www.googleapis.com/auth/userinfo.email"]
_STATE_ALG = "HS256"

def _sign_state(redirect): return jwt.encode({"r":redirect,"exp":time.time()+3600}, settings.auth_jwt_secret, algorithm=_STATE_ALG)
def _read_state(state):
    try: return jwt.decode(state, settings.auth_jwt_secret, algorithms=[_STATE_ALG])["r"]
    except Exception: raise HTTPException(400,"Invalid OAuth state")

def _resolve_account_email(creds, userinfo_payload=None):
    id_token = getattr(creds, "id_token", None)
    if isinstance(id_token, dict):
        email = id_token.get("email")
        if email: return email
    if isinstance(id_token, str):
        try:
            payload = jwt.decode(id_token, options={"verify_signature": False, "verify_aud": False, "verify_exp": False})
            email = payload.get("email")
            if email: return email
        except Exception:
            pass
    if isinstance(userinfo_payload, dict):
        email = userinfo_payload.get("email")
        if email: return email
    return None

def _normalize_origin(u: str) -> str:
    """Treat localhost / 127.0.0.1 / [::1] as equivalent so the app works
    regardless of which loopback hostname the browser used to load it."""
    try:
        p = urlparse(u)
        host = (p.hostname or "").lower()
        if host in ("127.0.0.1", "::1", "[::1]"):
            host = "localhost"
        port = p.port or (443 if p.scheme == "https" else 80)
        return f"{p.scheme}://{host}:{port}"
    except Exception:
        return u

def _origin_allowed(redirect, request=None):
    if not redirect: return False
    try: o = urlparse(redirect).scheme+"://"+urlparse(redirect).netloc
    except Exception: return False
    if os.environ.get("VERCEL") and request is not None:
        # same deployment = same origin = always allowed (frontend served by the API)
        if o == str(request.base_url).rstrip("/"): return True
    allowed = settings.parsed_frontend_origins
    if settings.cors_allow_all or "*" in allowed: return True
    no = _normalize_origin(o)
    return (no in [_normalize_origin(a) for a in allowed]
            or o in allowed or redirect in allowed or o == "null")

@auth_router.get("/start")
def auth_start(request: Request, redirect: str = Query(...)):
    from urllib.parse import quote_plus
    if not _origin_allowed(redirect, request): raise HTTPException(400,"redirect origin not allowlisted (FRONTEND_ORIGINS)")
    if not settings.gmail_client_id:
        sep = "&" if "?" in redirect else "?"
        return RedirectResponse(redirect + sep + "error=" + quote_plus("GMAIL_CLIENT_ID is not configured on the backend. Please check the backend .env file."))
    redirect_uri = settings.resolve_gmail_redirect_uri(request)
    flow = Flow.from_client_config(settings.google_client_config(request), scopes=OAUTH_SCOPES); flow.redirect_uri = redirect_uri
    url,_ = flow.authorization_url(access_type="offline", prompt="consent", state=_sign_state(redirect)); return RedirectResponse(url)

@auth_router.get("/callback")
async def auth_callback(request: Request, db: AsyncSession = Depends(get_session)):
    from urllib.parse import quote_plus
    state = request.query_params.get("state") or ""; redirect = _read_state(state) if state else ""
    if request.query_params.get("error") or not _origin_allowed(redirect, request):
        log.warning("oauth callback rejected: err=%r state_len=%d redirect=%r", request.query_params.get("error"), len(state), redirect)
        target = redirect or (settings.parsed_frontend_origins[0] if settings.parsed_frontend_origins else settings.app_base_url)
        err_msg = request.query_params.get("error") or "OAuth access was denied by Google or the user."
        sep = "&" if "?" in target else "?"; return RedirectResponse(target + sep + "error=" + quote_plus(err_msg))
    redirect_uri = settings.resolve_gmail_redirect_uri(request)
    flow = Flow.from_client_config(settings.google_client_config(request), scopes=OAUTH_SCOPES); flow.redirect_uri = redirect_uri
    try: flow.fetch_token(authorization_response=str(request.url))
    except Exception as e:
        log.exception("token exchange failed")
        target = redirect or (settings.parsed_frontend_origins[0] if settings.parsed_frontend_origins else settings.app_base_url)
        sep = "&" if "?" in target else "?"
        return RedirectResponse(target + sep + "error=" + quote_plus(f"Google Token exchange failed: {e}"))
    creds = flow.credentials
    email = _resolve_account_email(creds)
    if not email and getattr(creds, "token", None):
        try:
            async with httpx.AsyncClient() as hc:
                r = await hc.get("https://www.googleapis.com/oauth2/v3/userinfo", headers={"Authorization": f"Bearer {creds.token}"})
                r.raise_for_status()
                userinfo = r.json()
            email = _resolve_account_email(creds, userinfo)
        except Exception as e:
            log.warning("gmail userinfo lookup failed: %s", e)
    if not email:
        raise HTTPException(400, "Could not resolve Gmail account email from the OAuth response")
    acc = (await db.execute(select(Account).where(Account.email == email))).scalar_one_or_none()
    if acc is None:
        acc = Account(email=email, provider="gmail"); db.add(acc); await db.flush()
    acc.access_token = encrypt(creds.token); acc.refresh_token = encrypt(creds.refresh_token) or acc.refresh_token
    acc.token_expiry = creds.expiry.replace(tzinfo=None) if creds.expiry else None
    acc.scopes = " ".join(creds.scopes or OAUTH_SCOPES); acc.last_sync_at = datetime.utcnow(); await db.commit()
    token = create_token(acc.id); sep = "&" if "?" in redirect else "#"
    return RedirectResponse(redirect + sep + "prism_token=" + token)

@auth_router.post("/revoke")
async def auth_revoke(account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    account.access_token = None; account.refresh_token = None; await db.commit(); return {"ok": True}

# ============================ ROUTER: MAIL ============================
mail_router = APIRouter(prefix="/api/mail", tags=["mail"])

# ============================ SECURITY ENGINE ============================
# Trusted brand domains — legitimate companies (job boards, platforms). Mail from
# these domains is verified-safe, NOT a breach. Impersonation (brand name in
# display-name but a different real domain) is flagged separately as critical.
_TRUSTED_BRANDS = {
    "linkedin.com": "LinkedIn", "jobright.ai": "JobRight", "naukri.com": "Naukri",
    "indeed.com": "Indeed", "glassdoor.com": "Glassdoor", "lever.co": "Lever",
    "greenhouse.io": "Greenhouse", "upwork.com": "Upwork", "wellfound.com": "Wellfound",
    "google.com": "Google", "googlemail.com": "Google", "microsoft.com": "Microsoft",
    "outlook.com": "Microsoft", "amazon.com": "Amazon", "amazon.in": "Amazon",
    "apple.com": "Apple", "github.com": "GitHub", "gitlab.com": "GitLab",
    "vercel.com": "Vercel", "netlify.com": "Netlify", "stripe.com": "Stripe",
    "slack.com": "Slack", "zoom.us": "Zoom", "notion.so": "Notion",
    "substack.com": "Substack", "adobe.com": "Adobe", "netflix.com": "Netflix",
    "flipkart.com": "Flipkart", "paytm.com": "Paytm", "swiggy.com": "Swiggy",
    "zomato.com": "Zomato", "irctc.co.in": "IRCTC", "myntra.com": "Myntra",
    "canva.com": "Canva", "coursera.org": "Coursera", "udemy.com": "Udemy",
    "clickup.com": "ClickUp", "linear.app": "Linear", "figma.com": "Figma",
    "nvidia.com": "NVIDIA", "openai.com": "OpenAI", "anthropic.com": "Anthropic",
    "keetainc.com": "Keeta", "atlassian.com": "Atlassian", "atlassian.net": "Atlassian",
    "loom.com": "Loom", "teleprompter.com": "Teleprompter",
}
_SPOOF_NAMES = set(v.lower() for v in _TRUSTED_BRANDS.values())
_SPOOF_NAMES.update(("paypal", "rbi", "sbi", "hdfc", "icici", "axis", "kotak", "indusind",
                     "irs", "visa", "mastercard", "gpay", "phonepe", "upi", "youtube",
                     "meta", "whatsapp", "instagram", "telegram", "irctc"))
# Brand -> registrable domain the brand actually owns (for impersonation + link checks)
_BRAND_REAL = {
    "linkedin": "linkedin.com", "jobright": "jobright.ai", "naukri": "naukri.com",
    "indeed": "indeed.com", "glassdoor": "glassdoor.com", "lever": "lever.co",
    "greenhouse": "greenhouse.io", "upwork": "upwork.com", "wellfound": "wellfound.com",
    "google": "google.com", "microsoft": "microsoft.com", "amazon": "amazon.com",
    "apple": "apple.com", "github": "github.com", "gitlab": "gitlab.com",
    "vercel": "vercel.com", "netlify": "netlify.com", "stripe": "stripe.com",
    "slack": "slack.com", "zoom": "zoom.us", "notion": "notion.so",
    "substack": "substack.com", "adobe": "adobe.com", "netflix": "netflix.com",
    "flipkart": "flipkart.com", "paytm": "paytm.com", "swiggy": "swiggy.com",
    "zomato": "zomato.com", "irctc": "irctc.co.in", "myntra": "myntra.com",
    "canva": "canva.com", "coursera": "coursera.org", "udemy": "udemy.com",
    "paypal": "paypal.com", "rbi": "rbi.org.in", "sbi": "sbi.co.in",
    "hdfc": "hdfcbank.com", "icici": "icicibank.com", "axis": "axisbank.com",
    "kotak": "kotak.com", "visa": "visa.com", "mastercard": "mastercard.com",
    "whatsapp": "whatsapp.com", "instagram": "instagram.com", "telegram": "telegram.org",
    "gmail": "gmail.com", "youtube": "youtube.com", "amazonpay": "amazon.in",
}
_BRAND_REAL_SET = set(_BRAND_REAL.values()) | {
    "facebook.com", "x.com", "twitter.com", "reddit.com", "medium.com",
    "googleapis.com", "gstatic.com", "googlesyndication.com", "googleadservices.com",
    "doubleclick.net", "licdn.com", "fbcdn.net", "amazonaws.com", "awstrack.me",
    "cloudfront.net", "ampproject.org", "w3.org", "list-manage.com", "mcusercontent.com",
    "klclick.com", "klaviyo.com", "beefree.cloud", "mmgo.io", "sendgrid.net",
    "mailchimp.com", "youtube.com", "gmail.com", "slack-edge.com", "slack-files.com",
}
_PROMO_HOSTS = ("beehiiv.com", "mailchimp.com", "hubspot.com", "mailerlite.com",
                "convertkit.com", "activecampaign.com", "getresponse.com", "sendinblue.com",
                "brevo.com", "tealhq.com", "remote.co", "customeriomail.com", "klaviyo.com",
                "mailgun.org", "mailjet.com", "campaignmonitor.com", "sparkpostmail.com",
                "email.klaviyo.com")
_SUSP_TLDS = {"xyz", "top", "club", "online", "site", "live", "click", "link", "work",
              "gq", "ml", "tk", "ga", "cf", "ru", "cn", "buzz", "icu", "zip", "monster",
              "loan", "win", "review", "support", "account", "security", "verify",
              "login", "update", "password", "bank", "country"}
_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
               "rebrand.ly", "ow.ly", "buff.ly", "shorturl.at", "lnkd.in", "mstr.cc")
_DANGER_EXT = (".exe", ".scr", ".vbs", ".js", ".lnk", ".com", ".bat", ".cmd", ".msi",
               ".jar", ".apk", ".chm", ".wsf", ".ps1", ".reg", ".docm", ".xlsm", ".pptm")
_LOOKALIKE_BRANDS = ("paypal", "linkedin", "microsoft", "google", "amazon", "apple",
                     "netflix", "facebook", "whatsapp", "instagram", "flipkart",
                     "irctc", "hdfc", "sbi", "amazonpay", "gmail", "appleid")
_RE_AADHAAR = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")
_RE_PAN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
_RE_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_RE_CARD = re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b")
_RE_PHONE_IN = re.compile(r"(?:\+91|0)?[6-9]\d{9}")
_RE_IFSC = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
_RE_URGENT = re.compile(r"(within\s*\d+\s*(?:hours|minutes)|act now|immediately|asap|"
                        r"suspended|locked|reactivate|unusual activity|last warning|"
                        r"final notice|account will be (?:deleted|closed|suspended)|"
                        r"verify (?:your )?account)", re.I)
_RE_CRED = re.compile(r"(send|share|confirm|enter|verify)[^.]{0,30}"
                      r"(password|pin|secret|credential|card number|cvv|otp|verification code|code)"
                      r"|gift card[^.]{0,40}(?:code|pin|number)"
                      r"|wire transfer|western union|bitcoin|usdt|crypto"
                      r"|processing fee|upfront fee|tax refund|lottery|inheritance", re.I)
_RE_IP_HOST = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_RE_DBL_EXT = re.compile(r"\.\w{2,4}\.(exe|scr|vbs|js|lnk|com|bat)$")
_SEC_CACHE: dict[int, tuple[float, dict]] = {}


def _host_of(addr):
    """Raw lowercase host of an email address (keeps subdomains)."""
    a = (addr or "").strip()
    if "<" in a:
        a = a.split("<")[-1].rstrip(">")
    a = a.split("@")[-1] if "@" in a else a
    return a.split(":")[0].lower().strip().rstrip(".")

_SUFFIXES2 = {"co.in", "co.uk", "com.au", "org.in", "net.in", "ac.in", "gov.in",
              "com.br", "com.mx", "co.jp", "co.kr", "com.sg", "org.uk"}


def _registrable(host):
    """Registrable domain: google.com, accounts.google.com -> google.com; co.in keeps 3 labels."""
    p = host.split(".")
    if len(p) <= 2:
        return host
    if len(p) >= 3 and ".".join(p[-2:]) in _SUFFIXES2:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def _trusted_brand(dom: str):
    dom = (dom or "").lower().strip()
    for k, brand in _TRUSTED_BRANDS.items():
        if dom == k or dom.endswith("." + k):
            return brand
    return None


def _is_promo_host(host: str):
    return any(host == p or host.endswith("." + p) for p in _PROMO_HOSTS)


def _lookalike(host: str):
    """True when a host mimics a brand but is NOT owned by the brand's registrable domain.
    Legit subdomains (accounts.google.com) return None."""
    reg = _registrable(host)
    for br, real in _BRAND_REAL.items():
        if reg == real:
            return None
        if br in host:
            return br
    return None


def _sec_scan_message(m):
    host = _host_of(m.from_addr)
    brand = _trusted_brand(host)
    name = (m.from_name or "").strip()
    subj = (m.subject or "") or ""
    body = (m.body or "") or ""
    snip = (m.snippet or "") or ""
    text = (subj + " " + body + " " + snip).lower()
    # PII scan runs on URL/HTML-stripped text — image names, tracking IDs and
    # UUIDs in links contain random number runs that otherwise false-positive.
    clean = re.sub(r"https?://\S+", " ", text)
    clean = re.sub(r"<[^>]+>", " ", clean)
    clean = re.sub(r"\s+", " ", clean)
    # urgency / credential asks: only subject + snippet (newsletter bodies are
    # full of marketing pressure copy)
    head = (subj + " " + snip).lower()
    is_promo = ("CATEGORY_PROMOTIONS" in (m.raw_labels or "") or "CATEGORY_SOCIAL" in (m.raw_labels or "")
                or _is_promo_host(host))
    codes, reasons = [], []

    # Impersonation of a trusted brand from a foreign domain (critical).
    # A display name like "Google" <no-reply@accounts.google.com> is NOT a spoof.
    if not brand:
        for nm in _SPOOF_NAMES:
            if nm in name.lower():
                real = _BRAND_REAL.get(nm)
                if real and (host == real or host.endswith("." + real)):
                    break
                codes.append("spoof")
                reasons.append(f"display name impersonates {nm.title()} but real domain is {host}")
                break

    # Malicious payloads — attachment filenames (critical)
    att_names = [a.strip() for a in (m.att_names or "").split(",") if a.strip()] if m.att_names else []
    for fn in att_names:
        f = fn.lower()
        if f.endswith(_DANGER_EXT):
            codes.append("payload")
            reasons.append(f"dangerous executable attachment: {fn}")
        elif _RE_DBL_EXT.search(f):
            codes.append("payload")
            reasons.append(f"double-extension file: {fn}")
        elif (".zip" in f or ".rar" in f or ".7z" in f) and re.search(r"password|passphrase|key", text):
            codes.append("payload")
            reasons.append(f"password-protected archive from untrusted sender: {fn}")
    if m.att_count and not att_names and not brand:
        codes.append("payload")
        reasons.append(f"{m.att_count} attachment(s) from an untrusted sender")

    # Phishing links — shorteners, IP hosts, suspicious TLDs, lookalike domains.
    # Legit links to brand sites (accounts.google.com, github.com) are never suspicious.
    urls = re.findall(r"https?://[^\s\"'<>)\]]+", text)
    bad_urls = 0
    for u in urls[:14]:
        try:
            host = u.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].split("@")[-1].lower().rstrip(".")
        except Exception:
            continue
        if not host or host in ("gmail.com", "www.google.com"):
            continue
        reg = _registrable(host)
        if reg in _BRAND_REAL_SET:
            continue
        if host in _SHORTENERS or host.endswith(_SHORTENERS):
            bad_urls += 1
        elif _RE_IP_HOST.match(host):
            bad_urls += 1
        elif (host.rsplit(".", 1)[-1] if "." in host else host) in _SUSP_TLDS:
            bad_urls += 1
        elif _lookalike(host):
            bad_urls += 1
    if bad_urls:
        codes.append("phish")
        reasons.append(f"{bad_urls} suspicious link(s) — shortener/lookalike/suspicious domain")

    # PII / credential harvesting (URL/HTML-stripped text — never flag random IDs)
    if _RE_AADHAAR.search(clean): codes.append("pii"); reasons.append("Aadhaar number present")
    if _RE_PAN.search(clean): codes.append("pii"); reasons.append("PAN number present")
    if _RE_SSN.search(clean): codes.append("pii"); reasons.append("SSN present")
    if _RE_CARD.search(clean): codes.append("pii"); reasons.append("card number present")
    if _RE_IFSC.search(clean): codes.append("pii"); reasons.append("IFSC / bank code present")
    if not brand and _RE_CRED.search(head):
        codes.append("cred"); reasons.append("requests credentials / money transfer")

    # Personal data sent to a third party (sent mail carrying PII outside)
    if m.folder == "sent" and m.to_addr:
        to = (m.to_addr or "").lower()
        me_addr = (m.from_addr or "").lower()
        if me_addr not in to:
            if _RE_AADHAAR.search(clean) or _RE_PAN.search(clean) or _RE_CARD.search(clean) or \
               _RE_PHONE_IN.search(clean) or _RE_IFSC.search(clean) or _RE_SSN.search(clean):
                codes.append("3p")
                reasons.append(f"personal/financial data present — recipient: {(m.to_addr or '')[:60]}")

    # Pressure tactics (subject + snippet only)
    if not is_promo and _RE_URGENT.search(head):
        codes.append("urgency")
        reasons.append("pressure tactics — urgent / verify / account suspended")

    # Trusted brand mail is verified-safe — a legit company (LinkedIn, JobRight,
    # NVIDIA, OpenAI...) never triggers PII/urgency/phish flags; only actual
    # payloads (dangerous attachments) or spoof still escalate.
    if brand and not (set(codes) & {"payload", "spoof", "3p"}):
        return None, brand
    if is_promo and not (set(codes) & {"payload", "cred", "pii", "spoof", "3p"}):
        return None, brand
    if not codes:
        return None, brand

    if set(codes) & {"payload", "cred", "pii", "spoof", "3p"}:
        sev = "critical"
    elif "phish" in codes:
        sev = "high"
    else:
        sev = "mod"
    return {"verdict": "critical" if sev == "critical" else "fraud", "severity": sev,
            "codes": codes, "reasons": reasons, "dom": host or pretty_domain(m.from_addr),
            "name": name}, brand


def _llm_verify(cands):
    """AI review of pre-flagged candidates. Returns [{id, verdict, reasons}] or None."""
    if not settings.llm_api_key or not cands:
        return None
    brief = "\n".join(
        f'id:{c["id"]} from:{c["from_name"]} <{c["from_addr"]}> subj:{c["subj"][:90]} body:{c["body"][:240]}'
        for c in cands[:12])
    raw = _chat(
        "You are a world-class email security analyst. Decide if each email is real fraud "
        "(phishing, credential theft, malware, impersonation, PII exfiltration, money demands) "
        "or clean (including legit job-board mail from LinkedIn/JobRight/Naukri, promo campaigns). "
        'Reply with ONLY compact JSON: {"results":[{"id":..,"verdict":"clean|fraud|critical","reasons":[".."]}]}',
        f"Review these emails:\n{brief}")
    if not raw:
        return None
    d = _try_parse_json(raw)
    if isinstance(d, dict) and isinstance(d.get("results"), list):
        return [r for r in d["results"] if isinstance(r, dict) and "id" in r]
    return None


@mail_router.post("/security/scan")
async def security_scan(limit: int = 400, account: Account = Depends(get_current_account),
                        db: AsyncSession = Depends(get_session)):
    """Real-time security scan of the account's mailbox. Deterministic behavioral engine
    (trusted brands, payloads, PII, phishing, impersonation, 3rd-party exposure) with an
    LLM verdict override when LLM_API_KEY is configured. Cached 60s."""
    now = datetime.utcnow().timestamp()
    cached = _SEC_CACHE.get(int(account.id))
    if cached and now - cached[0] < 60:
        return cached[1]
    rows = (await db.execute(
        select(Message).where(Message.account_id == account.id,
                              Message.folder.in_(("inbox", "archive", "sent", "snoozed")))
        .order_by(Message.received_at.desc()).limit(limit))).scalars().all()
    results, trusted, cands = [], {}, []
    for m in rows:
        res, brand = _sec_scan_message(m)
        if brand:
            trusted[brand] = trusted.get(brand, 0) + 1
        if res:
            res["id"] = m.id
            res["subj"] = m.subject or ""
            if res["severity"] in ("high", "critical"):
                cands.append({"id": m.id, "from_name": m.from_name or "", "from_addr": m.from_addr or "",
                              "subj": m.subject or "", "body": (m.body or "")[:400]})
            results.append(res)
    ai = _llm_verify(cands)
    if ai:
        for v in ai:
            r = next((x for x in results if x.get("id") == v.get("id")), None)
            if not r:
                continue
            if v.get("verdict") == "clean":
                results.remove(r)
            elif v.get("verdict") in ("fraud", "critical") and v.get("reasons"):
                r["verdict"] = v["verdict"]
                r["severity"] = "critical" if v["verdict"] == "critical" else r["severity"]
                r["reasons"] = [str(x) for x in v["reasons"]][:6]
    crit = sum(1 for r in results if r["severity"] == "critical")
    high = sum(1 for r in results if r["severity"] == "high")
    pii_n = sum(1 for r in results if "pii" in r["codes"] or "3p" in r["codes"])
    pay_n = sum(1 for r in results if "payload" in r["codes"])
    ph_n = sum(1 for r in results if "phish" in r["codes"])
    out = {"engine": "ai" if settings.llm_api_key else "local",
           "model": settings.llm_model if settings.llm_api_key else None,
           "email": account.email, "ts": datetime.utcnow().isoformat() + "Z",
           "trusted": [{"brand": b, "count": n} for b, n in sorted(trusted.items())],
           "summary": {"scanned": len(rows), "threats": len(results), "critical": crit, "high": high,
                       "pii_events": pii_n, "payloads": pay_n, "phish_links": ph_n},
           "results": results}
    _SEC_CACHE[int(account.id)] = (now, out)
    return out

_BREACH_CACHE: dict[int, tuple[float, dict]] = {}


@mail_router.get("/security/breach/{email}")
async def security_breach(email: str, account: Account = Depends(get_current_account)):
    """Dark-web (HaveIBeenPwned) breach check for an email address. Cached 6h.
    Returns status 'no_key' when HIBP_API_KEY is not configured."""
    if not settings.hibp_api_key:
        return {"status": "no_key", "email": email,
                "hint": "Set HIBP_API_KEY in .env to enable dark-web breach monitoring"}
    now = time.time()
    cached = _BREACH_CACHE.get(int(account.id))
    if cached and now - cached[0] < 6 * 3600:
        return cached[1]
    headers = {"hibp-api-key": settings.hibp_api_key, "user-agent": "prism-mail-security/1.0"}
    breaches, pastes = [], 0
    try:
        async with httpx.AsyncClient(timeout=15) as hc:
            for path, is_paste in (("breachedaccount", False), ("pasteaccount", True)):
                r = await hc.get(f"https://haveibeenpwned.com/api/v3/{path}/{quote_plus(email)}", headers=headers)
                if r.status_code in (200, 201):
                    if is_paste:
                        pastes = len(r.json() or [])
                    else:
                        breaches = [{"name": b.get("Name", ""), "date": (b.get("BreachDate") or "")[:10],
                                     "data": (b.get("DataClasses") or [])} for b in r.json()]
                elif r.status_code == 404:
                    pass
                elif r.status_code == 401:
                    return {"status": "bad_key", "email": email, "hint": "HIBP_API_KEY is invalid or expired"}
                elif r.status_code == 429:
                    return {"status": "rate_limited", "email": email, "hint": "HIBP rate limit reached — retry later"}
                else:
                    return {"status": "error", "email": email, "code": r.status_code}
    except Exception as e:
        return {"status": "error", "email": email, "detail": str(e)[:200]}
    out = {"status": "ok", "email": email, "breaches": breaches, "pastes": pastes,
           "exposed": bool(breaches) or pastes > 0}
    _BREACH_CACHE[int(account.id)] = (now, out)
    return out

# ============================ HONEYPOT / DATA RETENTION API ============================
@mail_router.get("/security/honeypot")
async def honeypot_state(account: Account = Depends(get_current_account),
                         db: AsyncSession = Depends(get_session)):
    """Data-retention honeypot: armed state, engagement counters and decoy inventory."""
    row = await _hp_row(db)
    fails = {ip: len(v) for ip, v in _HP_AUTH_FAILS.items() if v}
    return {
        "armed": bool(row.armed),
        "engaged": bool(row.engaged or _HP_MEM["engaged"]),
        "source": row.source,
        "engaged_at": row.engaged_at.isoformat() if row.engaged_at else None,
        "served": (row.served or 0),
        "auth_fails": fails,
        "decoys": _HP_DECOYS,
    }

@mail_router.post("/security/honeypot")
async def honeypot_arm(payload: HoneypotArmIn, account: Account = Depends(get_current_account),
                       db: AsyncSession = Depends(get_session)):
    """Arm (protect with decoys) or disarm the data-retention honeypot."""
    row = await _hp_row(db)
    row.armed = bool(payload.armed)
    if not payload.armed:
        row.engaged = False
        row.source = None
        row.engaged_at = None
        _HP_MEM["engaged"] = False
    await db.commit()
    return {"armed": row.armed, "engaged": bool(row.engaged)}

@mail_router.post("/security/honeypot/engage")
async def honeypot_engage(account: Account = Depends(get_current_account),
                          db: AsyncSession = Depends(get_session)):
    """Manually engage the honeypot — hands the DECOY dataset to any suspicious caller."""
    row = await _hp_row(db)
    if not row.armed:
        raise HTTPException(400, "Arm the honeypot before engaging it")
    row.engaged = True
    row.engaged_at = datetime.utcnow()
    row.source = "manual"
    _HP_MEM["engaged"] = True
    await db.commit()
    return {"status": "engaged", "engaged": True, "source": "manual", "decoy": _hp_decoy_payload()}

@mail_router.post("/security/honeypot/reset")
async def honeypot_reset(account: Account = Depends(get_current_account),
                         db: AsyncSession = Depends(get_session)):
    """Stop engaging and clear the decoy served counter."""
    row = await _hp_row(db)
    row.engaged = False
    row.source = None
    row.engaged_at = None
    row.served = 0
    _HP_MEM["engaged"] = False
    await db.commit()
    return {"armed": bool(row.armed), "engaged": False, "served": 0}

async def _msg(db, account, mid):
    m = (await db.execute(select(Message).options(selectinload(Message.classification))
         .where(Message.id == mid, Message.account_id == account.id))).scalar_one_or_none()
    if m is None: raise HTTPException(404, "Message not found")
    return m

@mail_router.get("")
async def mail_list(folder: str | None = Query(None), cluster: str | None = Query(None), limit: int = Query(300, le=500000),
                    until: str | None = Query(None), has_att: bool = Query(False), q: str | None = Query(None),
                    cat: str | None = Query(None),
                    account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    stmt = select(Message).options(selectinload(Message.classification)).where(Message.account_id == account.id)
    if folder and folder != "starred": stmt = stmt.where(Message.folder == folder)
    if folder == "starred": stmt = stmt.where(Message.is_starred.is_(True))
    if cat == "updates":
        stmt = stmt.where(Message.raw_labels.like("%CATEGORY_UPDATES%") | Message.raw_labels.like("%CATEGORY_FORUMS%"))
    elif cat == "primary":
        stmt = stmt.where(Message.raw_labels.like("%CATEGORY_PERSONAL%"))
    elif cat == "promotions":
        stmt = stmt.where(Message.raw_labels.like("%CATEGORY_PROMOTIONS%"))
    elif cat == "social":
        stmt = stmt.where(Message.raw_labels.like("%CATEGORY_SOCIAL%"))
    if cluster:
        cid = int(cluster[1:]) if cluster.startswith("c") else int(cluster)
        stmt = stmt.join(ClusterMember, ClusterMember.message_id == Message.id).where(ClusterMember.cluster_id == cid)
    if until:
        try:
            end = datetime.strptime(until[:10], "%Y-%m-%d") + timedelta(days=1)
            stmt = stmt.where(Message.received_at < end)
        except ValueError:
            pass
    if has_att: stmt = stmt.where(Message.att_count > 0)
    if q:
        pat = f"%{q.strip()}%"
        stmt = stmt.where(or_(
            Message.subject.ilike(pat),
            Message.snippet.ilike(pat),
            Message.from_name.ilike(pat),
            Message.from_addr.ilike(pat),
            Message.to_addr.ilike(pat),
        ))
    stmt = stmt.order_by(Message.received_at.desc()).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    cmap = dict((await db.execute(select(ClusterMember.message_id, Cluster.id).join(Cluster, Cluster.id == ClusterMember.cluster_id)
                 .where(ClusterMember.message_id.in_([r.id for r in rows] or [0])))).all())
    # Strip full HTML bodies from list payload — only metadata + snippet.
    # The frontend fetches bodies on demand via mail_get, which live-re-fetches if missing.
    out = []
    for m in rows:
        d = mail_to_frontend(m); d["cluster"] = f"c{cmap[m.id]}" if m.id in cmap else None
        # Replace HTML body with snippet-only; body_html signals whether HTML content is on file
        d["body"] = None  # avoid serializing big HTML blobs in the list
        d["body_html"] = bool(m.body and ("<" in m.body and ">" in m.body))
        out.append(d)
    return out

@mail_router.get("/proxy-image/{gmail_id}/{attachment_id}")
async def proxy_attachment_image(gmail_id: str, attachment_id: str, mime: str | None = Query(None),
                                 account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    """Serve CID attachments as inline images."""
    try:
        data = await bcall(fetch_attachment_data, _service(account)[0], gmail_id, attachment_id)
        if data:
            return Response(content=data, media_type=mime or "image/jpeg",
                            headers={"Cache-Control": "public, max-age=86400"})
        raise HTTPException(404, "Attachment not found")
    except HTTPException:
        raise
    except Exception as e:
        log.exception("proxy_attachment_image failed")
        raise HTTPException(500, str(e))

@mail_router.get("/proxy-image")
async def proxy_remote_image(url: str, account: Account = Depends(get_current_account)):
    """Proxy remote images. Tracking beacons and blocked hosts return a transparent 1x1 GIF
    so the email layout is preserved (no broken-image icons)."""
    # Tracking/beacon domains: return a transparent pixel instead of fetching
    # (they're not images anyway, and fetching them causes tracking + breakage)
    _TRACKERS = ("beacon.", "/track/", "/open?", "/click?", "pixel.", "tracker.", "e.kit.com",
                 "beacon.kit.com", "mailtrack.", "sidekick.", "bananatag.")
    try:
        import ipaddress, socket
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise HTTPException(400, "Only http/https URLs allowed")
        host = (parsed.hostname or "").lower()
        if any(x in host or x in url.lower() for x in _TRACKERS):
            # transparent 1x1 GIF
            gif = base64.b64decode("R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==")
            return Response(content=gif, media_type="image/gif", headers={"Cache-Control": "public, max-age=86400"})
        # SSRF guard: block private, loopback, link-local and reserved hosts
        try:
            for res in socket.getaddrinfo(host, None):
                ip = ipaddress.ip_address(res[4][0])
                if ip.version == 6 and ip.ipv4_mapped is not None: ip = ip.ipv4_mapped
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
                    raise HTTPException(502, "Blocked: private or local host")
        except socket.gaierror:
            raise HTTPException(502, "Could not resolve host")
    except HTTPException:
        raise
    except Exception:
        pass
    try:
        import httpx
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PrismMail/1.3"})
            if resp.status_code == 200 and resp.content and len(resp.content) > 50:
                content_type = resp.headers.get("Content-Type", "image/jpeg")
                if not content_type.startswith("image/") and "octet-stream" not in content_type:
                    content_type = "image/jpeg"
                return Response(content=resp.content, media_type=content_type,
                                headers={"Cache-Control": "public, max-age=86400"})
            # Remote server returned an error or unusable body
            raise HTTPException(502, f"Remote image fetch failed (status {resp.status_code})")
    except HTTPException:
        raise
    except Exception:
        log.warning("proxy_remote_image fetch error for %s", url, exc_info=True)
        return Response(status_code=502)

@mail_router.get("/{mid}")
async def mail_get(mid: int, account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    m = await _msg(db, account, mid)
    # If the stored body has no HTML markup (legacy plain-text sync), re-fetch the full
    # message from Gmail so we can extract and serve the text/html part.
    if m.gmail_id and (not m.body or "<" not in m.body):
        try:
            service, _ = _service(account)
            full = await bcall(get_full_by_service, service, m.gmail_id)
            if full.get("body") and "<" in full["body"]:
                m.body = full["body"]
                await db.commit()
        except Exception:
            log.warning("live re-fetch failed for %s", m.gmail_id, exc_info=True)
    d = mail_to_frontend(m)
    cm = (await db.execute(select(Cluster.id).join(ClusterMember).where(ClusterMember.message_id == mid))).scalar_one_or_none()
    d["cluster"] = f"c{cm}" if cm else None; return d

@mail_router.post("/{mid}/archive")
async def mail_archive(mid: int, account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    m = await _msg(db, account, mid); m.folder = "trash"; m.is_read = True
    await db.commit()
    if m.gmail_id and (account.refresh_token or account.access_token):
        try: await modify(account, m.gmail_id, ["TRASH"], ["INBOX"], db)
        except Exception: log.warning("archive modify failed for %s", m.gmail_id, exc_info=True)
    return {"ok": True, "id": m.id, "folder": m.folder}

@mail_router.post("/{mid}/snooze")
async def mail_snooze(mid: int, payload: SnoozeIn | None = None, account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    m = await _msg(db, account, mid)
    m.folder = "snoozed"
    m.snoozed_until = (payload.until if payload and payload.until else datetime.utcnow() + timedelta(days=1))
    if m.gmail_id: await apply_snooze(account, m.gmail_id, db)
    await db.commit(); return {"ok": True, "id": m.id, "snoozed_until": m.snoozed_until.isoformat()}

@mail_router.post("/{mid}/star")
async def mail_star(mid: int, starred: bool = Query(...), account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    m = await _msg(db, account, mid); m.is_starred = starred
    if m.gmail_id: await apply_star(account, m.gmail_id, starred, db)
    await db.commit(); return {"ok": True, "id": m.id, "star": 1 if starred else 0}

@mail_router.patch("/{mid}")
async def mail_patch(mid: int, patch: StatePatch, account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    m = await _msg(db, account, mid)
    if patch.folder is not None: m.folder = patch.folder
    if patch.is_read is not None: m.is_read = patch.is_read
    if patch.is_starred is not None:
        m.is_starred = patch.is_starred
        if m.gmail_id: await apply_star(account, m.gmail_id, patch.is_starred, db)
    await db.commit(); return {"ok": True, "id": m.id}

@mail_router.post("/{mid}/draft")
async def mail_draft(mid: int, payload: DraftIn, account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    m = await _msg(db, account, mid); cls = m.classification or Classification(message_id=m.id); cls.draft_body = payload.body
    if m.classification is None: db.add(cls)
    await db.commit(); return {"ok": True}

@mail_router.post("/send")
async def mail_send(payload: SendIn, account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    if not account.refresh_token and not account.access_token: raise HTTPException(400, "Gmail not connected")
    send_name = (payload.name or "").strip() or account.display_name or account.email.split("@")[0]
    gid = await send_raw(account, payload.to, payload.subject or "(no subject)", payload.body, db, from_addr=account.email, sender_name=send_name, bcc=payload.bcc or None)
    m = Message(account_id=account.id, gmail_id=gid, from_name=send_name, from_addr=account.email, to_addr=payload.to,
                subject=payload.subject, snippet=(payload.body.splitlines() or [""])[0][:120], body=payload.body, folder="sent", is_read=True)
    db.add(m); await db.commit(); return {"ok": True, "id": m.id, "gmail_id": gid}

@mail_router.post("/{mid}/reply")
async def mail_reply(mid: int, payload: ReplyIn, account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    m = await _msg(db, account, mid)
    if not m.from_addr: raise HTTPException(400, "No recipient address on record")
    subj = m.subject or ""
    if not subj.lower().startswith("re:"): subj = "Re: " + subj
    send_name = account.display_name or account.email.split("@")[0]
    gid = await send_raw(account, m.from_addr, subj, payload.body, db, in_reply_to=m.message_id_header, references=m.message_id_header, from_addr=account.email, sender_name=send_name)
    out = Message(account_id=account.id, gmail_id=gid, thread_id=m.thread_id, from_name=send_name, from_addr=account.email, to_addr=m.from_addr,
                  subject=subj, snippet=(payload.body.splitlines() or [""])[0][:120], body=payload.body, folder="sent", is_read=True)
    db.add(out); await db.commit(); return {"ok": True, "id": out.id, "to": m.from_addr, "gmail_id": gid}

@mail_router.post("/{mid}/ai-reply")
async def mail_ai_reply(mid: int, account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    m = await _msg(db, account, mid); draft = await bcall(draft_reply, m.from_name or "", m.subject or "", m.body or "")
    cls = m.classification or Classification(message_id=m.id); cls.draft_body = draft
    if m.classification is None: db.add(cls)
    await db.commit(); return {"reply": draft}

@mail_router.post("/{mid}/trash")
async def mail_trash(mid: int, account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    """Move a message to Trash (archiving now routes to Trash)."""
    m = await _msg(db, account, mid)
    # Commit the DB state FIRST so the Trash list reflects the change immediately,
    # before the slow Gmail modify + full resync below.
    m.folder = "trash"; m.is_read = True
    await db.commit()
    if m.gmail_id and (account.refresh_token or account.access_token):
        try:
            await modify(account, m.gmail_id, ["TRASH"], ["INBOX"], db)
            # Re-assert in case the resync read stale labels (e.g. Gmail modify failed)
            m.folder = "trash"; m.is_read = True
            await db.commit()
        except Exception:
            log.warning("trash modify failed for %s", m.gmail_id, exc_info=True)
    return {"ok": True, "id": m.id}

@mail_router.post("/{mid}/delete-forever")
async def mail_delete_forever(mid: int, account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    """Permanently delete the message (irrecoverable)."""
    m = await _msg(db, account, mid)
    await db.delete(m); await db.commit()
    if m.gmail_id and (account.refresh_token or account.access_token):
        try:
            service, creds = _service(account)
            await bcall(lambda: service.users().messages().delete(userId="me", id=m.gmail_id).execute())
            await persist_refreshed(account, creds, db)
        except Exception:
            log.warning("delete-forever Gmail call failed for %s", m.gmail_id, exc_info=True)
    return {"ok": True, "id": m.id}

@mail_router.post("/bulk-archive")
async def mail_bulk_archive(payload: BulkIn, account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    rows = (await db.execute(select(Message).where(Message.id.in_(payload.ids), Message.account_id == account.id))).scalars().all()
    for m in rows:
        m.folder = "archive"; m.is_read = True
    await db.commit()
    for m in rows:
        if m.gmail_id and (account.refresh_token or account.access_token):
            try: await modify(account, m.gmail_id, ["TRASH"], ["INBOX"], db)
            except Exception: log.warning("bulk-archive modify failed for %s", m.gmail_id, exc_info=True)
    return {"ok": True, "archived": [m.id for m in rows]}

@mail_router.post("/bulk/action")
async def mail_bulk_action(payload: BulkActionIn, account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    """Generic batch action: archive | star | unstar | read | unread | trash | snooze | inbox"""
    rows = (await db.execute(select(Message).where(Message.id.in_(payload.ids or [0]), Message.account_id == account.id))).scalars().all()
    act = payload.action
    label_add, label_rm = [], []
    if act == "archive": label_rm = ["INBOX"]
    elif act == "star": label_add = ["STARRED"]
    elif act == "unstar": label_rm = ["STARRED"]
    elif act == "read": label_rm = ["UNREAD"]
    elif act == "unread": label_add = ["UNREAD"]
    elif act == "trash": label_add = ["TRASH"]
    elif act == "inbox": label_add = ["INBOX"]; label_rm = ["TRASH"]
    elif act == "snooze": label_add = ["PRISM/Snoozed"]
    else: raise HTTPException(400, f"Unknown action: {act}")
    for m in rows:
        if act == "archive": m.folder = "archive"
        elif act == "inbox": m.folder = "inbox"
        elif act in ("star","unstar"): m.is_starred = act == "star"
        elif act in ("read","unread"): m.is_read = act == "read"
        elif act == "trash": m.folder = "trash"
        elif act == "snooze":
            m.folder = "snoozed"; m.snoozed_until = payload.until or (datetime.utcnow() + timedelta(days=1))
    # Commit DB state first so folders reflect instantly; then push to Gmail.
    await db.commit()
    for m in rows:
        if m.gmail_id:
            try:
                await modify(account, m.gmail_id, label_add, label_rm, db)
            except Exception:
                log.warning("bulk %s modify failed for %s", act, m.gmail_id, exc_info=True)
    return {"ok": True, "n": len(rows)}

@mail_router.post("/{mid}/unsend")
async def mail_unsend(mid: int, account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    """Retract a sent email up to 24 hours after it was sent (Gmail delete removes it from recipients' inboxes)."""
    m = await _msg(db, account, mid)
    if m.folder != "sent": raise HTTPException(400, "Only sent messages can be unsent")
    sent_at = m.received_at or datetime.utcnow()
    age = datetime.utcnow() - sent_at
    if age > timedelta(hours=24): raise HTTPException(400, "The 24-hour unsend window has expired")
    if m.gmail_id and account.access_token:
        service, creds = _service(account)
        try:
            await bcall(lambda: service.users().messages().delete(userId="me", id=m.gmail_id).execute())
        except Exception as e:
            log.warning("unsend failed for %s: %s", m.gmail_id, e)
            raise HTTPException(502, "Gmail could not retract this message — it may already be too late")
        await persist_refreshed(account, creds, db)
    m.folder = "trash"; m.is_read = True
    await db.commit()
    return {"ok": True, "id": m.id, "window_secs_left": int((timedelta(hours=24) - age).total_seconds())}

@mail_router.post("/{mid}/unsubscribe")
async def mail_unsubscribe(mid: int, account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    """Return parsed List-Unsubscribe actions (mailto / https) for one-click unsubscribe."""
    m = await _msg(db, account, mid)
    raw = m.list_unsub or ""
    if not raw and m.gmail_id:
        try:
            service, _ = _service(account)
            msg = await bcall(lambda: service.users().messages().get(
                userId="me", id=m.gmail_id, format="metadata",
                metadataHeaders=["List-Unsubscribe"]).execute())
            raw = _header(msg, "List-Unsubscribe")
        except Exception:
            log.warning("unsubscribe header fetch failed for %s", m.gmail_id, exc_info=True)
    if not raw: raise HTTPException(404, "This sender doesn't support one-click unsubscribe")
    mailto = next((x[7:].strip() for x in raw.replace(",", " ").split() if x.lower().startswith("<mailto:")), None) or \
             next((x[7:].strip() for x in raw.split() if x.lower().startswith("mailto:")), None)
    url = next((x[1:-1].strip() for x in raw.replace(",", " ").split() if x.lower().startswith("<http")), None) or \
          next((x.strip() for x in raw.split() if x.lower().startswith("http")), None)
    return {"ok": True, "mailto": mailto, "url": url}

@mail_router.get("/{mid}/attachments")
async def mail_attachments(mid: int, account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    m = await _msg(db, account, mid)
    if not m.gmail_id: return []
    def _list_att():
        service = _service(account)[0]
        msg = service.users().messages().get(userId="me", id=m.gmail_id, format="metadata").execute()
        out, stack = [], [msg.get("payload") or {}]
        while stack:
            p = stack.pop()
            if not isinstance(p, dict): continue
            body = p.get("body", {}) or {}
            if body.get("attachmentId"):
                disp = ""
                for h in (p.get("headers") or []):
                    if (h.get("name") or "").lower() == "content-disposition": disp = h.get("value") or ""
                if "inline" in disp.lower(): continue
                out.append({"attachment_id": body["attachmentId"], "filename": p.get("filename") or "attachment",
                            "mime": p.get("mimeType") or "application/octet-stream", "size": body.get("size", 0)})
            stack.extend(p.get("parts") or [])
        return out
    return await bcall(_list_att)

@mail_router.get("/{mid}/attachment/{attachment_id}")
async def mail_attachment_download(mid: int, attachment_id: str, filename: str | None = Query(None),
                                   account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    m = await _msg(db, account, mid)
    if not m.gmail_id: raise HTTPException(404, "Message not synced")
    data = await bcall(fetch_attachment_data, _service(account)[0], m.gmail_id, attachment_id)
    if not data: raise HTTPException(404, "Attachment not found")
    fname = "".join(ch for ch in (filename or "attachment") if ch.isalnum() or ch in "._- ")[:80] or "attachment"
    return Response(content=data, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})

@mail_router.post("/ai/compose-draft")
async def mail_ai_compose(payload: ComposeDraftIn, account: Account = Depends(get_current_account)):
    return {"draft": await bcall(draft_compose, payload.to, payload.subject, payload.hint)}

# ============================ ROUTER: CLUSTERS ============================
clusters_router = APIRouter(prefix="/api/clusters", tags=["clusters"])

@clusters_router.get("")
async def clusters_list(refresh: bool = Query(False), account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    existing = (await db.execute(select(Cluster).where(Cluster.account_id == account.id))).scalars().all()
    if refresh or not existing:
        await recluster(account.id, db); existing = (await db.execute(select(Cluster).where(Cluster.account_id == account.id))).scalars().all()
    out = []
    for c in existing:
        mm = (await db.execute(select(Message).join(ClusterMember, ClusterMember.message_id == Message.id)
              .where(ClusterMember.cluster_id == c.id).order_by(Message.received_at.desc()).limit(3))).scalars().all()
        stack = [{"ini": _initials(m.from_name, m.from_addr), "h": _hash_hue(m.from_addr or m.from_name or ""),
                  "neu": 1 if _is_neu(m.from_addr, m.from_name) else 0,
                  "dom": pretty_domain(m.from_addr)} for m in mm]
        out.append(cluster_to_frontend(c, stack))
    return out

# ============================ ROUTER: SYNC ============================
sync_router = APIRouter(prefix="/api", tags=["sync"])
def _reauth_hint(): return f"{settings.app_base_url}/auth/gmail/start?redirect=<your-frontend-origin>"

@sync_router.post("/sync")
async def sync_post(account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    if not account.access_token and not account.refresh_token:
        raise HTTPException(401, detail={"error": "gmail_not_connected", "hint": _reauth_hint()})
    try:
        # Check if sync already completed recently — skip if done
        ss = await _get_or_create_ss(db, account.id)
        if ss.status in ("done", "partial") and ss.finished_at and (datetime.utcnow() - ss.finished_at).total_seconds() < 300:
            return await read_status(db, account.id)
        # Acquire lock and run sync with timeout to prevent hanging
        async with acquire_sync_lock(db, account.id):
            summary = await asyncio.wait_for(run_sync(account, db), timeout=120)
        return summary
    except SyncInProgress as e: raise HTTPException(409, detail={"error": "sync_in_progress", "progress": e.progress})
    except GmailAuthError as e: raise HTTPException(401, detail={"error": "gmail_auth_expired", "message": str(e), "hint": _reauth_hint()})

@sync_router.get("/sync")
async def sync_status(account: Account = Depends(get_current_account), db: AsyncSession = Depends(get_session)):
    return await read_status(db, account.id)

@sync_router.get("/me")
async def me(account: Account = Depends(get_current_account)):
    return {
        "connected": bool(account.refresh_token or account.access_token),
        "gmail_connected": bool(account.refresh_token or account.access_token),
        "email": account.email,
        "name": account.display_name or account.email.split("@")[0],
        "provider": account.provider,
        "last_sync": account.last_sync_at.isoformat() if account.last_sync_at else None,
        "client_url": settings.client_url,
        # E2E at-rest encryption: true when TOKEN_ENCRYPTION_KEY (Fernet) is configured
        "enc_at_rest": _fernet is not None,
    }

# ============================ CONTROL DECK (GET /) ============================
DECK_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Prism · Control Deck</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:ital,opsz,wght@0,9..144,400;0,9..144,600;1,9..144,400;1,9..144,600&family=Manrope:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#0b0b0e;--bg2:#101015;--ink:#ECEAE3;--dim:rgba(236,234,227,.62);--faint:rgba(236,234,227,.34);
 --line:rgba(236,234,227,.10);--line2:rgba(236,234,227,.055);--rose:#E0607E;--teal:#46C2A8;--amber:#F2B33D;--sig:var(--faint);
 --disp:'Fraunces',Georgia,serif;--ui:'Manrope',system-ui,sans-serif;--mono:'JetBrains Mono',ui-monospace,monospace;--spring:cubic-bezier(.22,1.15,.34,1)}
*{box-sizing:border-box;margin:0;padding:0}html,body{height:100%}
body{background:var(--bg);color:var(--ink);font-family:var(--ui);-webkit-font-smoothing:antialiased;overflow-x:hidden;
 background-image:linear-gradient(var(--line2) 1px,transparent 1px),linear-gradient(90deg,var(--line2) 1px,transparent 1px);background-size:46px 46px}
body[data-state="auth"]{--sig:var(--rose)}body[data-state="idle"]{--sig:var(--teal)}body[data-state="sync"]{--sig:var(--amber)}body[data-state="error"]{--sig:var(--rose)}
body::before{content:'';position:fixed;inset:-20%;z-index:0;pointer-events:none;opacity:.5;
 background:radial-gradient(40% 40% at 78% 18%,color-mix(in srgb,var(--sig) 30%,transparent),transparent 70%);animation:drift 64s ease-in-out infinite alternate;transition:background .6s}
@keyframes drift{to{transform:translate3d(-6%,5%,0) scale(1.12)}}
body::after{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.04;mix-blend-mode:overlay;
 background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='140' height='140'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.8' numOctaves='2'/%3E%3C/filter%3E%3Crect width='140' height='140' filter='url(%23n)'/%3E%3C/svg%3E")}
.scan{position:fixed;top:0;left:0;right:0;height:2px;z-index:5;opacity:0;transition:opacity .3s;
 background:linear-gradient(90deg,transparent,color-mix(in srgb,var(--sig) 80%,transparent),transparent);background-size:40% 100%}
body[data-state="sync"] .scan{opacity:1;animation:scan 1.4s linear infinite}
@keyframes scan{from{background-position:-40% 0}to{background-position:140% 0}}
.wrap{position:relative;z-index:2;max-width:1180px;margin:0 auto;padding:26px 30px 70px}
.mast{display:flex;align-items:flex-end;justify-content:space-between;gap:20px;padding-bottom:22px;border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:baseline;gap:13px}.mark{font-family:var(--disp);font-style:italic;font-weight:600;font-size:30px;letter-spacing:-.01em}
.mark b{font-style:normal}.brand .tag{font-family:var(--mono);font-size:9.5px;letter-spacing:.26em;color:var(--faint);transform:translateY(-3px)}
.meta{display:flex;align-items:center;gap:18px;font-family:var(--mono);font-size:10px;letter-spacing:.12em;color:var(--faint)}
.cap{display:flex;align-items:center;gap:6px}.cap i{width:7px;height:7px;border-radius:50%;background:var(--faint);transition:.3s}
.cap i.on{background:var(--teal);box-shadow:0 0 9px rgba(70,194,168,.7)}.cap i.bad{background:var(--rose)}#clock{color:var(--dim)}
.kicker{font-family:var(--mono);font-size:10px;letter-spacing:.3em;color:var(--sig);margin:46px 0 14px;transition:color .3s}
.big{font-family:var(--mono);font-weight:600;font-size:clamp(56px,12vw,150px);line-height:.92;letter-spacing:-.04em;text-shadow:0 0 40px color-mix(in srgb,var(--sig) 26%,transparent);transition:text-shadow .3s}
.bigword{font-family:var(--disp);font-style:italic;font-weight:600;font-size:clamp(48px,10vw,124px);line-height:.92;letter-spacing:-.02em}
.biglabel{font-family:var(--mono);font-size:12px;letter-spacing:.06em;color:var(--dim);display:flex;align-items:center;gap:9px;max-width:60ch}
.dot{width:8px;height:8px;border-radius:50%;background:var(--sig);flex-shrink:0;transition:background .3s}
body[data-state="sync"] .dot,body[data-state="idle"] .dot{animation:pulse 1.8s ease-in-out infinite}
@keyframes pulse{50%{opacity:.35;transform:scale(.78)}}
.actions{display:flex;flex-wrap:wrap;gap:11px;margin-top:8px}
.btn{font-family:var(--ui);font-weight:700;font-size:13.5px;color:var(--ink);cursor:pointer;padding:13px 22px;border-radius:11px;border:1px solid var(--line);background:var(--bg2);
 display:inline-flex;align-items:center;gap:10px;transition:transform .18s var(--spring),border-color .2s,background .2s,box-shadow .2s}
.btn .ar{transition:transform .2s var(--spring);color:var(--sig)}
.btn:hover{transform:translateY(-2px);border-color:color-mix(in srgb,var(--sig) 55%,var(--line));background:color-mix(in srgb,var(--sig) 9%,var(--bg2));box-shadow:0 12px 30px rgba(0,0,0,.4)}
.btn:hover .ar{transform:translateX(3px)}.btn:active{transform:translateY(0) scale(.98)}
.btn.primary{border-color:var(--sig);background:color-mix(in srgb,var(--sig) 12%,var(--bg2))}
.btn[disabled]{opacity:.4;cursor:not-allowed;transform:none;box-shadow:none}.btn.ghost{background:transparent}
.railwrap{margin-top:40px}.railhead{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:12px}
.railhead h2{font-family:var(--disp);font-style:italic;font-weight:400;font-size:21px}.railhead .mode{font-family:var(--mono);font-size:10px;letter-spacing:.16em;color:var(--faint)}
.rail{height:8px;border-radius:99px;background:var(--bg2);border:1px solid var(--line);overflow:hidden;position:relative}
.rail .fill{height:100%;width:0;background:var(--sig);border-radius:99px;transition:width .5s var(--spring),background .3s}
body[data-state="sync"] .rail .fill{width:100%!important;background:linear-gradient(90deg,color-mix(in srgb,var(--sig) 30%,transparent),var(--sig),color-mix(in srgb,var(--sig) 30%,transparent));background-size:200% 100%;animation:shim 1.1s linear infinite}
@keyframes shim{from{background-position:200% 0}to{background-position:-200% 0}}
.stats{display:flex;flex-wrap:wrap;gap:30px 44px;margin-top:22px}.stat .n{font-family:var(--mono);font-weight:600;font-size:42px;line-height:1;letter-spacing:-.03em}
.stat.lead .n{font-size:62px}.stat .l{font-family:var(--mono);font-size:9.5px;letter-spacing:.22em;color:var(--faint);margin-top:8px}
.logwrap{margin-top:46px}.logwrap h2{font-family:var(--disp);font-style:italic;font-weight:400;font-size:21px;margin-bottom:12px}
.log{font-family:var(--mono);font-size:11.5px;line-height:1.85;color:var(--dim);background:rgba(0,0,0,.28);border:1px solid var(--line);border-radius:13px;padding:15px 17px;height:230px;overflow-y:auto}
.log .ln{opacity:0;transform:translateY(6px)}.log .ln.in{opacity:1;transform:none;transition:opacity .35s,transform .35s var(--spring)}
.log .t{color:var(--faint);margin-right:10px}.log .ln.ok .m{color:var(--teal)}.log .ln.warn .m{color:var(--amber)}.log .ln.err .m{color:var(--rose)}
.log .caret{display:inline-block;width:7px;height:13px;background:var(--sig);vertical-align:-2px;margin-left:3px;animation:blink 1s steps(1) infinite}
@keyframes blink{50%{opacity:0}}
.foot{margin-top:48px;padding-top:20px;border-top:1px solid var(--line);display:flex;flex-wrap:wrap;gap:8px 22px;font-family:var(--mono);font-size:10px;letter-spacing:.12em;color:var(--faint)}
.foot b{color:var(--dim);font-weight:600}
.rv{opacity:0;transform:translateY(14px)}.rv.in{opacity:1;transform:none;transition:opacity .6s ease,transform .6s var(--spring)}
@media(max-width:640px){.wrap{padding:20px 18px 60px}.meta{gap:12px}.stats{gap:22px 30px}}
</style></head>
<body data-state="auth"><div class="scan"></div><div class="wrap">
 <header class="mast"><div class="brand"><span class="mark"><b>Prism</b> <i>deck</i></span><span class="tag">LOCAL · NO SCHEDULERS</span></div>
  <div class="meta"><span class="cap"><i id="capGmail"></i>GMAIL</span><span class="cap"><i id="capLlm"></i>LLM</span><span id="clock">--:--:--</span></div></header>
 <div class="kicker" id="kicker">CONNECTION</div>
 <section class="focal"><div class="big" id="big">—</div><div class="bigword" id="bigword" hidden></div>
  <div class="biglabel"><span class="dot"></span><span id="biglabel">no account connected</span></div><div class="actions" id="actions"></div></section>
 <section class="railwrap rv"><div class="railhead"><h2>Sync pipeline</h2><span class="mode" id="mode">idle</span></div>
  <div class="rail"><div class="fill" id="fill"></div></div>
  <div class="stats"><div class="stat lead"><div class="n" id="sFetched" data-v="0">0</div><div class="l">FETCHED</div></div>
   <div class="stat"><div class="n" id="sInserted" data-v="0">0</div><div class="l">INSERTED</div></div>
   <div class="stat"><div class="n" id="sUpdated" data-v="0">0</div><div class="l">REFRESHED</div></div>
   <div class="stat"><div class="n" id="sSkipped" data-v="0">0</div><div class="l">SKIPPED</div></div></div></section>
 <section class="logwrap rv"><h2>Event log</h2><div class="log" id="log"></div></section>
 <footer class="foot rv"><span><b>Prism</b> mail backend</span><span>API <b id="apiHost"></b></span>
  <span>You pull mail when you choose to — nothing runs in the background.</span></footer>
</div>
<script>
"use strict";
var API=location.origin,$=function(s){return document.querySelector(s);},TK="prism_token";
function tok(){try{return sessionStorage.getItem(TK);}catch(e){return null;}}
function setTok(t){try{t?sessionStorage.setItem(TK,t):sessionStorage.removeItem(TK);}catch(e){}}
(function(){var m=/prism_token=([^&]+)/.exec(location.hash||"");if(m){setTok(decodeURIComponent(m[1]));history.replaceState(null,"",location.pathname+location.search);}})();
$("#apiHost").textContent=location.host;
var me=null,sync=null,poll=null,lastFetched=-1;
function api(p,o){o=o||{};var h={"Accept":"application/json"};if(o.body)h["Content-Type"]="application/json";var t=tok();if(t)h["Authorization"]="Bearer "+t;
 var init={method:o.method||"GET",headers:h};if(o.body)init.body=JSON.stringify(o.body);
 return fetch(API+p,init).then(function(r){
  if(r.status===401){if(!o.soft)setTok(null);throw Object.assign(new Error("401"),{code:401});}
  if(r.status===409){return r.json().then(function(j){throw Object.assign(new Error("409"),{code:409,progress:j.progress});});}
  if(!r.ok)throw new Error("HTTP "+r.status);return r.json();});}
function log(msg,kind){var el=document.createElement("div");el.className="ln "+(kind||"");var d=new Date();
 var ts=[d.getHours(),d.getMinutes(),d.getSeconds()].map(function(n){return String(n).padStart(2,"0");}).join(":");
 el.innerHTML='<span class="t">'+ts+'</span><span class="m">'+msg+'</span>';var box=$("#log");var c=box.querySelector(".caret");if(c)c.remove();
 box.appendChild(el);var cc=document.createElement("span");cc.className="caret";box.appendChild(cc);
 while(box.querySelectorAll(".ln").length>60)box.removeChild(box.querySelector(".ln"));
 requestAnimationFrame(function(){el.classList.add("in");});box.scrollTop=box.scrollHeight;}
function num(id,to){var el=$(id),from=+el.dataset.v||0;if(from===to){el.textContent=to;return;}var t0=performance.now();
 (function step(now){var p=Math.min(1,(now-t0)/480);var v=Math.round(from+(to-from)*(1-Math.pow(1-p,3)));el.textContent=v;if(p<1)requestAnimationFrame(step);else el.dataset.v=to;})(t0);}
function setState(s){document.body.dataset.state=s;}
function localPart(e){return (e||"").split("@")[0]||"you";}
function focal(st){var big=$("#big"),word=$("#bigword"),lab=$("#biglabel"),act=$("#actions"),k=$("#kicker");act.innerHTML="";
 if(st==="auth"){k.textContent="CONNECTION";big.hidden=false;word.hidden=true;big.textContent="—";lab.textContent="no account connected — sign in with Gmail to begin";
  act.innerHTML='<button class="btn primary" data-act="connect">Connect Gmail <span class="ar">→</span></button>';}
 else if(st==="sync"){k.textContent="SYNCING";big.hidden=false;word.hidden=true;lab.textContent="pulling from Gmail · "+(sync&&sync.mode||"")+" · commit per page, resumable";
  act.innerHTML='<button class="btn" disabled>syncing…</button><button class="btn ghost" data-act="open">Open mail client <span class="ar">→</span></button>';}
 else if(st==="error"){k.textContent="SYNC HALTED";big.hidden=false;word.hidden=true;big.textContent="!";lab.textContent=(sync&&sync.last_error)||"something stopped the pull — what succeeded is saved";
  act.innerHTML='<button class="btn primary" data-act="sync">Retry sync <span class="ar">→</span></button><button class="btn ghost" data-act="connect">Reconnect</button>';}
 else{k.textContent=(sync&&sync.full_sync_completed)?"CONNECTED · IN SYNC":"CONNECTED · NOT SYNCED YET";big.hidden=true;word.hidden=false;word.textContent=localPart(me&&me.email);
  var tail=(sync&&sync.full_sync_completed)?"in sync · "+(sync.finished_at?sync.finished_at.replace("T"," ").slice(0,16):""):"connected · pull your mail when ready";
  lab.textContent=(me&&me.email)+" · "+tail;
  act.innerHTML='<button class="btn primary" data-act="sync">'+((sync&&sync.full_sync_completed)?"Sync again":"Sync now")+' <span class="ar">→</span></button>'+
   '<button class="btn" data-act="open">Open mail client <span class="ar">→</span></button><button class="btn ghost" data-act="disconnect">Disconnect</button>';}}
function paintSync(){if(!sync)return;num("#sFetched",sync.fetched||0);num("#sInserted",sync.inserted||0);num("#sUpdated",sync.updated||0);num("#sSkipped",sync.skipped||0);
 $("#mode").textContent=(sync.running?"running · ":"")+(sync.mode||"idle");$("#fill").style.width=(sync.running||sync.full_sync_completed)?"100%":"0%";}
function refresh(){return Promise.all([api("/api/me",{soft:true}).catch(function(){return null;}),api("/api/sync",{soft:true}).catch(function(){return null;})]).then(function(r){
 me=r[0];sync=r[1];if(!me){setState("auth");focal("auth");stopPoll();return;}paintSync();
 var st=sync&&sync.running?"sync":(sync&&sync.status==="failed"?"error":"idle");setState(st);focal(st);
 if(sync&&sync.running){startPoll();if(lastFetched!==-1&&sync.fetched>lastFetched)log("progress · fetched "+sync.fetched+" · inserted "+sync.inserted);lastFetched=sync.fetched;}
 else{stopPoll();lastFetched=-1;if(sync&&sync.status==="done")log("sync complete · inserted "+sync.inserted+" · updated "+sync.updated,"ok");}});}
function startPoll(){if(poll)return;poll=setInterval(refresh,900);}function stopPoll(){if(poll){clearInterval(poll);poll=null;}}
function doSync(){log("sync requested");api("/api/sync",{method:"POST"}).then(function(j){log("sync started · "+(j.mode||"")+" · capped "+(j.fetched||0)+" this call","ok");setState("sync");focal("sync");startPoll();refresh();}).catch(function(e){
 if(e.code===409){log("a sync is already running — attaching to its progress","warn");setState("sync");focal("sync");startPoll();}
 else if(e.code===401){log("session expired — reconnect","err");setTok(null);setState("auth");focal("auth");}
 else{log("sync failed: "+(e&&e.message),"err");refresh();}});}
function connect(){log("opening Gmail consent…");location.href=API+"/auth/gmail/start?redirect="+encodeURIComponent(location.origin+"/");}
function openClient(){if(!tok()){log("connect first","warn");return;}var base=(me&&me.client_url)||"http://localhost:8001/prism.html";
 var url=base+(base.indexOf("?")>=0?"&":"#")+"prism_token="+tok();log("opening mail client with your session → "+base.split("/").slice(0,3).join("/"),"ok");window.open(url,"_blank","noopener");}
function disconnect(){setTok(null);me=null;sync=null;setState("auth");focal("auth");stopPoll();log("disconnected","warn");}
document.addEventListener("click",function(e){var b=e.target.closest("[data-act]");if(!b)return;var a=b.getAttribute("data-act");
 if(a==="connect")connect();else if(a==="sync")doSync();else if(a==="open")openClient();else if(a==="disconnect")disconnect();});
fetch(API+"/healthz").then(function(r){return r.json();}).then(function(h){$("#capGmail").className=h.gmail?"on":"bad";$("#capLlm").className=h.llm?"on":"";
 log("backend online · gmail "+(h.gmail?"configured":"missing")+" · llm "+(h.llm?"configured":"fallback"),h.gmail?"ok":"warn");}).catch(function(){log("backend unreachable at "+API,"err");});
(function tick(){var d=new Date();$("#clock").textContent=[d.getHours(),d.getMinutes(),d.getSeconds()].map(function(n){return String(n).padStart(2,"0");}).join(":");})();setInterval(tick,1000);
var io=new IntersectionObserver(function(es){es.forEach(function(x){if(x.isIntersecting){x.target.classList.add("in");io.unobserve(x.target);}});},{threshold:.1});
document.querySelectorAll(".rv").forEach(function(el){io.observe(el);});
log("control deck ready · api "+location.host);if(tok())log("session restored from this browser","ok");refresh();
</script></body></html>"""

page_router = APIRouter(tags=["deck"])
@page_router.get("/", response_class=HTMLResponse, include_in_schema=False)
def deck():
    if os.environ.get("VERCEL"):
        return RedirectResponse("/prism.html")
    return DECK_HTML

# ============================ SECURITY HEADERS ============================
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds essential security headers to every response."""
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # Content-Security-Policy: tight for API responses
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://accounts.google.com https://fonts.googleapis.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self' https://www.googleapis.com https://oauth2.googleapis.com; "
            "frame-ancestors 'none'"
        )
        return response

# ============================ APP + LIFESPAN ============================
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Never let startup fail (e.g. a flaky DB on Vercel) — the API must boot;
    # /healthz reports db health and tables are re-created lazily if missing.
    try:
        if _is_sqlite:
            # WAL so background sync writes never block reads / the OAuth callback
            async with engine.begin() as conn:
                await conn.exec_driver_sql("PRAGMA journal_mode=WAL")
                await conn.exec_driver_sql("PRAGMA busy_timeout=30000")
        async with engine.begin() as conn:           # auto-create tables (no Alembic step)
            await conn.run_sync(Base.metadata.create_all)
        if _is_sqlite:
            # lightweight column migration for columns added after v1.3 (safe no-op if present)
            for col_sql in ("ALTER TABLE messages ADD COLUMN att_count INTEGER DEFAULT 0",
                            "ALTER TABLE messages ADD COLUMN list_unsub VARCHAR(512)",
                            "ALTER TABLE messages ADD COLUMN att_names TEXT"):
                try:
                    async with engine.begin() as conn:
                        await conn.exec_driver_sql(col_sql)
                except Exception:
                    pass
    except Exception:
        log.exception("lifespan: DB init failed — continuing without it")
    if not settings.gmail_client_id: log.warning("GMAIL_CLIENT_ID empty — Connect will 500 until set in .env")
    if not settings.llm_api_key: log.info("LLM_API_KEY empty — using deterministic fallback drafts/classifications")
    log.info("Prism backend ready on %s", settings.app_base_url)
    yield

app = FastAPI(title="Prism Mail Backend", version="1.3.0", lifespan=lifespan)

@app.exception_handler(HoneypotServed)
async def _honeypot_served_handler(request, exc):
    """Hand any suspicious unauthenticated caller the DECOY dataset (HTTP 200 with fake data)."""
    log.warning("HONEYPOT ENGAGED — decoy payload served to %s", request.client.host if request.client else "?")
    return JSONResponse(status_code=200, content=_hp_decoy_payload())

_origins = ["*"] if (settings.cors_allow_all or "*" in settings.parsed_frontend_origins) else settings.parsed_frontend_origins
try:
    from fastapi.middleware.cors import CORSMiddleware
    app.add_middleware(CORSMiddleware, allow_origins=_origins, allow_credentials=True,
                       allow_methods=["*"], allow_headers=["*"], expose_headers=["*"])
except Exception:
    log.warning("CORS middleware unavailable")
# Security headers applied after CORS (outermost layer)
try:
    app.add_middleware(SecurityHeadersMiddleware)
except Exception:
    log.warning("SecurityHeadersMiddleware unavailable; skipping security headers")

app.include_router(account_auth_router)
app.include_router(auth_router)
app.include_router(mail_router)
app.include_router(clusters_router)
app.include_router(sync_router)
app.include_router(page_router)

@app.get("/api/version")
def api_version():
    """Real update status: current app version vs optional newer release.
    Configure LATEST_VERSION / UPDATE_URL in .env (or leave empty = up to date)."""
    latest = settings.latest_version.strip()
    return {"current": "1.3", "latest": latest or "1.3", "url": settings.update_url.strip() or None}

@app.get("/healthz")
async def healthz(db: AsyncSession = Depends(get_session)):
    db_ok = False; db_err = ""
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception as e:
        db_err = str(e)[:400]
    return {"ok": db_ok, "db": db_ok, "db_err": db_err, "llm": bool(settings.llm_api_key), "gmail": bool(settings.gmail_client_id), "enc_at_rest": _fernet is not None}

# ============================ RUN ============================
if os.environ.get("VERCEL"):
    # Vercel boots this module directly (FastAPI framework preset). Serve the
    # frontend + assets too — the mangum api/index.py path may never run.
    from pathlib import Path
    from fastapi.responses import FileResponse
    _ROOT = Path(__file__).resolve().parent
    _ALLOWED_STATIC = {
        "prism.html", "boot-splash.png", "boot-logo.jpg", "splash.mp4",
        "app icon neon.jpg", "Screenshot 2026-08-02 213509 borderless.png",
        "Screenshot 2026-08-02 213509.png",
    }

    @app.get("/{path:path}", include_in_schema=False)
    async def _serve_static(path: str):
        if path in _ALLOWED_STATIC and (_ROOT / path).is_file():
            return FileResponse(_ROOT / path)
        raise HTTPException(status_code=404, detail="Not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
# >>>>>>>>>>>>>  TRUE END OF app.py — nothing appends after this  <<<<<<<<<<<