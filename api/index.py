"""
Reality Kernel Vercel Serverless API
====================================
Single FastAPI app — Vercel auto-detects and runs it from /api/index.py.
vercel.json rewrites /v1/* → /api/index/* so client URLs stay clean.

Hardening features:
  • Strict CORS allow-list.
  • Security headers middleware (CSP / XCTO / XFO / Referrer-Policy / HSTS).
  • Real client IP from X-Forwarded-For.
  • Per-key rate limit on /v1/check.
  • Idempotency-Key header support on /v1/check (in-memory, 5-min TTL).
  • Pydantic field caps on inbound strings.
  • Supabase error text is NEVER echoed to the client.
  • GZip + response compression.
  • Health + version probes (/healthz, /v1/version).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
import time
import datetime
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

# ── Ed25519 Signing (Public Verifiability) ────────────────────────────────────
# Lazily import so cold starts without cryptography installed still serve 200s.
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat, PrivateFormat, NoEncryption
    )
    import base64 as _b64
    _ED25519_AVAILABLE = True
except ImportError:
    _ED25519_AVAILABLE = False

# ──────────────────────────────────────────────────────────────────────────────
#  Signing Key & Policy Schemas
# ──────────────────────────────────────────────────────────────────────────────

SERVER_SECRET = os.environ.get("RK_SECRET_KEY", "").encode()
if not SERVER_SECRET:
    import logging
    logging.getLogger("uvicorn.error").warning("RK_SECRET_KEY is missing. Session tokens will not persist across restarts.")
    import secrets
    SERVER_SECRET = secrets.token_bytes(32)

# ── Ed25519 Key Pair ──────────────────────────────────────────────────────────
# The private key seed is derived from RK_SECRET_KEY so it's stable across
# Vercel cold starts. The public key can be freely shared for offline verification.
_ed25519_private_key = None
_ed25519_public_key_b64: str = ""

if _ED25519_AVAILABLE:
    try:
        # Derive a deterministic 32-byte seed from the server secret
        _seed = hashlib.sha256(b"rk_ed25519_v1:" + SERVER_SECRET).digest()
        _ed25519_private_key = Ed25519PrivateKey.from_private_bytes(_seed)
        _pub_raw = _ed25519_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        _ed25519_public_key_b64 = _b64.b64encode(_pub_raw).decode()
    except Exception as _e:
        logging.getLogger("rk_api").warning("Ed25519 key init failed: %s", _e)

def _ed25519_sign(data: str) -> str:
    """Sign `data` with the Ed25519 private key. Returns base64url signature or empty string."""
    if not _ED25519_AVAILABLE or _ed25519_private_key is None:
        return ""
    try:
        raw_sig = _ed25519_private_key.sign(data.encode("utf-8"))
        return _b64.b64encode(raw_sig).decode()
    except Exception:
        return ""


def _require_ed25519_signature(sign_data: str) -> tuple[str, str]:
    if not _ED25519_AVAILABLE or _ed25519_private_key is None or not _ed25519_public_key_b64:
        logger.error("ed25519 unavailable; refusing unsigned audit write")
        raise HTTPException(503, "Signing subsystem unavailable.")

    sig = _ed25519_sign(sign_data)
    if not sig:
        logger.error("ed25519 signing failed; refusing unsigned audit write")
        raise HTTPException(503, "Audit signing failed.")

    return sig, _ed25519_public_key_b64

class LeastAgencyPolicy(BaseModel):
    allowed_tools: list[str] | None = Field(default=None)
    allowed_egress: list[str] | None = Field(default=None)
    read_only_paths: list[str] | None = Field(default=None)


# Make sibling /core importable from a Vercel cold start
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.engine import MAX_COMMAND_LEN, MAX_INTENT_LEN, analyse, is_fast_path
from core.session_tracker import update_and_check_session  # noqa: E402
from core.discord_notifier import notify as discord_notify  # noqa: E402

# ──────────────────────────────────────────────────────────────────────────────
#  Config
# ──────────────────────────────────────────────────────────────────────────────

API_VERSION = "0.4.2-ELITE"

SUPABASE_URL  = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY  = os.environ.get("SUPABASE_SERVICE_KEY", "")

# We don't crash here. We will check these vars in the endpoints and return a 503 instead.
SUPABASE_REST = f"{SUPABASE_URL}/rest/v1" if SUPABASE_URL else ""

RK_ENV = os.environ.get("RK_ENV", "prod").lower()

# Origins allowed to call the API from a browser.
_DEFAULT_ORIGINS = (
    "https://realitykernel.dev,"
    "https://www.realitykernel.dev,"
    "https://rk-alpha-portal.vercel.app"
)
ALLOWED_ORIGINS = [
    o.strip() for o in os.environ.get("RK_ALLOWED_ORIGINS", _DEFAULT_ORIGINS).split(",")
    if o.strip()
]
if RK_ENV == "dev":
    ALLOWED_ORIGINS += [
        "http://localhost:3000", "http://127.0.0.1:3000",
        "http://localhost:5173", "http://127.0.0.1:5173",
        "http://localhost:8000", "http://127.0.0.1:8000",
    ]

FAST_PATH_COST       = 1
FULL_ENGINE_COST     = 5
LOW_CREDIT_THRESHOLD = 0.10

# Rate limits
DEMO_RPM         = int(os.environ.get("RK_DEMO_RPM", "10"))
DEMO_RATE_WINDOW = 60
CHECK_BURST_PM   = int(os.environ.get("RK_CHECK_BURST", "120"))
CHECK_WINDOW     = 60

# ⚠️  SERVERLESS NOTE (VULN-003): These in-memory buckets are NOT shared across
# Vercel cold-start instances. Rate limits are best-effort per instance only.
# TO FIX: Replace with Upstash Redis (UPSTASH_REDIS_URL) or a Supabase RPC.
_demo_calls:  dict = defaultdict(deque)
_check_calls: dict = defaultdict(deque)

# Idempotency cache (best-effort)
_IDEMP_TTL = 300
_idemp_cache: dict = {}

# Max body size
MAX_BODY_BYTES = 64 * 1024   # 64 KiB

logger = logging.getLogger("rk_api")
logger.setLevel(logging.INFO if RK_ENV == "dev" else logging.WARNING)

# Reusable, thread-safe client for Supabase connection pooling
sb_client = httpx.Client(timeout=10)


# ──────────────────────────────────────────────────────────────────────────────
#  App + middleware
# ──────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Reality Kernel API",
    description="Sovereign Reasoning Engine — Vercel + Supabase",
    version=API_VERSION,
    docs_url="/docs" if RK_ENV == "dev" else None,
    redoc_url=None,
    openapi_url="/openapi.json" if RK_ENV == "dev" else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Idempotency-Key"],
    expose_headers=[
        "X-RK-Credits-Remaining", "X-RK-Credits-Limit",
        "X-RK-Credits-Low", "X-RK-Credits-Warning",
        "X-RK-Request-Id", "X-RK-Idempotent-Replay"
    ],
    max_age=600,
)

app.add_middleware(GZipMiddleware, minimum_size=1024)

class ConfigurationGuardMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not SUPABASE_URL or not SUPABASE_KEY:
            if request.url.path in ["/healthz", "/v1/version"]:
                return await call_next(request)
            return JSONResponse(
                {"detail": "Service Unavailable. Supabase environment variables are missing.", "error": "config_error"},
                status_code=503
            )
        return await call_next(request)

app.add_middleware(ConfigurationGuardMiddleware)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "Request body too large"}, status_code=413)

        response: Response = await call_next(request)
        h = response.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        h.setdefault(
            "Permissions-Policy",
            "geolocation=(), camera=(), microphone=()",
        )
        h.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )
        h.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'",
        )
        h.setdefault(
            "X-RK-Request-Id",
            hashlib.sha256(
                f"{time.time()}:{id(request)}".encode()
            ).hexdigest()[:12],
        )
        h.setdefault("X-RK-API-Version", API_VERSION)
        return response


app.add_middleware(SecurityHeadersMiddleware)


# ──────────────────────────────────────────────────────────────────────────────
#  Supabase REST helpers
# ──────────────────────────────────────────────────────────────────────────────

def _sb_headers() -> dict:
    if not SUPABASE_KEY or not SUPABASE_URL:
        raise HTTPException(500, "Server misconfigured.")
    return {
        "apikey":        SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type":  "application/json",
        "Prefer":        "return=representation",
    }


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _fingerprint_text(value: str, label: str) -> str:
    # Changed from zero-retention hash to full plaintext per user request 
    # for auditor visibility. Old logs will remain redacted.
    if not value:
        return ''
    return value


def _validate_discord_webhook(url: str) -> str:
    cleaned = (url or '').strip()
    if not cleaned:
        return ''
    parsed = urlparse(cleaned)
    allowed_hosts = {'discord.com', 'discordapp.com', 'canary.discord.com', 'ptb.discord.com'}
    if parsed.scheme != 'https' or parsed.netloc.lower() not in allowed_hosts or not parsed.path.startswith('/api/webhooks/'):
        raise HTTPException(400, 'Webhook URL must be a valid Discord HTTPS webhook.')
    return cleaned


def _sb_get_key(key_hash: str) -> dict | None:
    url = f"{SUPABASE_REST}/api_keys?key_hash=eq.{key_hash}&select=*"
    try:
        r = sb_client.get(url, headers=_sb_headers())
    except httpx.HTTPError as e:
        logger.warning("supabase get_key transport error: %s", e)
        raise HTTPException(502, "Upstream auth store unreachable.") from e
    if r.status_code != 200:
        logger.warning(
            "supabase get_key non-200: %s %s", r.status_code, r.text[:200]
        )
        raise HTTPException(502, "Upstream auth store error.")
    rows = r.json()
    return rows[0] if rows else None


def _sb_deduct(key_hash: str, cost: int) -> int:
    url = f"{SUPABASE_REST}/rpc/deduct_credits"
    try:
        r = sb_client.post(
            url,
            headers=_sb_headers(),
            json={"p_key_hash": key_hash, "p_cost": cost},
        )
    except httpx.HTTPError as e:
        logger.warning("supabase deduct transport error: %s", e)
        raise HTTPException(502, "Credit ledger unreachable.") from e
    if r.status_code != 200:
        logger.warning(
            "supabase deduct non-200: %s %s", r.status_code, r.text[:200]
        )
        raise HTTPException(402, "Credit deduction failed.")
    try:
        return int(r.json())
    except (ValueError, TypeError) as e:
        raise HTTPException(
            502, "Credit ledger returned malformed payload."
        ) from e


def _sb_insert_audit(row: dict) -> None:
    url = f"{SUPABASE_REST}/audit_log"
    try:
        r = sb_client.post(url, headers=_sb_headers(), json=row)
        if r.status_code not in (200, 201):
            logger.warning("audit write non-200: %s %s", r.status_code, r.text[:200])
            raise HTTPException(502, "Audit ledger write failed.")
    except httpx.HTTPError as e:
        logger.warning("audit write failed: %s", e)
        raise HTTPException(502, "Audit ledger unreachable.")


def _sb_purge_old_audit(key_hash: str, days: int) -> None:
    if days <= 0:
        return
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=days)).isoformat()
    url = f"{SUPABASE_REST}/audit_log?key_hash=eq.{key_hash}&ts=lt.{cutoff}"
    try:
        sb_client.delete(url, headers=_sb_headers())
    except Exception as e:
        logger.warning("Failed to purge old audit logs: %s", e)


def _sb_recent_audit(key_hash: str, limit: int = 50) -> list:
    url = (
        f"{SUPABASE_REST}/audit_log"
        f"?key_hash=eq.{key_hash}&order=ts.desc&limit={limit}"
    )
    try:
        r = sb_client.get(url, headers=_sb_headers())
    except httpx.HTTPError as e:
        logger.warning("supabase audit-list transport error: %s", e)
        return []
    if r.status_code != 200:
        return []
    return r.json()


def _sb_recent_audit_strict(key_hash: str, limit: int = 50) -> list:
    url = (
        f"{SUPABASE_REST}/audit_log"
        f"?key_hash=eq.{key_hash}&order=ts.desc&limit={limit}"
    )
    try:
        r = sb_client.get(url, headers=_sb_headers())
    except httpx.HTTPError as e:
        logger.warning("supabase audit-list transport error (strict): %s", e)
        raise HTTPException(502, "Audit history store unreachable.") from e
    if r.status_code != 200:
        logger.warning(
            "supabase audit-list non-200 (strict): %s %s",
            r.status_code,
            r.text[:200],
        )
        raise HTTPException(502, "Audit history store error.")
    return r.json()


def _sb_insert_audit_chained(row: dict) -> None:
    """Fetch last proof_hash and insert atomically via Supabase RPC."""
    # Get the latest record for this key
    recent = _sb_recent_audit_strict(row["key_hash"], limit=1)
    prev_hash = recent[0].get("proof_hash", "") if recent else ""
    # Recompute proof_hash now that we have the definitive prev_hash
    # (caller passes raw fields, we chain here)
    if "_raw_payload" in row:
        payload_str = row.pop("_raw_payload") + f":{prev_hash}"
        row["proof_hash"] = hashlib.sha256(payload_str.encode()).hexdigest()
        if prev_hash:
            row.setdefault("evidence", [])
            if f"prev_hash:{prev_hash}" not in row["evidence"]:
                row["evidence"].append(f"prev_hash:{prev_hash}")
    _sb_insert_audit(row)


# ──────────────────────────────────────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _client_ip(request: Request) -> str:
    real = request.headers.get("x-real-ip", "")
    if real:
        return real.strip()[:64]
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        ips = [ip.strip() for ip in xff.split(",") if ip.strip()]
        return ips[-1][:64] if ips else "unknown"
    return (request.client.host if request.client else "unknown")[:64]


import re

def _extract_binaries(command: str) -> list[str]:
    parts = re.split(r';|&&|\|\||\|', command)
    binaries = []
    for part in parts:
        part = part.strip()
        if not part:
            continue
        subparts = part.split()
        for token in subparts:
            if "=" in token and not token.startswith("-"):
                continue
            bin_name = token.split("/")[-1].split("\\")[-1]
            bin_name = re.sub(r'["\'`()]', '', bin_name)
            if bin_name:
                binaries.append(bin_name.lower())
            break
    return binaries


def _extract_domains(command: str) -> list[str]:
    # FIX (Bug 4): Original regex only captured hostnames (letters in the URL host).
    # Raw IP addresses like `curl http://1.2.3.4/exfil` were silently skipped because
    # IPs have no alpha characters, so the `any(c.isalpha())` guard excluded them.
    # Now we capture BOTH hostname and IP targets from URLs.

    # Capture hostname/IP from http(s):// URLs — include digits-and-dots (IP addresses)
    urls = re.findall(r'https?://([a-zA-Z0-9][a-zA-Z0-9.\-]*)', command)
    domains = []
    for host in urls:
        domains.append(host.lower())

    # Also detect bare IPv4 addresses used as targets (e.g. nc 1.2.3.4 4444)
    ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    for match in ip_pattern.finditer(command):
        ip = match.group(1)
        # Exclude obvious non-targets (localhost, 0.0.0.0 — already caught by SSRF rules)
        if ip not in ('127.0.0.1', '0.0.0.0', '255.255.255.255'):
            domains.append(ip)

    # Bare domain words (no URL scheme)
    for word in command.split():
        word = word.strip().lower()
        if "." in word and not any(c in word for c in "/:\\'\"()$*"):
            if any(c.isalpha() for c in word):
                domains.append(word)

    return list(set(domains))




def _domain_matches(domain: str, pattern: str) -> bool:
    pattern = pattern.lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return domain == suffix[1:] or domain.endswith(suffix)
    return domain == pattern


def _verify_least_agency_policy(command: str, policy: LeastAgencyPolicy | None, token_scopes: list[str]) -> str | None:
    if not command:
        return None

    if token_scopes:
        scope_map = {
            "fs:read": ["ls", "ll", "la", "dir", "cat", "head", "tail", "less", "more", "view", "wc", "file", "stat", "find", "tree", "pwd", "du", "df"],
            "sys:info": ["echo", "printf", "date", "whoami", "id", "groups", "hostname", "uname", "uptime", "w", "ps", "top", "env", "printenv", "set", "which", "whereis", "type", "man", "help", "info", "history", "lsof", "free", "nproc"],
            "git": ["git"],
            "network": ["ping", "traceroute", "tracepath", "mtr", "nslookup", "dig", "host", "whois", "netstat", "ss", "ip", "ifconfig", "curl", "wget"]
        }
        allowed_bins = set()
        for scope in token_scopes:
            if scope in scope_map:
                allowed_bins.update(scope_map[scope])

        if allowed_bins:
            binaries = _extract_binaries(command)
            for b in binaries:
                if b not in allowed_bins:
                    return f"ScopeViolation: Binary '{b}' is not allowed by token scopes: {token_scopes}."

    if policy:
        if policy.allowed_tools is not None:
            allowed_tools_lower = [t.lower() for t in policy.allowed_tools]
            binaries = _extract_binaries(command)
            for b in binaries:
                if b not in allowed_tools_lower:
                    return f"PolicyViolation: Binary '{b}' is not in allowed_tools list."

        if policy.allowed_egress is not None:
            domains = _extract_domains(command)
            for d in domains:
                matched = False
                for pattern in policy.allowed_egress:
                    if _domain_matches(d, pattern):
                        matched = True
                        break
                if not matched:
                    return f"PolicyViolation: Outbound network request to '{d}' is not in allowed_egress list."

    return None



def _rate_limit(bucket: dict, key: str, limit: int, window: int) -> bool:
    now = time.time()
    q   = bucket[key]
    cutoff = now - window
    while q and q[0] < cutoff:
        q.popleft()
    if len(q) >= limit:
        return False
    q.append(now)
    return True


def _credit_headers(limit: int, used: int) -> dict:
    remaining = max(0, limit - used)
    low = remaining < (limit * LOW_CREDIT_THRESHOLD) if limit else False
    h = {
        "X-RK-Credits-Remaining": str(remaining),
        "X-RK-Credits-Limit":     str(limit),
    }
    if low:
        h["X-RK-Credits-Low"] = "true"
        h["X-RK-Credits-Warning"] = (
            f"Only {remaining} credits left "
            f"({round(remaining/limit*100,1)}% of your limit)."
        )
    return h


def _idemp_get(key_hash: str, idemp: str) -> dict | None:
    if not idemp:
        return None
    now = time.time()
    stale = [k for k, (_, exp) in _idemp_cache.items() if exp < now]
    for k in stale:
        _idemp_cache.pop(k, None)
    entry = _idemp_cache.get((key_hash, idemp))
    if entry and entry[1] >= now:
        return entry[0]
    return None


def _idemp_put(key_hash: str, idemp: str, payload: dict) -> None:
    if not idemp:
        return
    _idemp_cache[(key_hash, idemp)] = (payload, time.time() + _IDEMP_TTL)


# ──────────────────────────────────────────────────────────────────────────────
#  Auth dependency
# ──────────────────────────────────────────────────────────────────────────────

def get_api_key(authorization: str = Header(default="")) -> dict:
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authorization header must be: Bearer <your-api-key>")
    raw = authorization.removeprefix("Bearer ").strip()

    # Check if this is a signed ephemeral session token
    if raw.startswith("rk_session_"):
        parts = raw.split("_")
        if len(parts) != 4:  # rk, session, payload_hex, sig_hex
            raise HTTPException(401, "Malformed session token structure.")
        payload_hex = parts[2]
        sig_hex = parts[3]

        # Verify HMAC signature
        expected_sig = hmac.new(SERVER_SECRET, payload_hex.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, sig_hex):
            raise HTTPException(401, "Invalid session token signature.")

        # Decode and verify payload
        try:
            payload = json.loads(bytes.fromhex(payload_hex).decode("utf-8"))
        except Exception:
            raise HTTPException(401, "Malformed session token payload.")

        exp = payload.get("exp", 0)
        if time.time() > exp:
            raise HTTPException(401, "Session token has expired.")

        kh = payload.get("key_hash", "")
        row = _sb_get_key(kh)
        if not row:
            raise HTTPException(401, "Session key owner not found.")

        status = row.get("status")
        if status == "suspended":
            raise HTTPException(403, "This API key has been suspended.")
        if status == "revoked":
            raise HTTPException(401, "This API key has been revoked.")

        limit = int(row.get("credits_limit", 0) or 0)
        used  = int(row.get("credits_used",  0) or 0)
        if limit and used >= limit:
            raise HTTPException(402, "Credit limit reached. Please top up.")

        return {
            "raw_key": raw,
            "key_hash": kh,
            "row": row,
            "limit": limit,
            "agent_id": payload.get("agent_id", ""),
            "session_id": payload.get("session_id", ""),
            "scopes": payload.get("scopes", []),
            "is_session_token": True
        }

    # Standard Master API Key validation
    if len(raw) < 16 or len(raw) > 256:
        raise HTTPException(401, "Invalid API key.")
    kh  = _hash_key(raw)
    row = _sb_get_key(kh)
    if not row:
        raise HTTPException(401, "Invalid API key.")
    status = row.get("status")
    if status == "suspended":
        raise HTTPException(403, "This API key has been suspended.")
    if status == "revoked":
        raise HTTPException(401, "This API key has been revoked.")
    limit = int(row.get("credits_limit", 0) or 0)
    used  = int(row.get("credits_used",  0) or 0)
    if limit and used >= limit:
        raise HTTPException(402, "Credit limit reached. Please top up.")
    return {
        "raw_key": raw,
        "key_hash": kh,
        "row": row,
        "limit": limit,
        "agent_id": "",
        "session_id": "",
        "scopes": [],
        "is_session_token": False
    }


# ──────────────────────────────────────────────────────────────────────────────
#  Schemas
# ──────────────────────────────────────────────────────────────────────────────

class TokenRequest(BaseModel):
    agent_id:   str = Field(default="", max_length=120)
    session_id: str = Field(default="", max_length=120)
    scopes:     list[str] = Field(default=[])
    ttl:        int = Field(default=3600, ge=60, le=86400)


class CheckRequest(BaseModel):
    command:      str | None = Field(default="", max_length=MAX_COMMAND_LEN)
    prime_intent: str | None = Field(default="", max_length=MAX_INTENT_LEN)
    session_id:   str = Field(default="", max_length=120)
    agent_id:     str = Field(default="", max_length=120)
    policy:       LeastAgencyPolicy | None = None


class OverrideRequest(BaseModel):
    action_id: str = Field(min_length=1, max_length=120, pattern=r'^[a-zA-Z0-9\-_]+$')
    decision:  str = Field(min_length=1, max_length=20, pattern=r'^(approved|rejected)$')


class DirectOverrideRequest(BaseModel):
    action_id: str = Field(min_length=1, max_length=120, pattern=r'^[a-zA-Z0-9\-_]+$')
    decision:  str = Field(min_length=1, max_length=20, pattern=r'^(approved|rejected)$')
    token:     str = Field(min_length=64, max_length=64, pattern=r'^[a-f0-9]{64}$')
    expires:   str = Field(min_length=1, max_length=20, pattern=r'^\d+$')


class WebhookRequest(BaseModel):
    url: str = Field(default="", max_length=500)




# ──────────────────────────────────────────────────────────────────────────────
#  Routes
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "name":    "Reality Kernel API",
        "version": API_VERSION,
        "edge":    "vercel-serverless",
    }


@app.get("/healthz")
def healthz():
    return {"ok": True, "ts": time.time(), "version": API_VERSION}


@app.get("/v1/version")
def version():
    return {
        "api_version": API_VERSION,
        "fast_path_cost":   FAST_PATH_COST,
        "full_engine_cost": FULL_ENGINE_COST,
    }


@app.get("/v1/pubkey")
def get_public_key():
    """Public endpoint — no auth required.

    Returns the Ed25519 public key used to sign all Reality Kernel audit verdicts.
    Anyone (auditors, regulators, customers) can use this to verify that a verdict
    signature in an audit log is authentic, without needing an API key.

    Verification (Python):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        import base64, json

        pub_raw = base64.b64decode(pubkey_b64)
        pub = Ed25519PublicKey.from_public_bytes(pub_raw)
        # sign_data = f"{action_id}:{proof_hash}:{verdict}:{confidence}"
        pub.verify(base64.b64decode(signature_b64), sign_data.encode())  # raises if invalid
    """
    if not _ED25519_AVAILABLE or not _ed25519_public_key_b64:
        raise HTTPException(503, "Ed25519 signing not available on this instance.")
    return {
        "algorithm":  "Ed25519",
        "public_key": _ed25519_public_key_b64,
        "encoding":   "base64-raw",
        "sign_data_format": "{action_id}:{proof_hash}:{verdict}:{confidence}",
        "note": "Use this key to verify any Reality Kernel audit signature offline. No API key required.",
        "version": API_VERSION,
    }



@app.get("/v1/me")
def me(auth=Depends(get_api_key)):
    if auth.get("is_session_token"):
        raise HTTPException(403, "Session tokens cannot access configuration endpoints.")
    r = auth["row"]
    limit = auth["limit"]
    used  = int(r.get("credits_used", 0))
    remaining = max(0, limit - used)
    return {
        "name":              r.get("name"),
        "email":             r.get("email"),
        "company":           r.get("company"),
        "plan":              r.get("plan"),
        "status":            r.get("status"),
        "created_at":        r.get("created_at"),
        "expires_at":        r.get("expires_at"),
        "key_masked":        r["key_prefix"] + "…" + r["key_suffix"],
        "credits_used":      used,
        "credits_limit":     limit,
        "credits_remaining": remaining,
        "pct_used":          round(used / limit * 100, 1) if limit else 0,
        "low_credits":       (
            remaining < (limit * LOW_CREDIT_THRESHOLD) if limit else False
        ),
        "top_up_log":        r.get("top_up_log", []),
        "discord_webhook":   r.get("discord_webhook", ""),
        "strict_mode":       r.get("strict_mode", False),
        "retention_days":    r.get("retention_days", 30),
        "siem_url":          r.get("siem_url", ""),
    }


class SettingsUpdate(BaseModel):
    strict_mode: bool | None = None
    retention_days: int | None = None
    siem_url: str | None = None

@app.patch("/v1/settings")
def update_settings(body: SettingsUpdate, auth=Depends(get_api_key)):
    if auth.get("is_session_token"):
        raise HTTPException(403, "Session tokens cannot access configuration endpoints.")
    payload = {}
    if body.strict_mode is not None:
        payload["strict_mode"] = body.strict_mode
    if body.retention_days is not None:
        payload["retention_days"] = body.retention_days
    if body.siem_url is not None:
        payload["siem_url"] = body.siem_url
        
    if payload:
        url = f"{SUPABASE_REST}/api_keys?key_hash=eq.{auth['key_hash']}"
        try:
            r = sb_client.patch(url, headers=_sb_headers(), json=payload)
            if r.status_code not in (200, 204):
                logger.warning("supabase patch non-200: %s %s", r.status_code, r.text[:200])
                raise HTTPException(502, "Settings update failed.")
        except httpx.HTTPError as e:
            logger.warning("settings patch failed: %s", e)
            raise HTTPException(502, "Ledger unreachable.")
            
    return {"ok": True}



@app.get("/v1/audit")
def get_audit(limit: int = 50, auth=Depends(get_api_key)):
    if auth.get("is_session_token"):
        raise HTTPException(403, "Session tokens cannot access audit logs.")
    safe_limit = max(1, min(int(limit) if limit else 50, 200))
    
    retention_days = auth["row"].get("retention_days")
    if retention_days:
        _sb_purge_old_audit(auth["key_hash"], int(retention_days))
        
    rows = _sb_recent_audit(auth["key_hash"], limit=safe_limit)
    return {"entries": rows, "count": len(rows)}


@app.post("/v1/token")
def generate_token(body: TokenRequest, auth=Depends(get_api_key)):
    if auth.get("is_session_token"):
        raise HTTPException(400, "Cannot generate a session token using another session token.")

    now = int(time.time())
    payload = {
        "key_hash": auth["key_hash"],
        "agent_id": body.agent_id[:120],
        "session_id": body.session_id[:120],
        "scopes": body.scopes,
        "exp": now + body.ttl
    }
    payload_json = json.dumps(payload, sort_keys=True)
    payload_hex = payload_json.encode("utf-8").hex()
    sig_hex = hmac.new(SERVER_SECRET, payload_hex.encode(), hashlib.sha256).hexdigest()

    token = f"rk_session_{payload_hex}_{sig_hex}"
    return {
        "token": token,
        "expires_at": now + body.ttl,
        "scopes": body.scopes,
        "agent_id": body.agent_id,
        "session_id": body.session_id
    }


@app.post("/v1/check")
def check_command(
    body: CheckRequest,
    response: Response,
    request: Request,
    auth=Depends(get_api_key),
    idempotency_key: str = Header(default="", alias="Idempotency-Key"),
):
    cmd_val = body.command or ""
    intent_val = body.prime_intent or ""

    if not _rate_limit(_check_calls, auth["key_hash"], CHECK_BURST_PM, CHECK_WINDOW):
        raise HTTPException(429, "Rate limit exceeded per key.")

    if idempotency_key:
        idempotency_key = idempotency_key.strip()[:128]
        cached = _idemp_get(auth["key_hash"], idempotency_key)
        if cached:
            for k, v in cached.get("_headers", {}).items():
                response.headers[k] = v
            response.headers["X-RK-Idempotent-Replay"] = "true"
            return {k: v for k, v in cached.items() if k != "_headers"}

    # 1. Least Agency Policy Check
    policy_violation = _verify_least_agency_policy(cmd_val, body.policy, auth.get("scopes", []))
    if policy_violation:
        ts = time.time()
        action_id = hashlib.sha256(f"POLICY_BLOCK:{cmd_val}:{ts}".encode()).hexdigest()[:12]

        recent_logs = _sb_recent_audit_strict(auth["key_hash"], limit=1)
        prev_hash = recent_logs[0].get("proof_hash", "") if recent_logs else ""

        policy_str = body.policy.model_dump_json() if body.policy else ""
        payload_str = f"{action_id}:{cmd_val[:500]}:{intent_val[:500]}:BLOCK:1.0:{policy_str}:{prev_hash}"
        proof_hash = hashlib.sha256(payload_str.encode()).hexdigest()

        evidence_list = [policy_violation]
        if prev_hash:
            evidence_list.append(f"prev_hash:{prev_hash}")

        limit = auth["limit"]
        new_used = _sb_deduct(auth["key_hash"], FAST_PATH_COST)
        remaining = max(0, limit - new_used)

        ed_sign_data = f"{action_id}:{proof_hash}:BLOCK:1.0"
        ed25519_sig, ed25519_pubkey = _require_ed25519_signature(ed_sign_data)

        audit_row = {
            "key_hash":      auth["key_hash"],
            "action_id":     action_id,
            "command":       _fingerprint_text(cmd_val, "cmd"),
            "prime_intent":  _fingerprint_text(intent_val, "intent"),
            "session_id":    body.session_id[:120] or auth.get("session_id", "")[:120],
            "agent_id":      body.agent_id[:120] or auth.get("agent_id", "")[:120],
            "verdict":       "BLOCK",
            "confidence":    1.0,
            "evidence":      evidence_list,
            "proof_hash":    proof_hash,
            "cost":          FAST_PATH_COST,
            "credits_after": remaining,
            "fast_path":     True,
            "client_ip":     _client_ip(request),
            "ed25519_signature": ed25519_sig,
            "ed25519_pubkey": ed25519_pubkey,
        }

        _sb_insert_audit(audit_row)

        headers = _credit_headers(limit, new_used)
        for k, v in headers.items():
            response.headers[k] = v

        out = {
            "action_id":         action_id,
            "verdict":           "BLOCK",
            "confidence":        1.0,
            "worlds_evaluated":  0,
            "worlds_in_basin_b": 0,
            "max_divergence":    1.0,
            "evidence":          [policy_violation],
            "proof_hash":        proof_hash,
            "latency_ms":        0.1,
            "credits_consumed":  FAST_PATH_COST,
            "credits_remaining": remaining,
        }

        if idempotency_key:
            _idemp_put(auth["key_hash"], idempotency_key, {**out, "_headers": headers})

        return out

    is_fast = is_fast_path(cmd_val)
    cost    = FAST_PATH_COST if is_fast else FULL_ENGINE_COST

    limit = auth["limit"]
    used  = int(auth["row"].get("credits_used", 0))
    if (used + cost) > limit:
        raise HTTPException(402, "Insufficient credits for this operation.")

    t0 = time.perf_counter()
    
    # Session state tracking
    # Tie the session ledger to the Tenant ID (key_hash) and Agent ID
    # instead of the user-provided session_id, to prevent amnesia via rotation.
    session_id = f"{auth['key_hash']}_{auth.get('agent_id', 'default')}"
    is_escalated, session_evidence = update_and_check_session(
        session_id, cmd_val, sb_client, SUPABASE_REST, _sb_headers()
    )
    
    decision = analyse(
        command=cmd_val,
        prime_intent=intent_val,
        n_worlds=5,
        verbose=False,
        suppress_audit=True,
    )
    
    # Session escalation override
    if is_escalated and decision.verdict == "ALLOW":
        decision.verdict = "WARN"
        decision.confidence = max(decision.confidence, 0.65)
    if is_escalated and decision.verdict == "WARN" and any("Slow-Drip" in e for e in session_evidence):
        decision.verdict = "BLOCK"
        decision.confidence = 1.0
        
    if session_evidence:
        decision.evidence = list(decision.evidence) + session_evidence

    # Strict Mode Enforcement
    strict_mode = auth["row"].get("strict_mode", False)
    if strict_mode and decision.confidence >= 0.85 and decision.verdict != "BLOCK":
        decision.verdict = "BLOCK"
        decision.evidence = list(decision.evidence) + ["Strict Mode Enforcement: Confidence >= 85% automatically blocked."]
        
    latency_ms = round((time.perf_counter() - t0) * 1000, 1)

    new_used  = _sb_deduct(auth["key_hash"], cost)
    remaining = max(0, limit - new_used)

    # 2. Cryptographic Proof Chain Link
    recent_logs = _sb_recent_audit_strict(auth["key_hash"], limit=1)
    prev_hash = recent_logs[0].get("proof_hash", "") if recent_logs else ""

    policy_str = body.policy.model_dump_json() if body.policy else ""
    payload_str = f"{decision.action_id}:{cmd_val[:500]}:{intent_val[:500]}:{decision.verdict}:{decision.confidence}:{policy_str}:{prev_hash}"
    proof_hash = hashlib.sha256(payload_str.encode()).hexdigest()

    evidence_list = list(decision.evidence) if decision.evidence else []
    if prev_hash:
        evidence_list.append(f"prev_hash:{prev_hash}")

    # ── Ed25519 Signature ──────────────────────────────────────────────────────
    # Sign the canonical verdict payload so any third party can verify offline
    # using the public key at /v1/pubkey — no API key required.
    ed_sign_data = f"{decision.action_id}:{proof_hash}:{decision.verdict}:{decision.confidence}"
    ed25519_sig, ed25519_pubkey = _require_ed25519_signature(ed_sign_data)

    audit_row = {
        "key_hash":      auth["key_hash"],
        "action_id":     decision.action_id,
        "command":       _fingerprint_text(cmd_val, "cmd"),
        "prime_intent":  _fingerprint_text(intent_val, "intent"),
        "session_id":    body.session_id[:120] or auth.get("session_id", "")[:120],
        "agent_id":      body.agent_id[:120] or auth.get("agent_id", "")[:120],
        "verdict":       decision.verdict,
        "confidence":    decision.confidence,
        "evidence":      evidence_list,
        "proof_hash":    proof_hash,
        "cost":          cost,
        "credits_after": remaining,
        "fast_path":     is_fast,
        "client_ip":     _client_ip(request),
        "ed25519_signature": ed25519_sig,
        "ed25519_pubkey": ed25519_pubkey,
    }

    _sb_insert_audit(audit_row)

    # ── Discord Alert ─────────────────────────────────────────────────────────
    # Non-blocking: fires AFTER audit write, never delays the API response.
    # Notifies on WARN always; BLOCK only if DISCORD_NOTIFY_BLOCK=true.
    discord_webhook = auth["row"].get("discord_webhook") or ""
    discord_notify(
        verdict=decision.verdict,
        action_id=decision.action_id,
        command=cmd_val,
        prime_intent=intent_val,
        confidence=decision.confidence,
        max_divergence=decision.max_divergence,
        worlds_evaluated=decision.worlds_evaluated,
        evidence=evidence_list,
        webhook_url=discord_webhook,
        session_id=body.session_id[:120] or auth.get("session_id", "")[:120],
        agent_id=body.agent_id[:120] or auth.get("agent_id", "")[:120],
    )

    headers = _credit_headers(limit, new_used)
    for k, v in headers.items():
        response.headers[k] = v

    out = {
        "action_id":         decision.action_id,
        "verdict":           decision.verdict,
        "confidence":        decision.confidence,
        "worlds_evaluated":  decision.worlds_evaluated,
        "worlds_in_basin_b": decision.worlds_in_basin_b,
        "max_divergence":    decision.max_divergence,
        "evidence":          decision.evidence,
        "proof_hash":        proof_hash,
        "latency_ms":        latency_ms,
        "credits_consumed":  cost,
        "credits_remaining": remaining,
    }
    out["ed25519_signature"] = ed25519_sig
    out["ed25519_pubkey"] = ed25519_pubkey

    if idempotency_key:
        _idemp_put(auth["key_hash"], idempotency_key, {**out, "_headers": headers})

    return out


@app.post("/v1/override")
def override_verdict(body: OverrideRequest, auth=Depends(get_api_key)):
    if auth.get("is_session_token"):
        raise HTTPException(403, "Session tokens cannot override verdicts.")
    kh = auth["key_hash"]
    
    url_get = (
        f"{SUPABASE_REST}/audit_log"
        f"?key_hash=eq.{kh}&action_id=eq.{body.action_id}"
        f"&select=proof_hash,command,prime_intent,session_id,agent_id,confidence,client_ip"
    )
    try:
        r_get = sb_client.get(url_get, headers=_sb_headers())
        orig = r_get.json()[0] if r_get.status_code == 200 and r_get.json() else {}
    except Exception:
        orig = {}

    if not orig:
        raise HTTPException(404, "Action not found or access denied.")

    verdict_str = "WARN_APPROVED" if body.decision == "approved" else "WARN_REJECTED"
    conf = float(orig.get("confidence", 0.0))
    prev_hash = orig.get("proof_hash", "")

    import time as _time
    override_action_id = hashlib.sha256(
        f"OVERRIDE:{body.action_id}:{verdict_str}:{_time.time()}".encode()
    ).hexdigest()[:12]
    
    evidence = [f"override_of:{body.action_id}", f"prev_hash:{prev_hash}"]
    if conf > 0.60 and body.decision == "approved":
        evidence.append("Critical override: high-confidence WARN approved by operator")

    payload_str = f"{override_action_id}:override:{body.action_id}:{verdict_str}:1.0::{prev_hash}"
    override_proof = hashlib.sha256(payload_str.encode()).hexdigest()

    ed_sign_data = f"{override_action_id}:{override_proof}:{verdict_str}:1.0"
    ed25519_sig, ed25519_pubkey = _require_ed25519_signature(ed_sign_data)

    audit_row = {
        "key_hash": kh,
        "action_id": override_action_id,
        "command": orig.get("command", "[override]"),
        "prime_intent": orig.get("prime_intent", ""),
        "session_id": orig.get("session_id", ""),
        "agent_id": orig.get("agent_id", ""),
        "verdict": verdict_str,
        "confidence": 1.0,
        "evidence": evidence,
        "proof_hash": override_proof,
        "cost": 0,
        "credits_after": 0,
        "fast_path": True,
        "client_ip": orig.get("client_ip", ""),
        "ed25519_signature": ed25519_sig,
        "ed25519_pubkey": ed25519_pubkey,
    }

    _sb_insert_audit(audit_row)
    return {
        "ok": True,
        "verdict": verdict_str,
        "override_action_id": override_action_id,
        "warning_level": "critical" if conf > 0.60 and body.decision == "approved" else "standard",
    }


@app.post("/v1/override/direct")
def override_verdict_direct(body: DirectOverrideRequest, auth=Depends(get_api_key)):
    if auth.get("is_session_token"):
        raise HTTPException(403, "Session tokens cannot override verdicts.")
    import time as _time
    # Verify expiration
    try:
        if float(body.expires) < _time.time():
            raise HTTPException(400, "Token expired")
    except ValueError:
        raise HTTPException(400, "Invalid expiration format")

    # Verify HMAC
    secret = SERVER_SECRET if SERVER_SECRET else b"dev-fallback-secret-12345"
    payload = f"{body.action_id}:{body.decision}:{body.expires}".encode()
    expected_sig = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, body.token):
        raise HTTPException(403, "Invalid cryptographic token")

    kh = auth["key_hash"]
    verdict_str = "WARN_APPROVED" if body.decision == "approved" else "WARN_REJECTED"
    
    url_fetch = (
        f"{SUPABASE_REST}/audit_log?key_hash=eq.{kh}&action_id=eq.{body.action_id}"
        f"&select=proof_hash,command,prime_intent,session_id,agent_id,client_ip"
    )
    try:
        r_fetch = sb_client.get(url_fetch, headers=_sb_headers())
        orig = r_fetch.json()[0] if r_fetch.status_code == 200 and r_fetch.json() else {}
    except Exception:
        orig = {}

    if not orig:
        raise HTTPException(404, "Action not found or access denied.")

    prev_hash = orig.get("proof_hash", "")
    override_action_id = hashlib.sha256(
        f"OVERRIDE:{body.action_id}:{verdict_str}:{_time.time()}".encode()
    ).hexdigest()[:12]
    payload_str = f"{override_action_id}:direct-override:{body.action_id}:{verdict_str}:1.0::{prev_hash}"
    override_proof = hashlib.sha256(payload_str.encode()).hexdigest()

    ed_sign_data = f"{override_action_id}:{override_proof}:{verdict_str}:1.0"
    ed25519_sig, ed25519_pubkey = _require_ed25519_signature(ed_sign_data)

    audit_row = {
        "key_hash": kh,
        "action_id": override_action_id,
        "command": orig.get("command", "[direct-override]"),
        "prime_intent": orig.get("prime_intent", ""),
        "session_id": orig.get("session_id", ""),
        "agent_id": orig.get("agent_id", ""),
        "verdict": verdict_str,
        "confidence": 1.0,
        "evidence": [f"direct_override_of:{body.action_id}", f"prev_hash:{prev_hash}"],
        "proof_hash": override_proof,
        "cost": 0,
        "credits_after": 0,
        "fast_path": True,
        "client_ip": orig.get("client_ip", ""),
        "ed25519_signature": ed25519_sig,
        "ed25519_pubkey": ed25519_pubkey,
    }

    _sb_insert_audit(audit_row)

    return {"ok": True, "verdict": verdict_str, "override_action_id": override_action_id}



@app.post("/v1/webhook")
def save_webhook(body: WebhookRequest, auth=Depends(get_api_key)):
    if auth.get("is_session_token"):
        raise HTTPException(403, "Session tokens cannot modify webhooks.")
    kh = auth["key_hash"]
    webhook_url = _validate_discord_webhook(body.url)
    url = f"{SUPABASE_REST}/api_keys?key_hash=eq.{kh}"
    patch_data = {"discord_webhook": webhook_url}
    try:
        r = sb_client.patch(url, headers=_sb_headers(), json=patch_data)
    except httpx.HTTPError as e:
        logger.warning("supabase webhook patch transport error: %s", e)
        raise HTTPException(502, "Upstream auth store unreachable.") from e
        
    if r.status_code not in (200, 201, 204):
        logger.warning("supabase webhook patch non-200: %s %s", r.status_code, r.text[:200])
        raise HTTPException(502, "Failed to save webhook to database.")
    
    return {"ok": True}


@app.post("/v1/webhook/test")
def test_webhook(body: WebhookRequest, auth=Depends(get_api_key)):
    if auth.get("is_session_token"):
        raise HTTPException(403, "Session tokens cannot test webhooks.")
    webhook_url = _validate_discord_webhook(body.url)
    discord_notify(
        verdict="WARN",
        action_id="test-action-id",
        command="reality_kernel --verify-integration",
        prime_intent="Verify that Reality Kernel can successfully push alerts to this Discord channel.",
        confidence=1.0,
        max_divergence=1.0,
        worlds_evaluated=5,
        evidence=["This is a test alert requested from the Reality Kernel dashboard."],
        webhook_url=webhook_url,
        session_id="test-session",
        agent_id="Dashboard User"
    )
    return {"ok": True}


# ──────────────────────────────────────────────────────────────────────────────
#  /v1/scan — Batch CI/CD policy check
# ──────────────────────────────────────────────────────────────────────────────

class ScanEntry(BaseModel):
    command:      str = Field(default="", max_length=MAX_COMMAND_LEN)
    prime_intent: str = Field(default="", max_length=MAX_INTENT_LEN)
    label:        str = Field(default="", max_length=256)

class ScanRequest(BaseModel):
    commands:      list[ScanEntry] = Field(default=[], max_length=50)
    fail_on:       str = Field(default="BLOCK", pattern="^(BLOCK|WARN|BLOCK_WARN)$")
    agent_id:      str = Field(default="", max_length=120)
    session_id:    str = Field(default="", max_length=120)
    policy:        LeastAgencyPolicy | None = None


@app.post("/v1/scan")
def scan_commands(
    body: ScanRequest,
    response: Response,
    request: Request,
    auth=Depends(get_api_key),
):
    """
    Batch evaluation for CI/CD pipelines.

    Submits up to 50 (command, intent) pairs through the full analysis engine.
    Returns a per-entry report and a top-level `policy_pass` boolean so pipelines
    can gate on a single field.

    Cost: same as /v1/check per entry (1 credit fast-path, 5 credits full engine).
    Never returns a fabricated result — if the engine is unavailable, it errors loudly.
    """
    if not body.commands:
        raise HTTPException(400, "commands list must not be empty.")

    results = []
    total_cost = 0
    policy_fail = False

    limit = auth["limit"]
    used  = int(auth["row"].get("credits_used", 0))

    for entry in body.commands:
        cmd_val    = (entry.command or "").strip()
        intent_val = (entry.prime_intent or "").strip()
        label      = entry.label or cmd_val[:60]

        # Per-command policy check
        policy_violation = _verify_least_agency_policy(cmd_val, body.policy, auth.get("scopes", []))
        if policy_violation:
            cost = FAST_PATH_COST
            if (used + total_cost + cost) > limit:
                raise HTTPException(402, "Insufficient credits to complete scan.")
            new_used = _sb_deduct(auth["key_hash"], cost)
            total_cost += cost
            verdict = "BLOCK"
            evidence = [policy_violation]
            proof_hash = hashlib.sha256(
                f"POLICY_BLOCK:{cmd_val[:200]}:{intent_val[:200]}:{time.time()}".encode()
            ).hexdigest()
            action_id = proof_hash[:12]
        else:
            is_fast = is_fast_path(cmd_val)
            cost    = FAST_PATH_COST if is_fast else FULL_ENGINE_COST
            if (used + total_cost + cost) > limit:
                raise HTTPException(402, "Insufficient credits to complete scan.")
            new_used = _sb_deduct(auth["key_hash"], cost)
            total_cost += cost

            decision = analyse(
                command=cmd_val,
                prime_intent=intent_val,
                n_worlds=5,
                verbose=False,
                suppress_audit=True,
            )
            
            strict_mode = auth["row"].get("strict_mode", False)
            if strict_mode and decision.confidence >= 0.85 and decision.verdict != "BLOCK":
                decision.verdict = "BLOCK"
                decision.evidence = list(decision.evidence) + ["Strict Mode Enforcement: Confidence >= 85% automatically blocked."]
                
            verdict    = decision.verdict
            evidence   = list(decision.evidence) if decision.evidence else []
            proof_hash = hashlib.sha256(
                f"{decision.action_id}:{cmd_val[:200]}:{intent_val[:200]}:{verdict}:{decision.confidence}".encode()
            ).hexdigest()
            action_id  = decision.action_id

        final_conf = 1.0 if policy_violation else getattr(decision, "confidence", 1.0)
        ed_sign_data = f"{action_id}:{proof_hash}:{verdict}:{final_conf}"
        ed25519_sig, ed25519_pubkey = _require_ed25519_signature(ed_sign_data)

        audit_row = {
            "key_hash":      auth["key_hash"],
            "action_id":     action_id,
            "command":       _fingerprint_text(cmd_val, "cmd"),
            "prime_intent":  _fingerprint_text(intent_val, "intent"),
            "session_id":    body.session_id[:120] or auth.get("session_id", "")[:120],
            "agent_id":      body.agent_id[:120] or auth.get("agent_id", "")[:120],
            "verdict":       verdict,
            "confidence":    final_conf,
            "evidence":      evidence,
            "proof_hash":    proof_hash,
            "cost":          cost,
            "credits_after": new_used,
            "fast_path":     policy_violation or is_fast_path(cmd_val),
            "client_ip":     _client_ip(request),
            "ed25519_signature": ed25519_sig,
            "ed25519_pubkey": ed25519_pubkey,
        }

        _sb_insert_audit(audit_row)

        is_fail = (
            (body.fail_on == "BLOCK"      and verdict == "BLOCK") or
            (body.fail_on == "WARN"       and verdict in ("WARN", "WARN_APPROVED", "WARN_REJECTED")) or
            (body.fail_on == "BLOCK_WARN" and verdict in ("BLOCK", "WARN", "WARN_APPROVED", "WARN_REJECTED"))
        )
        if is_fail:
            policy_fail = True

        results.append({
            "label":      label,
            "verdict":    verdict,
            "evidence":   evidence,
            "proof_hash": proof_hash,
            "action_id":  action_id,
            "fail":       is_fail,
        })

    remaining = max(0, limit - new_used)
    for k, v in _credit_headers(limit, new_used).items():
        response.headers[k] = v

    return {
        "policy_pass":   not policy_fail,
        "fail_on":       body.fail_on,
        "total_entries": len(results),
        "violations":    sum(1 for r in results if r["fail"]),
        "credits_consumed": total_cost,
        "credits_remaining": remaining,
        "results":       results,
    }


@app.post("/v1/demo")
def demo_check(body: CheckRequest, request: Request):
    cmd_val = body.command or ""
    intent_val = body.prime_intent or ""

    ip = _client_ip(request)
    logger.info("playground query from %s: %s", ip, cmd_val[:80])

    # VULN-002 FIX: Removed User-Agent bypass — any client can now be rate limited
    if not _rate_limit(_demo_calls, ip, DEMO_RPM, DEMO_RATE_WINDOW):
        raise HTTPException(429, "Demo rate limit exceeded.")

    t0 = time.perf_counter()
    decision = analyse(
        command=cmd_val,
        prime_intent=intent_val,
        n_worlds=5, verbose=False, suppress_audit=True,
    )
    return {
        "action_id":         decision.action_id,
        "verdict":           decision.verdict,
        "status":            "blocked" if decision.verdict in ("BLOCK", "WARN") else "allowed",
        "confidence":        decision.confidence,
        "worlds_evaluated":  decision.worlds_evaluated,
        "worlds_in_basin_b": decision.worlds_in_basin_b,
        "max_divergence":    decision.max_divergence,
        "evidence":          decision.evidence,
        "proof_hash":        decision.proof_hash,
        "latency_ms":        round((time.perf_counter() - t0) * 1000, 1),
    }


@app.exception_handler(Exception)
async def _unexpected(request: Request, exc: Exception):
    logger.exception("unhandled error: %s", exc)
    return JSONResponse(
        status_code=500,
        content={
            "detail": (
                "Internal error. Please retry; contact support if it persists."
            )
        },
    )
