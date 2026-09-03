"""
Discord Webhook Notifier
========================
Fires a rich embed to a Discord channel when the engine returns WARN or BLOCK.

Configuration (set as Vercel environment variables):
  DISCORD_WEBHOOK_URL   — the full Discord webhook URL (required to enable)
  DISCORD_NOTIFY_BLOCK  — set "true" to also notify on BLOCK (default: false)
  RK_DASHBOARD_URL      — base URL for the dashboard link (default: realitykernel.dev)

The notifier is completely non-blocking:
  - Uses httpx with a tight 4-second timeout
  - Any exception is swallowed and logged — a Discord outage NEVER blocks the engine
  - Called after the audit log write so it never delays the API response to the agent
"""

from __future__ import annotations

import hmac
import hashlib
import logging
import os
import time
from datetime import datetime, timezone, timedelta

import httpx

logger = logging.getLogger("rk_discord")

NOTIFY_BLOCK     = os.environ.get("DISCORD_NOTIFY_BLOCK", "false").lower() == "true"
DASHBOARD_URL    = os.environ.get("RK_DASHBOARD_URL", "https://www.realitykernel.dev").rstrip("/")
GLOBAL_WEBHOOK   = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
SERVER_SECRET    = os.environ.get("RK_SECRET_KEY", "").encode()

# Colour codes (Discord uses decimal)
_COLOUR_WARN  = 0xF4A429   # amber
_COLOUR_BLOCK = 0xE03030   # red
_COLOUR_INFO  = 0x2ECC71   # green (not used for alerts)


def _should_notify(verdict: str, webhook_url: str) -> bool:
    if not webhook_url:
        return False
    if verdict == "WARN":
        return True
    if verdict == "BLOCK" and NOTIFY_BLOCK:
        return True
    return False


def _truncate(s: str, n: int) -> str:
    if not s:
        return ""
    return s if len(s) <= n else s[:n] + "…"


def _generate_action_token(action_id: str, decision: str) -> tuple[str, str]:
    """Generates a 24h HMAC-SHA256 token for direct Discord actions."""
    if not SERVER_SECRET:
        # Fallback for dev if secret not set, though api/index.py generates one
        secret = b"dev-fallback-secret-12345"
    else:
        secret = SERVER_SECRET
        
    expires_at = str(int((datetime.now(timezone.utc) + timedelta(hours=24)).timestamp()))
    payload = f"{action_id}:{decision}:{expires_at}".encode()
    sig = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return sig, expires_at


def _build_payload(
    verdict: str,
    action_id: str,
    command: str,
    prime_intent: str,
    confidence: float,
    max_divergence: float,
    worlds_evaluated: int,
    evidence: list[str],
    session_id: str = "",
    agent_id: str = "",
) -> dict:
    """Build the Discord embed payload."""

    timestamp = datetime.now(timezone.utc).isoformat()
    colour    = _COLOUR_WARN if verdict == "WARN" else _COLOUR_BLOCK

    # Verdict line
    if verdict == "WARN":
        verdict_display = "🟡  WARN — Human Review Required"
        description     = (
            "The Reality Kernel detected a **suspicious trajectory**. "
            "The agent is paused and waiting for operator decision."
        )
    else:
        verdict_display = "🔴  BLOCK — Reflexive Collapse Triggered"
        description     = (
            "The Reality Kernel triggered a **reflexive collapse**. "
            "The action has been blocked. No operator action required."
        )

    # Evidence field — max 3 lines to keep embed compact
    evidence_clean = [e for e in evidence if not e.startswith("prev_hash:")]
    evidence_text  = "\n".join(f"• {_truncate(e, 100)}" for e in evidence_clean[:3])
    if not evidence_text:
        evidence_text = "*No causal evidence captured*"

    # Dashboard link — goes straight to audit log
    dashboard_link = f"{DASHBOARD_URL}/dashboard"

    fields = [
        {
            "name":   "System Command",
            "value":  f"```{_truncate(command, 200)}```",
            "inline": False,
        },
        {
            "name":   "Prime Intent",
            "value":  f"*{_truncate(prime_intent, 200)}*",
            "inline": False,
        },
        {
            "name":   "Confidence",
            "value":  f"`{confidence:.0%}`",
            "inline": True,
        },
        {
            "name":   "Max Divergence",
            "value":  f"`{max_divergence:.3f}`",
            "inline": True,
        },
        {
            "name":   "Worlds Evaluated",
            "value":  f"`{worlds_evaluated}`",
            "inline": True,
        },
        {
            "name":   "Causal Evidence",
            "value":  evidence_text,
            "inline": False,
        },
        {
            "name":   "Action ID",
            "value":  f"`{action_id}`",
            "inline": True,
        },
    ]

    # Optional fields only if populated
    if session_id:
        fields.append({"name": "Session", "value": f"`{_truncate(session_id, 40)}`", "inline": True})
    if agent_id:
        fields.append({"name": "Agent", "value": f"`{_truncate(agent_id, 40)}`", "inline": True})

    # Dashboard link — goes straight to audit log / direct action
    dashboard_link = f"{DASHBOARD_URL}/dashboard"
    
    app_sig, app_exp = _generate_action_token(action_id, "approved")
    rej_sig, rej_exp = _generate_action_token(action_id, "rejected")
    
    app_url = f"{dashboard_link}?action=approve&action_id={action_id}&token={app_sig}&expires={app_exp}"
    rej_url = f"{dashboard_link}?action=reject&action_id={action_id}&token={rej_sig}&expires={rej_exp}"

    fields.append({
        "name":   "Review on Dashboard",
        "value":  f"[✅ Approve Action]({app_url}) • [❌ Block Action]({rej_url})",
        "inline": False,
    })

    embed = {
        "title":       verdict_display,
        "description": description,
        "color":       colour,
        "fields":      fields,
        "footer":      {
            "text": "Reality Kernel · Causal Divergence Engine",
        },
        "timestamp": timestamp,
    }

    return {
        "username":   "Reality Kernel",
        "avatar_url": f"{DASHBOARD_URL}/favicon.ico",
        "embeds":     [embed],
    }


def notify(
    verdict: str,
    action_id: str,
    command: str,
    prime_intent: str,
    confidence: float,
    max_divergence: float,
    worlds_evaluated: int,
    evidence: list[str],
    webhook_url: str,
    session_id: str = "",
    agent_id: str = "",
) -> None:
    """
    Fire a Discord webhook notification to a specific user's webhook URL.

    Completely non-blocking — any failure is silently logged.
    Never raises. Never delays the API response.
    """
    final_webhook = (webhook_url or "").strip() or GLOBAL_WEBHOOK
    if not _should_notify(verdict, final_webhook):
        return

    payload = _build_payload(
        verdict=verdict,
        action_id=action_id,
        command=command,
        prime_intent=prime_intent,
        confidence=confidence,
        max_divergence=max_divergence,
        worlds_evaluated=worlds_evaluated,
        evidence=evidence,
        session_id=session_id,
        agent_id=agent_id,
    )

    try:
        with httpx.Client(timeout=4.0) as client:
            r = client.post(final_webhook, json=payload)
            if r.status_code not in (200, 204):
                logger.warning(
                    "Discord webhook returned %s: %s",
                    r.status_code, r.text[:200],
                )
            else:
                logger.info("Discord notification sent for action_id=%s verdict=%s", action_id, verdict)
    except Exception as exc:
        # Discord outage / network error — never block the engine
        logger.warning("Discord notification failed (non-fatal): %s", exc)
