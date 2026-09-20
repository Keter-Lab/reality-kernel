"""
Reality Kernel Python Client SDK (v0.7.0)
Deterministic cryptographic intent-verification and execution barrier.
"""

from __future__ import annotations

import base64
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from realitykernel.exceptions import (
    ActionBlocked,
    ActionNeedsReview,
    InsufficientCreditsError,
    RateLimitExceededError,
    RealityKernelError,
    SignatureVerificationError,
)


@dataclass
class Verdict:
    action_id: str
    verdict: str                        # "ALLOW" | "WARN" | "BLOCK" | "WARN_APPROVED" | "WARN_REJECTED"
    confidence: float                  # 0.0 - 1.0
    evidence: List[str] = field(default_factory=list)
    proof_hash: str = ""
    ed25519_signature: str = ""
    ed25519_pubkey: str = ""
    latency_ms: float = 0.0
    credits_consumed: int = 0
    credits_remaining: int = 0
    shadow_mode: bool = False
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_allowed(self) -> bool:
        return self.verdict in ("ALLOW", "WARN_APPROVED")

    @property
    def is_blocked(self) -> bool:
        return self.verdict in ("BLOCK", "WARN_REJECTED")

    @property
    def sign_data(self) -> str:
        return f"{self.action_id}:{self.proof_hash}:{self.verdict}:{self.confidence:.2f}"

    def verify(self, pinned_pubkey_b64: Optional[str] = None) -> bool:
        """Verify the Ed25519 cryptographic signature returned by the Reality Kernel."""
        if not self.ed25519_signature:
            return False
        pub_b64 = pinned_pubkey_b64 or self.ed25519_pubkey
        if not pub_b64:
            return False
        try:
            pub_bytes = base64.b64decode(pub_b64)
            pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
            sig_bytes = base64.b64decode(self.ed25519_signature)
            pub.verify(sig_bytes, self.sign_data.encode("utf-8"))
            return True
        except (InvalidSignature, Exception):
            return False


class RealityKernel:
    """
    Reality Kernel client for pre-dispatch intent verification.
    
    Supports:
      - 0.31ms sub-millisecond fast-path checks
      - Cryptographic Ed25519 tamper-proof proof chains
      - Non-breaking safe Shadow Mode (audit without halting)
      - Least Agency Policy enforcement
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        agent_id: Optional[str] = None,
        timeout: float = 10.0,
        shadow_mode: bool = False,
    ):
        self.api_key = api_key or os.environ.get("RK_API_KEY", "")
        if not self.api_key:
            raise RealityKernelError("Missing RK_API_KEY. Pass api_key or set os.environ['RK_API_KEY'].")

        self.base_url = (base_url or os.environ.get("RK_BASE_URL", "https://www.realitykernel.dev")).rstrip("/")
        self.agent_id = agent_id or os.environ.get("RK_AGENT_ID", "")
        self.shadow_mode = shadow_mode
        self._http = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "User-Agent": "realitykernel-python/0.7.0",
            },
        )
        self._pubkey_b64: Optional[str] = None

    def pubkey(self) -> str:
        """Fetch and cache the server's public Ed25519 key for offline verification."""
        if self._pubkey_b64 is None:
            try:
                r = self._http.get("/v1/pubkey")
                r.raise_for_status()
                self._pubkey_b64 = r.json().get("public_key", "")
            except httpx.HTTPError as exc:
                raise RealityKernelError(f"Failed to fetch Reality Kernel public key: {exc}") from exc
        return self._pubkey_b64

    def check(
        self,
        command: str,
        prime_intent: str,
        *,
        session_id: str = "",
        policy: Optional[Dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        verify_signature: bool = True,
        shadow_mode: Optional[bool] = None,
        execution_binding: Optional[Dict[str, Any]] = None,
    ) -> Verdict:
        """
        Evaluate proposed command against prime intent.
        
        If shadow_mode is True, evaluates intent divergence and logs to audit ledger,
        but returns a non-blocking verdict.
        """
        is_shadow = self.shadow_mode if shadow_mode is None else shadow_mode
        body: Dict[str, Any] = {
            "command": command,
            "prime_intent": prime_intent,
            "session_id": session_id,
            "agent_id": self.agent_id,
            "shadow_mode": is_shadow,
        }
        if policy:
            body["policy"] = policy
        if execution_binding:
            body["execution_binding"] = execution_binding

        headers = {"Idempotency-Key": idempotency_key or uuid.uuid4().hex}

        try:
            r = self._http.post("/v1/check", json=body, headers=headers)
        except httpx.HTTPError as exc:
            raise RealityKernelError(f"Transport error connecting to Reality Kernel: {exc}") from exc

        if r.status_code == 402:
            raise InsufficientCreditsError("Insufficient credits — treat as BLOCK.")
        if r.status_code == 429:
            raise RateLimitExceededError("Rate limit exceeded — back off and retry.")
        if r.status_code >= 400:
            detail = r.json().get("detail", r.text) if "application/json" in r.headers.get("content-type", "") else r.text
            raise RealityKernelError(f"HTTP {r.status_code}: {detail}")

        j = r.json()
        verdict = Verdict(
            action_id=j.get("action_id", ""),
            verdict=j.get("verdict", "BLOCK"),
            confidence=float(j.get("confidence", 1.0)),
            evidence=list(j.get("evidence", [])),
            proof_hash=j.get("proof_hash", ""),
            ed25519_signature=j.get("ed25519_signature", ""),
            ed25519_pubkey=j.get("ed25519_pubkey", ""),
            latency_ms=float(j.get("latency_ms", 0.0)),
            credits_consumed=int(j.get("credits_consumed", 0)),
            credits_remaining=int(j.get("credits_remaining", 0)),
            shadow_mode=bool(j.get("shadow_mode", is_shadow)),
            raw=j,
        )

        if verify_signature and not verdict.verify(self.pubkey()):
            raise SignatureVerificationError(f"Cryptographic signature verification FAILED for {verdict.action_id}")

        if r.headers.get("X-RK-Credits-Low") == "true":
            warning_msg = r.headers.get("X-RK-Credits-Warning", "Low credits remaining.")
            print(f"[reality-kernel] Warning: {warning_msg}")

        return verdict

    def guard(
        self,
        command: str,
        prime_intent: str,
        *,
        session_id: str = "",
        policy: Optional[Dict[str, Any]] = None,
        shadow_mode: Optional[bool] = None,
        **kw,
    ) -> Verdict:
        """
        Execution barrier: Raises ActionBlocked or ActionNeedsReview unless allowed.
        
        In shadow mode (or if initialized with shadow_mode=True), does not raise exceptions
        and allows continuous execution while logging cryptographic verdicts.
        """
        is_shadow = self.shadow_mode if shadow_mode is None else shadow_mode
        v = self.check(command, prime_intent, session_id=session_id, policy=policy, shadow_mode=is_shadow, **kw)
        
        if is_shadow or v.shadow_mode:
            if v.verdict in ("BLOCK", "WARN"):
                print(f"[reality-kernel:shadow] action {v.action_id} evaluated as {v.verdict} (audit logged, non-blocking)")
            return v

        if v.verdict == "BLOCK":
            raise ActionBlocked(v)
        if v.verdict == "WARN":
            raise ActionNeedsReview(v)
        return v

    def override(self, action_id: str, approved: bool) -> Dict[str, Any]:
        """Operator override for human-in-the-loop review of WARN actions."""
        try:
            r = self._http.post("/v1/override", json={
                "action_id": action_id,
                "decision": "approved" if approved else "rejected",
            })
            r.raise_for_status()
            return r.json()
        except httpx.HTTPError as exc:
            raise RealityKernelError(f"Override failed: {exc}") from exc

    def close(self):
        """Close underlying HTTP transport."""
        self._http.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
