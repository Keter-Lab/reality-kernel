# SECURITY AUDIT REPORT — `api/index.py`

Date: 2026-09-03  
Scope: `/api/index.py` in uploaded Rust+eBPF workspace  
Focus areas requested: audit signing fields, silent failures, rate limiting, CORS strictness.

---

## Executive Summary

The API has good baseline hardening (strict CORS allowlist, security headers, bounded payload sizes, idempotency support, auth checks, and explicit transport error handling).  

P0 and P1 remediations have now been applied in code:
- P0 fail-closed mandatory Ed25519 signing is enforced before all audited write paths.
- P1 strict `prev_hash` retrieval is enforced where proof-hash chaining uses latest audit history.

---

## Findings by Severity

## CRITICAL

### 1) Conditional Ed25519 signing allows unsigned audit inserts
**Status:** ✅ FIXED in `api/index.py`.
**Location:** multiple audit-write flows:
- `/v1/check` policy-block branch (`if ed25519_sig: ... _sb_insert_audit(audit_row)`)
- `/v1/check` normal branch
- `/v1/scan`
- `/v1/override`
- `/v1/override/direct`

**Issue:** `_ed25519_sign(...)` returns `""` on failure/unavailable, and code only attaches signature fields under `if ed25519_sig:`. Insert still proceeds without `ed25519_signature` / `ed25519_pubkey`.

**Risk:** audit chain entries can be created without cryptographic attestation, undermining non-repudiation and external verification.

**Exact Fix (mandatory):** make signature generation fail-closed and block audit writes if signature/public key is missing.

```python
# Add near signing helpers

def _require_ed25519_signature(sign_data: str) -> tuple[str, str]:
    if not _ED25519_AVAILABLE or _ed25519_private_key is None or not _ed25519_public_key_b64:
        logger.error("ed25519 unavailable; refusing unsigned audit write")
        raise HTTPException(503, "Signing subsystem unavailable.")

    sig = _ed25519_sign(sign_data)
    if not sig:
        logger.error("ed25519 signing failed; refusing unsigned audit write")
        raise HTTPException(503, "Audit signing failed.")

    return sig, _ed25519_public_key_b64
```

Then replace every conditional pattern:

```python
ed_sign_data = f"{action_id}:{proof_hash}:BLOCK:1.0"
ed25519_sig, ed25519_pubkey = _require_ed25519_signature(ed_sign_data)

audit_row["ed25519_signature"] = ed25519_sig
audit_row["ed25519_pubkey"] = ed25519_pubkey
_sb_insert_audit(audit_row)
```

And for response payloads, include signature fields unconditionally after successful signing.

---

## HIGH

### 2) Silent chain-degradation on audit history read failure
**Status:** ✅ FIXED in `api/index.py` for chain write paths using recent audit history.
**Location:** `_sb_recent_audit(...)` and call sites for `prev_hash`.

**Issue:** `_sb_recent_audit` returns `[]` on transport/non-200 errors instead of raising. Upstream code treats this as “no prior record”, so `prev_hash` becomes empty without distinguishing outage vs true first record.

**Risk:** proof-chain continuity can silently degrade during transient Supabase failures.

**Fix:** for write paths, use a strict variant that raises on read failure:
- `def _sb_recent_audit_strict(...):` raise `HTTPException(502, ...)` on transport/non-200.
- Use strict function in all code paths that compute new chained `proof_hash` before `_sb_insert_audit`.

---

## MEDIUM

### 3) Demo rate limiting is per-instance (serverless bypass window)
**Location:** `_demo_calls` in-memory bucket + `/v1/demo`.

**Issue:** memory-local limiter is not shared across Vercel instances/cold starts.

**Risk:** attacker can exceed intended global rate by fan-out across instances.

**Fix:** move rate-limit state to shared store (Upstash Redis or Supabase RPC/table with atomic window counters).

---

## LOW

### 4) CORS posture is strict and mostly correct; governance improvement recommended
**Location:** `CORSMiddleware` setup and `RK_ALLOWED_ORIGINS` parsing.

**Observation:**
- `allow_origins` explicit allowlist ✅
- no wildcard origin ✅
- `allow_credentials=False` ✅
- limited methods/headers ✅

**Improvement:** add startup validation that rejects malformed origins and enforces `https` (except explicit localhost/dev entries) to prevent accidental misconfiguration through environment variables.

---

## Requested Control Checks (Pass/Fail)

- **Audit signing fields always present:** **PASS** ✅ (P0 fixed)  
- **Silent failure resistance in audit chain:** **PASS** ✅ for recent-history chaining paths (P1 fixed)  
- **Rate limiting robustness:** **PARTIAL** (medium; serverless-instance scope)  
- **CORS strictness:** **PASS** (with low-risk hardening recommendation)

---

## Remediation Priority

1. **P0:** ✅ Completed — mandatory Ed25519 signature/public key enforced with fail-closed behavior (`503` on signing unavailability/failure).  
2. **P1:** ✅ Completed — strict audit history retrieval added via `_sb_recent_audit_strict()` and applied to chain write paths that use latest `prev_hash`.  
3. **P2:** ⏳ Pending — migrate demo limiter to shared backend counter.  
4. **P3:** ⏳ Pending — startup validation for CORS origin configuration.

---

## Final Security Verdict

After P0/P1 code changes, the implementation now satisfies the mandatory audit-signing and strict recent-history chaining requirements. Remaining improvements are P2/P3 hardening recommendations.
