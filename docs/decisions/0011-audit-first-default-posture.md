# 0011. Explicit mode per profile; roll out in AUDIT, then ENFORCE

Date: 2026-10-23 · Status: Accepted (recorded in Phase 11 for a decision
taken earlier; see the design notes linked below)

## Context
Agents break when a policy they were never tested against starts denying.
Teams adopt enforcement only if they can see what it would do first.

## Decision
- Every profile must state its `mode` (the policy parser has no default, so
  nobody enforces by accident or audits by accident): AUDIT reports
  `audit_would_deny` without blocking; ENFORCE denies. The kernel reports
  both through the same events and counters.
- The documented rollout (docs/policy.md) starts a new profile in AUDIT and
  switches it to ENFORCE once its audit-would-deny records are reviewed.
- The stale-heartbeat rule fails closed for ENFORCE only (Phase 6); AUDIT
  workloads are never disrupted by the sensor's absence.

## Consequences
- The audit log and `rk_rule_hits_total` show exactly what ENFORCE would
  deny before anyone switches it on.
- Moving a profile to ENFORCE is a reviewed policy change, applied atomically
  (ADR-0005).
