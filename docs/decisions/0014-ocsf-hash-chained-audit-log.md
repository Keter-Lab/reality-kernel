# 0014. OCSF audit records in a hash-chained, signed log

Date: 2026-10-23 · Status: Accepted (recorded in Phase 11 for a decision
taken earlier; see the design notes linked below)

## Context
Operators need a record of every decision that standard tools can ingest and
that an attacker cannot quietly edit.

## Decision
- One OCSF 1.9.0 record per deny and audit-would-deny (Phase 9).
- Batches are hashed over the bytes as written, chained to the previous batch
  and signed with a per-host Ed25519 key; `rk audit verify` checks the chain.
- Lost events are recorded as loss records, so the log is complete by count;
  the kernel counts every decision independently.

## Consequences
- SIEMs ingest the records as is; tampering is detected (VM test
  `audit_tamper_detected`).
- Truncation by host root and key theft are documented limits
  (docs/threat-model.md).
