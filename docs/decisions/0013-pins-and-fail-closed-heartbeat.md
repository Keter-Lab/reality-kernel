# 0013. Pinned programs and a fail-closed heartbeat

Date: 2026-10-23 · Status: Accepted (recorded in Phase 11 for a decision
taken earlier; see the design notes linked below)

## Context
Protection that ends when the daemon crashes or restarts is no protection.
But programs that outlive the daemon forever would keep enforcing a policy
nobody maintains.

## Decision
- Programs, maps and links are pinned under `/sys/fs/bpf/rk`; a restarted
  sensor adopts them (Phase 6).
- The sensor writes a heartbeat; when it is older than the timeout (10 s by
  default), every governed ENFORCE action is denied until the sensor returns.
- Ending protection is explicit: `rk-sensor --uninstall`, which package
  removal runs (Phase 10).

## Consequences
- Crashes and restarts never open a gap; a sensor gone for good fails closed.
- `docs/hardening.md` explains the trade-off to operators.
