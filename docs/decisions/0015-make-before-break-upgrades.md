# 0015. Upgrades replace the BPF object make-before-break

Date: 2026-10-23 · Status: Accepted (recorded in Phase 11 for a decision
taken earlier; see the design notes linked below)

## Context
A new release usually changes the BPF object. Removing the old programs
before attaching the new ones leaves a window with no enforcement.
`BPF_LINK_UPDATE` cannot replace LSM or tracing links.

## Decision
- The new object loads beside the running one (`/sys/fs/bpf/rk-next`), takes
  over the policy and bindings, and attaches all its programs while the old
  ones still run (any deny wins). Only then is the old set removed
  (Phase 10).
- Every intermediate state is recoverable after a crash.

## Consequences
- Upgrades never open a gap: the upgrade suite and both package tests run a
  probe through the switch and require zero successful denied actions.
- For a moment both generations enforce, so the policy is briefly the
  stricter of the two.
