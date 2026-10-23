# 0009. cgroup v2 is the governance unit

Date: 2026-10-23 · Status: Accepted (recorded in Phase 11 for a decision
taken earlier; see the design notes linked below)

## Context
Policy must follow a workload and everything it starts, without tracking
PIDs, races on fork, or per-process bookkeeping.

## Decision
- A profile is bound to a cgroup v2 directory (`rk.slice/...`, or a
  Kubernetes pod's cgroup through NRI). Every hook looks up the current task's
  cgroup id in `rk_cgroup_profile`.
- `rk run` creates one cgroup per agent and places the agent in it atomically
  with `clone3(CLONE_INTO_CGROUP)` (Phase 5).
- Ungoverned cgroups take the fast path and are never affected.

## Consequences
- Children inherit governance by construction; there is no window between
  fork and binding.
- cgroup v2 (the unified hierarchy) is required; `rk doctor` checks it.
