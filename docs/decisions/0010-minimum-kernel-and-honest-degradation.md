# 0010. Minimum kernel 5.15; honest degradation without BPF LSM

Date: 2026-10-23 · Status: Accepted (recorded in Phase 11 for a decision
taken earlier; see the design notes linked below)

## Context
Many hosts run without `bpf` in the active LSM list. A security tool that
silently enforces less than it claims is worse than one that says so.

## Decision
- Enforcement is supported from 5.15 LTS with BTF and the BPF ring buffer;
  every row of docs/kernel-matrix.md is backed by CI.
- Without BPF LSM, the sensor attaches the network programs only, refuses
  policies that need LSM hooks (exec, file, raw-socket rules) with a clear
  error, and reports `rk_enforcement_available{capability="lsm"} 0` and
  `bpf_lsm: no` in `rk status`.
- `rk doctor` explains the missing feature and the boot parameter that
  enables it (Phase 10).

## Consequences
- The product never reports itself as enforcing rules it cannot enforce.
- Kubernetes CI runs on a kernel without BPF LSM and exercises this path.
