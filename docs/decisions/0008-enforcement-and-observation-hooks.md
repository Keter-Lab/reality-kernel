# 0008. BPF-LSM and cgroup sock_addr hooks enforce; tracepoints observe

Date: 2026-10-23 · Status: Accepted (recorded in Phase 11 for a decision
taken earlier; see the design notes linked below)

## Context
Syscall-entry tracepoints can observe but never deny, and a userspace verdict
arrives after the action. Enforcement must happen in a hook that can return
an error, on resolved kernel objects (no TOCTOU on paths).

## Decision
- Network: cgroup `connect4/6` and `sendmsg4/6` programs (Phase 2); raw and
  packet sockets: LSM `socket_create`.
- Exec: LSM `bprm_check_security`, keyed by the executable's (device, inode)
  (Phase 3). File access: LSM `file_open` and the inode hooks (Phase 4).
- Self-protection: LSM `bpf`, `task_kill`, `ptrace_access_check` and the bpffs
  hooks (Phase 6).
- Observation only: `tp_btf/sched_process_exec` records each committed exec
  for the audit log (Phases 3, 9).

## Consequences
- Every deny happens in the kernel, before the action; the VM suites check
  each hook with real syscalls (docs/testing.md).
- BPF-LSM must be active for exec, file and raw-socket rules (ADR-0010).
