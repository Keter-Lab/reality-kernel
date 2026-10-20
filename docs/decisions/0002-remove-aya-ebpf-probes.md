# 0002. Remove the Aya `rk-ebpf-probes` crate

Date: 2026-10-19 · Status: Accepted

## Context
`rk-ebpf-probes` (Rust BPF via aya-ebpf) did not compile against the locked
aya-ebpf, was not a workspace member, used an ABI that no longer exists, and
attached syscall-entry tracepoints that can only observe. The plan (section 4)
moves kernel code to C with libbpf CO-RE.

## Decision
Delete the crate now instead of excluding it until replacements land. Nothing
depends on it, it never produced an object, and it stays in git history.

## Consequences
The kernel layer has one implementation (`rk-bpf/`). Phases 2–4 add the
enforcing hooks there.
