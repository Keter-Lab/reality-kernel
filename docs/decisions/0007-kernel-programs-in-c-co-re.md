# 0007. Kernel programs in C with libbpf CO-RE, loaded by aya

Date: 2026-10-23 · Status: Accepted (recorded in Phase 11 for a decision
taken earlier; see the design notes linked below)

## Context
Aya's Rust BPF side has no CO-RE field relocation, so a program that walks
kernel structures from Rust is tied to the kernel it was built against. The
plan targets every LTS kernel from 5.15 on (docs/kernel-matrix.md).

## Decision
- Every kernel program is C (`rk-bpf/src`), compiled with clang `-target bpf`
  against a vendored `vmlinux.h` per architecture, relocated at load time with
  BTF (CO-RE).
- The objects are embedded in `rk-sensor` at build time and loaded by the Rust
  aya loader; release builds refuse a runtime object path (ADR-0001, Phase 0).
- One header, `rk-bpf/include/rk_abi.h`, defines every shared layout
  (ADR-0004).

## Consequences
- One object runs on 5.15 through 6.18 without rebuilding; the VM matrix
  proves it on every push (`kernel.yml`).
- Kernel code is reviewed as C; `-Wall -Werror` and the verifier are its first
  gates.
