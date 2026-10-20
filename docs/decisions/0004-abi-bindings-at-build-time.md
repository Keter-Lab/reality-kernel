# 0004. Generate ABI bindings at build time; vendor vmlinux.h

Date: 2026-10-19 · Status: Accepted

## Context
The plan asks for Rust types generated with bindgen from `rk_abi.h`, plus a drift
check. The design note proposed committed bindings and a byte-for-byte diff in
CI. Without a local toolchain, committed generated code can only be refreshed by
CI, which adds a round trip to every ABI change.

## Decision
- `rk-ebpf-common/build.rs` runs bindgen on every build. The bindings are never
  committed, so they cannot drift. libclang is a build dependency (installed in
  CI).
- bindgen adds `bytemuck::Pod`/`Zeroable` to every ABI struct. `derive(Pod)`
  fails to compile on implicit padding, enforcing the plan's "no padding" rule.
- Enums are constified modules, so kernel-supplied values are never transmuted
  into Rust enums.
- `vmlinux.h` for x86 and arm64 is vendored from libbpf/vmlinux.h at commit
  c32912840154a82205530cd6d498b346ac73a6d1 (Linux 6.19 BTF). CO-RE relocations
  make it valid across the matrix. Generating it on runners would need an arm64
  kernel with BTF that hosted runners don't provide.

## Consequences
- No `xtask check-bindgen-drift`; drift is impossible by construction.
- Building `rk-ebpf-common` needs libclang.
