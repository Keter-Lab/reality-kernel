# 0012. Dual GPL-2.0 / MIT licensing of the BPF programs

Date: 2026-10-23 · Status: Accepted (recorded in Phase 11 for a decision
taken earlier; see the design notes linked below)

## Context
Several BPF helpers used here are GPL-only. Relying on a loader default for
the license section is fragile, and the rest of the project is MIT or
Apache-2.0.

## Decision
- `rk-bpf/` is dual licensed GPL-2.0-only OR MIT (SPDX header in every file);
  each object declares `char LICENSE[] SEC("license") = "Dual MIT/GPL"`.
- Userspace crates are MIT OR Apache-2.0; cargo-deny enforces dependency
  licenses (`deny.toml`).

## Consequences
- GPL-only helpers are available, and the BPF code stays usable under MIT.
- License compliance is checked in CI (lint job).
