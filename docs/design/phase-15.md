# Design note: Phase 15 — a minimum Rust version that is proven

Status: **ACCEPTED** (2026-10-24; follow-up to Dependabot PR #37, agreed
with the maintainer before it was merged).
Branch: `phase-15-deps` (from `main` at acee8a9)

## 1. Problem

Dependabot PR #37 applied the upgrades deferred in Phase 13
(`ed25519-dalek` 3, `sha2` 0.11, `reqwest` 0.13) and patch updates. Every
check passed, including the kernel matrix, yet the workspace still declared
`rust-version = "1.87"`, which stopped being true: CI builds only on the
current stable toolchain, so nothing tested the declared minimum.

## 2. Acceptance criteria

1. `rust-version` in the workspace `Cargo.toml` equals the highest
   `rust-version` declared by any locked registry dependency.
2. CI builds every crate and test target on exactly that toolchain with the
   committed `Cargo.lock`, and fails if the toolchain and `rust-version`
   disagree.

## 3. Evidence for the number

From the crates.io index, for every registry package in `Cargo.lock` (208):

| Crate | Locked | Declared minimum |
|---|---|---|
| `uuid` | 1.29.0 | 1.89.0 |
| `sha2` | 0.11.1 | 1.88 |
| `proptest` | 1.12.0 | 1.88 |
| `icu_*` (via `url`) | 2.3.x | 1.88 |
| `aya`, `aya-obj` | 0.14.0, 0.3.0 | 1.87.0 |

36 crates declare no minimum; the CI job in §4 covers them by compiling.

So `rust-version = "1.89"`. The clippy lints that become active at 1.88 and
1.89 were reviewed in Phase 13 (docs/design/phase-13.md §2) and match no
code here; let chains need edition 2024 and this workspace is on 2021.

## 4. Change

- `Cargo.toml`: `rust-version` 1.87 → 1.89.
- `.github/workflows/ci.yml`: new job **Minimum Rust version (1.89)**:
  installs Rust 1.89, asserts it matches `rust-version`, then runs
  `cargo check --workspace --all-targets --locked`. When a future
  dependency raises the minimum, this job fails until both numbers move
  together.

Outside `rust-version`, as before: the BPF programs (C, built with clang in
`rk-bpf/`) and the fuzz workspace (nightly, excluded from the workspace).

## 5. Not in scope

Pinning dependencies to keep an older minimum: the project ships binaries
and packages, so users do not compile it with an old toolchain.
