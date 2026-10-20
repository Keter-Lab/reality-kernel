# 0001. Adopt the engineering plan; verify only in CI

Date: 2026-10-19 · Status: Accepted

## Context
The engineering plan (baseline 6975fbd) sets out Phases 0–11 and requires every
acceptance criterion to pass in CI, not on a developer machine. Maintainers do
not have a local toolchain (Rust, clang, bpftool).

## Decision
- Work proceeds phase by phase, with a design note in `docs/design/` approved
  before code.
- All verification runs on free GitHub-hosted runners (the repository is public).
- Failures are made readable without credentials: `.github/scripts/run-logged.sh`
  re-emits error blocks as check annotations, which the public checks API
  serves.
- `autofix.yml` applies rustfmt and refreshes `Cargo.lock` on `phase-*`
  branches, so formatting never depends on a local toolchain.

## Consequences
- Iteration is slower (push, wait for CI). Mitigated by keeping jobs parallel and
  cached.
- CI is the only source of truth, which matches the plan's rule.
