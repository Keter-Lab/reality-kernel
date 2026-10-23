# 0016. Retire the hosted API, the SDK and the analysis engine

Date: 2026-10-23 · Status: Accepted ([Phase 12](../design/phase-12.md))

## Context
Before the rebuild, Reality Kernel was a hosted service: a FastAPI service
with API keys and credits on Supabase, a Python analysis engine (and a Rust
port of it) that judged agent commands, and the `realitykernel` SDK that
called the API. The rebuild (Phases 0–11) produced a different product:
enforcement in the kernel, with every claim tied to tests. The hosted code
shared no code path with it, carried claims nothing tested, and kept a large
dependency surface that Dependabot, cargo-deny and Scorecard all counted.

## Decision
- Remove the hosted API (`api/`), the Python engine (`core/`), the SDK
  (`sdk/`), the backend crates (`rk-api`, `rk-supabase`, `rk-signing`,
  `rk-session`, `rk-types`), the Rust engine port (`rk-engine-core`) and its
  parity tests. They remain in git history.
- The hosted service is shut down, and the SDK is archived on PyPI with every
  release yanked.
- The website stays in this repository as static pages about the
  open-source project, with no accounts or API.

## Consequences
- One product, one release line, one version number (0.1.0 is the first).
- The workspace, its dependencies and the CI surface shrink; security
  scanners report on code that ships.
- Users of the SDK have no migration path inside this project. The CHANGELOG
  and SECURITY.md say so.
