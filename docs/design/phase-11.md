# Design note: Phase 11 — enterprise repository standards

Status: **ACCEPTED** (2026-10-23). All six decisions in §8 approved as recommended; decision 4: yes, sign-off with consent.
Later change: [Phase 12](phase-12.md) retired the hosted API, the Python SDK and the analysis engine, so the
best-effort SDK and API support in §3 and decision 1 no longer apply.
Branch: `phase-11-standards` (from `main` at 258cd37)
Plan reference: RealityKernel_Engineering_Plan.pdf, Phase 11 ("The
repository meets the expectations of enterprise security reviewers").

## 1. Goal and acceptance criteria

Plan acceptance criteria (must pass in CI):

1. OpenSSF Scorecard score of 8 or higher.
2. Every release artifact has a signature, SBOM and provenance attestation.
3. No README claim without a linked test or benchmark.

Plan deliverables: the docs set, release and supply-chain workflows, an
updated README.

## 2. What exists today

| Plan item | Status |
|---|---|
| cargo-deny, cargo-audit gates | Yes (lint job) |
| GitHub Actions pinned by commit SHA | Yes, every `uses:` |
| Container base images pinned by digest | Yes |
| Release workflow | Yes (Phase 10): binaries, deb/rpm, image, chart, SHA256SUMS, draft release; no signatures, SBOM or provenance |
| SECURITY.md | Exists but stale: lists 0.3.x as supported (the workspace is 0.1.0), describes the old architecture ("symbolic execution engine", `core/engine.py`), promises 48-hour responses |
| ADRs | 0001–0006; the plan's §4 decisions are mostly undocumented as ADRs |
| Threat model, architecture doc | No (README has a short "Threat Model" section) |
| CODEOWNERS, CHANGELOG, release policy, DCO | No |
| Dependabot config, Scorecard, CodeQL | No (Dependabot alerts are on in settings) |
| Python requirements pinned with hashes | No (roadmap item 4f) |
| README | Describes the pre-rebuild product (SDK-first, "deterministic sub-millisecond" claims) with no links to evidence |

## 3. Docs

- **`docs/threat-model.md`**: assets (enforcement continuity, policy
  integrity, audit log integrity, the audit key, agent containment), trust
  boundaries (kernel ↔ sensor, sensor ↔ `rk` clients over the agentd
  socket, agents, Kubernetes/NRI, policy authors, the release pipeline),
  attackers in scope (a malicious or compromised agent in a governed cgroup,
  local unprivileged users, a tampered artifact in transit) and explicit
  non-goals (root on the host, a compromised kernel, physical access, side
  channels, ungoverned workloads). Each mitigation links to the test that
  proves it.
- **`docs/architecture.md`**: components, data flow (decision → ring buffer
  → worker → audit log, metrics, OTLP), the pin lifecycle (adopt, replace
  make-before-break, uninstall), and where each phase's design note lives.
- **ADRs 0007–0015** for decisions that only live in design notes today:
  C CO-RE programs loaded by aya; BPF-LSM and cgroup `sock_addr` as the
  enforcement hooks; cgroup v2 as the governance unit; minimum kernel 5.15
  and honest degradation without BPF LSM; AUDIT-first default posture;
  dual GPL-2.0/MIT BPF licensing; pins plus a fail-closed heartbeat; the
  OCSF hash-chained audit log; make-before-break upgrades.
- **`SECURITY.md`** rewritten: scope (sensor, CLI, NRI plugin, chart; the
  legacy Python SDK and hosted API best-effort, see decision 1), private
  reporting through GitHub Security Advisories or security@, and a
  response window a single maintainer can keep (decision 5).
- **Governance**: `GOVERNANCE.md` (maintainers, decisions, the two-reviewer
  rule for kernel code, effective as soon as there are two maintainers),
  `.github/CODEOWNERS`, `CHANGELOG.md` (Keep a Changelog format, from
  0.1.0), `docs/releases.md` (semver per component, release cadence,
  support window, how to verify a release).
- **README rewritten** around what the rebuilt system does, with every
  claim linking to its evidence (§5).

## 4. Supply chain

- **Release signing, SBOM, provenance** (`release.yml`):
  - Every file in the release gets an SPDX SBOM from Syft (pinned binary,
    checksum-verified) and a Sigstore keyless signature (`cosign sign-blob
    --bundle`, identity: this repository's release workflow).
  - The image is signed by digest (`cosign sign`), with its SBOM attached
    as an attestation.
  - SLSA build provenance for every file and the image through GitHub
    artifact attestations (`actions/attest-build-provenance`).
  - A final `verify-release` job checks every artifact: `cosign verify-blob`
    against the expected workflow identity, `gh attestation verify`, and an
    SBOM present. A release with a gap fails.
  - `docs/releases.md` shows users the same verification commands.
- **OpenSSF Scorecard** workflow on `main` (weekly and on push),
  publishing results and the README badge.
- **CodeQL** workflow (static analysis) for Go, Python and GitHub Actions,
  plus Rust if CodeQL's Rust support is generally available when built
  (checked against GitHub's documentation at implementation time).
- **`.github/dependabot.yml`**: cargo, gomod, pip, npm, github-actions and
  docker, weekly, grouped.
- **Pinned dependencies**: Python requirements pinned with hashes and
  installed with `--require-hashes` (roadmap item 4f); any remaining
  unpinned install in a workflow is fixed.
- **Token permissions**: every workflow read-only at the top, write scopes
  only on the job that needs them (autofix currently grants `contents:
  write` workflow-wide).
- **Go native fuzz test** for the NRI plugin's message handling. It is worth
  fuzzing, and Scorecard detects Go fuzzing (it does not detect `cargo fuzz`
  targets, which keep running in the kernel workflow).
- The kernel workflow's push path filter also skips the new
  workflow-only and docs-only changes (`release.yml`, `scorecard.yml`,
  `codeql.yml`, `dependabot.yml`), as Phase 8 did for `ci.yml`.

## 5. README claims, checked

Every capability, security or performance statement in the README lives in
a marked block, one claim per item, each ending in an evidence link to a
criterion in `tests/traceability.toml` (or a benchmark key in
`tests/bench/budget.json`). `tests/readme_claims.py` (run in the python job)
fails when:

- an item in a claims block has no evidence link, or links to a criterion or
  benchmark that does not exist;
- outside the claims blocks, the README states a number with a performance
  unit (ms, µs, %, events/s, "x faster") or a superlative from a short
  list ("guaranteed", "unbreakable", "zero overhead", ...).

The traceability job already proves every criterion's tests passed on every
kernel, so a README claim links, through its criterion, to tests that ran.

## 6. Scorecard: what 8 needs

Estimated from Scorecard's published check weights (critical 10, high 7.5,
medium 5, low 2.5), after this phase and the settings in §7:

| Check | Risk | Expected | Why |
|---|---|---|---|
| Dangerous-Workflow | critical | 10 | no untrusted input in `run:` |
| Binary-Artifacts | high | 10 | none tracked |
| Branch-Protection | high | ~8 | ruleset: no force push or deletion, PR with 1 approval (admin may bypass), required checks |
| Code-Review | high | 0 | a single maintainer cannot have changes reviewed by someone else |
| Dependency-Update-Tool | high | 10 | dependabot.yml |
| Maintained | high | 10 | active commits and issues |
| Signed-Releases | high | 10 | after the first signed release |
| Token-Permissions | high | 10 | read-only defaults |
| Vulnerabilities | high | 10 | no open advisories (the gRPC ones were fixed on 2026-10-22) |
| Fuzzing | medium | 10 | Go native fuzz test |
| Pinned-Dependencies | medium | ~9 | hashes for pip |
| SAST | medium | 10 | CodeQL on every PR |
| Security-Policy | medium | 10 | SECURITY.md |
| CI-Tests, License | low | 10 | |
| CII-Best-Practices | low | 5 | "passing" on bestpractices.dev (project 15819) |
| Contributors | low | 0 | one organisation |

That comes to about 8.7. Without the reviewed-approval tier of branch
protection, the passing badge or the first signed release, it falls below
8. Those three are the maintainer's to do (§7); Code-Review stays 0 until a
second person reviews changes.

## 7. Maintainer tasks (settings only Tabrez can change)

1. Branch ruleset on `main`: no deletion or force push; pull request with
   **1 required approval** and **Repository admin in the bypass list
   ("for pull requests only")**; required checks Lint, Test (x86_64),
   Test (arm64), Python tests, Go, Traceability.
2. Settings → Code security: private vulnerability reporting and Dependabot
   security updates on.
3. bestpractices.dev project 15819: answer the questionnaire (answers
   prepared in this phase, one per criterion with an evidence link, kept
   outside the repository) until it shows "passing".
4. After this phase merges: push tag `v0.1.0`, review the draft release
   (signatures, SBOMs, provenance verified by the workflow), publish it.

## 8. Decisions requested from the reviewer

1. **Move the single analysis engine (PyO3, retiring the Python core)
   to its own later phase**, together with the decision on the legacy
   hosted API (roadmap 4d). Recommended: it is engineering work on a
   different product surface; Phase 11 stays about standards. SECURITY.md
   marks the SDK and hosted API as best-effort until then.
2. **Sigstore keyless signing, Syft SBOMs, GitHub artifact attestations for
   provenance.** Recommended: no long-lived signing key to protect, and all
   three are verifiable with standard tools. The alternative is a managed
   cosign key pair.
3. **README claims enforced through marked claims blocks plus a forbidden
   pattern list** (§5). Recommended: precise enough to fail CI, simple
   enough to maintain. The alternative is a review-only rule.
4. **DCO sign-off required on pull request commits**, checked by a small
   workflow (bot commits such as autofix exempt). Recommended. Since
   `Signed-off-by` is your attestation, commits I make under your identity
   would carry your sign-off only with your consent (yes or no).
5. **Security response window**: acknowledge within 3 business days,
   assessment within 7 days, fix for critical issues within 30 days,
   coordinated disclosure within 90 days. Recommended: what one maintainer
   can keep; the current 48 hours is a promise at risk.
6. **Versioning**: semver per component (sensor and CLI start at 0.1.0;
   the SDK keeps 0.7.x; the website is not released). Recommended: the
   numbers then mean something, and SECURITY.md lists what is supported.
