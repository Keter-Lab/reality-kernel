# Design note: Phase 12 — open-source cleanup and a releasable 0.1.0

Status: **ACCEPTED** (2026-10-23). Approved with all decisions in §9; the maintainer asked
for every file to be reviewed (§3.1) and for the website to be redesigned (§6).
Branch: `phase-12-cleanup` (from `main` at d855b85)
Not in the original plan. It resolves roadmap item 4d (the legacy hosted
API) and replaces the planned engine-unification phase. The maintainer
decided on 2026-10-23 to retire the hosted product, and has already shut
down its services (Vercel API variables removed, Supabase paused, PyPI
package yanked and archived).

## 1. Goal and acceptance criteria

The repository contains only the open-source project: the kernel
enforcement system, its tooling and its website. The first signed release
(0.1.0) is cut from the result.

1. Nothing of the retired hosted product remains: the API, its backend
   crates, the application-level analysis engine, the Python SDK, and the
   account, billing and API-key parts of the website.
2. Every existing acceptance criterion still passes on every kernel (full
   matrix and traceability, unchanged).
3. The release workflow can verify its own image (a bug, §4.2), and a test
   keeps the image complete for the Helm chart (§4.1).
4. No known vulnerability reachable from the shipped code, checked on every
   push (§4.3).
5. The website states only what the README can back. It has no link to a
   removed page, no performance number or superlative, and no
   account, API-key or pricing content. This is checked in CI.

## 2. What is removed

| Path | What it was | Used by the kernel product |
|---|---|---|
| `api/`, `vercel.json` API routes and function config | Hosted API (FastAPI): API keys, credits, rate limits | No |
| `core/` | Python analysis engine behind the API | No |
| `rk-api`, `rk-supabase`, `rk-signing`, `rk-session`, `rk-types` | Rust hosted backend (Supabase, sessions, request signing) | No (only `rk-api` used the others) |
| `rk-engine-core`, `tests/parity` | Rust port of the Python engine and its parity corpus | No (only `rk-api` and the parity tests) |
| `rk-policy` crate root (`verify_least_agency_policy`, `LeastAgencyPolicy`) and its `regex` dependency | Command check used only by `rk-api` | No (the sensor uses `rk_policy::net`) |
| `sdk/` | Python client for the hosted API, archived on PyPI | No |
| `tests/test_security_regressions.py` | Tests of the hosted API | No |
| `requirements.txt`, and fastapi, pydantic, httpx, cryptography and their dependencies in `requirements-ci.txt` | Python dependencies of the API, SDK and their tests | No |
| `DEPLOY.md`, `REPO_MIGRATION.md`, `SECURITY_AUDIT.md`, `.env.example` | Hosted-service operations, a one-off migration, an audit of `api/index.py`, API environment variables | No |
| Website: `login`, `dashboard` (+ `dashboard.js`), `pricing`, `playground`, `verifier`, `sdk`, `integration`, `benchmark`, `demo` (+ `demo.js`, `demo.css`), `faq`, `landing` | Accounts, billing, API-key docs, demos and benchmarks of the old engine | No |
| Website: `blog` (+ `teardown/` images) | One article whose traces and "how it intercepts" sections describe the retired engine | No |
| Website: `styles.css`, `theme.css`, `tw.css`, `rk-fixes.css`, `landing.js`, `causal-graph.js`, `operator_dashboard.png`, `src/tailwind.css`, `tailwind.config.js`, `package.json`, `package-lock.json` | The old site's styles, scripts and Tailwind/npm toolchain, replaced by the redesign (§6) | No |
| `assets/rk-interception-demo.svg` | Marketing image of the old engine, referenced nowhere | No |

All of it stays in git history. The workspace keeps `rk-ebpf-common`,
`rk-sensor`, `rk-audit`, `rk-policy`, `rk-agentd`, `rk-cli`, `xtask` and
`tests/integration`.

ADR-0016 records the decision: retire the hosted API, the SDK and the
application-level engine, and keep one product, kernel enforcement.

## 3. What changes

- **Docs:** remove every SDK and hosted-API mention from README.md,
  SECURITY.md (supported versions), docs/releases.md (versioning table),
  CHANGELOG.md and tests/README.md. CHANGELOG 0.1.0 gets a "Removed" note for
  users of the archived SDK; its date is set when the tag is pushed.
- **Dependabot:** drop the npm ecosystem; pip keeps `requirements-ci.txt`,
  now only pytest and its dependencies.
- **CI:** the coverage job's crate list is unchanged, since it never
  included the removed crates. The lint job's `cargo deny` and `cargo audit`
  then cover a smaller, product-only dependency tree.

### 3.1 Every remaining file reviewed

All 194 remaining tracked files were read for leftovers of the closed-source
product. Changes beyond the removals above:

- **Issue and PR templates** rewritten for the real components; a template
  config sends vulnerability reports to private reporting and questions to
  Discussions.
- **Licensing:** `LICENSE` now states both licence sets (userspace
  MIT OR Apache-2.0; `rk-bpf/` GPL-2.0-only OR MIT) and the fonts' OFL;
  `LICENSE-GPL-2.0` added, since the BPF programs offer it; packages and
  tarballs ship every licence file; the package licence field says
  `(MIT OR Apache-2.0) AND (GPL-2.0-only OR MIT)`.
- **One company name:** "Keter Labs" everywhere (the OCSF `vendor_name`, the
  package maintainer and vendor said "Keter Lab").
- **`.gitignore`** reduced to build output and Python tooling; entries for
  personal working files move to the maintainer's local `.git/info/exclude`.
  It no longer ignores every `*.txt`, which would have dropped the fonts'
  licence. `.gitattributes` loses rules for removed paths.
- **Stale references:** the Dockerfile and Helm values comments, a test
  fixture naming `tests/parity`, the `rk-signing` mention in `rk-audit`,
  `deny.toml`'s exception for the TLS stack only the removed crates used, and
  the phase list in docs/architecture.md.
- **A documented gap, not a cleanup:** ADR-0006 promised a TUN/TAP device
  rule in Phase 4; Phase 4 deferred it and nothing implements it. ADR-0006
  gets a dated status note and the threat model a residual-risk row. Agents
  launched with `rk run` are unaffected (no capabilities); the rule itself
  is planned hardening work.
- **Design notes** stay as historical records; the Phase 11 note gets a
  one-line pointer to this phase.

## 4. Release and dependency fixes

### 4.1 The release image keeps every binary the chart runs (guard)

The Helm chart runs `rk-sensor` and `rk-nri` from one image (both containers
in `deploy/helm/reality-kernel/templates/daemonset.yaml` use `rk.image`).
The release workflow's binaries job builds `rk-sensor`, `rk` and `rk-nri`
for each architecture, and the image copies all of them, so a release is
complete. Nothing tested that, though, because the Kubernetes test builds
its own image. New test: `test_workflows.py` checks that every command the
chart's containers run is built by the release binaries job.

### 4.2 The release job cannot read a private image (bug)

GHCR creates a new package as private. The release job runs
`cosign verify` and `gh attestation verify oci://` against the image without
registry credentials, so the first tagged release would fail at its last
step. Fix: the release job gets `packages: read` and logs in to ghcr.io
before verifying. Test: `test_workflows.py` checks that the login comes
before the first image verification. After the first release the maintainer
makes the package public, so users can pull it (§7).

### 4.3 Known vulnerabilities in remaining dependencies

An OSV scan of every lockfile on `main` (2026-10-23, 389 packages) reports:

| Package | Where | Advisories | In the shipped code? |
|---|---|---|---|
| Go standard library 1.25.0 | `rk-nri`: `go 1.25.0` and no `toolchain` line, so CI and releases build with exactly 1.25.0 | GO-2026-6603, -6610, -6611, -6612, -6617 (`net/http` HTTP/2) and every earlier 1.25.x fix | Yes: the standard library is compiled into every binary. Fixed in Go 1.26.9 and 1.27.2; 1.25 receives no fix |
| `golang.org/x/net` 0.57.0, `golang.org/x/text` 0.40.0 | `rk-nri/go.sum` only | the same five; GO-2026-6629 | No. Since Go 1.17, `go.mod` lists every module whose packages are compiled in, and neither is there; these are module-graph checksums |
| `braces` 3.0.3 | `package-lock.json` (Tailwind, website build only) | GHSA-vfj7-8cjw-p6xm | No (a development tool), but scanners count it; no fix is published |

Fix:

- `rk-nri/go.mod`: `go 1.26.0` and `toolchain go1.27.3` (the current
  release), which `setup-go` installs in CI and in the release workflow.
- `govulncheck` (golang.org/x/vuln v1.9.0) becomes a `tool` dependency of
  `rk-nri`, pinned in `go.mod` and `go.sum`. The Go CI job runs
  `go tool govulncheck ./...` on every push, which fails on any known
  vulnerability that is reachable from the code, including the standard
  library. Rust already has `cargo audit` and `cargo deny`.
- The website no longer uses Tailwind or npm (§6), so `package.json`,
  `package-lock.json` and `braces` leave the repository.

The scan is repeated before the pull request.

## 5. README

- Two Mermaid diagrams, which GitHub renders. One shows the decision flow:
  agent → syscall → BPF hook → allow or EPERM → ring buffer → audit log,
  metrics, traces. The other shows how a workload becomes governed:
  `rk run` / Kubernetes NRI → cgroup → profile binding → policy maps.
- A short example policy, an example audit record (`rk audit tail`), and
  the supported-kernel table.
- The claims rule from Phase 11 is unchanged.

## 6. Website

The site stays in this repository, deployed as static files, and is
redesigned for the open-source project.

- **One stylesheet, no build step:** `public/site.css` defines the whole
  design as tokens, with light and dark themes that follow the system or the
  visitor's choice. No Tailwind, npm or Node.js.
- **No third parties:** IBM Plex fonts are self-hosted under the OFL
  (`public/fonts/`); the only external request is Vercel's own cookie-free
  performance metrics.
- **Strict Content-Security-Policy:** no inline scripts or styles anywhere, so
  `vercel.json` sends `script-src 'self'; style-src 'self'` with
  `frame-ancestors 'none'` and the existing security headers. `app.js` (theme,
  menu, copy buttons) loads in `<head>` so the saved theme applies before the
  first paint.
- **Pages:** `index` (what it is, the boundary, capabilities each linked to
  their evidence, how it works, quick start, the kernel matrix), `docs` (a hub
  of the repository docs), `security` (threat model summary, reporting,
  verifying releases), `about` (the project, its history, Keter Labs), and
  `privacy`, `terms`, `cookies` and `404`, rewritten for a site with no
  accounts or cookies.
- **Real content only:** the policy example is valid syntax from the policy
  reference; the example trace uses the exact `rk audit tail` line format
  and the `EPERM` the hooks return; the kernel list is the CI matrix.
- **Partials:** `scripts/partials.py` expands one head, header and footer
  into every page.
- **Redirects:** every removed path redirects permanently to the nearest kept
  page. `public/vercel.json` mirrors the root file until the Vercel project's
  root directory is confirmed.
- **Social preview:** a new `og-preview.png` without the old engine's figures.
- **New test, `tests/test_site.py`:** links, assets, anchors and evidence links
  resolve; nothing of the retired product appears; the README's rules on
  performance numbers and superlatives apply to every page; no inline script
  or style; partials current; the two Vercel files match, every redirect
  lands on a page, and the sitemap lists exactly the pages.

## 7. Maintainer tasks

1. After merge: tag `v0.1.0` (`docs/releases.md`, "Making a release"),
   review and publish the draft release.
2. After the first release: ghcr.io package `reality-kernel` → Package
   settings → Change visibility → Public.
3. Optional, Scorecard Branch-Protection: in the `main` ruleset, enable
   "dismiss stale approvals", "require approval of the most recent push"
   and "require review from Code Owners". The admin bypass keeps these from
   blocking a solo maintainer.
4. Later: delete the paused Supabase project.
5. Vercel → Settings → Build and Deployment: note the Root Directory (empty or
   `public`), so the duplicate `vercel.json` can be removed later. The site needs
   no build command.

## 8. Acceptance tests and CI cost

| Criterion | Tests |
|---|---|
| `retired_product_removed`: only the open-source project remains | `py:test_retired_product_is_gone` |
| `release_complete`: the release builds every binary the chart runs, and the release job can verify a private image | `py:test_release_builds_every_chart_binary`, `py:test_release_job_logs_in_before_verifying`, `ci:release` |
| `go_vulnerabilities`: pinned current Go toolchain, govulncheck on every push | `py:test_go_vulnerabilities_are_checked`, `ci:go` |
| `site_honest`: links, no retired product, claims rules, strict CSP | the six `test_site.py` tests |
| Every existing criterion | Unchanged, on every kernel |

Removing workspace crates changes `Cargo.lock` and the sensor's build
inputs, so the full kernel matrix runs once, as for every phase.

## 9. Decisions

The maintainer delegated these on 2026-10-23 ("do as u think would suit
better"); they are listed for the record and for objection:

1. Delete the analysis engine (Python and Rust) rather than keep it as a
   library. Nothing uses it, and its claims are not backed by tests the way
   the kernel's are.
2. Keep the website in this repository, trimmed and rewritten (§6), rather
   than moving it to a separate repository.
3. Redesign the website on one hand-written stylesheet instead of keeping
   Tailwind (§6). It removes the npm toolchain and its `braces` advisory, and
   lets the site run under a strict Content-Security-Policy.
4. Tag 0.1.0 after this phase rather than before, so the first public
   release contains only the open-source product and the two release fixes.
