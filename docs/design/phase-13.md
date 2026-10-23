# Design note: Phase 13 — dependency maintenance after 0.1.0

Status: **ACCEPTED** (2026-10-23; the maintainer asked for the Dependabot
batch to be reviewed and applied).
Branch: `phase-13-maintenance` (from `main` at 417189b, the v0.1.0 tag)

## 1. Goal and acceptance criteria

Apply the first round of Dependabot updates as one reviewed change instead
of five pull requests, each with a full CI run.

1. Every upgrade is researched against how this repository uses the
   dependency (official changelogs and the source of the exact versions), and
   applied only where the result is known to build and behave the same.
2. Every existing acceptance criterion still passes on every kernel (full
   matrix and traceability).
3. The declared minimum Rust version stays true.

No new behaviour, so no new criteria.

## 2. What changes

| Update | Decision | Why |
|---|---|---|
| `ed25519-dalek` 2 → 3, `sha2` 0.10 → 0.11 | Applied together | Every API we call is unchanged; ed25519-dalek 3 depends on sha2 0.11, so they move as one |
| `lru` 0.18 → 0.19 | Applied | The only change is a `Sync` bound on iterators, which we do not use |
| `bindgen` 0.72 → 0.73 | Held at 0.72 | Our API use is unchanged, but bindgen 0.73 accepts `syn` 2–3 and `prettyplease` 0.2–0.3 independently. With `syn` 3 already in the tree, Cargo built bindgen on `syn` 3 against a `syn`-2 `prettyplease`, and bindgen itself failed to compile (first CI run of this phase). Other projects report the same. Dependabot skips 0.73 until upstream ties the two |
| `reqwest` 0.12 → 0.13 | Applied | The new default TLS backend sits behind default features, which we disable: still no TLS stack in the sensor |
| `rust-version` 1.87 → 1.89 | Applied | `sha2` 0.11.1 needs 1.88 and `uuid` 1.27+ needs 1.89. The clippy lints gated on 1.88/1.89 (let chains, `as_chunks`, raw-pointer `Default`, `NonNull::from_mut`) match no code here |
| GitHub Actions: checkout 7.0.1, setup-python 7.0.0, upload-artifact 7.0.2, download-artifact 8.0.2, cache 6.1.0, rust-cache 2.9.3, codeql-action 4.39.0, scorecard-action 2.5.0 | Applied, every SHA verified against its tag | All need Node 24, which GitHub-hosted runners have. Every input we pass keeps its meaning; upload and download move together because download-artifact 8 checks digests by default |
| `containerd/nri` 0.11 → 0.12.3 | Applied | Our stub and API calls are unchanged; 0.12 adds dedicated lifecycle RPCs that containerd 2.3 (our kind cluster) prefers |
| Rocky Linux test image 9.6 → 10.2 | Declined; Dependabot now ignores majors ≥ 10 | The package test is the evidence for Rocky Linux 9. Adding Rocky 10 would be a deliberate matrix change |
| Tailwind 3 → 4 | Declined | npm left the repository in Phase 12 |
| Patch updates (clap, serde_json, libc, ipnet, tokio, uuid) | Left to the next Dependabot run | Semver-compatible; no local toolchain to refresh `Cargo.lock` |

Also: `public/vercel.json`, a duplicate, is removed, and the root
`vercel.json` pins `"framework": null` (Vercel's "Other" preset), so a
dashboard setting can no longer make Vercel build the site as a Python app.

Newer releases published the day before this change (`setup-python` 7.1.0,
`nri` 0.12.4) are left for a later run.

## 3. CI cost

One full run: the change touches `kernel.yml` and the Rust and Go dependency
manifests. The release workflow's artifact flow can be exercised before the
next tag with a manual run (`workflow_dispatch`), which builds everything but
neither pushes nor signs.
