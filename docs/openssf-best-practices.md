# OpenSSF Best Practices: answers

Answers for the "passing" level of the
[OpenSSF Best Practices badge](https://www.bestpractices.dev/projects/15819)
(project 15819), one per criterion, with the evidence a reviewer can check.
When this repository changes in a way that affects an answer, update the
answer here and on the site.

Links are to `main`: https://github.com/Keter-Lab/reality-kernel (abbreviated
`REPO` below; on the site, paste the full URL).

## Basics

| Criterion | Answer | Justification |
|---|---|---|
| description_good | Met | REPO#readme: what it does, in a claims block where each claim links to its tests. |
| interact | Met | README links install, docs and contributing; issues and discussions are on GitHub: REPO/issues, REPO/discussions. |
| contribution | Met | REPO/blob/main/CONTRIBUTING.md |
| contribution_requirements | Met | CONTRIBUTING.md, "What a pull request needs": tests, clean checks, docs, design notes, DCO sign-off. |
| floss_license | Met | MIT OR Apache-2.0 (userspace); GPL-2.0-only OR MIT (BPF programs). |
| floss_license_osi | Met | All three are OSI approved. |
| license_location | Met | REPO/blob/main/LICENSE, LICENSE-APACHE, LICENSE-MIT |
| documentation_basics | Met | REPO/blob/main/docs/install.md, docs/policy.md, docs/architecture.md |
| documentation_interface | Met | Policy format: docs/policy.md; audit record format: docs/audit.md; CLI: `rk --help`; ABI: docs/abi.md. |
| sites_https | Met | https://github.com/Keter-Lab/reality-kernel, https://realitykernel.dev |
| discussion | Met | GitHub issues and discussions: searchable, addressable by URL, no proprietary client needed. |
| english | Met | All documentation is in English. |
| maintained | Met | Active development; see the commit history and CHANGELOG.md. |

## Change control

| Criterion | Answer | Justification |
|---|---|---|
| repo_public | Met | REPO |
| repo_track | Met | Git, with every change through a reviewed pull request. |
| repo_interim | Met | Work happens on public `phase-*` branches before it is merged. |
| repo_distributed | Met | Git. |
| version_unique | Met | One workspace version per release; the release workflow refuses a tag that differs from it. docs/releases.md |
| version_semver | Met | docs/releases.md, "Versioning". |
| version_tags | Met | Releases are tagged `vX.Y.Z`; the release workflow runs from the tag. |
| release_notes | Met | REPO/blob/main/CHANGELOG.md (Keep a Changelog). |
| release_notes_vulns | Met | CHANGELOG.md has a "Security" section per release; SECURITY.md says fixes are listed there. |

## Reporting

| Criterion | Answer | Justification |
|---|---|---|
| report_process | Met | GitHub issues (REPO/issues); SECURITY.md for vulnerabilities. |
| report_tracker | Met | GitHub issues. |
| report_responses | Met | Reports are acknowledged by the maintainer; see the issue history. |
| enhancement_responses | Met | Enhancement requests are answered in issues and discussions. |
| report_archive | Met | REPO/issues?q=is%3Aissue (public, searchable). |
| vulnerability_report_process | Met | REPO/blob/main/SECURITY.md |
| vulnerability_report_private | Met | GitHub private vulnerability reporting (REPO/security/advisories/new) or security@realitykernel.dev. |
| vulnerability_report_response | Met | SECURITY.md commits to acknowledgement within 3 business days and an assessment within 7 days. |

## Quality

| Criterion | Answer | Justification |
|---|---|---|
| build | Met | `cargo build --workspace`, `cargo xtask build-sensor` (CONTRIBUTING.md); release builds in .github/workflows/release.yml. |
| build_common_tools | Met | Cargo, clang/LLVM, Go, nFPM, Helm. |
| build_floss_tools | Met | All build tools are FLOSS. |
| test | Met | Unit, property, conformance, fuzz and kernel integration tests; docs/testing.md. |
| test_invocation | Met | `cargo test --workspace`, `go test ./...`, `pytest tests` (CONTRIBUTING.md). |
| test_most | Met | Every acceptance criterion maps to named tests that must pass on every supported kernel: docs/evidence.md. |
| test_continuous_integration | Met | GitHub Actions on every push and pull request: ci.yml, kernel.yml (five kernels in VMs, Kubernetes, packages on two distributions). |
| test_policy | Met | CONTRIBUTING.md: every behaviour change comes with a test that fails without it. |
| tests_are_added | Met | Each phase added tests for its criteria; tests/traceability.toml and docs/evidence.md. |
| tests_documented_added | Met | CONTRIBUTING.md and the pull request template. |
| warnings | Met | `cargo clippy -D warnings`, BPF built with `-Wall -Werror`, `go vet`, rustfmt and gofmt. |
| warnings_fixed | Met | Warnings fail CI, so none are merged. |
| warnings_strict | Met | Warnings are errors in every language. |

## Security

| Criterion | Answer | Justification |
|---|---|---|
| know_secure_design | Met | docs/threat-model.md, ADRs in docs/decisions/ (least privilege: bounded systemd capabilities; fail closed: heartbeat; complete mediation in kernel hooks). |
| know_common_errors | Met | Bypass classes are tested explicitly (raw and packet sockets, io_uring, TCP Fast Open, symlinks, replaced binaries, memfd), and decisions use file identity rather than paths; docs/evidence.md. |
| crypto_published | Met | Ed25519 (audit batch signatures), SHA-256 (audit hash chain); Sigstore for releases. |
| crypto_call | Met | Uses ed25519-dalek and sha2; no cryptography is implemented by the project. |
| crypto_floss | Met | All cryptographic libraries are FLOSS. |
| crypto_keylength | Met | Ed25519 (128-bit security level). |
| crypto_working | Met | No broken algorithms are used. |
| crypto_weaknesses | Met | No SHA-1, MD5 or CBC-mode use. |
| crypto_pfs | N/A | The software implements no key-agreement protocol; OTLP export goes over plain HTTP to a node-local collector by design. |
| crypto_password_storage | N/A | The software stores no passwords. |
| crypto_random | Met | The audit signing key is generated from getrandom(2) (rk-audit/src/key.rs). |
| delivery_mitm | Met | Releases are downloaded over HTTPS from GitHub; every file is Sigstore-signed with provenance (docs/releases.md). |
| delivery_unsigned | Met | Checksums are not fetched over HTTP; SHA256SUMS is itself signed. |
| vulnerabilities_fixed_60_days | Met | No unpatched vulnerability of medium or higher severity has been public for more than 60 days (the gRPC advisories were fixed within a day of being reported). |
| vulnerabilities_critical_fixed | Met | SECURITY.md commits to fixing critical issues within 30 days. |
| no_leaked_credentials | Met | No valid private credentials are in the repository; only documentation placeholders. |

## Analysis

| Criterion | Answer | Justification |
|---|---|---|
| static_analysis | Met | CodeQL (Rust, Go, Python, Actions) on every pull request; clippy; cargo-deny and cargo-audit. |
| static_analysis_common_vulnerabilities | Met | CodeQL security queries. |
| static_analysis_fixed | Met | CodeQL and Dependabot alerts are triaged in the Security tab; medium and higher findings are fixed, and cargo-deny/cargo-audit findings fail CI. |
| static_analysis_often | Met | Every pull request and push to main, and weekly. |
| dynamic_analysis | Met | cargo-fuzz targets (event decoder, policy parser) in the kernel workflow; Go native fuzzing of the NRI protocol; kernel integration tests on five kernels. |
| dynamic_analysis_unsafe | Met | The userspace is Rust and Go; the BPF programs in C are checked by the kernel verifier on every supported kernel, and fuzzing covers the decoders of kernel data. |
| dynamic_analysis_enable_assertions | Met | Tests and fuzzing run debug builds with assertions enabled. |
| dynamic_analysis_fixed | Met | Fuzzing and test failures fail CI. |
