# Changelog

Notable changes to the sensor, kernel programs, CLI, NRI plugin, Helm chart
and container image. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) as described in
[docs/releases.md](docs/releases.md).

## [Unreleased]

## [0.2.0] - 2026-10-24

### Added

- Adoption path (docs/design/adoption.md): `install.sh` (one command;
  verifies the checksum, and the Sigstore signature when cosign is present),
  `rk init` (a starter profile in AUDIT that fits the host),
  `rk policy suggest` (an ENFORCE profile from the audit log, never applied
  automatically), and docs/agents.md, a runbook coding agents can follow.
- ROADMAP.md and a root THREAT_MODEL.md pointer.
- TUN/TAP containment: governed processes can no longer create a TUN/TAP
  interface, attach to an existing one (including one their own user owns,
  which needs no capability) or re-attach a detached queue. It follows
  `network.deny_raw_sockets`, so no policy change is needed. The CI kernel
  matrix now builds every kernel with `CONFIG_TUN` to prove it
  (phase 16, ADR-0017).

### Changed

- The minimum Rust version is 1.89, checked in CI on exactly that toolchain
  (phase 15).
- Dependencies: `ed25519-dalek` 3, `sha2` 0.11, `reqwest` 0.13, `lru` 0.19,
  `containerd/nri` 0.12.3 and current GitHub Actions (phase 13, Dependabot).
- The website: rebuilt around the Warden, with an enforce/audit mode switch
  (phase 14).

### Fixed

- Audit records of an `rk run` agent that exits quickly keep its profile
  name; before, its last records could be written after the agent was
  unbound and name no profile.

## [0.1.0] - 2026-10-23

The first release of the rebuilt, kernel-enforced Reality Kernel. Each item
names the design note that specifies it; the tests behind every claim are
listed in [docs/evidence.md](docs/evidence.md).

### Added

- Kernel programs in C with libbpf CO-RE, loaded by a Rust sensor (aya), with
  a single ABI header shared by both sides and size checks on x86_64 and
  arm64 (phases 0–1).
- Network enforcement in cgroup `sock_addr` hooks: allow and deny by CIDR
  and port for TCP and UDP over IPv4 and IPv6, `EPERM` on deny, with raw and
  packet sockets, io_uring, TCP Fast Open and NAT64 addresses covered;
  atomic policy reload by slot flip; AUDIT mode (phase 2).
- Exec allowlists decided on file identity in BPF-LSM, covering symlinks,
  replaced binaries, interpreters and memfd (phase 3).
- File protection per access type (read, write, delete, rename, link,
  create, setattr) on inode identity, with subtree rules that fail closed
  (phase 4).
- `rk-agentd` and `rk run`: agents placed in their own cgroup and bound to a
  profile before their first instruction; authorised callers only; policy
  validate, diff, apply and rollback (phase 5).
- Kubernetes: an NRI plugin binding annotated pods to profiles at container
  creation, and a Helm chart (phase 5b).
- Self-protection against governed workloads (`bpf()`, signals, ptrace,
  pin removal), enforcement that survives sensor restarts through pinned
  programs, and a heartbeat that fails closed (phase 6).
- Performance: an epoll-driven drain thread, a bounded pipeline, per-hook
  cost measured in CI against a committed budget (phase 7).
- Test strategy: criterion-to-test traceability checked against every
  kernel's results, a policy conformance corpus run against both the
  reference evaluator and the kernel, property tests and fuzzing (phase 8).
- Observability: a signed, hash-chained OCSF 1.9.0 audit log with
  `rk audit tail` and `rk audit verify`, kernel decision counters,
  Prometheus metrics, OpenTelemetry traces and a Grafana dashboard
  (phase 9).
- Packaging: a hardened systemd unit, deb and rpm packages tested on
  Ubuntu 24.04 and Rocky Linux 9, `rk doctor`, and upgrades that replace the
  kernel programs make-before-break, without a protection gap (phase 10).
- Release supply chain: Sigstore signatures, SLSA build provenance and SPDX
  SBOMs for every artifact and the image, verified by the release workflow
  before the release is drafted; CodeQL, OpenSSF Scorecard, Dependabot, a
  DCO check, hash-pinned Python CI dependencies and a Go fuzz test for the
  NRI protocol (phase 11).
- Documentation: architecture, threat model, ADRs 0007–0015, security
  policy, governance, release policy and an evidence page generated from
  the traceability map (phase 11).

### Removed

- The earlier hosted product: the hosted API, the `realitykernel` Python SDK
  (archived on PyPI, every release yanked) and the application-level analysis
  engine. The hosted service is shut down; there is no migration path within
  this project ([ADR-0016](docs/decisions/0016-retire-the-hosted-product.md),
  phase 12).

### Security

- `rk-nri` builds with Go 1.27.3 (the standard library of the previous
  toolchain, 1.25.0, had known vulnerabilities), and CI runs `govulncheck` on
  every push (phase 12).
- The release workflow can verify its own container image before the first
  release makes the package public (phase 12).
- The NRI plugin uses `google.golang.org/grpc` v1.84.0, which fixes the five
  advisories reported by Dependabot on 2026-10-22.

[Unreleased]: https://github.com/Keter-Lab/reality-kernel/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Keter-Lab/reality-kernel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Keter-Lab/reality-kernel/releases/tag/v0.1.0
