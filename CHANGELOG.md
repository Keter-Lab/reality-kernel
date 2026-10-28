# Changelog

Notable changes to the sensor, kernel programs, CLI, NRI plugin, Helm chart
and container image. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) as described in
[docs/releases.md](docs/releases.md).

## [Unreleased]

### Security

- `rk init` and `rk policy suggest --out` no longer write through a
  symbolic link. Run as root in a directory the user or the governed agent
  can write, a link planted at the output path (or at `rk init`'s fixed
  staging name or predictable backup name) made root overwrite the file it
  pointed to. Files are now staged under a fresh name created with
  `O_EXCL|O_NOFOLLOW` and renamed into place; an existing regular file at
  `--out` is still replaced, a symbolic link there is refused. The
  `--force` backup is created exclusively, mode 0600.
- `rk policy suggest` no longer widens more than eight observed port ranges
  for one address into one covering range (nine ports produced
  `22-65535`). It keeps the lowest eight, the most the kernel holds per
  address, and lists the rest in the header, not allowed.
- `rk policy suggest` no longer learns an executable whose path now holds a
  different file (device and inode differ from what the audit record shows
  ran); it is listed in the header instead.
- The traceability check now fails when a referenced Rust test is
  `#[ignore]`d or not a `#[test]`, a referenced Python test is marked skip
  or xfail (or would not be collected), or a referenced CI job is disabled
  or has no step left that does anything.
- Audit log: startup recovery no longer signs records it finds after the
  last sealed batch. They were sealed with the live key, so anyone who could
  write the log could get records of their own signed. They are now moved,
  unsigned, to `<segment>.jsonl.unsealed`, the sensor logs a warning, and
  `rk audit verify` lists the file. A crash mid-batch therefore loses that
  batch (at most one second of records) from the verified chain instead of
  sealing it.
- Audit recovery trusts only lines that verify: a header or trailer
  appended to the newest segment can no longer choose where the chain
  continues (or get the segment's signed batches truncated). Such a segment
  is left in place for `rk audit verify` to report, or, holding no batch
  that verifies, moved aside to `<segment>.jsonl.forged`, which fails
  verification.
- Audit batches now sign their record count (trailer `"v":2`, hash domain
  `rk-audit-v2`), and a current trailer cannot carry the `recovered` marker.
  Logs from rk 0.2.0 still verify.
- The sensor no longer rewrites a published `audit.key.pub`. If it does not
  match the private key, or exists without it (as after `dpkg --purge` and a
  reinstall), the audit log is not opened and the error says why: move the
  old public key aside if the key change is intended. An existing key owned
  by another user, or in a directory others can write, is refused.
- `rk audit tail` escapes control characters (C0, C1, ESC, DEL) and Unicode
  bidi overrides in what it prints, so a governed process cannot rewrite the
  operator's terminal through a path or argument; `rk audit verify` and the
  comments of `rk policy suggest` do the same.

### Changed

- `rk audit verify` exits 2 (verification failed) in cases it used to pass
  with a warning or silently: an empty audit directory or one with no batch
  that verifies (a header alone is not signed), a change of signing
  key between segments, and a chain that does not start at batch 0. Repeat
  `--pubkey` to accept a key rotation, and pass `--allow-pruned` if you
  removed old segments on purpose. `rk policy suggest` refuses such a log
  too (or use `--no-verify`).
- `rk audit verify --head SEQ:HASH` checks that the chain still passes
  through a head recorded earlier (`rk_audit_head_seq` and the `head_hash`
  label of `rk_audit_info`, or the new `head:` line of `rk audit verify`,
  printed only when the log verifies), so
  removal of the newest batches is detected. docs/audit.md and the threat
  model now say that trust in the log rests on the pinned key and a recorded
  head kept off the host.

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
