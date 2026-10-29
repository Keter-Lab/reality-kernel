# Changelog

Notable changes to the sensor, kernel programs, CLI, NRI plugin, Helm chart
and container image. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) as described in
[docs/releases.md](docs/releases.md).

## [Unreleased]

### Security

- Governance is now ancestor-aware (docs/design/cgroup-ancestry.md). A task
  that moves into a descendant of its bound cgroup — which only a privileged or
  delegated workload can do — stays governed under that cgroup's profile,
  instead of becoming silently ungoverned in every domain. On an exact-lookup
  miss the kernel resolves the nearest bound ancestor, bounded by the set of
  bound hierarchy levels the sensor publishes. A cgroup bound deeper than 16
  levels keeps its exact match but its descendants are not covered (logged at
  apply). Moving to an unbound sibling or the root by a separate privileged
  process is still outside the guarantee (threat model §6).

### Changed

- The kernel/userspace ABI is version 2 (`rk_config` gained a field). The pin
  set is replaced once on upgrade, as on any ABI change.

## [0.3.0] - 2026-10-28

A security release. An external white-box review of 0.2.0 confirmed 26
issues; this release closes them or documents them as residual risks in
docs/threat-model.md. Upgrade from 0.2.0: it fixes ways enforcement could
silently do nothing.

### Upgrading from 0.2.0

These changes are incompatible with 0.2.0:

- `rk status` and `rk policy diff` need a policy admin (root or group `rk`).
- `rk audit verify` fails (exit 2) on an empty log or one with no sealed
  batch, a signing-key change (pass every legitimate key with `--pubkey`),
  and removed oldest segments (pass `--allow-pruned` if you pruned them).
  New batches use trailer `"v":2`; logs written by 0.2.0 still verify.
- After `dpkg --purge` and a reinstall, the audit log stays off until the
  old `audit.key.pub` is moved aside (docs/install.md).
- Profiles with `deny_raw_sockets` (the default) can no longer create ICMP
  ping, UDP-Lite, SCTP, DCCP or MPTCP sockets.
- Exec allowlists on btrfs are refused at apply time (they never matched
  there before, so every exec was denied).
- Kubernetes: while rk-sensor is unreachable, rk-nri refuses every
  container except unannotated pods in `exemptNamespaces`, which are never
  governed. Add your cluster's network, storage and node-agent namespaces
  there. The chart refuses a namespace that is both exempt and governed.

### Security

- File and exec rules now resolve to the superblock device the kernel hooks
  compare (read from `/proc/self/mountinfo`) instead of `stat`'s `st_dev`.
  On btrfs subvolumes and snapshots the two differ, so every file rule, every
  exec allow-list entry and the built-in credentials list silently never
  matched there. A rule path whose mount cannot be found now fails the apply;
  a path on another filesystem whose `stat` device differs (for example
  overlayfs) is logged as a warning. `rk policy suggest` matches the
  executables it learns the same way, so it finds them on btrfs too. Exec
  allowlists on btrfs are refused at apply time: inode numbers repeat across
  subvolumes, so an entry would also allow another subvolume's file.
- `network.deny_raw_sockets` (on by default) now also denies every inet
  socket the connect and send hooks cannot see: ICMP ping, UDP-Lite, SCTP,
  DCCP, MPTCP, `SOCK_SEQPACKET` and any non-TCP stream or non-UDP datagram
  socket. Before, such sockets reached a denied destination with no verdict
  and no event. Plain TCP and UDP sockets (protocol 0 included) are
  unaffected. docs/policy.md now says that `proto = ["other"]` matches
  almost nothing.
- The `create` right of a protected directory is now checked for every way
  of adding a name to it: the destination of `rename(2)` and `link(2)`, and
  `symlink(2)` and `mknod(2)` (new `rk_file_symlink` and `rk_file_mknod`
  programs on `inode_symlink` and `inode_mknod`). Before, only `open(O_CREAT)`
  and `mkdir` were checked, so entries could be planted in a protected
  directory.
- docs/threat-model.md lists the remaining gaps: leaving the bound cgroup is
  only prevented by cgroupfs permissions (privileged workloads and delegated
  agent cgroups are outside the guarantee until governance is ancestor-aware),
  address families other than inet and packet are not classified, and
  subtree rules stop at nested mounts.
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
  comments of `rk policy suggest` do the same. `rk audit tail --json` writes
  them as `\uXXXX` escapes, so its lines are the same JSON values as stored.

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
- `rk status` and `rk policy diff` now require a policy admin (root or a
  member of group `rk`), like `rk policy apply`: they disclose the whole
  policy and the agent inventory.
- `rk run` refuses an unknown profile and one the caller may not launch with
  the same message, so an unprivileged caller cannot probe which profiles
  exist. A policy admin still gets the reason.
- rk-nri: while rk-sensor is unreachable, every container is refused except
  unannotated pods in an explicit exempt set (new Helm value
  `exemptNamespaces`, default `kube-system`, plus the chart's own namespace).
  Before, any namespace missing from the chart's `namespaces` list started
  ungoverned, including one given rules after the plugin started.
  `-governed-namespaces` is ignored. `failurePolicy: Ignore` is now logged
  as starting containers UNGOVERNED, at startup and for each container.
  Unannotated pods in an exempt namespace are never governed and start
  without a call to rk-sensor, so an outage cannot delay them; rk-nri logs
  each exempt namespace at startup and each refused container, and the chart
  refuses to render if an exempt namespace (including its own) has rules in
  `namespaces`. Upgrading: with rk-sensor down, pods in other namespaces wait
  for it, retried by kubelet with backoff (`kubectl rollout restart`
  unsticks one that gave up). List your cluster's network, storage and node
  agent namespaces in `exemptNamespaces` (see values.yaml).

### Fixed

- Launcher fork fallback (kernels without `clone3`): the child now runs the
  command only after the explicit release byte, and is killed and reaped if
  the cgroup attach fails. Before, a failed attach could leave a uid-0 child
  that later ran the command in the daemon's own, ungoverned cgroup. A
  launch whose `/proc/<pid>/cgroup` cannot be read is now a failed launch.
- `rk` Signal requests go through the agent's pidfd, and the agent leaves
  the registry as soon as it is reaped, so a signal can never reach a
  process that reused the pid.
- Container binding: the cgroup read from the runtime's pid must name the
  container id, and the process is held with a pidfd while it is read, so a
  recycled pid cannot bind another workload's cgroup.
- Audit enrichment checks process start times, so after pid reuse a decision
  is recorded with `enrichment: unavailable` instead of naming another
  process's executable. A cached entry whose start time could not be read
  is not used either.
- A sensor restart that adopts pins without a usable state file keeps every
  cgroup binding in the kernel instead of removing all that the policy file
  does not name, which unbound every running agent and container.
- A runtime binding whose cgroup is gone no longer blocks removing its
  profile; the next apply drops it.
- An apply that would overflow a map is refused before the generation flip
  (and by `--dry-run` alike), and a failure after the flip no longer leaves
  the daemon reporting the previous policy.
- An interrupted pin-set replacement can no longer delete the only pin set
  still holding links: the old set is renamed away before anything is
  removed, and a replacement is discarded only while the live set holds
  links.
- On arm64 the launcher's capability drop called the wrong syscall (it
  used x86_64's number for `capset`); it now takes the number from libc.

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

[Unreleased]: https://github.com/Keter-Lab/reality-kernel/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Keter-Lab/reality-kernel/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Keter-Lab/reality-kernel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Keter-Lab/reality-kernel/releases/tag/v0.1.0
