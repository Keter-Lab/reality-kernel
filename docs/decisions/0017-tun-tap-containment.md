# 0017. TUN/TAP containment through the kernel's TUN LSM hooks

Date: 2026-10-24 · Status: Accepted ([Phase 16 design note](../design/phase-16.md))

## Context
ADR-0006 planned to stop governed agents from using TUN/TAP devices by
treating `/dev/net/tun` as a forbidden device in `file_open` and
`file_ioctl` (Phase 4). That was never built. Its premise, that TUN/TAP
needs `CAP_NET_ADMIN`, is also incomplete: attaching to an existing
persistent interface needs no capability when the interface belongs to the
caller's user or group (`tun_not_capable()` in `drivers/net/tun.c`).

## Decision
- Attach BPF-LSM programs to `tun_dev_create`, `tun_dev_open` and
  `tun_dev_attach_queue`, which the TUN driver calls before creating an
  interface, attaching to an existing one, and re-attaching a detached
  queue. Governed tasks are denied with `EPERM` in ENFORCE and recorded as
  `audit_would_deny` in AUDIT.
- The rule follows `network.deny_raw_sockets` (on by default), which now
  covers every packet-injection surface that bypasses the network hooks:
  raw sockets, packet sockets and TUN/TAP.
- The CI kernel matrix builds each kernel from source with the pinned
  image's version and config plus `CONFIG_TUN=y`, so the rule is proven on
  every supported kernel.

## Consequences
- A capability-free agent can no longer tunnel traffic through a TUN device
  its user owns.
- No new policy setting; existing policies keep working, including those on
  hosts without BPF-LSM.
- A TUN queue descriptor attached before the process became governed and
  handed to it stays usable; the threat model records this.
- CI builds five kernels on a cache miss instead of one.
- Supersedes the TUN/TAP part of ADR-0006.
