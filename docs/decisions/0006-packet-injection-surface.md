# 0006. Packet injection surface and raw socket containment

Date: 2026-10-20 · Status: Accepted

## Context
Phase 2 attaches `cgroup/sock_addr` hooks (`connect4`, `connect6`, `sendmsg4`, `sendmsg6`) to `/sys/fs/cgroup/rk.slice` to mediate standard TCP and UDP socket egress over IPv4 and IPv6.

However, standard cgroup socket address hooks only intercept standard `AF_INET` and `AF_INET6` stream and datagram operations. They do not cover lower-level packet injection vectors that malicious or compromised agent workloads could invoke:

1. **`AF_PACKET` sockets:** Sockets in the `AF_PACKET` family operate at Layer 2 (link layer). A process can construct arbitrary raw Ethernet frames and inject arbitrary IP packets directly into the network interface, completely bypassing `cgroup/connect*` and `cgroup/sendmsg*` hooks.
2. **`PACKET_VNET_HDR`:** With an `AF_PACKET` socket, userland can enable the `PACKET_VNET_HDR` socket option (`SOL_PACKET`), prefixing transmitted frames with a `virtio_net_hdr`. This allows userland to supply arbitrary deferred checksum offload metadata (`csum_start`, `csum_offset`). As demonstrated in recent hypervisor and container escape research (e.g. PwnEscape), weaponizing deferred checksum calculation can mutate Layer 3 IP headers in-flight (flipping `0x45` to `0x4F`), causing kernel packet fragmenters to read and transmit raw host kernel memory, bypassing host KASLR and escaping isolation.
3. **`SOCK_RAW` on `AF_INET` and `AF_INET6`:** Allows crafting raw IP datagrams with custom protocol numbers, bypassing transport-layer port controls.
4. **Virtual network devices (TUN/TAP):** Opening `/dev/net/tun` and issuing `ioctl(TUNSETIFF)` creates a virtual network interface, allowing an agent to establish an unmonitored Layer 2/3 tunnel.

## Decision
- **BPF-LSM `socket_create` hook:** `rk_net_socket_create` attaches host-wide to `lsm/socket_create`. Ungoverned tasks pay the cost of a single fast-path cgroup lookup (`rk_governance`), which returns immediately for non-agent workloads.
- **Immediate denial of raw injection in ENFORCE mode:**
  - If a governed task belongs to a profile with `RK_PROFILE_DENY_RAW_SOCKETS` (default in ENFORCE):
    - Any attempt to create an `AF_PACKET` socket (`family == AF_PACKET`) is denied immediately with `-EPERM`. This prevents acquiring an `AF_PACKET` file descriptor altogether, blocking `PACKET_VNET_HDR`, packet injection, and raw frame manipulation at the root.
    - Any attempt to create a raw socket (`type == SOCK_RAW` for `AF_INET` or `AF_INET6`) is denied immediately with `-EPERM`.
- **TUN/TAP containment across phases:**
  - **Phase 2:** Creating a TUN/TAP interface requires `CAP_NET_ADMIN`. Governed agent workloads running under Phase 2 test environments are verified without `CAP_NET_ADMIN`.
  - **Phase 4 (File & Device Policy):** Opening `/dev/net/tun` and invoking device ioctls will be explicitly governed under LSM `file_open` and `file_ioctl` hooks, treating `/dev/net/tun` as an unauthorized device node.
  - **Phase 5 (`rk-agentd`):** Autonomous agents run with dropped capabilities (`CAP_NET_ADMIN` and `CAP_NET_RAW` permanently stripped from the bounding set).
- **Integration verification:**
  - `net_raw_socket_denied`: Proves `socket(AF_INET, SOCK_RAW, ...)` and `socket(AF_INET6, SOCK_RAW, ...)` are denied with `EPERM`.
  - `net_packet_vnet_hdr_denied`: Proves `socket(AF_PACKET, SOCK_RAW, ...)` is denied with `EPERM`.

## Consequences
- Malicious or compromised agent processes cannot circumvent kernel egress policies by assembling raw packets or exploiting deferred checksum offload vulnerabilities.
- Packet sniffers (e.g. `tcpdump`) and link-layer injection tools cannot run within governed agent cgroups.
- Clean defense-in-depth: socket creation is blocked at Layer 4/LSM in Phase 2; character device access (`/dev/net/tun`) is blocked at Layer 0/VFS in Phase 4.

## Status note (2026-10-23)

The Phase 4 TUN/TAP item above was not implemented: `docs/design/phase-4.md`
deferred it to an addendum that was never written, and no hook governs
`/dev/net/tun`. What holds today: creating a TUN/TAP interface needs
`CAP_NET_ADMIN`, and agents launched with `rk run` run with every capability
cleared and `no_new_privs` set (Phase 5). A governed workload that keeps
`CAP_NET_ADMIN`, such as a privileged pod or a statically bound service, is not
covered. The threat model lists this as a residual risk; closing it is planned
hardening work and will be recorded in a new ADR.
