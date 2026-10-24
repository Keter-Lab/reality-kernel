# Design note: Phase 16 — TUN/TAP containment

Status: **ACCEPTED** (2026-10-24; the maintainer approved the design and
its CI cost before implementation).
Branch: `phase-16-tun` (from `main` at 0fc1037)
Roadmap: hardening item h. Decision record: [ADR-0017](../decisions/0017-tun-tap-containment.md).

## 1. Problem

ADR-0006 promised that governed agents could not use TUN/TAP devices. That
was never built (ADR-0006 status note). A TUN/TAP interface lets a process
read and write whole IP packets or Ethernet frames through a virtual
interface, so traffic leaving through it never passes the `cgroup/connect*`
and `sendmsg*` hooks.

The threat model says the residual risk needs `CAP_NET_ADMIN`. Reading
`drivers/net/tun.c` (identical on 5.15 and 6.18) shows that is only half
true:

- **Creating** a TUN/TAP interface (`TUNSETIFF` with a new name) needs
  `CAP_NET_ADMIN` in the network namespace's user namespace.
- **Attaching** to an existing persistent interface (`TUNSETIFF` with its
  name) needs **no capability** when the interface's owner or group matches
  the caller (`tun_not_capable()`). An administrator who once ran
  `ip tuntap add mode tun user agent` has made a tunnel any process running
  as that user can open, including an `rk run` agent with every capability
  cleared.

So today a capability-free governed agent can bypass network policy through
a persistent TUN device that belongs to its user.

## 2. Acceptance criteria

1. **ENFORCE:** a governed process cannot create a TUN/TAP interface,
   attach to an existing one (including one it owns), or re-attach a
   detached queue. Each attempt fails with `EPERM`.
2. **AUDIT:** the same attempts succeed and each is recorded as
   `audit_would_deny`.
3. Processes outside governed cgroups are unaffected. A negative control
   shows that the attach in criterion 1 succeeds for the same user outside
   governance, so the denial is ours and not `tun_not_capable()`.
4. Every attempt is counted in the decision counters and emitted as an
   audit record (OCSF Network Activity) that names the operation.
5. Profiles that set `network.deny_raw_sockets = false` are unaffected, as
   are hosts without BPF-LSM (the rule needs it, like raw sockets).
6. Proven on every kernel in the matrix (5.15, 6.1, 6.6, 6.12, 6.18).

## 3. Design

### 3.1 Hooks

The kernel has LSM hooks made for exactly these operations, called from
`tun.c` after its own permission checks:

| Hook | Called from | Operation |
|---|---|---|
| `tun_dev_create` | `tun_set_iff()`, new interface | create |
| `tun_dev_open` | `tun_set_iff()`, existing interface | attach |
| `tun_dev_attach_queue` | `tun_set_queue()`, `IFF_ATTACH_QUEUE` | re-attach a detached queue |

All three exist with the same signatures from 5.15 to 6.18
(`include/linux/lsm_hook_defs.h`), are compiled whenever
`CONFIG_SECURITY_NETWORK` is set (already required for `socket_create`),
and are not in BPF-LSM's disabled set (`kernel/bpf/bpf_lsm.c`). They are
called whether TUN is built in or a module.

Each program does what `rk_net_socket_create` does: one governance lookup
(ungoverned tasks return at once), count the decision, emit an event,
return `-EPERM` when enforced.

**Why not ADR-0006's plan (`file_open` on `/dev/net/tun`, `file_ioctl`)?**
Opening `/dev/net/tun` does nothing by itself; the hooks above sit on the
operations that matter. A device-number match in `file_open` would also miss
descriptors opened before the process was governed, and `file_ioctl` would
have to decode ioctl numbers that the kernel already decodes for us.

### 3.2 Policy

The rule is governed by the existing `network.deny_raw_sockets` setting
(kernel flag `RK_PROFILE_DENY_RAW_SOCKETS`, on by default), which now means
"deny packet-injection surfaces that bypass the network hooks": raw and
packet sockets, and TUN/TAP.

A separate setting defaulting to on would break existing policies on hosts
without BPF-LSM: those must already set `deny_raw_sockets = false`
(`rk-sensor/src/policy.rs`), and would be rejected after upgrade until they
also turned off the new setting. The setting keeps its name for
compatibility; `docs/policy.md` documents the wider meaning.

### 3.3 ABI and records

- `enum rk_hook`: `RK_HOOK_TUN = 8`; `RK_HOOK_MAX` 9; `RK_CNT_MAX`
  2 + 9 × 3 = 29. Counters live in a per-object map, so an upgrade loads the
  larger map beside the old one (ADR-0015); nothing is copied by index.
- `enum rk_event_type`: `RK_EV_TUN = 12`, payload `struct rk_payload_tun`
  (8 bytes: `__u32 op` with 1 create, 2 attach, 3 attach_queue; `__u32 _pad`).
  The hooks receive no interface name, so none is recorded.
- Decoder, `metrics::HOOKS` (`"tun"`), `docs/abi.md`.
- OCSF: Network Activity (4001), activity 99, activity name
  `TUN/TAP Create`, `TUN/TAP Attach` or `TUN/TAP Attach Queue`;
  `unmapped.rk.tun_op`.

`RK_ABI_VERSION` stays 1: records keep their envelope, and the decoder and
objects ship together in one binary.

### 3.4 Residual risk (documented, not fixed)

A descriptor already attached to a TUN queue before the process became
governed (inherited or passed over a Unix socket by an ungoverned process)
keeps working: reads and writes on it reach no TUN hook. This needs a
cooperating ungoverned process with access to the device, which is outside
the agent's control. The threat model records it.

## 4. Tests

The pinned LVH kernel images are built without TUN (`# CONFIG_TUN is not
set` in all five, checked 2026-10-24). The hooks would load there, but
nothing could exercise them. The matrix therefore builds every kernel from
source, as it already does for 5.15: same version as the pinned image
(5.15.222, 6.1.189, 6.6.158, 6.12.112, 6.18.56), the image's own config, plus
`CONFIG_TUN=y` (and `CONFIG_VIRTIO_CONSOLE=y`, which 5.15 needed). Tarballs
are pinned by the SHA-256 published in kernel.org's `sha256sums.asc`. Builds are
cached per version and config, so only the first run pays for them.

New VM tests (`tests/integration`), each in the enforce, audit and
ungoverned cgroups as the criteria require:

| Test | Shows |
|---|---|
| `tun_create_denied` | a governed root process with `CAP_NET_ADMIN` cannot create `rktun0` (`EPERM`) |
| `tun_attach_owned_denied` | the harness creates a persistent `rktun1` owned by uid 65534; a governed process running as 65534 with no capabilities cannot attach (`EPERM`) |
| `tun_attach_owned_ungoverned` | negative control: the same process outside governance attaches |
| `tun_attach_queue_denied` | a detached multi-queue descriptor handed to a governed process cannot be re-attached (`EPERM`) |
| `tun_audit_would_deny` | in the audit cgroup create and attach succeed and both records carry `audit_would_deny` and the right `tun_op` |
| `tun_allowed_without_flag` | a profile with `deny_raw_sockets = false` creates and attaches |

Decoder and OCSF mapping get unit tests like the other events. The new
criterion joins `tests/traceability.toml`.

## 5. Not in scope

- Other device nodes (`/dev/kvm`, `/dev/vhost-net`, macvtap): the deferred
  edge/device-control work in the roadmap.
- `CAP_NET_ADMIN`-gated netlink paths that create other virtual links
  (veth, macvlan): they need `CAP_NET_ADMIN`, which `rk run` agents never
  have; a netlink rule is a separate decision.
