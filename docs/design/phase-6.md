# Design note: Phase 6 — resilience and self-protection

Status: **ACCEPTED** (2026-10-22). All five decisions in §9 approved as recommended.
Branch: `phase-6-resilience` (from `main` at f5eb4ec)
Plan reference: RealityKernel_Engineering_Plan.pdf, Phase 6 ("Protection
survives daemon restarts and governed workloads cannot weaken it").

## 1. Goal and scope

Today, killing `rk-sensor` drops every BPF link, so protection ends with the
process. A governed workload with enough privilege can also attack the sensor
itself (signals, ptrace, `bpf()`), and nothing forces a decision when the
sensor is gone for good. Phase 6 makes protection outlive the process,
makes a long absence fail closed, and stops governed workloads from tampering.

Plan acceptance criteria:

1. Restarting or killing the sensor does not remove protection; enforcing
   verdicts continue.
2. After the heartbeat timeout, governed ENFORCE workloads are denied until
   the sensor returns.
3. Governed workloads get EPERM for the actions covered by the
   self-protection hooks.

Out of scope: upgrading to a *different* BPF object with no gap (Phase 10's
"upgrade path that adopts pinned objects without a protection gap"); here an
incompatible pin set is replaced, with a logged gap (§3.4).

## 2. Prerequisite: aya 0.14 (ring buffer adoption)

Adopting a pinned ring buffer means a new process opens a ring whose consumer
position is not 0. aya 0.13.1's `RingBuf` starts its producer-position cache
at 0, so in that case `data_available` reports data without loading the real
producer position and walks stale ring memory forever. This is the root cause
of the Phase 2 eight-hour hang (memory note: single reader). aya 0.14.0
(2026-06-24) fixes it (`pos_cache = load_producer_pos(&mmap)` at construction)
and also adds a missing StoreLoad barrier that could leave committed records
unnotified. 0.14 needs Rust 1.87 (we are at 1.85); its changelog shows no
breaking change in the APIs we use, which CI will confirm.

The upgrade lands first, as its own small PR, proven green on all five kernels
before any Phase 6 feature depends on it (decision 1).

## 3. Pinning and adoption

### 3.1 Layout

```
/sys/fs/bpf/rk/            0700 root
  maps/<name>              every map, pinned by name (LIBBPF_PIN_BY_NAME)
  links/<program>[@<root>] every link; cgroup links once per attach root
  meta                     rk_meta map: ABI version, object hash, pin epoch
```

Maps are declared with `__uint(pinning, LIBBPF_PIN_BY_NAME)` and loaded with
`EbpfLoader::map_pin_path("/sys/fs/bpf/rk/maps")`. aya then opens a map that
is already pinned instead of creating a new one, so a restarted sensor writes
into the very maps the live programs read. Links are converted to `FdLink`
and pinned (`FdLink::pin`).

### 3.2 First start

Load, attach, pin links, write `rk_meta` (`RK_ABI_VERSION`, a SHA-256 of the
embedded object, a random pin epoch), then start the heartbeat (§4).

### 3.3 Restart: adopt

If `rk_meta` matches the embedded object, the sensor **does not attach
anything**. Every pinned link is opened (`PinnedLink::from_pin`) to check it
is present; a missing one is re-attached and pinned. Programs are not reloaded.
The links never dropped, so enforcement never paused (criterion 1).

The policy engine's in-memory state (profile id allocation, generation,
active slot, dynamic agent and container bindings, quarantine, the active and
previous policy text) must survive too: profile ids are baked into binding
values, so re-allocating them could point a live binding at the wrong profile.
It is persisted to `/run/rk/engine-state.json` (0600) after every change and
reloaded on adoption, accepted only if its pin epoch equals the one in
`rk_meta` (decision 2). The inactive slot's contents are not trusted from the
file: on adoption it is cleared by scanning the maps for keys whose scope
carries the inactive slot bit. Then the policy file is applied as usual.

### 3.4 Incompatible pins

If `rk_meta` differs (another ABI or object), the old pin set is removed and
a fresh one created. This leaves a gap of one load-and-attach (well under a
second), logged as a warning. Zero-gap replacement (`BPF_LINK_UPDATE` per
link) is Phase 10.

### 3.5 Removing protection on purpose

`rk-sensor --uninstall` detaches by removing `/sys/fs/bpf/rk`. It is the only
way to turn protection off without waiting for the heartbeat to fail closed;
`SIGTERM` keeps the pins (an upgrade or restart must not open a gap).

Kubernetes: the chart mounts host `/sys/fs/bpf` and moves the state file to a
hostPath (`/var/run/reality-kernel`), so a DaemonSet pod replacement adopts
too. This also closes the restart gap documented in Phase 5b.

## 4. Heartbeat: fail closed when the sensor is gone

- `rk_heartbeat`, an array map with one `u64`: the last `CLOCK_BOOTTIME` the
  sensor wrote. `rk_config` holds the timeout (`--heartbeat-timeout`, default
  10 s, minimum 1 s). Both are created `BPF_F_RDONLY_PROG`: programs read
  them, only userspace can write them.
- The sensor writes the heartbeat every timeout/4 from a dedicated OS thread,
  so a busy async runtime can't starve it.
- `rk_governance()` sets `g->stale` when `bpf_ktime_get_boot_ns()` minus the
  heartbeat exceeds the timeout (a heartbeat of 0, never written, is stale).
  `rk_enforced_deny()` and `rk_reported_verdict()` treat a stale ENFORCE
  profile as DENY for every governed action: connect, sendmsg, exec, every
  file hook. AUDIT profiles keep their verdicts (criterion 2).
- Events denied for this reason carry `rule_id = RK_RULE_HEARTBEAT`
  (`0xFFFFFFFF`, new ABI constant; no struct change), so audit logs say why.

This is deliberately harsh: a governed ENFORCE workload whose sensor has been
gone longer than the timeout can do almost nothing. That is the plan's
fail-closed requirement; operators who prefer availability use AUDIT, a
longer timeout, or `--uninstall`.

## 5. Self-protection hooks (`guard.bpf.c`)

All apply to governed tasks only (the usual `rk_governance()` lookup). ENFORCE
returns `-EPERM`; AUDIT emits the event and allows. Events use the existing
`RK_EV_TAMPER` type with a small payload naming the hook and target.

| Hook | Denies |
|---|---|
| `lsm/bpf` | every `bpf()` command (map/prog/link manipulation, pin access) |
| `lsm/task_kill` | any signal to the sensor, including `pidfd_send_signal` |
| `lsm/ptrace_access_check` | ptrace attach, `/proc/<sensor>/mem`, `process_vm_readv` on the sensor |
| `lsm/inode_unlink`, `inode_rename`, `inode_rmdir` on bpffs | removing or moving pins |
| `lsm/sb_umount` on bpffs | unmounting bpffs (which drops pins when it is the last mount) |

The sensor is identified by `{tgid, start_boottime}` in `rk_guard`
(`BPF_F_RDONLY_PROG`), so a recycled PID after the sensor dies is not
mistaken for it. bpffs is recognised by its superblock magic (`0xcafe4a11`).

Agents launched by `rk run` already run unprivileged and could not do most of
this anyway; the hooks matter for root containers and for any privileged
workload placed under a profile.

## 6. Read-only configuration

- Userspace-only maps (`rk_config`, `rk_heartbeat`, `rk_guard`, `rk_meta`)
  are `BPF_F_RDONLY_PROG`.
- Constants that never change for a loaded object move to `const volatile`
  globals in `.rodata`, which the loader freezes.
- Pin directory `0700` root; state file `0600`.

Policy maps stay writable by userspace only (programs never write them); BPF
has no per-map "userspace writes only from this PID" control, which is why the
`bpf()` guard exists.

## 7. Hardening guide (`docs/hardening.md`)

Kernel lockdown (`integrity`) where available, BPF LSM enabled, unprivileged
BPF disabled (`kernel.unprivileged_bpf_disabled=2`), CAP_BPF and
CAP_SYS_ADMIN limited to the sensor, bpffs mounted only in the host
namespace, the heartbeat timeout trade-off, `--uninstall`, and what each guard
hook does and does not cover.

## 8. Tests (each acceptance criterion maps to a named test)

A new resilience suite in `rk-integration` drives the real daemon in the VM
matrix (5.15–6.18), like the Phase 5 agent suite. Workloads run as root in
bound cgroups, since the guard hooks matter for privileged workloads.

| Criterion | Test |
|---|---|
| Killing the sensor keeps enforcement | `sensor_kill_keeps_enforcement`: SIGKILL the daemon; a denied connect and exec stay EPERM, allowed ones stay allowed |
| Restart adopts, no gap | `sensor_restart_adopts_pins`: link ids unchanged (bpftool), policy generation continues, a running agent's binding kept; a paced workload sees no allowed event for a denied destination across the restart |
| Stale heartbeat fails closed | `heartbeat_stale_denies_enforce`: after the timeout an ENFORCE workload's *allowed* connect gets EPERM with `RK_RULE_HEARTBEAT`; an AUDIT workload is unaffected |
| Recovery | `heartbeat_recovers_on_restart` |
| Guard: bpf() | `guard_bpf_syscall_denied` (root in a governed cgroup; an ungoverned control succeeds) |
| Guard: signals | `guard_signal_sensor_denied` (SIGCONT, harmless; control succeeds) |
| Guard: ptrace | `guard_ptrace_sensor_denied` (PTRACE_SEIZE and `/proc/<pid>/mem`; control succeeds) |
| Guard: pins | `guard_pins_cannot_be_removed` (unlink, rename, umount) |
| Permissions | `pin_dir_restricted` |
| Incompatible pins | `incompatible_pins_replaced` |
| Uninstall | `uninstall_removes_protection` |

kind: `k8s_daemon_restart_resyncs` is tightened. A running pod stays denied
*during* the DaemonSet pod restart, not only after it.

## 9. Decisions requested from the reviewer

1. **Upgrade to aya 0.14.0 first, as its own PR.** Recommended: it fixes the
   ring-reader bug that makes adoption unsafe and a missed-notification race,
   and keeps us on a maintained release. The alternative, our own ~150-line
   ring reader on aya 0.13, adds code we must maintain.
2. **Persist engine state in `/run/rk/engine-state.json`, checked against a
   pin epoch.** Recommended: simple, inspectable, same lifetime as the pins
   (both end at reboot). The alternative, storing it as a blob in a pinned
   map, is atomic with the pins but opaque and awkward to inspect.
3. **Heartbeat: default 10 s, stale ENFORCE denies every governed action,
   AUDIT unaffected.** Recommended: it is the plan's fail-closed semantics,
   with a clear rule id in every such event.
4. **Guard scope as in §5, ENFORCE denies and AUDIT logs.** Recommended:
   covers the plan's three items plus the pin-removal and umount routes that
   would otherwise undo criterion 1.
5. **Incompatible pins are replaced with a logged gap; zero-gap upgrade in
   Phase 10.** Recommended: keeps this phase focused; the gap is a single
   load-and-attach.
