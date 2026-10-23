# Design note: Phase 10 — packaging and deployment

Status: **ACCEPTED** (2026-10-22). All six decisions in §8 approved as recommended.
Branch: `phase-10-packaging` (from `main` at e68e2dc)
Plan reference: RealityKernel_Engineering_Plan.pdf, Phase 10 ("Installable,
upgradeable and supportable in enterprise environments").

## 1. Goal and acceptance criteria

Plan acceptance criteria (must pass in CI):

1. Fresh install, upgrade and uninstall are tested in CI on at least two
   distributions.
2. Upgrade keeps enforcement continuous (verified by an integration test).

Plan tasks: a systemd unit with the minimal capability set and hardening
options; a distroless image and a Helm chart; deb and rpm packages; an
upgrade path that adopts pinned objects without a protection gap; a kernel
support matrix and a preflight check (`rk doctor`) that explains missing
kernel features. Deliverables: `deploy/` and a release workflow producing all
artifacts.

## 2. What exists today

| Item | Status |
|---|---|
| Distroless image | `deploy/docker/Dockerfile` (static binaries on `distroless/static`, pinned by digest), built only inside the kind test |
| Helm chart | `deploy/helm/reality-kernel`, tested on kind (Phase 5b, 9) |
| Kernel support matrix | `docs/kernel-matrix.md`, every row backed by the VM job |
| Restart without a gap | Yes when the BPF object is unchanged: pins are adopted (Phase 6) |
| Upgrade without a gap | **No.** A new release usually changes `rk.bpf.o`; `pins::open` then removes the old pin set before loading the new one, a gap of one load-and-attach (Phase 6 §3.4 deferred this here) |
| `rk doctor` | Exists, but checks a 5.8 minimum and a legacy kprobe fallback, and does not explain how to fix what is missing |
| systemd unit, deb, rpm, release workflow | None |
| Clean stop | Fixed in Phase 9: SIGTERM exits within 2 s, pins kept |

## 3. Zero-gap object replacement (criterion 2)

`BPF_LINK_UPDATE` swaps a program atomically, but only cgroup links support
it; the LSM and `tp_btf` links (`bpf_tracing_link`) have no `update_prog`.
So replacement is **make-before-break**:

1. `pins::open` finds `/sys/fs/bpf/rk` created by a different object. It
   loads the new object with its maps pinned under `/sys/fs/bpf/rk-next`
   and returns `Adoption::Replacing`.
2. The sensor starts the heartbeat on the new maps, and the engine migrates
   its state: the state file is read with the **old** pin set's epoch (from
   the old `rk_meta`), then the stored policy text, static and dynamic
   bindings and quarantine are applied to the new maps.
3. All programs are attached, with links pinned under `rk-next/links`. Both
   generations now run: for cgroup `sock_addr` and BPF-LSM hooks every
   attached program runs and any deny wins, so for this moment the effective
   policy is the stricter of the two, never looser.
4. Events the old programs left in the old ring buffer are drained through
   the audit observer, so the audit log keeps them.
5. The old pin set is removed (its links detach: nothing else holds them),
   and `rk-next` is renamed to `rk` (bpffs supports rename).

Crash safety: a sensor that dies in steps 1–4 leaves `rk` attached;
the next start deletes the partial `rk-next` and starts over. One that dies
between removing `rk` and the rename leaves only `rk-next`, which the next
start renames and adopts. At no point is neither set attached.

The old programs check the old heartbeat, which stops being renewed when the
old sensor exits. A package upgrade takes well under the 10 s default
timeout; if it took longer, the old programs would fail closed (deny), which
is disruption, never a gap.

## 4. systemd unit (`deploy/systemd/rk-sensor.service`)

Runs as root with a bounded capability set, derived from the kernel's checks
(`kernel/bpf/syscall.c`, v6.12) and the sensor's own syscalls:

| Capability | Needed for |
|---|---|
| `CAP_BPF` | maps, BTF, program load (`kernel.unprivileged_bpf_disabled` is irrelevant with it) |
| `CAP_PERFMON` | loading LSM and tracing programs (`is_perfmon_prog_type`), kernel reads in them |
| `CAP_NET_ADMIN` | loading and attaching cgroup `sock_addr` programs (`is_net_admin_prog_type`) |
| `CAP_SETUID`, `CAP_SETGID` | `rk run`: the launcher drops agents to the service user |
| `CAP_KILL` | stopping agents, which run as another user |

Not granted: `CAP_SYS_ADMIN` (only for `*_get_fd_by_id`, `bpf_enable_stats`,
mounting bpffs, which systemd already mounts, and the Kubernetes cgroup
namespace switch, which runs in the privileged pod instead);
`CAP_SYS_RESOURCE` (BPF memory is memcg-accounted since 5.11 and the minimum
kernel is 5.15; `LimitMEMLOCK=infinity` is set anyway); `CAP_SYS_PTRACE`
(only needed to read `/proc/<pid>/exe` of other users' processes for
enrichment, which then falls back to `unavailable`; exec records cover
governed processes).

Hardening (as designed; reduced during the build so launched agents keep working, see §9): `NoNewPrivileges`, `ProtectSystem=strict` (with `StateDirectory`,
`LogsDirectory` and `RuntimeDirectory` for `/var/lib/rk`, `/var/log/rk` and
`/run/rk`), `ProtectHome=read-only` (built-in credential rules must see
`~/.ssh` inodes), `PrivateTmp`, `PrivateDevices`, `ProtectKernelModules`,
`ProtectKernelLogs`, `ProtectClock`, `ProtectHostname`,
`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `RestrictNamespaces`,
`RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`,
`MemoryDenyWriteExecute`, `SystemCallArchitectures=native`. Not set:
`ProtectControlGroups` and `ProtectKernelTunables`, which make
`/sys/fs/cgroup` and `/sys/fs/bpf` read-only. `KillMode=process`,
`TimeoutStopSec=10`. The state file moves to `/var/lib/rk` so it survives a
restart (the runtime directory is removed on stop).

CI runs `systemd-analyze verify` on the unit and publishes the
`systemd-analyze security` exposure score.

## 5. Packages and release

- **deb and rpm** built with [nFPM] (one pinned, checksum-verified binary
  for both formats) from the static musl binaries, for x86_64 and arm64:
  `/usr/bin/rk-sensor`, `/usr/bin/rk`, the unit, `/etc/rk/policy.toml` (a
  config file: a default policy that defines profiles but binds nothing, so
  installing governs nothing until configured), docs.
- **Maintainer scripts.** Install: `daemon-reload`, enable and start.
  Upgrade: restart, which adopts or replaces without a gap (§3). Remove:
  stop, then `rk-sensor --uninstall` (otherwise orphaned programs would deny
  every governed ENFORCE action once the heartbeat goes stale). Purge
  additionally deletes the private audit key, but keeps the audit logs and
  `audit.key.pub`, which are evidence.
- **Release workflow** (`release.yml`, on `v*` tags): the static binaries,
  the deb and rpm packages, a multi-arch image on `ghcr.io`, the packaged
  Helm chart, and `SHA256SUMS`, attached to a GitHub release. On pull
  requests the same build runs without publishing and feeds the package
  tests. Signing and SBOMs are Phase 11.

## 6. `rk doctor`

Rewritten around what the sensor actually needs, each check `ok`, `warn` or
`fail` with how to fix it:

| Check | Fail or warn | Explains |
|---|---|---|
| Kernel ≥ 5.15 (supported matrix) | warn below 5.15, fail below 5.8 | upgrade path |
| BTF (`/sys/kernel/btf/vmlinux`) | fail | `CONFIG_DEBUG_INFO_BTF` |
| `CONFIG_BPF_SYSCALL`, `BPF_JIT`, `CGROUP_BPF`, `BPF_LSM` (from `/proc/config.gz` or `/boot/config-*`) | fail / warn for LSM | which option is missing |
| BPF LSM active (`/sys/kernel/security/lsm`) | warn: network rules only | the `lsm=` boot parameter, with the current list |
| cgroup v2 unified hierarchy | fail | `systemd.unified_cgroup_hierarchy=1` |
| bpffs at `/sys/fs/bpf` | fail | the mount |
| Lockdown: `confidentiality` | fail | it forbids the kernel reads the programs make |
| `kernel.unprivileged_bpf_disabled` | warn unless 2 | hardening guide |
| Sensor running, pins present, heartbeat fresh | info | `rk status` |

The legacy kprobe-fallback check is removed. `--json` output; exit 0 when
nothing failed, 2 otherwise. Checks read from an injectable root, so unit
tests run them against fake `/proc`, `/sys` and `/boot` trees.

## 7. Tests

| Criterion | Test |
|---|---|
| Upgrade keeps enforcement continuous | `vm:upgrade_replaces_object_without_gap` on all five kernels: CI builds a second sensor, `rk-sensor-next`, whose embedded object differs (built with `-DRK_OBJECT_VARIANT=1`). A governed child hammers a denied UDP target and an exec deny for the whole switch; zero successes allowed, and thousands of attempts required, so the window was really covered. `vm:upgrade_gap_detector_works`: the same detector across `rk-sensor --uninstall` must see successes, proving it can see a gap. Also checks that the old ring's events reached the audit log and that a crash between steps is recovered (`unit:` tests on the directory state machine) |
| Install, upgrade, uninstall on two distributions | `pkg:` tests on **Ubuntu 24.04** (the deb on the runner itself, real systemd) and **Rocky Linux 9** (the rpm in a privileged systemd container, as kind nodes run): `pkg_fresh_install_enforces` (service active, `rk status` healthy, `rk run` under a deny profile gets EPERM, audit log verifies), `pkg_upgrade_keeps_enforcement` (upgrade to the `-next` package while a governed loop runs: zero successes, object replaced, chain continues), `pkg_uninstall_removes_everything` (no pins, no attached programs, the cgroup is no longer governed, key purged on purge) |
| Minimal capabilities | the package tests run the daemon under the unit's bounded set, so a missing capability fails them; `ci:systemd_unit` runs `systemd-analyze verify` |
| `rk doctor` | unit tests on fake trees (each check's pass, warn and fail); `vm:doctor_passes_on_supported_kernels` on all five kernels; the Ubuntu package test checks that the runner kernel's missing BPF LSM is explained as a warning |
| Release workflow | `ci:package` builds every artifact on pull requests; `release.yml` publishes only on tags |

The `pkg:` kind joins `tests/traceability.toml`, with per-distro reports
checked by the `traceability` job like the VM and kind reports.

## 8. Decisions requested from the reviewer

1. **Capability set: `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN`, `CAP_SETUID`,
   `CAP_SETGID`, `CAP_KILL`; no `CAP_SYS_ADMIN`.** Recommended: it is what
   the kernel checks require. The cost is that procfs enrichment of other
   users' processes needs `CAP_SYS_PTRACE`, which is left out.
2. **Make-before-break replacement** (§3). Recommended: it is the only way
   to replace LSM and tracing links without a gap. The alternative,
   `BPF_LINK_UPDATE`, covers only the cgroup links.
3. **Distributions: Ubuntu 24.04 (deb, native runner) and Rocky Linux 9
   (rpm, systemd container).** Recommended: the two enterprise families, on
   free runners. The runner kernel has no BPF LSM, so the package tests
   cover network enforcement; LSM enforcement stays covered by the five-kernel
   VM matrix.
4. **nFPM for deb and rpm.** Recommended: one tool, one config, built from
   the static binaries CI already produces. The alternative is cargo-deb
   plus cargo-generate-rpm.
5. **Install starts the service with a policy that binds nothing; remove
   uninstalls the pins; purge deletes the private key but keeps the logs
   and the public key.** Recommended.
6. **Release on tags only; signing and SBOM in Phase 11.** Recommended.

[nFPM]: https://nfpm.goreleaser.com/

## 9. Implementation notes (recorded during the build)

- **One more capability: `CAP_DAC_READ_SEARCH`.** File rules key by inode,
  so the engine `stat`s every built-in credential path, including `~/.ssh`
  in each user's home directory. Home directories are 0700, and without this
  capability root cannot traverse them, so those rules would be skipped
  silently. It grants read and search, not write.
- **Unit verification** runs inside the package test (`pkg_unit_verifies`:
  `systemd-analyze verify` and the `security` exposure score), where the
  binary the unit names is installed, rather than in a separate CI job.
- **Replacement order** in the sensor: load the new object under `rk-next`,
  start its heartbeat, attach every program, carry the policy over (the old
  pin set's state file, else the policy file; if neither works the new set is
  removed and the old one keeps enforcing), drain the old ring buffer through
  the audit observer, then remove `rk` and rename `rk-next`.
  `rk-sensor --uninstall` also removes a leftover `rk-next`.
- **rpm has no purge**: `rpm -e` deletes the private key and engine state,
  like `dpkg --purge`; `dpkg --remove` keeps them.
- **Rocky Linux 9 container**: built in CI from the digest-pinned
  `rockylinux:9.6` base with systemd installed, run privileged with a private
  cgroup namespace. bpffs is mounted by the test when the container has none.
- **Upgrade variant**: `rk-bpf/build/<arch>-next` holds `rk.bpf.o` compiled
  with `-DRK_OBJECT_VARIANT=1` (one extra `.rodata` constant);
  `RK_BPF_VARIANT=next` at build time embeds it. The sensor job checks that
  `rk-sensor-next` differs from `rk-sensor`.
- **Release**: the GitHub release is created as a draft, so a person
  reviews and publishes it; the image is pushed as `:<version>` (per-arch
  tags plus a manifest list), never `:latest`.
- **Sandboxing reduced to what agents can live with.** Agents launched by
  `rk run` are children of the service and inherit its mount namespace and
  seccomp filters. `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
  `PrivateDevices`, `MemoryDenyWriteExecute` and `RestrictAddressFamilies`
  would break ordinary agents (working directories, GPU devices, JIT
  runtimes, netlink in libc), and `RestrictNamespaces` makes systemd block
  `clone3` outright, which would push every launch onto the fork fallback
  instead of `CLONE_INTO_CGROUP`. The unit keeps `ProtectSystem=full`,
  kernel module, log, clock and hostname protection, `RestrictRealtime`,
  `RestrictSUIDSGID`, `LockPersonality` and `SystemCallArchitectures`. A
  sensor that launches no agents could be sandboxed further; that split is
  future work.
- **The old-ring drain is bounded** (1 s): the old programs keep writing
  until they are detached, so an unbounded drain could never finish under
  sustained traffic.
- **Stopping is bounded.** Under heavy governed traffic (the upgrade probe
  makes ~85 000 denied connects a second), stopping used to process every
  queued event first and could take arbitrarily long. Now the final ring
  drain is capped at 0.5 s (the rest stays in the pinned ring for the next
  sensor) and the worker at 2 s (the rest is counted as dropped and recorded
  in the audit log as a loss).
- **bpffs refuses dotted names** (`bpf_lookup` returns `EPERM`), so the
  replacement directory is `rk-next`, not `rk.next`.
- **rk.slice is created by `ExecStartPre=+`**: the cgroup root is mode 0555
  (kernfs), so creating a top-level cgroup needs `CAP_DAC_OVERRIDE`, which
  the sensor does not get. That one step runs with full privileges.
- **Per-decision log lines are debug level.** At INFO they flooded the
  system journal under load (the upgrade probe makes ~85 000 decisions a
  second), and journald's rate limit (10 000 messages per 30 s per service)
  then dropped the sensor's own messages, including "replaced the running
  object without a gap". The signed audit log is the record of every
  decision; the line is still available with
  `RUST_LOG=info,rk_sensor::pipeline=debug`, which the agent, resilience and
  Kubernetes suites set because they read it.

