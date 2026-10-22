# Host hardening guide

Reality Kernel enforces policy in the kernel, so its guarantees are only as
strong as the host they run on. This guide lists what to configure on hosts
that run `rk-sensor`, and what each Phase 6 protection does and does not
cover (docs/design/phase-6.md).

## Required

| Setting | Why |
|---|---|
| BPF LSM active: `lsm=...,bpf` on the kernel command line, verified with `cat /sys/kernel/security/lsm` | Exec, file, raw-socket and self-protection rules run as BPF-LSM programs. Without it `rk-sensor` refuses those rules, and `rk status` shows `bpf_lsm: inactive`. Network rules still work |
| bpffs mounted at `/sys/fs/bpf` in the host namespace (systemd does this by default) | Pins live there; they are what keeps protection running across sensor restarts |
| cgroup v2 | Every binding is a cgroup |
| `kernel.unprivileged_bpf_disabled = 2` | Only privileged processes may call `bpf()` at all. The guard additionally denies `bpf()` to every governed workload |

## Recommended

| Setting | Why |
|---|---|
| Kernel lockdown (`lockdown=integrity`) | Stops root from loading unsigned modules or writing kernel memory, which would bypass any BPF-based control |
| CAP_BPF, CAP_PERFMON and CAP_SYS_ADMIN only for `rk-sensor` | Anything else holding them can load programs or manipulate maps. Governed workloads should run without them; agents started by `rk run` always do |
| Drop CAP_NET_RAW from workloads that don't need it | Raw sockets bypass connect rules. They are denied for governed profiles with BPF LSM; without it, dropping the capability is the only control |
| Mount bpffs only in the host mount namespace; never into workload containers | A workload that can see the pins can try to remove them. The guard denies this to governed tasks, but ungoverned privileged containers are not covered |
| Keep `/sys/fs/bpf/rk` at mode 0700, root | `rk-sensor` sets this; don't relax it |

## What Phase 6 protects

- **Restarts and crashes.** Programs, maps and links are pinned under
  `/sys/fs/bpf/rk`. Killing or restarting the sensor does not pause
  enforcement; a restarted sensor adopts the pins.
- **Long absence.** The sensor writes a heartbeat every `timeout / 4`. If it
  is older than `--heartbeat-timeout` (default 10 s), every governed ENFORCE
  workload is denied every action until the sensor returns. Events say why
  (`rule_id = 4294967295`). AUDIT workloads are unaffected.
- **Tampering by governed workloads.** For any task in a governed cgroup, the
  guard denies `bpf()`, any signal to the sensor, ptrace access to it
  (including `/proc/<pid>/mem`), and removing pins (unlink, rename, rmdir in
  bpffs, unmounting bpffs). AUDIT profiles report these attempts and allow
  them.

## What it does not protect

- **Ungoverned root.** A process outside every governed cgroup with
  CAP_SYS_ADMIN or CAP_BPF can remove pins or detach programs. Limit those
  capabilities to the sensor, and use kernel lockdown.
- **The kernel itself.** A kernel exploit defeats any in-kernel control. Keep
  kernels patched.
- **What a policy allows.** Self-protection does not widen policy: a workload
  can still do everything its profile permits.

## Operating it

- **Ending protection on purpose:** `rk-sensor --uninstall` removes the pin
  set, and the kernel detaches the programs within a moment. Stop the sensor
  first. `SIGTERM` alone keeps the pins (so upgrades leave no gap), and after
  the heartbeat timeout governed ENFORCE workloads are then denied
  everything.
- **Kubernetes:** the chart mounts the host bpffs and keeps engine state in
  `/var/run/reality-kernel` on the node, so replacing the DaemonSet pod
  leaves no gap. Before `helm uninstall`, run
  `kubectl -n <ns> exec <pod> -c rk-sensor -- rk-sensor --uninstall` on each
  node. Otherwise the pins stay and governed pods are denied once the
  heartbeat goes stale.
- **Choosing the heartbeat timeout:** shorter fails closed sooner after a
  real outage, but longer tolerates slow restarts. Upgrades complete well
  inside the 10 s default.
