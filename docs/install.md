# Installing Reality Kernel

Reality Kernel runs as one daemon per host, `rk-sensor`, with the `rk` CLI
beside it. This page covers installing, configuring, upgrading and removing
it. Design: [docs/design/phase-10.md](design/phase-10.md).

## 1. Check the host

```console
$ rk doctor
Reality Kernel preflight (kernel 6.8.0-1017-azure)
  ok    kernel_version    6.8.0-1017-azure (supported: 5.15 and later)
  ok    btf               /sys/kernel/btf/vmlinux present
  WARN  bpf_lsm           not active (lockdown,capability,landlock,yama,apparmor): only network rules can be enforced; ...
                          fix: add `lsm=lockdown,capability,landlock,yama,apparmor,bpf` to the kernel command line ...
  ...
No blocking problem found.
```

`rk doctor` exits 2 when something blocks the sensor (no BTF, no cgroup v2,
no bpffs, `lockdown=confidentiality`, a kernel older than 5.8), and says how
to fix each finding. `--json` gives the same report for automation. Without
BPF LSM only network rules can be enforced; exec, file and raw-socket rules
are refused. Supported kernels: [kernel-matrix.md](kernel-matrix.md).

## 2. Install

The installer picks the deb or rpm for this host, checks it against the
release's `SHA256SUMS` and, when [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
is installed, checks its signature against this repository's release
workflow ([releases.md](releases.md)). A failed check stops the install.

```sh
curl -fsSL https://realitykernel.dev/install.sh | sh
sh install.sh --version 0.2.0       # a given release
sh install.sh --from DIR --dry-run  # local files: verify only
```

Then `sudo rk init` writes a starter policy in AUDIT and
[docs/agents.md](agents.md) walks through the rest. By hand:
packages are attached to each [release](https://github.com/Keter-Lab/reality-kernel/releases),
with `SHA256SUMS`:

```sh
sha256sum -c SHA256SUMS --ignore-missing
sudo dpkg -i reality-kernel_<version>-1_amd64.deb      # Debian, Ubuntu
sudo rpm -Uvh reality-kernel-<version>-1.x86_64.rpm    # RHEL, Rocky, Alma, Fedora
```

Installing enables and starts `rk-sensor.service` with an empty policy: it
loads and attaches its programs but governs nothing until you configure it.

| Path | What |
|---|---|
| `/usr/bin/rk-sensor`, `/usr/bin/rk` | static binaries (BPF objects embedded) |
| `/usr/lib/systemd/system/rk-sensor.service` | the unit |
| `/etc/rk/policy.toml` | the policy (a config file: upgrades keep your edits) |
| `/var/lib/rk/` | engine state and the audit signing key (`audit.key`, 0600; `audit.key.pub`) |
| `/var/log/rk/audit/` | the signed audit log ([audit.md](audit.md)) |
| `/run/rk/agentd.sock` | the control socket used by `rk` |
| `/sys/fs/bpf/rk` | pinned programs, maps and links |

The service runs as root with only the capabilities it needs
(`CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_KILL
CAP_DAC_READ_SEARCH`), `NoNewPrivileges`, and the systemd protections that
are also right for the agents it launches, which inherit them
(`ProtectSystem=full`, kernel module, log, clock and hostname protection,
no realtime scheduling, no set-uid files). An agent's confinement is its
profile's kernel policy. See the comments in the unit and
[hardening.md](hardening.md).

Kubernetes: the Helm chart in `deploy/helm/reality-kernel` runs the same
sensor as a DaemonSet (packaged chart and image `ghcr.io/keter-lab/reality-kernel`
in each release).

## 3. Configure

Edit `/etc/rk/policy.toml` ([policy.md](policy.md)), then apply it:

```sh
sudo systemctl reload rk-sensor     # or: rk policy apply /etc/rk/policy.toml
rk status
```

Launch an agent under a profile with `rk run --profile NAME -- CMD`, or bind
cgroups in the policy. Metrics are served on `127.0.0.1:9464/metrics`.

## 4. Upgrade

```sh
sudo dpkg -i reality-kernel_<new>-1_amd64.deb    # or: sudo rpm -Uvh reality-kernel-<new>-1.x86_64.rpm
```

The package restarts the service. Enforcement never pauses:

- If the new release has the same BPF object, the new sensor adopts the
  pinned programs as they are.
- If the object changed, the new sensor loads it beside the running one,
  moves the policy, bindings and agent sessions over, attaches its programs,
  and only then detaches the old ones (make-before-break). For that moment
  both run, and a deny from either wins.
- The audit chain continues across the upgrade.

While the service is stopped, the pinned programs keep enforcing. If it stays
down longer than the heartbeat timeout (10 s), governed ENFORCE workloads are
denied everything until it returns: fail closed, by design.

## 5. Remove

```sh
sudo dpkg --purge reality-kernel    # or: sudo rpm -e reality-kernel
```

Removal stops the service and runs `rk-sensor --uninstall`, which detaches
every program: protection ends, explicitly. The private audit key and the
engine state are deleted (`dpkg --remove` keeps them; `--purge` and `rpm -e`
delete them). The audit logs and the public key stay, as evidence; delete
`/var/log/rk` and `/var/lib/rk` yourself when you no longer need them. If
you install again after a purge, the sensor will not replace the kept
`audit.key.pub` with a new key's: move it aside first (keep it to verify
the old segments, with `rk audit verify --pubkey OLD --pubkey NEW`), or the
audit log stays off ([audit.md](audit.md#reading-and-verifying)).

To end protection without removing the package: `sudo rk-sensor --uninstall`
after stopping the service.
