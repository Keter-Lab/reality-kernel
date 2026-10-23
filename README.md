<div align="center">

<p align="center">
  <img src="assets/logo.png" alt="Reality Kernel" width="100" height="100" style="border-radius: 50%;" />
</p>

# Reality Kernel

### Kernel-level enforcement for AI agents on Linux

Network, exec and file policy decided in the kernel, before the action, with a
signed record of every decision.

[![CI](https://img.shields.io/github/actions/workflow/status/Keter-Lab/reality-kernel/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Keter-Lab/reality-kernel/actions/workflows/ci.yml)
[![Kernel matrix](https://img.shields.io/github/actions/workflow/status/Keter-Lab/reality-kernel/kernel.yml?branch=main&style=flat-square&label=kernels%205.15%E2%80%936.18)](https://github.com/Keter-Lab/reality-kernel/actions/workflows/kernel.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Keter-Lab/reality-kernel/badge)](https://scorecard.dev/viewer/?uri=github.com/Keter-Lab/reality-kernel)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15819/badge)](https://www.bestpractices.dev/projects/15819)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=flat-square)](LICENSE)

**[Install](docs/install.md) · [Policy](docs/policy.md) · [Architecture](docs/architecture.md) · [Threat model](docs/threat-model.md) · [Evidence](docs/evidence.md) · [Website](https://realitykernel.dev/)**

</div>

---

AI agents run shell commands, read files and open network connections with
real privileges. Guardrails that inspect prompts or tool calls sit in front of
the agent; a prompt injection, a bug or a child process can step around them.
Reality Kernel puts the decision where it cannot be stepped around: in eBPF
programs attached to the Linux kernel's BPF-LSM and cgroup socket hooks, for
every process in a governed cgroup.

## What it does

Every statement below links to the criterion whose tests prove it, on every
supported kernel, in every CI run ([how this is checked](docs/testing.md)).

<!-- claims:begin -->
- Denies governed network connections in the kernel with `EPERM`, over TCP and UDP, IPv4 and IPv6. [evidence](docs/evidence.md#net-enforce-eperm)
- Closes the usual bypasses: raw and packet sockets, io_uring, TCP Fast Open and NAT64 addresses. [evidence](docs/evidence.md#net-bypasses)
- Allows only listed executables, decided on file identity rather than path, so symlinks, replaced binaries, scripts and memfd tricks do not get around it. [evidence](docs/evidence.md#exec-allowlist) · [evidence](docs/evidence.md#exec-identity)
- Protects files per access type (read, write, delete, rename, link, create, setattr), whatever name the file is reached by. [evidence](docs/evidence.md#file-access-types) · [evidence](docs/evidence.md#file-identity)
- Governs an agent launched with `rk run` from its first instruction, and every process it starts. [evidence](docs/evidence.md#agent-first-instruction) · [evidence](docs/evidence.md#agent-children)
- Governs Kubernetes pods selected by annotation, through an NRI plugin, from their first instruction. [evidence](docs/evidence.md#k8s-first-instruction)
- Applies policy changes atomically and rolls them back with one command. [evidence](docs/evidence.md#net-atomic-reload) · [evidence](docs/evidence.md#policy-pipeline)
- Offers an audit mode that reports what would be denied without blocking it. [evidence](docs/evidence.md#net-audit)
- Keeps enforcing when the sensor restarts or crashes, and fails closed if it stays down. [evidence](docs/evidence.md#survives-restart) · [evidence](docs/evidence.md#heartbeat-fail-closed)
- Denies governed workloads the means to tamper with it: `bpf()`, signals, ptrace and removing its pins. [evidence](docs/evidence.md#self-protection)
- Upgrades without a protection gap, even when the kernel programs change. [evidence](docs/evidence.md#upgrade_continuous)
- Records every deny and audit-would-deny in a signed, hash-chained OCSF audit log, and detects tampering with it. [evidence](docs/evidence.md#audit_complete) · [evidence](docs/evidence.md#audit_tamper) · [evidence](docs/evidence.md#ocsf_schema)
- Exports Prometheus metrics and OpenTelemetry traces linking agent sessions to their kernel decisions. [evidence](docs/evidence.md#metrics) · [evidence](docs/evidence.md#otlp)
- Says plainly when the kernel lacks BPF LSM, and refuses the rules it could not enforce instead of pretending. [evidence](docs/evidence.md#capability-honesty)
- Measures its per-hook overhead in CI and fails the build when it exceeds the budget. [evidence](docs/evidence.md#perf-gate) · [evidence](docs/evidence.md#perf-reported)
<!-- claims:end -->

## How it works

```
 rk run / Kubernetes ──► rk-sensor ──► cgroup per agent, bound to a profile
 policy.toml ──────────► compiled to BPF maps, swapped atomically

 governed syscall ─► BPF-LSM / cgroup hook ─► allow or EPERM   (in the kernel)
                              └─► ring buffer ─► audit log · metrics · traces
```

Kernel programs are C with libbpf CO-RE, loaded by a Rust sensor that pins
them so they outlive it. Details: [architecture](docs/architecture.md),
[decisions](docs/decisions/README.md), [design notes](docs/design/).

## Quick start

On a host with kernel 5.15 or newer ([supported kernels](docs/kernel-matrix.md)):

```sh
sudo dpkg -i reality-kernel_<version>-1_amd64.deb   # or: sudo rpm -Uvh reality-kernel-<version>-1.x86_64.rpm
rk doctor                                          # checks the kernel features, says how to fix gaps
sudoedit /etc/rk/policy.toml                       # define a profile (docs/policy.md)
sudo systemctl reload rk-sensor
rk run --profile agent -- python my_agent.py       # governed from its first instruction
rk audit tail -f                                   # what it decided, as it happens
```

Kubernetes: the Helm chart in [`deploy/helm/reality-kernel`](deploy/helm/reality-kernel)
runs the sensor as a DaemonSet with the NRI plugin. Full guide:
[docs/install.md](docs/install.md).

Releases are signed with Sigstore and carry SLSA provenance and an SBOM;
[how to verify one](docs/releases.md).

## Documentation

| | |
|---|---|
| [Install, upgrade, remove](docs/install.md) | packages, systemd, Kubernetes, `rk doctor` |
| [Policy reference](docs/policy.md) | profiles, network, exec, files, bindings, rollout |
| [Audit log](docs/audit.md) | format, verification, OCSF fields |
| [Architecture](docs/architecture.md) and [ADRs](docs/decisions/README.md) | how it is built and why |
| [Threat model](docs/threat-model.md) | what it protects against, and what it does not |
| [Hardening](docs/hardening.md) | host settings that matter |
| [Testing](docs/testing.md) and [evidence](docs/evidence.md) | how every claim is tested |
| [Releases](docs/releases.md) | versioning, support window, verifying artifacts |

## Python SDK

The `realitykernel` package on PyPI (`sdk/`) is the earlier, application-level
guard API. It is maintained on a best-effort basis while the analysis engine is
consolidated; see [SECURITY.md](SECURITY.md) for what is supported.

## Contributing and security

Contributions are welcome: [CONTRIBUTING.md](CONTRIBUTING.md) (commits are
signed off under the [DCO](https://developercertificate.org/)),
[GOVERNANCE.md](GOVERNANCE.md). Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

## License

Userspace code is dual-licensed under [Apache-2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT), at your option. The BPF programs in `rk-bpf/` are dual
GPL-2.0-only or MIT ([ADR-0012](docs/decisions/0012-bpf-licensing.md)).
