# Security policy

Reality Kernel enforces policy in the Linux kernel on behalf of its users, so
a flaw in it can widen what a governed workload is allowed to do. Reports
are welcome and are handled as described here.

## Supported versions

| Component | Version | Status |
|---|---|---|
| Sensor (`rk-sensor`), kernel programs, CLI (`rk`) | 0.1.x | Supported |
| NRI plugin (`rk-nri`), Helm chart, container image | 0.1.x | Supported |
| Anything older | — | Not supported |
| Python SDK (`realitykernel` on PyPI) and the hosted API | — | Retired ([ADR-0016](docs/decisions/0016-retire-the-hosted-product.md)) |

"Supported" means fixes are released for the latest minor version.
Versioning and the support window: [docs/releases.md](docs/releases.md).

## Reporting a vulnerability

Please do **not** open a public issue, discussion or pull request.

Report privately through either channel:

- **GitHub:** [Report a vulnerability](https://github.com/Keter-Lab/reality-kernel/security/advisories/new)
  (private vulnerability reporting), or
- **Email:** security@realitykernel.dev

Helpful details:

- the affected component and version (`rk-sensor --version`, `rk --version`);
- the kernel version and distribution (`uname -r`, and `rk doctor` output);
- the policy profile involved, reduced to the smallest one that reproduces it;
- steps to reproduce, or a proof of concept;
- the impact as you understand it: for example, a governed workload making
  a connection, running a program or touching a file its profile denies.

## What happens next

| Step | Target |
|---|---|
| Acknowledgement of your report | within 3 business days |
| Initial assessment (confirmed or not, severity) | within 7 days |
| Fix released for a critical issue | within 30 days |
| Coordinated public disclosure | within 90 days of the report, or earlier once a fix is released |

Fixes are published as a GitHub Security Advisory with a CVE where one
applies, and are listed in [CHANGELOG.md](CHANGELOG.md). Reporters are
credited unless they ask not to be.

## Scope

In scope:

- a governed workload acting outside its profile (network, exec, file);
- a governed workload tampering with the sensor, its pins or its maps;
- an enforcement gap during restart, reload or upgrade;
- an unprivileged local user changing policy or bindings through the agentd
  socket;
- forging or undetectably altering the audit log;
- release artifacts that verify but were not built by this repository's
  release workflow.

Out of scope, by design ([threat model](docs/threat-model.md#5-explicitly-out-of-scope)):
root on the host or a compromised kernel, ungoverned workloads, kernels
without BPF LSM for exec and file rules (reported by `rk doctor`), side
channels, physical access and denial of service against the host.

## Safe harbour

Good-faith research that follows this policy, avoids privacy violations and
service disruption, and is limited to systems you own or are authorised to
test will not be pursued by the maintainers.

## Verifying what you run

Every release file is signed with Sigstore and carries SLSA build provenance
and an SPDX SBOM: [docs/releases.md](docs/releases.md#verifying-a-release).
