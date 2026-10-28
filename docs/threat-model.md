# Threat model

What Reality Kernel protects, from whom, and where its protection ends.
Every mitigation links to the acceptance criterion whose tests prove it on
every supported kernel ([evidence.md](evidence.md)). Architecture:
[architecture.md](architecture.md).

## 1. What it is for

Reality Kernel confines AI agents and other workloads on a Linux host. A
governed workload can only make the network connections, run the programs
and touch the files its profile allows, and every decision is recorded in a
tamper-evident log. Enforcement happens in the kernel, before the action,
not in a wrapper the agent could step around.

## 2. Assets

| Asset | Why it matters |
|---|---|
| Enforcement continuity | A gap, even of milliseconds, is a window for exfiltration |
| Policy integrity | A governed workload must not change its own policy or binding |
| Agent containment | An agent and every process it starts stay governed |
| Credentials and secrets on the host | The most common target of a misbehaving agent (built-in deny lists for credential stores and cloud metadata) |
| Audit log integrity | Evidence of what was attempted and what was decided |
| The audit signing key | Whoever holds it can sign a forged history |
| The release artifacts | Users run them as root |

## 3. Trust boundaries

```
 governed workload (untrusted)        ─┐
   └ syscalls ─► kernel hooks (BPF)    │ boundary 1: the kernel decides
 rk CLI / rk-nri (local clients)      ─┤ boundary 2: agentd socket, peer credentials
   └ requests ─► rk-sensor (root)      │
 policy author (trusted, reviewed)    ─┤ boundary 3: policy files, atomic apply
 Kubernetes control plane via NRI     ─┤ boundary 4: container lifecycle events
 release pipeline ─► users            ─┘ boundary 5: signed, attested artifacts
```

## 4. Attackers in scope

### A1. A malicious or compromised agent in a governed cgroup
The primary adversary: prompt-injected, misaligned or simply buggy, running
with the agent's privileges.

| Attack | Mitigation | Evidence |
|---|---|---|
| Connect to a denied address, over TCP, UDP, IPv4 or IPv6 | cgroup `sock_addr` hooks deny in the kernel | [net-enforce-eperm](evidence.md#net-enforce-eperm) |
| Bypass the connect hooks: raw and packet sockets, io_uring, TCP Fast Open, NAT64 | Each path is hooked or denied | [net-bypasses](evidence.md#net-bypasses) |
| Tunnel traffic through a TUN/TAP device: create one (needs `CAP_NET_ADMIN`), or attach to a persistent one the agent's user owns (needs no capability) | Create, attach and queue re-attach are denied in the TUN LSM hooks ([ADR-0017](decisions/0017-tun-tap-containment.md)) | [tun-containment](evidence.md#tun-containment) |
| Run an unlisted program, through symlinks, replaced binaries, scripts or memfd | Exec decided on file identity (device, inode) | [exec-allowlist](evidence.md#exec-allowlist), [exec-identity](evidence.md#exec-identity) |
| Read or modify a protected file under another name | File decisions on inode identity, per access type, subtrees fail closed | [file-identity](evidence.md#file-identity), [file-access-types](evidence.md#file-access-types), [file-subtree](evidence.md#file-subtree) |
| Escape governance by forking or leaving the cgroup | cgroup v2 inheritance; agents cannot write their cgroup | [agent-children](evidence.md#agent-children), [agent-unprivileged](evidence.md#agent-unprivileged) |
| Act before governance starts | Placed in its cgroup atomically at creation | [agent-first-instruction](evidence.md#agent-first-instruction), [k8s-first-instruction](evidence.md#k8s-first-instruction) |
| Tamper with the sensor: bpf(), signals, ptrace, removing pins | Self-protection LSM hooks deny it | [self-protection](evidence.md#self-protection) |
| Kill the sensor, hoping enforcement stops | Pins keep enforcing; a stale heartbeat fails closed | [survives-restart](evidence.md#survives-restart), [heartbeat-fail-closed](evidence.md#heartbeat-fail-closed) |
| Flood events to hide an action | Decisions never depend on telemetry; losses are counted and logged | [net-telemetry-independent](evidence.md#net-telemetry-independent), [audit_complete](evidence.md#audit_complete) |

### A2. A local unprivileged user
Can talk to the agentd socket. Only authorised callers may change policy or
launch a profile; agents never run as root.
[agent-authorisation](evidence.md#agent-authorisation),
[agent-unprivileged](evidence.md#agent-unprivileged).

### A3. Someone who edits the audit log
Any modified, inserted, removed or reordered batch fails `rk audit verify`,
and so do an emptied log, removed oldest segments and a change of signing
key. The sensor never signs records it did not write: lines it finds after
the last sealed batch at startup are set aside unsigned. The files can only
prove that they are consistent with themselves, so the guarantee is
relative to an anchor kept off the host: verify with `--pubkey` (the public
key copied at install time) and `--head` (a chain head recorded from the
metrics). Without them a log rewritten whole under a new key, or with its
newest batches removed, goes unnoticed. Batches newer than the last recorded
head are protected only by shipping records off the host (OTLP).
[audit_tamper](evidence.md#audit_tamper),
[what verification cannot detect](audit.md#what-verification-detects-and-what-it-cannot).

### A4. A tampered artifact between the release workflow and the user
Every release file is signed by this repository's release workflow
(Sigstore), with SLSA provenance and an SBOM; the workflow refuses to
release anything that does not verify. How to check: [releases.md](releases.md).

### A5. Operational gaps an attacker could wait for
Upgrades replace the kernel programs make-before-break, so there is no window
without enforcement: [upgrade_continuous](evidence.md#upgrade_continuous).
Policy reloads are atomic: [net-atomic-reload](evidence.md#net-atomic-reload).

## 5. Explicitly out of scope

- **Root on the host, or a compromised kernel.** Root can unload programs,
  edit maps, delete the newest audit batches or read the audit key. Kernel
  lockdown (`lockdown=integrity`) and the hardening guide raise the bar; they
  do not make root untrusted. [hardening.md](hardening.md)
- **Ungoverned workloads.** Only cgroups bound to a profile are governed; the
  rest of the host is deliberately untouched
  ([net-ungoverned](evidence.md#net-ungoverned)).
- **Kernels without BPF LSM** enforce network rules only, and say so
  ([capability-honesty](evidence.md#capability-honesty)).
- **Side channels, physical access, and denial of service against the
  host.**
- **What an allowed connection carries.** A profile that allows a destination
  allows whatever is sent there; content inspection is not a goal.

## 6. Residual risks and how they are handled

| Risk | Handling |
|---|---|
| Truncation of the newest audit batches by host root | The chain head is exported in the metrics and the OTLP stream ships records off host |
| Theft of the audit signing key by host root | Out of scope (§5); a hardware-backed key is future work |
| A TUN/TAP queue descriptor attached before a process became governed, and handed to it by an ungoverned process | Reads and writes on an attached descriptor reach no TUN hook ([ADR-0017](decisions/0017-tun-tap-containment.md)). It needs a cooperating ungoverned process; re-attaching a detached queue is denied |
| A single maintainer reviews every change | CI is the reviewer of record: every criterion's tests must pass on every kernel before merge; GOVERNANCE.md requires two reviewers for kernel code once there are two maintainers |
