# Containment scorecard

What a misbehaving AI agent tries, and what Reality Kernel does about it.
Every "contained" row links to an acceptance criterion whose named tests run
as real attempts (real syscalls by a governed process, not mocks) in VMs on
**Linux 5.15, 6.1, 6.6, 6.12 and 6.18**, and passed on all five.

**As of v0.2.0:** commit `64ef9f9`, [Kernel workflow run](https://github.com/Keter-Lab/reality-kernel/actions/runs/40083811442).
Every pull request reruns all of it; a change that breaks a row cannot merge
([how this is checked](testing.md)). The full list of criteria and test
names is the [evidence page](evidence.md).

The attempts below are made against profiles in ENFORCE. Network, program,
file and TUN/TAP rules can also run in AUDIT, where the same attempts succeed
and are recorded as audit-would-deny, so a profile can be tried before it
blocks ([net-audit](evidence.md#net-audit), [exec-audit](evidence.md#exec-audit),
[file-audit-reload-ungoverned](evidence.md#file-audit-reload-ungoverned),
[tun-containment](evidence.md#tun-containment)).

## Contained

### Network

| The agent tries to… | Result | Evidence |
|---|---|---|
| connect to a denied address over TCP or UDP, IPv4 or IPv6 (or IPv4 written as IPv6) | `EPERM` | [net-enforce-eperm](evidence.md#net-enforce-eperm) |
| get around the connect rules with raw or packet sockets, io_uring, TCP Fast Open or a NAT64 address | each path denied | [net-bypasses](evidence.md#net-bypasses) |
| tunnel traffic through a TUN/TAP device, including one its own user owns, which needs no capability | create, attach and queue re-attach denied | [tun-containment](evidence.md#tun-containment) |

### Programs

| The agent tries to… | Result | Evidence |
|---|---|---|
| run a program that is not on the profile's allowlist | `EPERM` | [exec-allowlist](evidence.md#exec-allowlist) |
| sneak one in through a symlink, a replaced binary, a script or a deleted / in-memory file | decided on file identity, denied | [exec-identity](evidence.md#exec-identity) |
| modify or replace a program that *is* allowed | denied | [file-protect-allowlist](evidence.md#file-protect-allowlist) |

### Files

| The agent tries to… | Result | Evidence |
|---|---|---|
| read, write, truncate, delete, rename, link, create in or change attributes of a protected file | each access type denied separately | [file-access-types](evidence.md#file-access-types) |
| reach that file under another name: hard link, bind mount, symlink, relative path, `/proc/self/fd` | same verdict for every name | [file-identity](evidence.md#file-identity) |
| hide it deep inside a protected directory | subtree rules apply; too-deep nesting fails closed | [file-subtree](evidence.md#file-subtree) |

### Escaping governance

| The agent tries to… | Result | Evidence |
|---|---|---|
| act before its policy applies | governed from its first instruction (`rk run` and Kubernetes pods) | [agent-first-instruction](evidence.md#agent-first-instruction), [k8s-first-instruction](evidence.md#k8s-first-instruction) |
| do the work in a child process | children are governed automatically | [agent-children](evidence.md#agent-children) |
| leave its cgroup or gain privileges | it runs unprivileged and cannot leave | [agent-unprivileged](evidence.md#agent-unprivileged) |
| change the policy or launch a looser profile | refused unless the caller is authorised | [agent-authorisation](evidence.md#agent-authorisation) |

### Attacking the defense itself

| The agent tries to… | Result | Evidence |
|---|---|---|
| use `bpf()`, signal or trace the sensor, remove its pins or unmount bpffs | `EPERM` | [self-protection](evidence.md#self-protection) |
| kill the sensor | the kernel programs keep enforcing | [survives-restart](evidence.md#survives-restart) |
| outlast it: keep the sensor down | after the heartbeat timeout every governed ENFORCE action is denied (fails closed) | [heartbeat-fail-closed](evidence.md#heartbeat-fail-closed) |
| slip through during an upgrade | zero denied actions get through while the new version replaces the old | [upgrade_continuous](evidence.md#upgrade_continuous) |
| cover its tracks by editing the audit log | detected by `rk audit verify` | [audit_tamper](evidence.md#audit_tamper) |
| act without leaving a record | every enforced or would-deny decision is logged with its rule; lost events are counted, not silent | [audit_complete](evidence.md#audit_complete) |

### Honesty

| Situation | Result | Evidence |
|---|---|---|
| the host lacks BPF-LSM, so program, file and raw-socket rules cannot be enforced | those rules are refused, never silently unenforced | [capability-honesty](evidence.md#capability-honesty) |

## Not contained (yet)

| The agent tries to… | Status |
|---|---|
| send data out through DNS lookups via an allowed resolver | **Open.** DNS query filtering is the v0.4.0 milestone ([ROADMAP.md](../ROADMAP.md)) |
| reach a service whose address changed (CDN) under an IP rule, or be allowed by hostname | Rules are by IP address until hostname rules (v0.4.0) |
| send data to a destination the policy *allows* | Out of reach of syscall-level rules: the kernel sees where, not what. v0.5.0 narrows it (taint, credential broker); some covert channels cannot be closed in general |
| use a TUN/TAP queue that an ungoverned process attached and handed over | Residual risk, needs a cooperating ungoverned process ([ADR-0017](decisions/0017-tun-tap-containment.md)) |
| exploit a kernel bug | Out of reach of any defense running in the same kernel. Keep kernels patched; for hostile workloads, also use isolation (microVMs) |
| all of the above on arm64 | Built and unit-tested on arm64; the VM suites run on x86_64 only ([kernel-matrix.md](kernel-matrix.md)) |

The full list of attackers, mitigations and residual risks is the
[threat model](threat-model.md).
