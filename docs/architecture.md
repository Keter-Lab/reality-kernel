# Architecture

How Reality Kernel is put together. Why each part is the way it is: the
ADRs in [decisions/](decisions/README.md) and the per-phase design notes in
[design/](design/). Threats: [threat-model.md](threat-model.md).

## Components

| Component | Where | Role |
|---|---|---|
| Kernel programs | `rk-bpf/` (C, CO-RE) | Decide every governed network, exec and file action in BPF-LSM and cgroup `sock_addr` hooks; protect the sensor; emit events; count decisions |
| ABI | `rk-bpf/include/rk_abi.h` → `rk-ebpf-common` (bindgen) | The one definition of every shared layout |
| Policy compiler | `rk-policy` | Parses the TOML policy, validates it, compiles it to map entries; the reference evaluator |
| Sensor | `rk-sensor` | Loads and pins the programs, writes policy maps, heartbeats, drains events, runs the audit log, metrics and OTLP export |
| Agent daemon | `rk-agentd` (in the sensor process) | The control socket: `rk run`, policy apply, status, Kubernetes bindings |
| Audit log | `rk-audit` | OCSF records, hash chain, signed batches, verification |
| CLI | `rk-cli` (`rk`) | `run`, `policy`, `status`, `audit`, `doctor` |
| NRI plugin | `rk-nri` (Go) | Binds Kubernetes containers to profiles at creation |
| Deployment | `deploy/` | systemd unit, deb/rpm, Helm chart, image, Grafana dashboard |

## Data flow

```
 rk run / NRI ──► rk-agentd ──► cgroup rk.slice/<agent>, binding written to rk_cgroup_profile
 policy.toml  ──► rk-policy ──► compiled maps (inactive slot) ──► one-word slot flip (atomic)

 governed syscall ─► BPF hook ─► verdict (EPERM or allow)      ← decided here, in the kernel
                         │
                         ├─► rk_counters (per hook × verdict)
                         └─► ring buffer ─► drain thread ─► bounded channel ─► worker
                                                                                │
                              audit log (OCSF, hash chain, signed) ◄────────────┤
                              /metrics (Prometheus) ◄───────────────────────────┤
                              OTLP spans (session trace) ◄──────────────────────┘
```

The verdict never waits for userspace: telemetry can fail or fall behind
without changing a decision ([ADR-0008](decisions/0008-enforcement-and-observation-hooks.md)).

## Lifecycle of the kernel programs

| Event | What happens |
|---|---|
| First start | Objects loaded, maps and links pinned under `/sys/fs/bpf/rk`, heartbeat started |
| Restart, same object | Pins adopted; enforcement never paused |
| Upgrade, new object | Loaded beside the old one under `rk-next`, policy carried over, all programs attached, then the old set removed ([ADR-0015](decisions/0015-make-before-break-upgrades.md)) |
| Sensor gone longer than the heartbeat timeout | Governed ENFORCE workloads denied until it returns ([ADR-0013](decisions/0013-pins-and-fail-closed-heartbeat.md)) |
| Removal | `rk-sensor --uninstall` removes the pins; protection ends |

## Phases

The system was built in twelve phases, each with a design note and
acceptance criteria proven in CI: build and truthful CI (0), the ABI (1),
network (2), exec (3), files (4), the agent daemon and policy pipeline (5,
5b for Kubernetes), self-protection and resilience (6), performance (7),
test strategy (8), observability and audit (9), packaging (10) and
repository standards (11). Design notes: [design/](design/). Evidence for
every criterion: [evidence.md](evidence.md).
