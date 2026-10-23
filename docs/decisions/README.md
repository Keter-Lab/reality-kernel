# Architecture Decision Records

One file per decision, numbered in order. Any deviation from the engineering
plan is recorded here before code lands.

| # | Decision | Status |
|---|---|---|
| [0001](0001-adopt-engineering-plan-and-ci-only-verification.md) | Adopt the engineering plan; verify only in CI | Accepted |
| [0002](0002-remove-aya-ebpf-probes.md) | Remove the Aya `rk-ebpf-probes` crate | Accepted |
| [0003](0003-kernel-matrix-vmtest-lvh.md) | Kernel matrix with vmtest and pinned LVH kernels | Accepted |
| [0004](0004-abi-bindings-at-build-time.md) | Generate ABI bindings at build time, vendor vmlinux.h | Accepted |
| [0005](0005-network-policy-representation-and-atomic-reload.md) | Network policy representation and atomic reload | Accepted |
| [0006](0006-packet-injection-surface.md) | Packet injection surface and raw socket containment | Accepted |
| [0007](0007-kernel-programs-in-c-co-re.md) | Kernel programs in C with libbpf CO-RE, loaded by aya | Accepted |
| [0008](0008-enforcement-and-observation-hooks.md) | BPF-LSM and cgroup sock_addr hooks enforce; tracepoints observe | Accepted |
| [0009](0009-cgroup-v2-governance-unit.md) | cgroup v2 is the governance unit | Accepted |
| [0010](0010-minimum-kernel-and-honest-degradation.md) | Minimum kernel 5.15; honest degradation without BPF LSM | Accepted |
| [0011](0011-audit-first-default-posture.md) | Explicit mode per profile; roll out in AUDIT, then ENFORCE | Accepted |
| [0012](0012-bpf-licensing.md) | Dual GPL-2.0 / MIT licensing of the BPF programs | Accepted |
| [0013](0013-pins-and-fail-closed-heartbeat.md) | Pinned programs and a fail-closed heartbeat | Accepted |
| [0014](0014-ocsf-hash-chained-audit-log.md) | OCSF audit records in a hash-chained, signed log | Accepted |
| [0015](0015-make-before-break-upgrades.md) | Upgrades replace the BPF object make-before-break | Accepted |
