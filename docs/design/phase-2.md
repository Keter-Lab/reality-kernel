# Design note: Phase 2 — network policy enforcement

Status: **ACCEPTED** (2026-10-20). All four decisions in §9 approved as recommended.
Amendment: the raw/packet socket block uses the BPF-LSM `socket_create` hook
instead of `cgroup/sock_create`, which only sees AF_INET/AF_INET6 sockets and so
could never block `AF_PACKET`. BPF-LSM is already required for ENFORCE.
Branch: `phase-2-network` (from `phase-0-1-foundations`)
Plan reference: RealityKernel_Engineering_Plan.pdf, Phase 2 and sections 3–5

## 1. Goal and scope

**Goal (plan):** per-agent egress policy decided in the kernel, independent of
telemetry.

In scope:
- TCP and UDP egress over IPv4 and IPv6, decided by CIDR, port and protocol.
- AUDIT and ENFORCE modes per profile.
- A reviewed default deny list for cloud instance-metadata endpoints.
- A minimal policy file (TOML) and an atomic reload.

Out of scope for Phase 2, with the phase that covers each:

| Item | Phase |
|---|---|
| Hostname/FQDN rules (needs a DNS-aware userspace component) | Later ADR |
| Fail-closed heartbeat (decision-path step 3) | 6 |
| Self-protection, including stopping agents from leaving their cgroup | 6 |
| `rk run` and dynamic agent placement | 5 |
| Ingress or bind policy | Not planned |

Phase 2 still reserves the mode and heartbeat fields so Phase 6 adds no ABI break.

### Facts this design relies on (measured in CI, Phase 0/1)
- `bpf_get_current_cgroup_id()` and `bpf_get_current_pid_tgid()` are available to
  `cgroup/connect4` on every supported kernel, 5.15 to 6.18 (`docs/kernel-matrix.md`).
- Attaching cgroup programs through BPF links works on all of them. Links are
  multi-attach by nature.

## 2. Hooks

The four `cgroup/sock_addr` programs are attached through BPF links to
**`/sys/fs/cgroup/rk.slice`**, never to the host root. They therefore
run only for sockets created inside `rk.slice`, and other cgroup programs
(Cilium, systemd) coexist with them. Where several programs are attached, the
kernel denies if any of them denies, so the most restrictive verdict wins.

| Program | Hook | Covers |
|---|---|---|
| `rk_net_connect4` | `cgroup/connect4` | TCP connect, connected UDP, TCP Fast Open (*verified by test*), io_uring connect |
| `rk_net_connect6` | `cgroup/connect6` | Same for IPv6, including IPv4-mapped destinations |
| `rk_net_sendmsg4` | `cgroup/sendmsg4` | Unconnected UDP `sendto`/`sendmsg` |
| `rk_net_sendmsg6` | `cgroup/sendmsg6` | Same for IPv6 |
| `rk_net_socket_create` | `lsm/socket_create` | Denies `SOCK_RAW` (inet) and `AF_PACKET` sockets for governed ENFORCE cgroups, which would otherwise bypass every hook above. Runs host-wide, at the cost of one hash lookup for ungoverned tasks |

Each decision uses the **current task's** cgroup (`bpf_get_current_cgroup_id`).
That matches the exec and file hooks in Phases 3–4, and if a socket is handed
between agents the receiver's (current) policy applies.

## 3. Decision path (the plan's shared path, implemented in `common.bpf.h`)

```
1. cg   = bpf_get_current_cgroup_id()
2. bind = lookup(rk_cgroup_profile, cg)          -> none: return ALLOW   (fast path, no event)
3. slot = rk_active_slot[0]                       (read once per decision)
   prof = lookup(rk_profiles, slot * MAX_PROFILES + bind.profile)
   [Phase 6 inserts the heartbeat check here]
4. addr = 16-byte address (IPv4 stored as ::ffff:a.b.c.d); port = ntohs(user_port)
   if match(rk_net_deny,  {slot, profile, addr}, port, proto) -> DENY,  rule_id
   elif match(rk_net_allow, {slot, profile, addr}, port, proto) -> ALLOW, rule_id
   else -> prof.net_default, rule_id 0
5. emit event (best effort, after the verdict is final)
6. return (prof.mode == ENFORCE && verdict == DENY) ? 0 /* EPERM */ : 1
```

The verdict is a local variable fixed before step 5, and the emit helper returns
`void`. A test pins this invariant (§7).

## 4. Maps and ABI additions (`rk_abi.h`; RK_ABI_VERSION stays 1, new types only)

| Map | Type | Key → value | Written by |
|---|---|---|---|
| `rk_cgroup_profile` | HASH (4096) | `u64 cgroup_id` → `struct rk_binding { u32 profile; u32 _pad; }` | Sensor, when a cgroup is bound |
| `rk_profiles` | ARRAY (2 × 1024) | `slot*1024 + profile` → `struct rk_profile { u8 mode; u8 net_default; u16 flags; u32 _pad; u64 policy_gen; }` | Policy apply |
| `rk_net_deny`, `rk_net_allow` | LPM_TRIE (65536, `NO_PREALLOC`) | `struct rk_net_key { u32 prefixlen; u32 scope; u8 addr[16]; }` → `struct rk_net_rule` | Policy apply |
| `rk_active_slot` | ARRAY (1) | `0` → `u32 slot` | Policy apply (the commit point) |

- `scope = slot << 31 | profile`. The trie `prefixlen` is `32 + cidr_len`, so a
  lookup can only ever match entries for the right generation slot and profile.
- `struct rk_net_rule { u32 rule_id; u8 proto_mask; u8 nranges; u16 _pad;
  struct { u16 lo, hi; } ranges[8]; }` (40 bytes, no padding). Ports are in host
  order; `nranges == 0` means all ports.
- New event bodies: the existing `rk_payload_net` plus `rk_payload_sock_create`
  (family, type, protocol).

### Atomic policy reload (plan: "no half-applied policy is ever visible")
Two generation slots. Applying a new policy:
1. Write the inactive slot: its profiles, deny entries and allow entries.
2. Flip `rk_active_slot` with a single 4-byte array update. This is the commit
   point.
3. Clear the old slot's entries at the start of the **next** apply, and no sooner
   than 1 s after the flip. Programs read the slot once and run for
   microseconds, so no running decision can see a slot being cleared.

Binding a cgroup to a profile is a single hash update, atomic per cgroup.
Profile ids stay stable across reloads, so bindings never need rewriting.

### Correctness of longest-prefix matching with ports
An LPM trie returns only the longest matching prefix. Suppose the rules are
`deny 10.0.0.0/8 (all ports)` and `deny 10.1.0.0/16 port 22`. A connection to
`10.1.2.3:443` hits the /16 entry, whose ports don't match, and the /8 rule would
be missed. The compiler therefore **flattens**: every entry carries the union of
its own port ranges and those of all covering shorter prefixes in the same trie
("all ports" absorbs everything). More than 8 merged ranges is a compile error
with a clear message. A **reference evaluator** in `rk-policy` (plain Rust,
linear scan over the rules) defines the intended semantics, and property tests
compare compiled-map lookups against it on random rules and addresses.

## 5. Policy file (`rk-policy`, new `net` module; TOML, not YAML because `serde_yaml` is unmaintained)

```toml
[profiles.research-agent]
mode = "enforce"                 # or "audit"
network.default = "deny"         # or "allow"
network.include = ["cloud-metadata"]  # built-in deny list; on unless removed explicitly

[[profiles.research-agent.network.allow]]
cidr = "10.20.0.0/16"
ports = ["443", "8000-8100"]
proto = ["tcp"]

[[profiles.research-agent.network.deny]]
cidr = "10.20.5.0/24"            # deny always wins over allow

[[bindings]]                     # Phase 2 only; Phase 5 replaces this with rk-agentd
cgroup = "rk.slice/agent-demo"
profile = "research-agent"
```

- Pipeline: file → typed IR (validated, every rule gets a stable `rule_id`) →
  compiled map contents → generation stamp. `rk-policy` has no BPF dependency; the
  sensor writes the maps.
- **NAT64 equivalence:** for each IPv4 deny rule the compiler also emits the
  `64:ff9b::/96` form, so a NAT64 address cannot reach a denied IPv4 destination.
  This is on by default and can be turned off per profile.
- **Built-in `cloud-metadata` list:** `deploy/policy/cloud-metadata.toml`, with one
  reviewed source link per entry. It covers 169.254.169.254 (AWS, GCP, Azure,
  OCI, DigitalOcean and others), `fd00:ec2::254` (AWS IPv6), 169.254.170.2 (ECS task
  role), 168.63.129.16 (Azure wire server) and 100.100.100.200 (Alibaba).
- **Loading:** the daemon reads `/etc/rk/policy.toml` at start and on `SIGHUP`. A
  file that fails to parse or compile is rejected as a whole, and the active
  policy is left unchanged.

## 6. Bypass analysis

| Vector | Handling |
|---|---|
| Raw or packet sockets | `rk_net_socket_create` (LSM) denies them in ENFORCE (they also need `CAP_NET_RAW`, which governed agents won't have from Phase 5) |
| IPv4-mapped IPv6 (`::ffff:a.b.c.d`) | Normalised; one trie serves both families |
| NAT64 (`64:ff9b::/96`) | Equivalence rules (§5) |
| Other network namespaces | Cgroup hooks don't depend on the namespace; covered |
| io_uring `IORING_OP_CONNECT` | Uses the same kernel connect path; integration test |
| TCP Fast Open (`sendto(MSG_FASTOPEN)`) | Integration test. If a kernel doesn't run the connect hook for it, the sensor refuses ENFORCE on that kernel and says so |
| Moving out of the cgroup | Phase 5 (no delegation) and Phase 6 (self-protection); documented as a Phase 2 limitation |
| Socket created outside `rk.slice` and passed in via `SCM_RIGHTS` | Hooks don't run for sockets created outside the attach point. Needs a cooperating ungoverned process, so it is outside the threat model; documented |
| An allowed local proxy | Policy concern (a proxy is an allowed destination); documented |

## 7. Tests (each acceptance criterion maps to a named test)

A new static binary, `rk-integration` (`tests/integration/`), runs inside the same
vmtest VMs as the selftest, on all five kernels. It loads the production object
through the same library code as the daemon, creates
`rk.slice/{enforce,audit,ungoverned-sibling}` cgroups, adds test addresses to
`lo` (`10.99.0.0/24`, `fd99::/64`) with local listeners, and runs workloads as
child processes placed in those cgroups.

| Plan criterion | Test |
|---|---|
| ENFORCE: deny set gives EPERM over TCP and UDP, IPv4 and IPv6 | `net_enforce_{tcp,udp_connect,udp_sendmsg}_{v4,v6}`, `net_enforce_v4_mapped` |
| Same verdicts with the consumer paused | `net_verdicts_independent_of_telemetry`: nothing drains the ring buffer, which is filled until it drops; verdicts are unchanged and `RK_CNT_RINGBUF_DROP > 0` |
| AUDIT: operations succeed and emit audit-would-deny with the correct rule id | `net_audit_reports_rule_id` |
| Processes outside rk.slice unaffected | `net_ungoverned_untouched` (outside `rk.slice`) and `net_unbound_sibling_untouched` (inside, but not bound) |
| (added) Atomic reload | `net_reload_atomic`: 10k connects while flipping between two generations; every outcome matches the `policy_gen` in its event |
| (added) Bypasses | `net_raw_socket_denied`, `net_io_uring_connect_denied`, `net_tcp_fastopen_denied`, `net_nat64_equivalence` |
| (added) Compiler correctness | `rk-policy` unit tests plus property tests: compiled lookup equals the reference evaluator |
| (added) The verdict cannot depend on emit | `net_verdicts_with_emit_failing`: a test-only build flag makes every emit fail (scratch lookup forced to miss and the ring buffer full), and the full verdict suite must still pass. The emit helpers return `void` by construction. |

The kernel-matrix CI job gains one step that runs `rk-integration` in the VM. Its
JSON results are uploaded beside the selftest report.

## 8. Deliverables

- `rk-bpf/src/net.bpf.c`: the five programs. Shared decision helpers go in
  `common.bpf.h`; `rk.bpf.c` includes `net.bpf.c`.
- `rk_abi.h` additions and regenerated bindings (automatic).
- `rk-policy::net`: parser, IR, compiler, reference evaluator and tests.
- `rk-sensor`:
  - attaching to `rk.slice` through links;
  - a map writer for policy apply and slot flip;
  - `SIGHUP` reload;
  - loader entries for the new program types.
- `deploy/policy/cloud-metadata.toml` (reviewed list).
- `tests/integration` and the CI step.
- Docs: a network policy section in a new `docs/policy.md`, updates to
  `docs/abi.md`, and ADR-0005 (policy representation and atomic reload).

## 9. Decisions requested from the reviewer

1. Use a **TOML** policy format (proposed) rather than YAML.
2. The `cloud-metadata` deny list is **included by default** in every profile and
   can only be removed explicitly, as the plan requires.
3. Fall back to **refusing ENFORCE** on kernels where the TFO or io_uring tests
   show a bypass, rather than running ENFORCE with a known gap.
4. Phase 2 uses **static bindings** in the policy file until `rk-agentd`
   (Phase 5).
