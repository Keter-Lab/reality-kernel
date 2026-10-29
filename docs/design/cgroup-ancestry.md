# Design note: ancestor-aware governance (cgroup escape)

Status: **ACCEPTED** (2026-10-29). All four decisions in §9 settled as
recommended; Decision 2 = option (b), warn-but-allow when A covers it. No code
written yet; this note is the design-first step.
Branch: `design-cgroup-ancestry` (from `main` at the v0.3.0 release).
Reference: the Strix white-box review (2026-10-28), the single High (7.1), and
the residual-risk row in [threat-model.md](../threat-model.md) §6. This is the
top open item after v0.3.0.

## 1. Problem

Governance is decided once per syscall, in `rk_governance()`
(`rk-bpf/src/common.bpf.h`): it reads `bpf_get_current_cgroup_id()` and looks
that exact id up in the `rk_cgroup_profile` hash map. A miss returns 0, and the
caller treats 0 as **ungoverned — allow everything**. There is no ancestor
fallback.

So a task that leaves its bound cgroup is ungoverned in every domain at once —
network, exec, file, self-protection, TUN/TAP — and silently, because the
ungoverned fast path returns before any counter or audit record. The simplest
move is into a *child* cgroup the task creates under its own:

```
rk.slice/agent-<uuid>        (bound: id X -> profile)
rk.slice/agent-<uuid>/sub    (id Y, not bound)   <-- task writes cgroup.procs, escapes
```

`bpf_get_current_cgroup_id()` now returns Y, the lookup misses, and the task is
free.

**Who can do this.** Moving a task between cgroups requires writing
`cgroup.procs` (or `clone3(CLONE_INTO_CGROUP)` with a writable target). In the
default deployment the agent cgroup is root-owned, mode 0755, so a
zero-capability agent cannot — proven by `agent_cannot_leave_cgroup`
([agent-unprivileged](../evidence.md#agent-unprivileged)). It becomes reachable
when the workload is **privileged** (has `CAP_SYS_ADMIN`/`CAP_DAC_OVERRIDE`, or
runs as the delegation owner) or when the host **delegates** the agent's cgroup
subtree to the workload (a common container pattern: the runtime chowns the
cgroup dir into the container so it can manage its own sub-cgroups). For those,
containment is void today. The threat model scopes host root out, so this is a
**defence-in-depth failure that becomes a full containment void for privileged
or delegated workloads** — honest framing, matching Strix.

## 2. Goals and non-goals

Goals:

1. A task that moves into a **descendant** of its bound cgroup stays governed,
   under the same profile, in every domain.
2. The common delegated-container pattern is made safe, or refused loudly at
   bind time rather than silently unenforced.
3. The ungoverned fast path (the cost every process on the host pays) stays
   within a re-measured budget — no unbounded ancestor walk per syscall.
4. Works on every supported kernel (5.15 → 6.18) and passes the verifier on
   each.

Non-goals:

- Containing **host root**. Root can edit maps, detach programs or move any
  task anywhere; out of scope (threat-model §5).
- A task moved into a **sibling or the root** cgroup by a *separate* privileged
  process. Ancestor lookup cannot see a cgroup that is not an ancestor; this is
  handled only by refusing delegation and by cgroupfs permissions, and what
  remains is documented in §8.
- Per-task (thread-granular) governance. We govern at the cgroup a task belongs
  to via `bpf_get_current_cgroup_id()`, as today.

## 3. Prior art

- **cgroup v2 delegation model** (kernel `Documentation/admin-guide/cgroup-v2.rst`,
  "Delegation"): a subtree is delegated by making the directory and its
  `cgroup.procs`/`cgroup.subtree_control` writable by a less-privileged user.
  The kernel's own containment rule is that a delegated user may move a task
  only within the delegated subtree (the common-ancestor check in
  `cgroup_procs_write_permission`). That is exactly the invariant we want to
  mirror in policy: a task under a governed subtree stays governed anywhere in
  that subtree.
- **Cilium / cgroup-based network policy** key BPF decisions on the ancestor
  cgroup id at a fixed hierarchy level (via `bpf_get_current_ancestor_cgroup_id`
  / `bpf_sk_ancestor_cgroup_id`), precisely so that a pod's child cgroups are
  still matched. This is the pattern we adopt.
- **systemd** manages the hierarchy and does not let a unit's payload re-parent
  itself out of its slice without privilege; our "refuse delegation" option is
  the analogue for agent cgroups.
- **The ancestor helper.** `bpf_get_current_ancestor_cgroup_id(level)` returns
  the id of the current task's ancestor at `level` (root = 0), the task's own
  id when `level` equals the task's depth, and 0 when no ancestor exists at that
  level. The PR5 kernel investigation found it in 5.15's `bpf_tracing_func_proto`
  (covers our LSM hooks) and it has long been in the cgroup/sock_addr proto
  (covers the net hooks). §7 gates this with a load test, since the whole design
  rests on it.

## 4. Design overview

Three parts, in priority order. Part A is the core and is enough to close the
descendant-escape on its own; B removes the ability to escape at all in the
common case; C is a guard with known limits.

### A. Ancestor-aware lookup, bounded by published levels

`rk_governance()` becomes: exact lookup first (unchanged fast path for a
directly-bound task); on a miss, walk only the **hierarchy levels that actually
hold a binding**, deepest first, and take the first bound ancestor.

The sensor already knows every bound cgroup's path, so it knows each one's
hierarchy *level* (depth from the root). It publishes the set of bound levels as
a 64-bit mask in `rk_config` (new field `governed_levels`; bit L set means "at
least one cgroup is bound at level L"). The kernel then does, on an exact miss:

```c
__u64 best = 0; __u32 best_level = 0;
__u64 levels = cfg->governed_levels;        // few bits set in practice
#pragma unroll
for (int L = RK_CGROUP_MAX_DEPTH; L >= 1; L--) {
    if (!(levels & (1ULL << L))) continue;  // no binding at this level: skip
    __u64 anc = bpf_get_current_ancestor_cgroup_id(L);
    if (!anc) continue;                      // task shallower than L
    if (bpf_map_lookup_elem(&rk_cgroup_profile, &anc)) { best = anc; break; }
}
```

Deepest-first means the **nearest** bound ancestor wins, so a child of a bound
cgroup inherits that cgroup's profile, and a child of a *different* bound
cgroup nested deeper still resolves to the closest one. The report header
(`rk_hdr.cgroup_id`) records the task's own id, so an escaped-but-caught
decision is visible as "governed under ancestor X while running in Y".

Why a published bitmask and not a blind walk of all levels: the ungoverned fast
path is the cost every process on the host pays. A blind walk to a fixed max
depth would add up to `RK_CGROUP_MAX_DEPTH` map lookups to *every* ungoverned
syscall. The bitmask bounds it to `popcount(governed_levels)` lookups —
typically **one** (agents bound at a single slice depth, or k8s pods at a fixed
level), at most a handful. A directly-bound (governed) task hits the exact
lookup first and pays nothing extra.

`RK_CGROUP_MAX_DEPTH`: proposed **16**. cgroup v2 hierarchies are rarely deeper
than ~6 (systemd slice + container runtime + pod + container). 16 is a safe
unrolled bound; levels beyond the mask are never walked anyway.

### B. Refuse (or neutralise) delegation at bind time

Ancestor lookup catches a move into a *descendant*. It does not stop the move,
and it cannot help if the task is moved to a sibling/root. The cleaner fix for
the common delegated-container case is to not hand the workload a writable
cgroup subtree in the first place.

At launch/bind, the sensor checks whether the governed cgroup's subtree is
delegated to the workload — i.e. the cgroup directory, `cgroup.procs`,
`cgroup.threads` or `cgroup.subtree_control` are writable by the workload's uid
(not root-owned 0755/0644 as the launcher creates them). If so:

- **Launcher-created agent cgroups** (`rk run`): the launcher already owns the
  cgroup and creates it root-owned; assert this invariant and fail the launch
  if something made it writable. No normal path hits this.
- **Adopted / container cgroups** (NRI, `bind_container`): the runtime may have
  delegated the subtree. Default to **refuse the binding with a clear error**
  naming the delegated cgroup, with an opt-out (`--allow-delegated-cgroups`, off
  by default) for operators who accept the residual risk. Document that a
  delegated subtree is outside the guarantee unless A also covers it.

This is a policy decision with a compatibility cost (see §9, Decision 2): some
Kubernetes setups delegate pod cgroups. With A in place, a delegated subtree is
*still governed* (the ancestor walk catches child cgroups), so B's refusal is
defence-in-depth, not the only line. A reasonable middle setting is: **warn, do
not refuse, when A can cover it** (the pod cgroup is bound and at a published
level); refuse only when A cannot (binding at an unpublished level).

### C. A guard against moving to an unbound sibling/root

There is **no LSM hook for cgroup migration**, and `clone3(CLONE_INTO_CGROUP)`
needs only a readable target directory fd, so a migration-deny hook is not
cleanly available. Writes to `cgroup.procs` go through the VFS write path; a
`file_permission`/`inode_permission` guard that denies a *governed* task writing
any `cgroup.procs`/`cgroup.threads` outside its own subtree is possible but
heavy (runs on every write) and fragile across kernels. **Recommendation: do
not build C now.** Rely on A (descendant moves) + B (no delegated subtree) +
cgroupfs permissions (root-owned), and record the sibling/root-move-by-a-
separate-privileged-process case as a residual risk (§8). Revisit C only if a
concrete deployment needs it.

## 5. ABI and pin migration

`rk_config` grows one field:

```c
struct rk_config {
    __u64 heartbeat_timeout_ns; /* offset 0 */
    __u64 governed_levels;      /* offset 8: bit L set => a cgroup is bound at level L */
};
```

`sizeof(struct rk_config)` goes 8 → 16; bump `RK_ABI_VERSION` 1 → 2 (and the
hand-written mirror asserts in `rk-ebpf-common/src/lib.rs`). The `rk_config` map
value size changes, so its pin is incompatible with a v1 pin. This is already
handled: `pins.rs` replaces a pinned map whose `meta.abi != RK_ABI_VERSION`, so
an upgrade from v0.3.0 goes through the normal make-before-break pin
replacement. No new maps, no change to `rk_cgroup_profile` or the profile maps.
Decoder/event ABI is untouched (events already carry `cgroup_id`). Migration
note for the CHANGELOG: upgrading replaces the pin set once (as every ABI bump
does).

## 6. Sensor changes

- Compute each bound cgroup's level from its path depth under the cgroup v2
  mount (count path segments below `/sys/fs/cgroup`), at apply and at each
  dynamic/container bind.
- Maintain `governed_levels` as the OR of all bound levels; write it into
  `rk_config` on every apply and bind/unbind that changes the set. Clearing the
  last binding at a level clears its bit.
- The existing device/path resolution is unaffected.
- `bind_container` gains the delegation check from §4.B (behind the chosen
  default from Decision 2).

## 7. Testing

New criterion `governance-ancestor-aware`, VM suite, every kernel:

- `agent_in_child_cgroup_stays_governed`: bind a cgroup, create a child, move a
  task in (as the privileged test harness), assert a denied connect/exec/open
  is still denied and audited under the parent's profile. The mirror of today's
  `agent_cannot_leave_cgroup`, but now asserting *enforcement follows* for the
  privileged case, not just that the unprivileged case cannot move.
- `nested_bindings_resolve_to_nearest`: two bound cgroups, one nested under the
  other; a task in a child of the inner one resolves to the inner profile.
- `ancestor_helper_loads_on_every_kernel`: a tiny program using
  `bpf_get_current_ancestor_cgroup_id` in an LSM hook loads and attaches on
  5.15 → 6.18 (guards the §3 assumption; fail = we need the CO-RE parent-walk
  fallback instead).
- Delegation: `delegated_cgroup_is_refused_or_warned` per Decision 2.
- Rust: `governed_levels_bitmask_from_paths` (level computation); the ABI size
  assert updates to 16.

Benchmark: the ungoverned fast path gains `popcount(governed_levels)` lookups on
a miss. Re-measure and **rebaseline `tests/bench/budget.json`** from the first
run on the branch (the plan's rule: budgets are the worst first-run value ×2,
1 µs floor). Expect the ungoverned p50 to rise by roughly one hash lookup;
confirm it stays within a sane budget and that governed p50 is unchanged (exact
lookup still hits first). Gate as today.

## 8. Residual risks (documented, not closed here)

- A task moved to an **unbound sibling or the root** cgroup by a *separate*
  privileged process. Not an ancestor, so A cannot see it; B removes the
  self-move path, and cgroupfs permissions remain the control. Needs host-level
  write access ≈ root/privileged, near the §5 line.
- **Host root** detaching programs or editing maps — out of scope as before.
- A workload that legitimately needs a delegated subtree and binds at a depth
  the sensor did not publish (e.g. it creates cgroups far below the bound
  level). A covers any depth that is an ancestor chain from a bound level only
  if that binding's level is in the mask; document that bindings must be at a
  published level, which they are by construction.

## 9. Decisions (settled 2026-10-29)

1. **ACCEPTED — ancestor-aware lookup via a published `governed_levels` bitmask
   (§4.A), ABI v2.** The cheapest correct option (one extra lookup on the
   ungoverned path in the common case); the directly-bound fast path is
   unchanged. A blind walk to a fixed depth was rejected (up to `MAX_DEPTH`
   lookups on every ungoverned syscall).
2. **ACCEPTED — option (b): warn but allow a delegated container cgroup when A
   covers it (its binding is at a published level), refuse only when A cannot.**
   Keeps existing Kubernetes delegated-pod setups working, since A still governs
   them, while logging the posture. `bind_container` grows the delegation check
   and the warn/refuse split; no new flag is needed for the default, and an
   `--allow-delegated-cgroups` escape hatch covers the refuse case if an
   operator wants the uncovered binding anyway.
3. **ACCEPTED — do not build the cgroup-migration guard (§4.C) now.** Rely on
   A + B + cgroupfs permissions; the sibling/root-move-by-a-separate-privileged-
   process case is documented as a residual (§8). Revisit only if a concrete
   deployment needs it.
4. **ACCEPTED — `RK_CGROUP_MAX_DEPTH = 16`** as the unrolled ancestor bound.

Implementation is a kernel + ABI change: GOVERNANCE.md asks for two-person
review once there are two maintainers; until then CI is the reviewer of record,
and the §7 load test on every kernel is the gate on the §3 helper assumption.

## 10. Implementation order (for the follow-up PR)

1. ABI: add `governed_levels` to `rk_abi.h`, bump `RK_ABI_VERSION` to 2, update
   the `rk-ebpf-common` size asserts. (Compiles; pins replace on upgrade.)
2. Sensor: compute bound-cgroup levels, maintain and publish the bitmask on
   apply/bind/unbind. Unit test the level computation.
3. Kernel: the ancestor walk in `rk_governance()` (§4.A), plus the
   `ancestor_helper_loads_on_every_kernel` self-test. This is the verifier-risk
   step; keep the walk a bounded `#pragma unroll`.
4. Rebaseline `tests/bench/budget.json` from the first branch run; confirm the
   governed p50 is unchanged.
5. Delegation check in `bind_container` (§4.B, Decision 2) + the
   `--allow-delegated-cgroups` escape hatch.
6. VM tests (§7), threat-model update (move the row from §6 residual to a closed
   guarantee for descendants, keep the sibling/root residual), CHANGELOG with
   the ABI/pin-replacement upgrade note.
