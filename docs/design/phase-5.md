# Design note: Phase 5 — agent governance and policy pipeline

Status: **PROPOSED**, waiting for review
Branch: `phase-5-agentd` (from `main` at f8ad36d)
Plan reference: RealityKernel_Engineering_Plan.pdf, Phase 5

## 1. Goal and scope

**Goal (plan):** a simple, safe way to run an agent under a profile, locally and
in Kubernetes.

Phases 2–4 can already enforce network, exec and file policy, but only for
cgroups listed statically in the policy file (`[[bindings]]`). Phase 5 turns
that into something people can use:

```
rk run --profile research-agent -- python agent.py
```

The agent is governed **from its first instruction**, its children are governed
automatically, and policy changes are atomic and reversible with one command.

The work is split into two pull requests (decision 1):
- **5a, local:** `rk-agentd`, the `rk` CLI, the policy pipeline (dry-run, diff,
  rollback) and session linkage.
- **5b, Kubernetes:** a DaemonSet plus a pod annotation, through an NRI plugin,
  and Helm values.

## 2. Architecture

```
rk run / rk policy / rk status            (unprivileged CLI)
        |  Unix socket /run/rk/agentd.sock (SO_PEERCRED-authorised)
        v
rk-sensor daemon (root)                   (single privileged process; decision 2)
  ├─ loader + BPF programs (Phases 0–4)
  ├─ PolicyEngine (maps, generation slots)
  └─ agentd module: agent cgroups, dynamic bindings, launch
```

- **One privileged daemon.** The agentd logic is a library crate, `rk-agentd`,
  that runs inside the existing `rk-sensor` daemon, because that process already
  owns the BPF maps and `PolicyEngine`. Splitting it into a second daemon would
  need pinned, shared maps, which arrive in Phase 6, so that's revisited there.
- **The socket API** takes small JSON requests: `run`, `apply`, `diff`,
  `rollback`, `status`. The peer's uid is checked with `SO_PEERCRED`:
  - root and the `rk` group may apply or roll back policy;
  - any local user may `run` an agent, but only under a profile the policy
    marks as `launchable_by` that user or group (default: root only).

## 3. Governed from the first instruction

The plan's acceptance criterion requires that no instruction of the agent runs
ungoverned. The launch sequence:

1. The daemon creates `rk.slice/agent-<uuid>`:
   - with systemd present, as a transient scope via `StartTransientUnit` over
     D-Bus, so systemd stays the owner of the cgroup tree;
   - otherwise directly in cgroupfs.
2. The daemon binds that cgroup to the profile with one hash-map update
   (`rk_cgroup_profile`) **before any agent process exists**.
3. The daemon spawns the agent **directly into the cgroup** with
   `clone3(CLONE_INTO_CGROUP)` (5.7+). There's no window in which the process
   runs elsewhere and then moves. On kernels without it (none in the support
   matrix), a pre-exec fallback is used: the child joins the cgroup, then signals
   the parent and waits for confirmation before `exec`.
4. Children inherit the cgroup automatically. No PID bookkeeping is needed.

**The agent runs without privilege**, and `rk status` verifies each item:
- with the caller's uid/gid, or a configured service user;
- with an empty capability set: no `CAP_SYS_ADMIN`, `CAP_BPF`, `CAP_PERFMON`
  or `CAP_SYS_PTRACE`;
- with `no_new_privs` set;
- with **no cgroup delegation**: the agent cgroup is owned by root and not
  writable by the agent, so the agent can't move itself out or create
  sub-cgroups with different bindings.

When the agent exits, the daemon removes the binding and then the cgroup.

## 4. Policy pipeline (extends ADR-0005)

- **Dynamic bindings** replace static `[[bindings]]` for launched agents. Static
  bindings stay supported for hand-made cgroups. Dynamic bindings survive policy
  reloads, because profile IDs are stable (ADR-0005).
- **Dry run:** `rk policy apply FILE --dry-run` parses, compiles and resolves
  every path, then prints what would change, without touching the kernel.
- **Diff:** `rk policy diff FILE` prints profiles, rules and bindings added,
  removed or changed relative to the active policy, with rule origins.
- **Rollback:** the daemon keeps the previous policy text and its generation.
  `rk policy rollback` re-applies it with the same atomic slot flip, so a bad
  apply is reversible with one command. Rolling back twice returns to the newer
  policy.
- **The policy language reference** (`docs/policy.md`) is written in this phase:
  every section, field, default and error, with examples.

## 5. Session linkage

`rk run --session <id>` (or `RK_SESSION_ID`) records `cgroup_id -> session_id`
in the daemon. `rk status` shows it, and the sensor's event log adds `session_id`
to every event from that cgroup, so each kernel event can be tied to an agent
session and its attestation (`rk-session`). The full audit schema is Phase 9.

## 6. CLI (`rk-cli`)

The binary is renamed `rkctl` → `rk`:

| Command | Purpose |
|---|---|
| `rk run --profile P [--session S] -- CMD...` | launch a governed agent; exits with the agent's exit code |
| `rk policy apply FILE [--dry-run]` | atomic apply |
| `rk policy diff FILE` | changes against the active policy |
| `rk policy rollback` | re-apply the previous policy |
| `rk status [--json]` | daemon health, generation, agents with their profile, session and privilege checks, and kernel capabilities |
| `rk doctor` | the existing preflight checks (formerly `rkctl preflight`) |

## 7. Tests (each acceptance criterion maps to a named test)

These extend `rk-integration`: the VM starts the daemon, then drives it through
the `rk` CLI.

| Plan criterion | Test |
|---|---|
| An agent started with `rk run` is governed from its first instruction | `agent_governed_from_first_instruction`: the agent's first action, an `exec` and a `connect` that the profile denies, fails with EPERM and the event carries the agent's cgroup |
| Children of a governed agent are governed automatically | `agent_children_governed` (fork, then exec, then a grandchild's connect) |
| A policy apply is visible to the kernel atomically and is reversible with one command | `policy_apply_atomic` (reuses the reload-atomic method), `policy_rollback_one_command` |
| (added) Agents run unprivileged | `agent_runs_unprivileged`: capabilities, `no_new_privs`, and no write access to its cgroup, all checked from inside the agent |
| (added) Agent can't escape its cgroup | `agent_cannot_leave_cgroup` (writing to another `cgroup.procs` fails) |
| (added) Pipeline tools | `policy_dry_run_changes_nothing`, `policy_diff_reports_changes` |
| (added) Authorisation | `socket_rejects_unauthorised_apply`, `run_rejects_non_launchable_profile` |
| (added) Lifecycle | `agent_exit_removes_binding_and_cgroup` |
| (added) Session linkage | `agent_session_id_in_events` |

Phase 5b (Kubernetes) adds a kind-based CI job. Network enforcement through
cgroup hooks works on the runner kernel, so a pod with the annotation is checked
for EPERM on a denied destination, and an unannotated pod for no effect.

## 8. Decisions requested from the reviewer

1. **Split Phase 5 into 5a (local) and 5b (Kubernetes)** as separate PRs.
   Recommended: 5a is self-contained and testable in the existing VM matrix,
   while 5b needs its own kind-based CI job.
2. **One privileged daemon** (agentd inside `rk-sensor`) until Phase 6 adds pinned
   maps. Recommended: one process owning the maps is simpler and has a smaller
   attack surface.
3. **`clone3(CLONE_INTO_CGROUP)` as the launch mechanism**, with the
   handshake fallback. Recommended: it's the only way to have no instruction run
   outside the agent cgroup.
4. **`rk run` restricted by profile `launchable_by`, default root-only.**
   Recommended: no profile can be launched by an unexpected user unless the
   policy says so.
