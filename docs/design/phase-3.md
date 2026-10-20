# Design note: Phase 3 — process execution policy

Status: **PROPOSED**, waiting for review
Branch: `phase-3-exec` (from `main` at ff5684b)
Plan reference: RealityKernel_Engineering_Plan.pdf, Phase 3 and sections 3–5

## 1. Goal and scope

**Goal (plan):** allow-listed execution for governed agents, with ground-truth
exec records.

In scope:
- An LSM exec check that allows or denies each `execve`/`execveat` of a governed
  agent, based on the identity of the binary on disk (device and inode), never
  on its path string.
- Ground-truth exec records from the `sched_process_exec` tracepoint:
  the kernel-reported filename plus the argument list exactly as the new process
  sees it.
- AUDIT and ENFORCE modes, the same profiles and bindings as Phase 2, and the
  same atomic generation-slot reload.
- A built-in **quarantine** profile that userspace can move an agent into with a
  single map update.

Out of scope, with the phase that covers each:

| Item | Phase |
|---|---|
| Preventing modification of allow-listed binaries by governed agents | 4 (file policy) |
| Script-level control inside an allowed interpreter (for example what `python3` runs) | Userspace pre-dispatch engine (plan, Phase 3 text) |
| Mapping container image paths to host identities | 5 (`rk-agentd` and Kubernetes) |
| Fail-closed heartbeat | 6 |

### Facts this design relies on (measured in CI, Phases 0–2)
- BPF-LSM programs load and attach on 5.15, 6.1, 6.6, 6.12 and 6.18.
- LSM return values must be provably within [-4095, 0] on 6.12. Pin the decision
  with `barrier_var()` (Phase 2 lesson).
- The governance lookup, generation slots and fail-closed handling in
  `common.bpf.h` already exist and are tested.

## 2. Hooks

| Program | Hook | Role |
|---|---|---|
| `rk_exec_check` | `lsm/bprm_check_security` | **Decides.** Runs for every binary the kernel is about to execute, including each stage of a script (`#!`): the script file first, then its interpreter, so both must be allowed. |
| `rk_exec_record` | `tp_btf/sched_process_exec` | **Observes**, after the exec has committed. Emits the exec record for governed tasks only. Never affects a verdict. |

## 3. Identity of an executable

The plan requires decisions on kernel objects, not strings.

- **Identity = (device, inode)** of `bprm->file`, read with CO-RE
  (`f_inode->i_sb->s_dev`, `f_inode->i_ino`). The device uses the kernel `dev_t`
  encoding already defined in `docs/abi.md`.
- **No stable on-disk identity means deny in ENFORCE:** if the file has no links
  (`i_nlink == 0`), which covers `memfd_create` + `fexecve` and binaries deleted
  while open, the exec is denied unless the profile explicitly sets
  `exec.allow_unlinked = true` (admin override, logged in every event).
- **Optional content hash:** where the kernel offers `bpf_ima_inode_hash` with
  IMA enabled (probed at startup and reported under `kernel_features`), a profile
  may set `exec.require_hash = true`. The allowlist then stores the expected
  SHA-256 too, and a mismatch is a deny. If the probe fails, a profile that
  requires hashes is refused (honest degradation) instead of silently dropping
  the check.
- **Known limit, documented:** an allowed file modified *in place* keeps its
  (device, inode). Phase 4 closes this by denying governed agents write access
  to allow-listed binaries. Until then, `require_hash` is the mitigation. Replacing
  a file with `rename` produces a new inode, which is denied until a reload
  re-resolves the path.

## 4. Policy representation (extends ADR-0005)

**Policy file** (new `exec` section per profile):

```toml
[profiles.research-agent.exec]
default = "deny"                 # "allow" | "deny"; see §8, decision 1
allow = ["/usr/bin/python3", "/usr/bin/git", "/bin/sh"]
allow_dirs = ["/opt/agent/bin"]  # snapshot of regular files at apply time
allow_unlinked = false
require_hash = false
```

- **Apply-time resolution:** paths are resolved by the sensor with `stat()`,
  following symlinks to the real file, into (device, inode). `allow_dirs` expands
  to the regular files in that directory at apply time (non-recursive, capped at
  4096 entries per profile). A new file needs a reload, which is documented.
  A path that doesn't exist is an apply error, not a silent skip.
- **Kernel map** `rk_exec_allow`, a HASH map:
  `struct rk_exec_key { u32 scope; u32 _pad; u64 dev; u64 ino; }` (24 bytes),
  where `scope = slot << 31 | profile` as in Phase 2, mapping to
  `struct rk_exec_rule { u32 rule_id; u32 flags; u8 sha256[32]; }`. Entries are
  double-buffered by slot, so a reload is atomic with the network rules: one flip
  covers both.
- **Profile flags** (no layout change to `rk_profile`): `RK_PROFILE_EXEC_DENY_DEFAULT`,
  `RK_PROFILE_EXEC_ALLOW_UNLINKED`, `RK_PROFILE_EXEC_REQUIRE_HASH`.
- **Decision:**
  1. Ungoverned task: allow (one hash lookup).
  2. Look up `(scope, dev, ino)` in `rk_exec_allow`. A hit (and a matching hash
     where required) allows, with that `rule_id`.
  3. Otherwise apply the profile's exec default, with rule 0. Unlinked files are
     denied first unless overridden.
  4. Emit the event, then return `-EPERM` only for an ENFORCE deny.

## 5. Exec records (ground truth)

- `rk_exec_record` reads `bprm->filename` (kernel-resolved) and the new process's
  argument area (`mm->arg_start..arg_end`), copied in bounded chunks into the
  existing `rk_payload_exec` string tail. That is one string for the filename
  plus one per argument, as the new process sees them.
- If arguments exceed the 2 KiB payload, the record sets
  `RK_EXEC_ARGV_TRUNCATED` in `flags` and carries what fits. Nothing is silently
  dropped.
- Denied execs never reach this tracepoint, so the LSM hook emits its own
  `RK_EV_EXEC` record with verdict DENY or AUDIT_WOULD_DENY and the filename.
- **Removed:** the old syscall-entry exec probes and `/proc` cmdline enrichment
  were already deleted in Phase 0 (ADR-0002), so nothing remains to remove.

## 6. Quarantine

- Every policy has a built-in `quarantine` profile: ENFORCE, exec default deny
  with an empty allowlist, network default deny with no allow rules, and raw
  sockets denied. It can't be redefined by the policy file.
- `PolicyEngine::quarantine(cgroup)` rebinds the cgroup to it with one hash-map
  update, which is atomic per cgroup. Processes already running keep running but
  can no longer exec anything or open new connections.
- If a process must also be stopped, the sensor uses `pidfd_open` +
  `pidfd_send_signal`, so a recycled PID can never hit the wrong process. Each
  signal is logged as its own audit entry (full audit schema in Phase 9).

## 7. Tests (each acceptance criterion maps to a named test)

These extend `rk-integration` (same harness, same five kernels, same deadlines and
progress logging). They run against both `rk.bpf.o` and `rk_emitfail.bpf.o`.

| Plan criterion | Test |
|---|---|
| ENFORCE: unlisted executables fail with EPERM/EACCES; listed ones run | `exec_enforce_unlisted_denied`, `exec_enforce_listed_runs` |
| AUDIT: everything runs and unlisted executions produce audit-would-deny events | `exec_audit_reports_would_deny` (exact rule 0, cgroup ID, filename) |
| Exec events contain the full argument list, including multi-argument shell invocations | `exec_records_full_argv` (`/bin/sh -c 'echo a b'` style, with an exact argv comparison), `exec_records_truncation_flag` |
| Policy reload is atomic | `exec_reload_atomic` (paced execs across slot flips; every outcome matches its event's `policy_gen`) |
| (added) Scripts check both script and interpreter | `exec_script_requires_interpreter` |
| (added) No stable identity | `exec_unlinked_denied`, `exec_unlinked_override_allows` |
| (added) Symlinks resolve to their target; a replaced file needs a reload | `exec_symlink_resolves_to_target`, `exec_replaced_binary_denied_until_reload` |
| (added) Quarantine | `exec_quarantine_blocks_exec_and_network` |
| (added) Ungoverned untouched | `exec_ungoverned_untouched`, `exec_unbound_sibling_untouched` |
| (added) Records never change verdicts | Covered by the `rk_emitfail.bpf.o` pass over every test above |
| (added) Compiler and resolver | `rk-policy` unit tests (parsing, defaults, errors) and `rk-sensor` resolver tests (missing path fails apply, symlink handling, directory cap) |

## 8. Decisions requested from the reviewer

1. **Exec default when a profile has no `exec` section.** I recommend **allow**,
   so existing Phase 2 network-only profiles keep working unchanged, and
   **deny** (allowlist mode) as the default as soon as an `exec` section exists.
2. **Unlinked executables (memfd, deleted files) denied in ENFORCE by default**,
   with an explicit per-profile override, as the plan requires. Recommended.
3. **`allow_dirs` as an apply-time snapshot** (with reload to pick up new files)
   rather than in-kernel directory matching, which Phase 4's dentry walk makes
   possible later. Recommended for Phase 3.
4. **Content hashes are optional** (`require_hash`), and a profile that requires
   them is refused on kernels without `bpf_ima_inode_hash` support.
   Recommended.
