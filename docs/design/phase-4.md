# Design note: Phase 4 — file access policy

Status: **ACCEPTED** (2026-10-21). All four decisions in §7 approved as recommended.
Branch: `phase-4-files` (from `main` at eed228f)
Plan reference: RealityKernel_Engineering_Plan.pdf, Phase 4 and sections 3–5

## 1. Goal and scope

**Goal (plan):** protect sensitive files and directories for governed agents,
based on file identity.

In scope:
- Kernel-enforced protection of files and directory subtrees, chosen per access
  type: read, write, exec, create, delete, rename, truncate, link, set-attributes.
- Decisions on (device, inode) identity, so every way of naming the same file
  (hard links, bind mounts, symlinks, relative paths, `/proc/self/fd`) gets the
  same verdict.
- **Closing the Phase 3 gap:** allow-listed executables are protected from
  modification, deletion and replacement by governed agents by default.
- AUDIT and ENFORCE modes, the same profiles and bindings, and the same atomic
  generation-slot reload as Phases 2–3.
- The TUN/TAP default deny that ADR-0006 assigns to Phase 4. It will be
  specified in a separate addendum to this note.

Out of scope:

| Item | Where |
|---|---|
| Automatic re-protection when a protected path is replaced after apply (inotify watcher) | Later ADR; Phase 4 re-resolves on reload |
| Fail-closed heartbeat, self-protection of the sensor's own files | Phase 6 |
| Container-path to host-identity mapping | Phase 5 |

### Facts this design relies on (measured in CI, Phases 0–3)
- BPF-LSM hooks load and attach on 5.15–6.18. LSM return values must be pinned
  with `barrier_var()` (6.12).
- aya 0.13 can't load task-storage maps. Use hash or LRU maps for per-task state.
- The governance lookup, generation slots and fail-closed handling already
  exist in `common.bpf.h`.

## 2. Hooks

All hooks are BPF-LSM programs, so they decide on resolved kernel objects.

| Program | Hook | Access types decided |
|---|---|---|
| `rk_file_open` | `file_open` | read, write, exec (from `f_mode`), truncate (`O_TRUNC`) |
| `rk_file_unlink` | `inode_unlink` | delete |
| `rk_file_rename` | `inode_rename` | rename (source) and replace or delete (an existing target) |
| `rk_file_link` | `inode_link` | link (a new name for a protected file) |
| `rk_file_create` | `inode_create`, `inode_mkdir` | create inside a protected directory |
| `rk_file_setattr_*` | `inode_setattr` | truncate (`ATTR_SIZE`, which covers `truncate(2)` and `ftruncate(2)` on every kernel without needing `CONFIG_SECURITY_PATH`) and set-attributes (mode, owner, times) |

`inode_setattr` gained an `idmap` argument in 6.3. Two programs are compiled:
`rk_file_setattr_v1` (5.15–6.2) and `rk_file_setattr_v2` (6.3+). The loader loads
the one whose signature matches the running kernel's BTF and reports which one
in the selftest. It's an error if neither loads.

## 3. Matching

- **Protected-object map** `rk_file_protect` (HASH): key
  `{ u32 scope; u32 _pad; u64 dev; u64 ino; }` (the Phase 3 key layout, with
  `scope = slot << 31 | profile`) maps to
  `{ u32 rule_id; u32 deny_mask; u32 flags; u32 _pad; }`.
  `flags & RK_FILE_SUBTREE` marks a directory rule that covers everything
  beneath it.
- **Lookup order:** the object itself first. Then each ancestor directory,
  walking `d_parent` up to **32 levels** with a bounded loop, checking for
  subtree rules. The first match whose `deny_mask` covers the requested access
  decides, and its `rule_id` is reported.
- **Fail closed on depth:** if the walk reaches 32 levels without reaching the
  root, and the profile has subtree rules, the access is denied in ENFORCE with
  `RK_FILE_DEPTH_EXCEEDED` set in the event. Otherwise nesting a file deeper
  than the walk would be an easy bypass.
- **Ungoverned tasks:** one hash lookup (the governance check) and no event,
  which is the plan's fast-path rule.
- **Path strings are for logs only:** `bpf_d_path` where the verifier allows it
  for the hook (`file_open`), otherwise a bounded dentry-name walk.

## 4. Policy representation (extends ADR-0005)

```toml
[profiles.research-agent.files]
include = ["credentials"]              # built-in list; see §7 decision 2
protect_exec_allowlist = true          # default true when an [exec] section exists

[[profiles.research-agent.files.deny]]
path = "/home/agent/.ssh"
subtree = true
access = ["all"]

[[profiles.research-agent.files.deny]]
path = "/etc/hosts"
access = ["write", "truncate", "delete", "rename"]
```

- **Access names:** `read`, `write`, `exec`, `create`, `delete`, `rename`,
  `truncate`, `link`, `setattr`, `all`. They compile to `RK_FILE_*` bits.
- **Apply-time resolution** to (device, inode), symlinks followed. A missing
  path is an apply error. Every reload re-resolves, so a replaced file is
  protected again after the next reload.
- **`protect_exec_allowlist`:** every resolved exec-allowlist entry of the
  profile also gets a file rule denying write, truncate, delete, rename, link
  and setattr. That closes Phase 3's "modified in place" gap.
- **Generation slots:** entries are double-buffered like the network and exec
  rules. One slot flip makes network, exec and file policy visible together.

## 5. Events

New `RK_EV_FILE_DENY` body: the file identity, the requested access bits, the
matched rule's subtree flag, depth-exceeded and the hook that decided, followed
by the log path string. Events are emitted for deny and audit-would-deny only.
Allowed accesses are far too frequent to record and are measured in Phase 7.

## 6. Tests (each acceptance criterion maps to a named test)

These extend `rk-integration` (same harness, five kernels, emit-fail variant).

| Plan criterion | Test(s) |
|---|---|
| ENFORCE: every covered access type is denied for protected objects, regardless of syscall or I/O interface; one test per interface | `file_open_read_denied`, `file_open_write_denied`, `file_openat2_denied`, `file_io_uring_openat_denied`, `file_o_trunc_denied`, `file_truncate_denied`, `file_ftruncate_denied`, `file_unlink_denied`, `file_unlinkat_dir_denied`, `file_rename_source_denied`, `file_rename_replace_target_denied`, `file_rename_exchange_denied`, `file_link_denied`, `file_create_in_protected_dir_denied`, `file_chmod_denied` |
| Equivalent names give the same verdict | `file_hardlink_same_verdict`, `file_bind_mount_same_verdict`, `file_symlink_same_verdict`, `file_proc_fd_reopen_same_verdict`, `file_relative_path_same_verdict` |
| Ungoverned file opens stay within the Phase 7 overhead budget | `file_ungoverned_untouched` now; the overhead number is measured and gated in Phase 7 |
| (added) Subtree rules and depth fail-closed | `file_subtree_rule_applies`, `file_deep_nesting_fails_closed` |
| (added) Phase 3 gap closed | `file_exec_allowlist_write_denied`, `file_exec_allowlist_replace_denied` |
| (added) AUDIT, reload, siblings | `file_audit_reports_would_deny`, `file_reload_atomic`, `file_unbound_sibling_untouched` |
| (added) setattr signature selection | the selftest reports which `rk_file_setattr_v*` loaded on each kernel |

## 7. Decisions requested from the reviewer

1. **Protect allow-listed executables by default** (`protect_exec_allowlist =
   true` whenever a profile has an `[exec]` section). Recommended, because it
   closes the Phase 3 gap without extra configuration.
2. **A built-in `credentials` deny list, included by default** like
   `cloud-metadata`. It would cover `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`
   and `/etc/sudoers.d/`, SSH host keys and `/root/.ssh/`, for read and every
   write-type access, and could be removed explicitly. Recommended.
3. **Fail closed when the ancestor walk exceeds 32 levels** and the profile has
   subtree rules. Recommended. The alternative, treating it as "no match", is a
   bypass.
4. **Record only deny and audit-would-deny file events**, not allowed
   accesses. Recommended for volume; allowed-access statistics come with Phase 7
   metrics.
