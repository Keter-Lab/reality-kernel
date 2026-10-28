//! Network hook attachment and atomic policy apply (docs/design/phase-2.md §4).
//!
//! An apply writes the *inactive* generation slot (profiles plus deny and allow
//! trie entries), then flips `rk_active_slot` with one 4-byte array update: that
//! update is the commit point. A slot is cleared only at the start of the next
//! apply, and never within [`SLOT_GRACE`] of the flip that retired it, so no
//! running decision (which reads the slot once and lasts microseconds) can
//! observe a slot being rewritten. A failed apply never touches the active slot.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, HashMap as BpfHashMap};
use aya::programs::links::FdLink;
use aya::programs::{BtfTracePoint, CgroupAttachMode, CgroupSockAddr, Lsm};
use aya::Ebpf;
use bytemuck::Zeroable;
use rk_ebpf_common::{
    rk_binding, rk_exec_key, rk_exec_rule, rk_file_key, rk_file_rule, rk_net_range, rk_net_rule,
    rk_profile, RK_MAX_PROFILES,
};
use rk_policy::net::{
    self, Action, Compiled, CompiledExec, CompiledFile, Entry, ExecPathKind, FileTarget, Mode,
    Policy, ProfileIds, MAX_EXEC_DIR_FILES, QUARANTINE,
};
use serde::{Deserialize, Serialize};

use crate::loader::SETATTR_VARIANTS;
use crate::selftest::kernel_dev;

/// cgroup v2 mount point.
pub const CGROUP_FS: &str = "/sys/fs/cgroup";

/// `cgroup/sock_addr` programs, attached to `rk.slice`.
pub const SOCK_ADDR_PROGRAMS: [&str; 4] = [
    "rk_net_connect4",
    "rk_net_connect6",
    "rk_net_sendmsg4",
    "rk_net_sendmsg6",
];

/// Host-wide network LSM programs: raw and packet sockets, and TUN/TAP
/// (docs/design/phase-16.md).
pub const LSM_PROGRAMS: [&str; 4] = [
    "rk_net_socket_create",
    "rk_net_tun_create",
    "rk_net_tun_open",
    "rk_net_tun_attach_queue",
];

/// Minimum time between retiring a slot and rewriting it.
pub const SLOT_GRACE: Duration = Duration::from_secs(1);

const MAP_BINDINGS: &str = "rk_cgroup_profile";
const MAP_PROFILES: &str = "rk_profiles";
const MAP_ACTIVE: &str = "rk_active_slot";
const MAP_DENY: &str = "rk_net_deny";
const MAP_ALLOW: &str = "rk_net_allow";
const MAP_EXEC: &str = "rk_exec_allow";
const MAP_FILE: &str = "rk_file_protect";

/// Exec policy programs (Phase 3): the LSM check and the exec record.
pub const EXEC_LSM_PROGRAM: &str = "rk_exec_check";
pub const EXEC_RECORD_PROGRAM: &str = "rk_exec_record";

// aya's map types need aya::Pod; these newtypes satisfy the orphan rule.

/// `struct rk_net_key` without its leading `prefixlen` (aya's `Key` adds it).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KeyData {
    scope: u32,
    addr: [u8; 16],
}
// SAFETY: repr(C), only integer fields, no padding (4 + 16 bytes).
unsafe impl aya::Pod for KeyData {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct NetRule(rk_net_rule);
// SAFETY: rk_net_rule derives bytemuck::Pod (no padding, any bit pattern valid).
unsafe impl aya::Pod for NetRule {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct Profile(rk_profile);
// SAFETY: as above.
unsafe impl aya::Pod for Profile {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct Binding(rk_binding);
// SAFETY: as above.
unsafe impl aya::Pod for Binding {}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExecKey(rk_exec_key);
// SAFETY: as above.
unsafe impl aya::Pod for ExecKey {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct ExecRule(rk_exec_rule);
// SAFETY: as above.
unsafe impl aya::Pod for ExecRule {}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileKey(rk_file_key);
// SAFETY: as above.
unsafe impl aya::Pod for FileKey {}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct FileRule(rk_file_rule);
// SAFETY: as above.
unsafe impl aya::Pod for FileRule {}

/// One resolved file protection entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResolvedFile {
    profile: u32,
    rule_id: u32,
    dev: u64,
    ino: u64,
    deny_mask: u32,
    subtree: bool,
}

/// Resolves file rules to (device, inode), following symlinks. Several rules
/// on the same object in one profile merge into one entry: masks are OR-ed,
/// the first rule id is kept. A path from a built-in list that is missing or
/// not accessible on this host is skipped and returned in the second list so
/// the apply report shows it; any other resolution failure fails the apply
/// before the kernel changes.
fn resolve_files(entries: &[CompiledFile]) -> Result<(Vec<ResolvedFile>, Vec<String>)> {
    let mut skipped = Vec::new();
    let mut merged: BTreeMap<(u32, u64, u64), ResolvedFile> = BTreeMap::new();
    let mut add = |r: ResolvedFile| {
        merged
            .entry((r.profile, r.dev, r.ino))
            .and_modify(|m| {
                m.deny_mask |= r.deny_mask;
                m.subtree |= r.subtree;
            })
            .or_insert(r);
    };
    let mut exec_targets = Vec::new();
    for e in entries {
        match e.target {
            FileTarget::Path { subtree, optional } => match fs::metadata(&e.path) {
                Ok(meta) => add(ResolvedFile {
                    profile: e.profile,
                    rule_id: e.rule_id,
                    dev: kernel_dev(meta.dev()),
                    ino: meta.ino(),
                    deny_mask: e.deny_mask,
                    subtree: subtree && meta.is_dir(),
                }),
                Err(err)
                    if optional
                        && matches!(
                            err.kind(),
                            std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                        ) =>
                {
                    skipped.push(format!("{} ({err})", e.path));
                }
                Err(err) => {
                    return Err(err)
                        .with_context(|| format!("file rule: cannot resolve `{}`", e.path))
                }
            },
            FileTarget::Exec(kind) => exec_targets.push((
                CompiledExec {
                    profile: e.profile,
                    rule_id: e.rule_id,
                    path: e.path.clone(),
                    kind,
                },
                e.deny_mask,
            )),
        }
    }
    for (target, mask) in &exec_targets {
        for r in resolve_exec(std::slice::from_ref(target))? {
            add(ResolvedFile {
                profile: r.profile,
                rule_id: r.rule_id,
                dev: r.dev,
                ino: r.ino,
                deny_mask: *mask,
                subtree: false,
            });
        }
    }
    Ok((merged.into_values().collect(), skipped))
}

/// Pinned link file for a program; cgroup links are pinned once per root.
fn link_pin(links: Option<&Path>, name: &str, root: Option<&Path>) -> Option<PathBuf> {
    let dir = links?;
    Some(match root {
        None => dir.join(name),
        Some(root) => {
            let rel = root.strip_prefix(CGROUP_FS).unwrap_or(root);
            let tag = rel
                .to_string_lossy()
                .trim_matches('/')
                .replace('/', "+")
                .replace('.', "_");
            dir.join(format!("{name}@{tag}"))
        }
    })
}

/// Attaches one LSM program. With a pin path (docs/design/phase-6.md §3), a
/// link already pinned there by an earlier sensor is adopted as is, and a new
/// link is pinned so it outlives this process.
fn attach_lsm(ebpf: &mut Ebpf, name: &str, pin: Option<&Path>) -> Result<String> {
    if pin.is_some_and(Path::exists) {
        return Ok(format!("{name} (lsm, adopted)"));
    }
    let program: &mut Lsm = ebpf
        .program_mut(name)
        .with_context(|| format!("program `{name}` missing from rk.bpf.o"))?
        .try_into()?;
    let id = program
        .attach()
        .with_context(|| format!("attach LSM program `{name}`"))?;
    if let Some(pin) = pin {
        let link: FdLink = program.take_link(id)?.into();
        link.pin(pin)
            .with_context(|| format!("pin {}", pin.display()))?;
    }
    Ok(format!("{name} (lsm)"))
}

/// Attaches the exec programs (already loaded): the host-wide LSM exec check
/// and the `sched_process_exec` record. Without `links`, links detach when
/// `ebpf` drops.
pub fn attach_exec(ebpf: &mut Ebpf, links: Option<&Path>) -> Result<Vec<String>> {
    let mut attached = vec![attach_lsm(
        ebpf,
        EXEC_LSM_PROGRAM,
        link_pin(links, EXEC_LSM_PROGRAM, None).as_deref(),
    )?];
    let pin = link_pin(links, EXEC_RECORD_PROGRAM, None);
    if pin.as_deref().is_some_and(Path::exists) {
        attached.push(format!("{EXEC_RECORD_PROGRAM} (tp_btf, adopted)"));
    } else {
        let program: &mut BtfTracePoint = ebpf
            .program_mut(EXEC_RECORD_PROGRAM)
            .with_context(|| format!("program `{EXEC_RECORD_PROGRAM}` missing from rk.bpf.o"))?
            .try_into()?;
        let id = program
            .attach()
            .with_context(|| format!("attach `{EXEC_RECORD_PROGRAM}`"))?;
        if let Some(pin) = &pin {
            let link: FdLink = program.take_link(id)?.into();
            link.pin(pin)
                .with_context(|| format!("pin {}", pin.display()))?;
        }
        attached.push(format!("{EXEC_RECORD_PROGRAM} (tp_btf/sched_process_exec)"));
    }
    Ok(attached)
}

const FILE_PROGRAMS: &[&str] = &[
    "rk_file_open",
    "rk_file_unlink",
    "rk_file_rmdir",
    "rk_file_rename",
    "rk_file_link",
    "rk_file_create",
    "rk_file_mkdir",
];

/// Self-protection LSM programs (guard.bpf.c, docs/design/phase-6.md §5).
pub const GUARD_PROGRAMS: &[&str] = &[
    "rk_guard_bpf",
    "rk_guard_task_kill",
    "rk_guard_ptrace",
    "rk_guard_pin_unlink",
    "rk_guard_pin_rename",
    "rk_guard_pin_rmdir",
    "rk_guard_umount",
];

/// Attaches the self-protection LSM programs (already loaded).
pub fn attach_guard(ebpf: &mut Ebpf, links: Option<&Path>) -> Result<Vec<String>> {
    GUARD_PROGRAMS
        .iter()
        .map(|name| attach_lsm(ebpf, name, link_pin(links, name, None).as_deref()))
        .collect()
}

/// Attaches the file LSM programs (already loaded). One `inode_setattr`
/// variant is used: v2 where the hook has the `idmap` argument (6.9+), else
/// v1; its link is pinned as `rk_file_setattr` either way.
pub fn attach_file(ebpf: &mut Ebpf, links: Option<&Path>) -> Result<Vec<String>> {
    let mut attached = FILE_PROGRAMS
        .iter()
        .map(|name| attach_lsm(ebpf, name, link_pin(links, name, None).as_deref()))
        .collect::<Result<Vec<_>>>()?;

    let pin = link_pin(links, "rk_file_setattr", None);
    if pin.as_deref().is_some_and(Path::exists) {
        attached.push("rk_file_setattr (lsm, adopted)".to_string());
        return Ok(attached);
    }
    let v2_loaded = ebpf.program_mut(SETATTR_VARIANTS[0]).is_some();
    let v2 = if v2_loaded {
        attach_lsm(ebpf, SETATTR_VARIANTS[0], pin.as_deref())
    } else {
        Err(anyhow::anyhow!("{} not loaded", SETATTR_VARIANTS[0]))
    };
    attached.push(match v2 {
        Ok(name) => name,
        Err(_) => attach_lsm(ebpf, SETATTR_VARIANTS[1], pin.as_deref())?,
    });
    Ok(attached)
}

/// Attaches every enforcement program: network hooks on `cgroup_root`, exec,
/// file and self-protection programs. Links are not pinned (test harness).
pub fn attach_all(ebpf: &mut Ebpf, cgroup_root: &Path) -> Result<Vec<String>> {
    let mut attached = attach_network(ebpf, cgroup_root, None)?;
    attached.extend(attach_exec(ebpf, None)?);
    attached.extend(attach_file(ebpf, None)?);
    attached.extend(attach_guard(ebpf, None)?);
    Ok(attached)
}

/// Whether `bpf` is in the kernel's active LSM list. When it is not, LSM
/// programs attach but are never called.
pub fn bpf_lsm_active() -> bool {
    fs::read_to_string("/sys/kernel/security/lsm")
        .map(|list| list.trim().split(',').any(|lsm| lsm == "bpf"))
        .unwrap_or(false)
}

/// Sends SIGKILL through a pidfd, so a recycled PID can never be hit. Used
/// together with [`PolicyEngine::quarantine`] when a process must also stop.
pub fn kill_process(pid: i32) -> Result<()> {
    // SAFETY: plain syscalls with integer arguments; the fd is closed below.
    unsafe {
        let fd = libc::syscall(libc::SYS_pidfd_open, pid, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("pidfd_open({pid})"));
        }
        let rc = libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd as libc::c_int,
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        );
        let err = std::io::Error::last_os_error();
        libc::close(fd as libc::c_int);
        if rc < 0 {
            return Err(err).with_context(|| format!("pidfd_send_signal({pid}, SIGKILL)"));
        }
    }
    Ok(())
}

/// One resolved exec allowlist entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResolvedExec {
    profile: u32,
    rule_id: u32,
    dev: u64,
    ino: u64,
}

/// Resolves exec allowlist paths to (device, inode), following symlinks to the
/// real file. A missing path, a non-file entry or an oversized directory is an
/// error: the apply fails before anything visible to the kernel changes.
fn resolve_exec(entries: &[CompiledExec]) -> Result<Vec<ResolvedExec>> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut dir_files: BTreeMap<u32, usize> = BTreeMap::new();
    let mut push =
        |profile: u32, rule_id: u32, meta: &fs::Metadata, out: &mut Vec<ResolvedExec>| {
            let r = ResolvedExec {
                profile,
                rule_id,
                dev: kernel_dev(meta.dev()),
                ino: meta.ino(),
            };
            // First rule wins for the same file in the same profile.
            if seen.insert((r.profile, r.dev, r.ino)) {
                out.push(r);
            }
        };
    for e in entries {
        match e.kind {
            ExecPathKind::File => {
                let meta = fs::metadata(&e.path)
                    .with_context(|| format!("exec allowlist: cannot resolve `{}`", e.path))?;
                if !meta.is_file() {
                    anyhow::bail!("exec allowlist: `{}` is not a regular file", e.path);
                }
                push(e.profile, e.rule_id, &meta, &mut out);
            }
            ExecPathKind::Dir => {
                let dir = fs::read_dir(&e.path).with_context(|| {
                    format!("exec allowlist: cannot read directory `{}`", e.path)
                })?;
                for item in dir {
                    let item = item.with_context(|| format!("read entry in `{}`", e.path))?;
                    let Ok(meta) = fs::metadata(item.path()) else {
                        continue; // dangling symlink: nothing to execute
                    };
                    if !meta.is_file() {
                        continue;
                    }
                    let count = dir_files.entry(e.profile).or_default();
                    *count += 1;
                    if *count > MAX_EXEC_DIR_FILES {
                        anyhow::bail!(
                            "exec allowlist: directories expand to more than {MAX_EXEC_DIR_FILES} files for one profile"
                        );
                    }
                    push(e.profile, e.rule_id, &meta, &mut out);
                }
            }
        }
    }
    Ok(out)
}

/// Attaches the network programs (already loaded) to `cgroup_root`, creating
/// it if needed, and the LSM programs host-wide.
pub fn attach_network(
    ebpf: &mut Ebpf,
    cgroup_root: &Path,
    links: Option<&Path>,
) -> Result<Vec<String>> {
    let mut attached = attach_sock_addr(ebpf, cgroup_root, links)?;
    attached.extend(attach_network_lsm(ebpf, links)?);
    Ok(attached)
}

/// Attaches the `sock_addr` programs to one more cgroup subtree, creating it
/// if needed. Unlike the LSM programs, these can be attached at several roots
/// (`rk.slice` and the Kubernetes root, Phase 5b); each root has its own pins.
pub fn attach_sock_addr(
    ebpf: &mut Ebpf,
    cgroup_root: &Path,
    links: Option<&Path>,
) -> Result<Vec<String>> {
    fs::create_dir_all(cgroup_root).with_context(|| format!("create {}", cgroup_root.display()))?;
    let cgroup =
        fs::File::open(cgroup_root).with_context(|| format!("open {}", cgroup_root.display()))?;

    let mut attached = Vec::new();
    for name in SOCK_ADDR_PROGRAMS {
        let pin = link_pin(links, name, Some(cgroup_root));
        if pin.as_deref().is_some_and(Path::exists) {
            attached.push(format!("{name} -> {} (adopted)", cgroup_root.display()));
            continue;
        }
        let program: &mut CgroupSockAddr = ebpf
            .program_mut(name)
            .with_context(|| format!("program `{name}` missing from rk.bpf.o"))?
            .try_into()?;
        // bpf_link based cgroup attachments take no flags and are always multi-attach.
        let id = program
            .attach(&cgroup, CgroupAttachMode::Single)
            .with_context(|| format!("attach `{name}` to {}", cgroup_root.display()))?;
        if let Some(pin) = &pin {
            let link = FdLink::try_from(program.take_link(id)?)?;
            link.pin(pin)
                .with_context(|| format!("pin {}", pin.display()))?;
        }
        attached.push(format!("{name} -> {}", cgroup_root.display()));
    }
    Ok(attached)
}

/// Attaches the network LSM programs (raw sockets, TUN/TAP) host-wide, once.
pub fn attach_network_lsm(ebpf: &mut Ebpf, links: Option<&Path>) -> Result<Vec<String>> {
    LSM_PROGRAMS
        .iter()
        .map(|name| attach_lsm(ebpf, name, link_pin(links, name, None).as_deref()))
        .collect()
}

/// Keys written into one slot, so it can be cleared before reuse.
#[derive(Debug, Default)]
struct SlotContents {
    profiles: Vec<u32>,
    deny: Vec<(u32, KeyData)>,
    allow: Vec<(u32, KeyData)>,
    exec: Vec<ExecKey>,
    files: Vec<FileKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReport {
    pub generation: u64,
    pub slot: u32,
    pub profiles: usize,
    pub deny_entries: usize,
    pub allow_entries: usize,
    pub exec_entries: usize,
    pub file_entries: usize,
    /// Built-in file rules not active on this host (missing or inaccessible).
    pub skipped_files: Vec<String>,
    pub bindings: usize,
}

/// How many unbound agent cgroups [`PolicyEngine::audit_context`] still names.
pub const RETIRED_MAX: usize = 1024;

/// Owns the policy maps of one loaded `rk.bpf.o`.
pub struct PolicyEngine {
    cgroup_fs: PathBuf,
    ids: ProfileIds,
    generation: u64,
    active_slot: u32,
    last_flip: Option<Instant>,
    written: [SlotContents; 2],
    /// cgroup id -> (path, profile id)
    bindings: BTreeMap<u64, (String, u32)>,
    /// cgroup ids currently held in the built-in quarantine profile. Survives
    /// policy reloads until released.
    quarantined: BTreeSet<u64>,
    /// Agent cgroups bound at runtime (`rk run`): cgroup id -> (path, profile
    /// name). Kept across reloads; profile ids are stable (ADR-0005).
    dynamic: BTreeMap<u64, (String, String)>,
    /// Bindings found in the kernel map when pins were adopted without a
    /// usable state file: cgroup id -> (path found in the cgroup filesystem,
    /// or "" if none; profile id). They are runtime bindings (agents,
    /// containers) the engine cannot attribute to a profile name, so it keeps
    /// them exactly as they are: an apply never removes one while its cgroup
    /// may still exist, and a static binding or a container rebind of the
    /// same cgroup takes it over (docs/design/phase-6.md §3.3).
    adopted: BTreeMap<u64, (String, u32)>,
    /// Agent cgroups unbound most recently, oldest first: (cgroup id,
    /// profile name). An agent's last events can reach the audit log after
    /// it exited and was unbound; they still name its profile. Capped at
    /// [`RETIRED_MAX`]; cgroup ids are not reused.
    retired: VecDeque<(u64, String)>,
    policy: Option<Policy>,
    /// Text of the active and the previous policy, for `rk policy rollback`.
    text: Option<String>,
    previous_text: Option<String>,
    /// Whether BPF LSM is active on this kernel. Without it, exec and file
    /// rules are refused (docs/design/phase-5b.md §6).
    lsm_active: bool,
    /// Where the engine persists its state after every change, and the pin
    /// epoch that state belongs to (docs/design/phase-6.md §3.3).
    state_file: Option<PathBuf>,
    epoch: String,
}

/// What survives a sensor restart beyond the kernel maps themselves.
#[derive(Debug, Serialize, Deserialize)]
struct EngineState {
    epoch: String,
    ids: ProfileIds,
    generation: u64,
    bindings: BTreeMap<u64, (String, u32)>,
    quarantined: BTreeSet<u64>,
    dynamic: BTreeMap<u64, (String, String)>,
    /// Absent in files written before it existed.
    #[serde(default)]
    adopted: BTreeMap<u64, (String, u32)>,
    text: Option<String>,
    previous_text: Option<String>,
}

/// Map capacities (`max_entries` in rk-bpf; pinned by the test
/// `map_capacities_match_the_bpf_sources`). An apply that would not fit is
/// refused before anything is written, so it never fails after the flip.
const CAP_BINDINGS: usize = 4096;
const CAP_NET: usize = 65536;
const CAP_EXEC: usize = 65536;
const CAP_FILE: usize = 65536;

/// How deep `cgroup_paths` looks below the cgroup root.
const MAX_CGROUP_DEPTH: usize = 32;

/// Whether the cgroup bound as `id` may still exist at `path` (relative to
/// `cgroup_fs`). Only a definite answer counts as gone: the directory is
/// missing, or is now a different cgroup. An unknown path ("") or an error
/// other than not-found keep the binding.
fn cgroup_alive(cgroup_fs: &Path, path: &str, id: u64) -> bool {
    if path.is_empty() {
        return true;
    }
    match fs::metadata(cgroup_fs.join(path)) {
        Ok(meta) => meta.ino() == id,
        Err(e) => e.kind() != std::io::ErrorKind::NotFound,
    }
}

/// Paths, relative to `cgroup_fs`, of the cgroups whose ids are in `ids`,
/// found by walking the cgroup filesystem (a cgroup's id is its directory's
/// inode number). Ids not found are left out.
fn cgroup_paths(cgroup_fs: &Path, ids: &BTreeSet<u64>) -> BTreeMap<u64, String> {
    let mut found = BTreeMap::new();
    let mut stack = vec![(cgroup_fs.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if found.len() == ids.len() {
            break;
        }
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            // Neither call follows symlinks; most entries are interface
            // files, so the cheap type check comes first.
            if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let path = entry.path();
            if ids.contains(&meta.ino()) {
                if let Ok(rel) = path.strip_prefix(cgroup_fs) {
                    found.insert(meta.ino(), rel.to_string_lossy().into_owned());
                }
            }
            if depth < MAX_CGROUP_DEPTH {
                stack.push((path, depth + 1));
            }
        }
    }
    found
}

/// Refuses an apply whose entries would not fit the maps. The inactive slot
/// is cleared before it is written, so each map must hold the live slot's
/// entries plus the new ones; bindings are rewritten in place.
fn check_capacity(
    live: &SlotContents,
    deny: usize,
    allow: usize,
    exec: usize,
    files: usize,
    bindings: usize,
) -> Result<()> {
    for (what, live_n, new_n, cap) in [
        ("network deny", live.deny.len(), deny, CAP_NET),
        ("network allow", live.allow.len(), allow, CAP_NET),
        ("exec allowlist", live.exec.len(), exec, CAP_EXEC),
        ("file protection", live.files.len(), files, CAP_FILE),
    ] {
        if live_n + new_n > cap {
            anyhow::bail!(
                "the policy needs {new_n} {what} entries; with the {live_n} of the live \
                 generation that exceeds the map's capacity of {cap}. Nothing was changed"
            );
        }
    }
    if bindings > CAP_BINDINGS {
        anyhow::bail!(
            "the policy and running agents need {bindings} cgroup bindings, more than the \
             map's capacity of {CAP_BINDINGS}. Nothing was changed"
        );
    }
    Ok(())
}

/// Snapshot of the active policy for naming decisions in the audit log.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AuditContext {
    pub generation: u64,
    /// rule id -> (profile name, where the rule is in the policy text)
    pub rules: BTreeMap<u32, (String, String)>,
    /// cgroup id -> bound profile name
    pub cgroups: BTreeMap<u64, String>,
}

impl AuditContext {
    /// Profile and rule origin for a decision. The rule names its profile;
    /// a default decision (rule 0) is named by the cgroup's binding.
    pub fn describe(&self, rule_id: u32, cgroup_id: u64) -> (Option<&str>, Option<&str>) {
        match self.rules.get(&rule_id) {
            Some((profile, origin)) => (Some(profile.as_str()), Some(origin.as_str())),
            None => (self.cgroups.get(&cgroup_id).map(String::as_str), None),
        }
    }
}

/// Reads a state file, accepting it only when it belongs to the pin set with
/// `epoch` (hex). A missing, unreadable or foreign file yields `None`: the
/// engine then rebuilds what it can from the maps alone.
fn load_state(path: &Path, epoch: &str) -> Option<EngineState> {
    let state: EngineState = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    (!epoch.is_empty() && state.epoch == epoch).then_some(state)
}

/// What `rk policy apply --dry-run` reports: the apply that would happen,
/// computed without touching the kernel or creating cgroups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRun {
    pub generation: u64,
    pub profiles: usize,
    pub deny_entries: usize,
    pub allow_entries: usize,
    pub exec_entries: usize,
    pub file_entries: usize,
    pub skipped_files: Vec<String>,
    /// Static bindings whose cgroup does not exist yet (an apply creates them).
    pub cgroups_to_create: Vec<String>,
    /// `rk_policy::net::diff` against the active policy.
    pub changes: Vec<String>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new(PathBuf::from(CGROUP_FS))
    }
}

impl PolicyEngine {
    pub fn new(cgroup_fs: PathBuf) -> Self {
        PolicyEngine {
            cgroup_fs,
            ids: ProfileIds::default(),
            generation: 0,
            active_slot: 0,
            last_flip: None,
            written: [SlotContents::default(), SlotContents::default()],
            bindings: BTreeMap::new(),
            quarantined: BTreeSet::new(),
            dynamic: BTreeMap::new(),
            adopted: BTreeMap::new(),
            retired: VecDeque::new(),
            policy: None,
            text: None,
            previous_text: None,
            lsm_active: true,
            state_file: None,
            epoch: String::new(),
        }
    }

    /// Persists the engine state to `path` after every change, tagged with
    /// the pin set's `epoch`. Nothing is written yet, so [`Self::adopt`]
    /// can still read the previous sensor's file.
    pub fn set_state_file(&mut self, path: PathBuf, epoch: &[u8; 16]) {
        self.state_file = Some(path);
        self.epoch = hex::encode(epoch);
    }

    /// Writes the state file atomically (temporary file, then rename), 0600.
    /// A failure is logged: the kernel change it follows has already happened.
    fn persist(&self) {
        let Some(path) = &self.state_file else {
            return;
        };
        let state = EngineState {
            epoch: self.epoch.clone(),
            ids: self.ids.clone(),
            generation: self.generation,
            bindings: self.bindings.clone(),
            quarantined: self.quarantined.clone(),
            dynamic: self.dynamic.clone(),
            adopted: self.adopted.clone(),
            text: self.text.clone(),
            previous_text: self.previous_text.clone(),
        };
        let write = || -> Result<()> {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            use std::os::unix::fs::PermissionsExt as _;
            // A new directory is made 0755; an existing one (e.g. systemd's
            // 0700 StateDirectory) keeps its mode.
            if let Some(dir) = path.parent() {
                if !dir.exists() {
                    fs::create_dir_all(dir)?;
                    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
                }
            }
            let tmp = path.with_extension("tmp");
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(&serde_json::to_vec(&state)?)?;
            file.sync_all()?;
            fs::rename(&tmp, path)?;
            Ok(())
        };
        if let Err(e) = write() {
            tracing::error!(path = %path.display(), error = %format!("{e:#}"), "engine state not saved");
        }
    }

    /// Carries the state of a pin set being replaced into a new, empty one
    /// (docs/design/phase-10.md §3): the state file is read with the old pin
    /// set's `old_epoch`, then its policy text, dynamic agent and container
    /// bindings and quarantine are written into `ebpf`'s maps. Call after
    /// [`Self::set_state_file`] (with the new epoch) and before the old pin
    /// set is removed. Returns false, changing nothing, when there is no
    /// state for the old epoch or it holds no policy.
    pub fn migrate(&mut self, ebpf: &mut Ebpf, old_epoch: &[u8; 16]) -> Result<bool> {
        let Some(path) = self.state_file.clone() else {
            return Ok(false);
        };
        let Some(state) = load_state(&path, &hex::encode(old_epoch)) else {
            return Ok(false);
        };
        let Some(text) = state.text else {
            return Ok(false);
        };
        self.ids = state.ids;
        self.generation = state.generation;
        self.dynamic = state.dynamic;
        self.adopted = state.adopted;
        self.quarantined = state.quarantined;
        // The new maps hold no binding yet: forget the old ones so every
        // binding is written.
        self.bindings = BTreeMap::new();
        self.text = None;
        self.apply_text(ebpf, &text)?;
        self.previous_text = state.previous_text;
        self.persist();
        Ok(true)
    }

    /// Takes over the kernel state of an adopted pin set
    /// (docs/design/phase-6.md §3.3). The live slot, both slots' contents and
    /// the newest generation always come from the maps, so the next apply can
    /// never write into the live slot. The state file adds what the maps
    /// cannot say (profile id allocation, binding paths, agent bindings,
    /// quarantine, policy text) when it belongs to the same pin set; call
    /// [`Self::set_state_file`] first. Returns whether it was used.
    pub fn adopt(&mut self, ebpf: &mut Ebpf) -> Result<bool> {
        let active =
            Array::<_, u32>::try_from(ebpf.map(MAP_ACTIVE).context("rk_active_slot missing")?)?;
        self.active_slot = active.get(&0, 0).context("read rk_active_slot")? & 1;
        self.written = [scan_slot(ebpf, 0)?, scan_slot(ebpf, 1)?];

        let profiles =
            Array::<_, Profile>::try_from(ebpf.map(MAP_PROFILES).context("rk_profiles missing")?)?;
        let mut kernel_gen = 0;
        for &id in &self.written[self.active_slot as usize].profiles {
            let p = profiles.get(&profile_index(self.active_slot, id), 0)?;
            kernel_gen = kernel_gen.max(p.0.policy_gen);
        }

        let state = self
            .state_file
            .as_deref()
            .and_then(|path| load_state(path, &self.epoch));
        let used = state.is_some();
        match state {
            Some(s) => {
                self.ids = s.ids;
                self.generation = s.generation.max(kernel_gen);
                self.bindings = s.bindings;
                self.quarantined = s.quarantined;
                self.dynamic = s.dynamic;
                self.adopted = s.adopted;
                self.text = s.text;
                self.previous_text = s.previous_text;
            }
            None => {
                // Only the kernel's view. Every binding in the map is kept
                // as an adopted binding: the engine cannot tell an agent's or
                // container's binding from a static one, and must not unbind
                // a running workload because the state file is gone. Paths
                // come from the cgroup filesystem where the cgroup is found.
                self.generation = kernel_gen;
                let map = ebpf
                    .map(MAP_BINDINGS)
                    .context("rk_cgroup_profile missing")?;
                let bindings = BpfHashMap::<_, u64, Binding>::try_from(map)?;
                let kernel: BTreeMap<u64, u32> = bindings
                    .iter()
                    .filter_map(|entry| entry.ok())
                    .map(|(id, b)| (id, b.0.profile))
                    .collect();
                let ids: BTreeSet<u64> = kernel.keys().copied().collect();
                let paths = cgroup_paths(&self.cgroup_fs, &ids);
                self.bindings = kernel
                    .into_iter()
                    .map(|(id, profile)| {
                        (id, (paths.get(&id).cloned().unwrap_or_default(), profile))
                    })
                    .collect();
                self.adopted = self.bindings.clone();
                if !self.adopted.is_empty() {
                    tracing::warn!(
                        bindings = self.adopted.len(),
                        found = paths.len(),
                        "adopted pins without a usable state file: keeping every cgroup binding \
                         in the kernel until its cgroup is removed or rebound"
                    );
                }
            }
        }
        if let Some(text) = self.text.clone() {
            let mut ids = self.ids.clone();
            if let Ok(policy) = net::parse(&text, &mut ids) {
                self.ids = ids;
                self.policy = Some(policy);
            }
        }
        self.persist();
        Ok(used)
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Records whether BPF LSM is active (see [`bpf_lsm_active`]).
    pub fn set_lsm_active(&mut self, active: bool) {
        self.lsm_active = active;
    }

    /// Without BPF LSM, exec and file programs load and attach but are never
    /// called. Refuse such rules instead of reporting protection that does not
    /// exist. The built-in quarantine profile is exempt; it is network-only
    /// on such kernels.
    fn check_capabilities(&self, policy: &Policy) -> Result<()> {
        if self.lsm_active {
            return Ok(());
        }
        for p in policy.profiles.iter().filter(|p| p.name != net::QUARANTINE) {
            if p.exec.is_some() || !p.files.rules.is_empty() || p.deny_raw_sockets {
                anyhow::bail!(
                    "profile `{}` has exec, file or raw-socket rules, but BPF LSM is not active \
                     on this kernel (`bpf` is missing from /sys/kernel/security/lsm), so they \
                     would not be enforced. Boot with `lsm=...,bpf`, or make the profile \
                     network-only: remove `[exec]`, set `files.include = []` with no \
                     `files.deny` rules, and set `network.deny_raw_sockets = false` (then drop \
                     CAP_NET_RAW from the workloads and give them no TUN/TAP device, since raw \
                     sockets and TUN/TAP bypass connect rules)",
                    p.name
                );
            }
        }
        Ok(())
    }

    pub fn policy(&self) -> Option<&Policy> {
        self.policy.as_ref()
    }

    /// What the audit log needs to name a decision's rule and profile
    /// (docs/design/phase-9.md §3.2): rule origins and cgroup bindings.
    pub fn audit_context(&self) -> AuditContext {
        let mut ctx = AuditContext {
            generation: self.generation,
            ..AuditContext::default()
        };
        let Some(policy) = &self.policy else {
            return ctx;
        };
        for o in &policy.origins {
            ctx.rules
                .insert(o.id, (o.profile.clone(), o.origin.clone()));
        }
        // First, so a current binding of the same id wins.
        for (cgroup, profile) in &self.retired {
            ctx.cgroups.insert(*cgroup, profile.clone());
        }
        for (&cgroup, (_, profile)) in &self.bindings {
            if let Some(p) = policy.profile(*profile) {
                ctx.cgroups.insert(cgroup, p.name.clone());
            }
        }
        for (&cgroup, (_, profile)) in &self.dynamic {
            ctx.cgroups.insert(cgroup, profile.clone());
        }
        ctx
    }

    /// cgroup id of a bound cgroup path, if bound.
    pub fn cgroup_id(&self, path: &str) -> Option<u64> {
        self.bindings
            .iter()
            .find(|(_, (p, _))| p == path)
            .map(|(id, _)| *id)
    }

    /// Parses, compiles and atomically applies a policy file. On error nothing
    /// visible to the kernel changes.
    pub fn apply_text(&mut self, ebpf: &mut Ebpf, text: &str) -> Result<ApplyReport> {
        let mut ids = self.ids.clone();
        let policy = net::parse(text, &mut ids)?;
        self.check_capabilities(&policy)?;
        let generation = self.generation + 1;
        let compiled = net::compile(&policy, generation)?;
        let mut bindings = self.resolve_bindings(&policy, true)?;
        let (stale, kept_adopted) = self.add_runtime_bindings(&policy, &mut bindings)?;
        let exec = resolve_exec(&compiled.exec)?;
        let (files, skipped_files) = resolve_files(&compiled.files)?;
        check_capacity(
            &self.written[self.active_slot as usize],
            compiled.deny.len(),
            compiled.allow.len(),
            exec.len(),
            files.len(),
            bindings.len(),
        )?;

        if let Some(flip) = self.last_flip {
            let elapsed = flip.elapsed();
            if elapsed < SLOT_GRACE {
                std::thread::sleep(SLOT_GRACE - elapsed);
            }
        }

        let slot = self.active_slot ^ 1;
        self.clear_slot(ebpf, slot)?;
        self.write_slot(ebpf, slot, &compiled, &exec, &files)?;

        // Commit point.
        let map = ebpf.map_mut(MAP_ACTIVE).context("rk_active_slot missing")?;
        let mut active = Array::<_, u32>::try_from(map)?;
        active.set(0, slot, 0).context("flip rk_active_slot")?;
        self.active_slot = slot;
        self.last_flip = Some(Instant::now());
        self.generation = generation;
        self.ids = ids;

        // The new policy is live: record it before anything else can fail,
        // so what the engine reports and persists never lags the kernel.
        let mut report = ApplyReport {
            generation,
            slot,
            profiles: compiled.profiles.len(),
            deny_entries: compiled.deny.len(),
            allow_entries: compiled.allow.len(),
            exec_entries: exec.len(),
            file_entries: files.len(),
            skipped_files,
            bindings: 0,
        };
        self.policy = Some(policy);
        self.previous_text = self.text.replace(text.to_string());
        for id in stale {
            if let Some((_, profile)) = self.dynamic.remove(&id) {
                self.retire(id, profile);
            }
        }
        self.adopted.retain(|id, _| kept_adopted.contains(id));

        // Profile ids are stable, so (re)binding after the flip is safe.
        let synced = self.sync_bindings(ebpf, bindings);
        self.persist();
        synced.with_context(|| {
            format!(
                "generation {generation} is live, but not every cgroup binding could be written"
            )
        })?;
        report.bindings = self.bindings.len();
        Ok(report)
    }

    /// Re-applies the previous policy with the same atomic flip. Rolling back
    /// twice returns to the newer policy.
    pub fn rollback(&mut self, ebpf: &mut Ebpf) -> Result<ApplyReport> {
        let previous = self
            .previous_text
            .clone()
            .context("no previous policy to roll back to")?;
        self.apply_text(ebpf, &previous)
    }

    /// Everything an apply would do, without changing the kernel or the
    /// filesystem. Fails exactly where `apply_text` would fail.
    pub fn dry_run(&self, text: &str) -> Result<DryRun> {
        let mut ids = self.ids.clone();
        let policy = net::parse(text, &mut ids)?;
        self.check_capabilities(&policy)?;
        let generation = self.generation + 1;
        let compiled = net::compile(&policy, generation)?;
        let mut bindings = self.resolve_bindings(&policy, false)?;
        self.add_runtime_bindings(&policy, &mut bindings)?;
        let exec = resolve_exec(&compiled.exec)?;
        let (files, skipped_files) = resolve_files(&compiled.files)?;
        let cgroups_to_create: Vec<String> = policy
            .bindings
            .iter()
            .filter(|b| !self.cgroup_fs.join(&b.cgroup).is_dir())
            .map(|b| b.cgroup.clone())
            .collect();
        // An apply creates those cgroups, each a new binding.
        check_capacity(
            &self.written[self.active_slot as usize],
            compiled.deny.len(),
            compiled.allow.len(),
            exec.len(),
            files.len(),
            bindings.len() + cgroups_to_create.len(),
        )?;
        Ok(DryRun {
            generation,
            profiles: compiled.profiles.len(),
            deny_entries: compiled.deny.len(),
            allow_entries: compiled.allow.len(),
            exec_entries: exec.len(),
            file_entries: files.len(),
            skipped_files,
            cgroups_to_create,
            changes: net::diff(self.policy.as_ref(), &policy),
        })
    }

    /// `rk_policy::net::diff` between the active policy and `text`.
    pub fn diff_text(&self, text: &str) -> Result<Vec<String>> {
        let mut ids = self.ids.clone();
        let policy = net::parse(text, &mut ids)?;
        Ok(net::diff(self.policy.as_ref(), &policy))
    }

    /// Static bindings of `policy`, keyed by cgroup id. With `create`, missing
    /// cgroup directories are created; without it they are skipped (dry run).
    fn resolve_bindings(
        &self,
        policy: &Policy,
        create: bool,
    ) -> Result<BTreeMap<u64, (String, u32)>> {
        let mut out = BTreeMap::new();
        for b in &policy.bindings {
            let path = self.cgroup_fs.join(&b.cgroup);
            if create {
                fs::create_dir_all(&path)
                    .with_context(|| format!("create cgroup {}", path.display()))?;
            } else if !path.is_dir() {
                continue;
            }
            let id = fs::metadata(&path)
                .with_context(|| format!("stat cgroup {}", path.display()))?
                .ino();
            out.insert(id, (b.cgroup.clone(), b.profile));
        }
        Ok(out)
    }

    /// Adds the runtime bindings to `wanted`: agents' and containers'
    /// (`dynamic`), and those adopted without a state file (`adopted`). Fails,
    /// before anything in the kernel changes, if `policy` drops a profile a
    /// running agent uses, or statically binds an agent's cgroup.
    ///
    /// A runtime binding whose cgroup is gone (see `cgroup_alive`) is stale:
    /// it is left out and does not block the apply, so an agent or container
    /// whose unbind never arrived cannot pin its profile forever. An adopted
    /// binding the policy now binds statically is left to the policy. Returns
    /// the stale `dynamic` ids, for the apply to drop, and the adopted ids
    /// still kept.
    fn add_runtime_bindings(
        &self,
        policy: &Policy,
        wanted: &mut BTreeMap<u64, (String, u32)>,
    ) -> Result<(Vec<u64>, BTreeSet<u64>)> {
        let mut stale = Vec::new();
        for (id, (path, profile)) in &self.dynamic {
            if !cgroup_alive(&self.cgroup_fs, path, *id) {
                stale.push(*id);
                continue;
            }
            let pid = policy
                .profiles
                .iter()
                .find(|p| &p.name == profile)
                .map(|p| p.id)
                .with_context(|| {
                    format!("profile `{profile}` is used by running agent `{path}` and cannot be removed")
                })?;
            if wanted.contains_key(id) {
                anyhow::bail!(
                    "`{path}` is a running agent's cgroup and cannot also be bound statically"
                );
            }
            wanted.insert(*id, (path.clone(), pid));
        }
        let mut kept = BTreeSet::new();
        for (id, (path, profile)) in &self.adopted {
            if wanted.contains_key(id) || !cgroup_alive(&self.cgroup_fs, path, *id) {
                continue;
            }
            wanted.insert(*id, (path.clone(), *profile));
            kept.insert(*id);
        }
        Ok((stale, kept))
    }

    /// Binds an agent cgroup (created by the caller under `rk.slice/`) to a
    /// profile, with one map update, and keeps the binding across reloads.
    /// Returns the cgroup id.
    pub fn bind_dynamic(&mut self, ebpf: &mut Ebpf, cgroup: &str, profile: &str) -> Result<u64> {
        let cgroup = net::validate_cgroup(cgroup).map_err(|m| anyhow::anyhow!(m))?;
        let pid = self
            .policy
            .as_ref()
            .context("no policy applied yet")?
            .profiles
            .iter()
            .find(|p| p.name == profile && p.name != QUARANTINE)
            .map(|p| p.id)
            .with_context(|| format!("unknown profile `{profile}`"))?;
        let path = self.cgroup_fs.join(&cgroup);
        let id = fs::metadata(&path)
            .with_context(|| format!("stat cgroup {}", path.display()))?
            .ino();
        if self.bindings.contains_key(&id) {
            anyhow::bail!("`{cgroup}` is already bound");
        }
        self.set_binding(ebpf, id, pid)?;
        self.bindings.insert(id, (cgroup.clone(), pid));
        self.dynamic.insert(id, (cgroup, profile.to_string()));
        self.persist();
        Ok(id)
    }

    /// Binds a Kubernetes container's cgroup (Phase 5b). `cgroup` is relative
    /// to the cgroupfs root; the caller has checked it lies under the
    /// Kubernetes cgroup root. Binding an already bound container again (NRI
    /// resync) updates its profile, except while it is quarantined.
    /// Returns the cgroup id.
    pub fn bind_container(&mut self, ebpf: &mut Ebpf, cgroup: &str, profile: &str) -> Result<u64> {
        let cgroup = cgroup.trim_matches('/');
        if cgroup.is_empty()
            || cgroup
                .split('/')
                .any(|s| s.is_empty() || s == "." || s == "..")
        {
            anyhow::bail!("invalid container cgroup `{cgroup}`");
        }
        let pid = self
            .policy
            .as_ref()
            .context("no policy applied yet")?
            .profiles
            .iter()
            .find(|p| p.name == profile && p.name != QUARANTINE)
            .map(|p| p.id)
            .with_context(|| format!("unknown profile `{profile}`"))?;
        let path = self.cgroup_fs.join(cgroup);
        let id = fs::metadata(&path)
            .with_context(|| format!("stat cgroup {}", path.display()))?
            .ino();
        // A binding adopted without a state file may be this very container
        // (NRI resyncs after a restart): rebinding it attributes it.
        if self.bindings.contains_key(&id)
            && !self.dynamic.contains_key(&id)
            && !self.adopted.contains_key(&id)
        {
            anyhow::bail!("`{cgroup}` is bound statically by the policy");
        }
        if self.quarantined.contains(&id) {
            return Ok(id);
        }
        self.set_binding(ebpf, id, pid)?;
        self.bindings.insert(id, (cgroup.to_string(), pid));
        self.adopted.remove(&id);
        self.dynamic
            .insert(id, (cgroup.to_string(), profile.to_string()));
        self.persist();
        Ok(id)
    }

    /// Removes an agent binding (after the agent exited).
    pub fn unbind_dynamic(&mut self, ebpf: &mut Ebpf, id: u64) -> Result<()> {
        let Some((_, profile)) = self.dynamic.remove(&id) else {
            anyhow::bail!("cgroup {id} is not a runtime agent binding");
        };
        self.retire(id, profile);
        self.bindings.remove(&id);
        self.quarantined.remove(&id);
        let map = ebpf
            .map_mut(MAP_BINDINGS)
            .context("rk_cgroup_profile missing")?;
        let mut bindings = BpfHashMap::<_, u64, Binding>::try_from(map)?;
        let _ = bindings.remove(&id);
        self.persist();
        Ok(())
    }

    fn retire(&mut self, id: u64, profile: String) {
        self.retired.push_back((id, profile));
        while self.retired.len() > RETIRED_MAX {
            self.retired.pop_front();
        }
    }

    /// Runtime agent bindings: cgroup id -> (path, profile name).
    pub fn dynamic_bindings(&self) -> &BTreeMap<u64, (String, String)> {
        &self.dynamic
    }

    fn clear_slot(&mut self, ebpf: &mut Ebpf, slot: u32) -> Result<()> {
        let contents = std::mem::take(&mut self.written[slot as usize]);
        for (map_name, keys) in [(MAP_DENY, &contents.deny), (MAP_ALLOW, &contents.allow)] {
            let map = ebpf
                .map_mut(map_name)
                .with_context(|| format!("{map_name} missing"))?;
            let mut trie = LpmTrie::<_, KeyData, NetRule>::try_from(map)?;
            for (prefix_len, data) in keys {
                // Already-absent keys are fine: the goal is an empty slot.
                let _ = trie.remove(&Key::new(*prefix_len, *data));
            }
        }
        let map = ebpf.map_mut(MAP_EXEC).context("rk_exec_allow missing")?;
        let mut exec = BpfHashMap::<_, ExecKey, ExecRule>::try_from(map)?;
        for key in &contents.exec {
            let _ = exec.remove(key);
        }
        let map = ebpf.map_mut(MAP_FILE).context("rk_file_protect missing")?;
        let mut file = BpfHashMap::<_, FileKey, FileRule>::try_from(map)?;
        for key in &contents.files {
            let _ = file.remove(key);
        }
        let map = ebpf.map_mut(MAP_PROFILES).context("rk_profiles missing")?;
        let mut profiles = Array::<_, Profile>::try_from(map)?;
        for id in &contents.profiles {
            profiles.set(profile_index(slot, *id), Profile(rk_profile::zeroed()), 0)?;
        }
        Ok(())
    }

    fn write_slot(
        &mut self,
        ebpf: &mut Ebpf,
        slot: u32,
        compiled: &Compiled,
        exec: &[ResolvedExec],
        files: &[ResolvedFile],
    ) -> Result<()> {
        {
            let map = ebpf.map_mut(MAP_FILE).context("rk_file_protect missing")?;
            let mut map = BpfHashMap::<_, FileKey, FileRule>::try_from(map)?;
            for r in files {
                let key = FileKey(rk_file_key {
                    scope: (slot << 31) | r.profile,
                    dev: r.dev,
                    ino: r.ino,
                    ..rk_file_key::zeroed()
                });
                self.written[slot as usize].files.push(key);
                let rule = FileRule(rk_file_rule {
                    rule_id: r.rule_id,
                    deny_mask: r.deny_mask,
                    flags: u32::from(r.subtree),
                    ..rk_file_rule::zeroed()
                });
                map.insert(key, rule, 0)
                    .with_context(|| format!("write file entry for profile {}", r.profile))?;
            }
        }
        {
            let map = ebpf.map_mut(MAP_EXEC).context("rk_exec_allow missing")?;
            let mut map = BpfHashMap::<_, ExecKey, ExecRule>::try_from(map)?;
            for r in exec {
                let key = ExecKey(rk_exec_key {
                    scope: (slot << 31) | r.profile,
                    dev: r.dev,
                    ino: r.ino,
                    ..rk_exec_key::zeroed()
                });
                self.written[slot as usize].exec.push(key);
                let rule = ExecRule(rk_exec_rule {
                    rule_id: r.rule_id,
                    ..rk_exec_rule::zeroed()
                });
                map.insert(key, rule, 0)
                    .with_context(|| format!("write exec entry for profile {}", r.profile))?;
            }
        }
        {
            let map = ebpf.map_mut(MAP_PROFILES).context("rk_profiles missing")?;
            let mut profiles = Array::<_, Profile>::try_from(map)?;
            for p in &compiled.profiles {
                let value = rk_profile {
                    mode: match p.mode {
                        Mode::Audit => 0,
                        Mode::Enforce => 1,
                    },
                    net_default: action_value(p.net_default),
                    flags: p.flags,
                    policy_gen: compiled.generation,
                    ..rk_profile::zeroed()
                };
                self.written[slot as usize].profiles.push(p.id);
                profiles
                    .set(profile_index(slot, p.id), Profile(value), 0)
                    .with_context(|| format!("write profile {}", p.id))?;
            }
        }
        for (map_name, entries, is_deny) in [
            (MAP_DENY, &compiled.deny, true),
            (MAP_ALLOW, &compiled.allow, false),
        ] {
            let map = ebpf
                .map_mut(map_name)
                .with_context(|| format!("{map_name} missing"))?;
            let mut trie = LpmTrie::<_, KeyData, NetRule>::try_from(map)?;
            for entry in entries {
                let (prefix_len, data) = trie_key(slot, entry);
                let written = &mut self.written[slot as usize];
                if is_deny {
                    written.deny.push((prefix_len, data));
                } else {
                    written.allow.push((prefix_len, data));
                }
                trie.insert(&Key::new(prefix_len, data), NetRule(trie_value(entry)), 0)
                    .with_context(|| {
                        format!("write {map_name} entry for profile {}", entry.profile)
                    })?;
            }
        }
        Ok(())
    }

    fn sync_bindings(
        &mut self,
        ebpf: &mut Ebpf,
        mut wanted: BTreeMap<u64, (String, u32)>,
    ) -> Result<()> {
        // Quarantine overrides the file's binding until released.
        if let Some(qid) = self.quarantine_id() {
            self.quarantined.retain(|id| wanted.contains_key(id));
            for id in &self.quarantined {
                if let Some(entry) = wanted.get_mut(id) {
                    entry.1 = qid;
                }
            }
        }
        let map = ebpf
            .map_mut(MAP_BINDINGS)
            .context("rk_cgroup_profile missing")?;
        let mut bindings = BpfHashMap::<_, u64, Binding>::try_from(map)?;
        // Removals first, so the map never holds more than the bindings
        // wanted (the capacity check counts exactly those).
        for id in self.bindings.keys() {
            if !wanted.contains_key(id) {
                let _ = bindings.remove(id);
            }
        }
        // Keep going past a failed write, and record what the kernel really
        // holds: a failed binding keeps its previous entry, if any.
        let mut first_err = None;
        let mut applied = BTreeMap::new();
        for (id, entry) in wanted {
            let current = self.bindings.get(&id);
            if current.map(|(_, p)| *p) == Some(entry.1) {
                applied.insert(id, entry);
                continue;
            }
            let value = rk_binding {
                profile: entry.1,
                ..rk_binding::zeroed()
            };
            match bindings.insert(id, Binding(value), 0) {
                Ok(()) => {
                    applied.insert(id, entry);
                }
                Err(e) => {
                    if let Some(old) = current {
                        applied.insert(id, old.clone());
                    }
                    if first_err.is_none() {
                        first_err =
                            Some(anyhow::Error::from(e).context(format!("bind cgroup {id}")));
                    }
                }
            }
        }
        self.bindings = applied;
        if let Some(e) = first_err {
            return Err(e);
        }
        Ok(())
    }
}

impl PolicyEngine {
    fn quarantine_id(&self) -> Option<u32> {
        self.policy
            .as_ref()
            .and_then(|p| p.profiles.iter().find(|p| p.name == QUARANTINE))
            .map(|p| p.id)
            .or_else(|| self.ids.clone().id(QUARANTINE).ok())
    }

    /// Moves a bound cgroup into the built-in quarantine profile with a single
    /// map update: no new exec and no new connections. Running processes keep
    /// running; use [`kill_process`] if one must stop.
    pub fn quarantine(&mut self, ebpf: &mut Ebpf, cgroup: &str) -> Result<()> {
        let id = self
            .cgroup_id(cgroup)
            .with_context(|| format!("`{cgroup}` is not bound to a profile"))?;
        let qid = self
            .quarantine_id()
            .context("no policy applied yet: quarantine profile unknown")?;
        self.set_binding(ebpf, id, qid)?;
        self.quarantined.insert(id);
        self.persist();
        Ok(())
    }

    /// Restores a quarantined cgroup to the profile its policy binds it to.
    pub fn release(&mut self, ebpf: &mut Ebpf, cgroup: &str) -> Result<()> {
        let id = self
            .cgroup_id(cgroup)
            .with_context(|| format!("`{cgroup}` is not bound to a profile"))?;
        let policy = self.policy.as_ref().context("no policy applied yet")?;
        let profile = policy
            .bindings
            .iter()
            .find(|b| b.cgroup == cgroup)
            .map(|b| b.profile)
            .or_else(|| {
                let name = &self.dynamic.get(&id)?.1;
                policy
                    .profiles
                    .iter()
                    .find(|p| &p.name == name)
                    .map(|p| p.id)
            })
            .with_context(|| format!("`{cgroup}` has no binding in the active policy"))?;
        self.quarantined.remove(&id);
        self.set_binding(ebpf, id, profile)?;
        self.persist();
        Ok(())
    }

    fn set_binding(&mut self, ebpf: &mut Ebpf, id: u64, profile: u32) -> Result<()> {
        let map = ebpf
            .map_mut(MAP_BINDINGS)
            .context("rk_cgroup_profile missing")?;
        let mut bindings = BpfHashMap::<_, u64, Binding>::try_from(map)?;
        let value = rk_binding {
            profile,
            ..rk_binding::zeroed()
        };
        bindings.insert(id, Binding(value), 0)?;
        if let Some(entry) = self.bindings.get_mut(&id) {
            entry.1 = profile;
        }
        Ok(())
    }
}

/// What one generation slot holds in the kernel maps, found by scanning them
/// (keys carry the slot in bit 31 of their scope). Used on adoption, when the
/// record of what an earlier sensor wrote is gone.
fn scan_slot(ebpf: &Ebpf, slot: u32) -> Result<SlotContents> {
    let in_slot = |scope: u32| scope >> 31 == slot;
    let mut contents = SlotContents::default();

    let profiles =
        Array::<_, Profile>::try_from(ebpf.map(MAP_PROFILES).context("rk_profiles missing")?)?;
    for id in 0..RK_MAX_PROFILES {
        if profiles.get(&profile_index(slot, id), 0)?.0.policy_gen != 0 {
            contents.profiles.push(id);
        }
    }
    for (name, out) in [
        (MAP_DENY, &mut contents.deny),
        (MAP_ALLOW, &mut contents.allow),
    ] {
        let trie = LpmTrie::<_, KeyData, NetRule>::try_from(
            ebpf.map(name).with_context(|| format!("{name} missing"))?,
        )?;
        for key in trie.keys() {
            let key = key?;
            if in_slot(key.data().scope) {
                out.push((key.prefix_len(), key.data()));
            }
        }
    }
    let exec = BpfHashMap::<_, ExecKey, ExecRule>::try_from(
        ebpf.map(MAP_EXEC).context("rk_exec_allow missing")?,
    )?;
    for key in exec.keys() {
        let key = key?;
        if in_slot(key.0.scope) {
            contents.exec.push(key);
        }
    }
    let files = BpfHashMap::<_, FileKey, FileRule>::try_from(
        ebpf.map(MAP_FILE).context("rk_file_protect missing")?,
    )?;
    for key in files.keys() {
        let key = key?;
        if in_slot(key.0.scope) {
            contents.files.push(key);
        }
    }
    Ok(contents)
}

fn profile_index(slot: u32, profile: u32) -> u32 {
    slot * RK_MAX_PROFILES + profile
}

fn action_value(action: Action) -> u8 {
    match action {
        Action::Allow => 0,
        Action::Deny => 1,
    }
}

fn trie_key(slot: u32, entry: &Entry) -> (u32, KeyData) {
    (
        32 + u32::from(entry.prefix_len),
        KeyData {
            scope: (slot << 31) | entry.profile,
            addr: entry.addr,
        },
    )
}

fn trie_value(entry: &Entry) -> rk_net_rule {
    let mut rule = rk_net_rule::zeroed();
    rule.nranges = entry.ranges.len() as u32;
    for (slot, r) in rule.ranges.iter_mut().zip(&entry.ranges) {
        *slot = rk_net_range {
            rule_id: r.rule_id,
            port_lo: r.lo,
            port_hi: r.hi,
            proto_mask: r.proto,
            ..rk_net_range::zeroed()
        };
    }
    rule
}

#[cfg(test)]
mod tests {
    use super::*;
    use rk_policy::net::CompiledRange;

    fn state_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rk-state-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir.join("engine.json")
    }

    /// An agent's last events can be logged after it exited and was
    /// unbound: they still name its profile (docs/design/adoption.md).
    #[test]
    fn audit_context_names_recently_unbound_agents() {
        let mut engine = PolicyEngine::new(PathBuf::from("/nonexistent"));
        engine.policy = Some(
            rk_policy::net::parse(
                "[profiles.agent]\nmode = \"audit\"\n",
                &mut ProfileIds::default(),
            )
            .unwrap(),
        );
        engine
            .dynamic
            .insert(5, ("rk.slice/agent-5".into(), "agent".into()));
        engine.retire(4, "agent".into());
        let ctx = engine.audit_context();
        assert_eq!(ctx.describe(0, 4).0, Some("agent"));
        assert_eq!(ctx.describe(0, 5).0, Some("agent"));
        for i in 0..(RETIRED_MAX as u64 + 10) {
            engine.retire(100 + i, "other".into());
        }
        assert_eq!(engine.retired.len(), RETIRED_MAX);
        assert_eq!(engine.audit_context().describe(0, 4).0, None);
    }

    /// Phase 8 §3.3: what `persist` writes, `load_state` reads back for the
    /// same pin epoch, and the file is private to root.
    #[test]
    fn engine_state_round_trips() {
        use std::os::unix::fs::PermissionsExt as _;
        let path = state_path("round-trip");
        let mut engine = PolicyEngine::new(PathBuf::from("/nonexistent"));
        engine.set_state_file(path.clone(), &[7; 16]);
        engine.generation = 42;
        engine.bindings.insert(1234, ("rk.slice/agent".into(), 3));
        engine.quarantined.insert(99);
        engine
            .dynamic
            .insert(1234, ("ns/pod".into(), "restricted".into()));
        engine.text = Some("[profiles.p]\nmode = \"audit\"\n".into());
        engine.persist();

        let s = load_state(&path, &hex::encode([7u8; 16])).expect("same epoch is accepted");
        assert_eq!(s.generation, 42);
        assert_eq!(s.bindings, engine.bindings);
        assert_eq!(s.quarantined, engine.quarantined);
        assert_eq!(s.dynamic, engine.dynamic);
        assert_eq!(s.text, engine.text);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    /// A state file from another pin set (or with no epoch, or corrupt) is
    /// never used: its profile ids would not match the maps.
    #[test]
    fn engine_state_rejects_foreign_epoch() {
        let path = state_path("epoch");
        let mut engine = PolicyEngine::new(PathBuf::from("/nonexistent"));
        engine.set_state_file(path.clone(), &[1; 16]);
        engine.persist();
        assert!(load_state(&path, &hex::encode([1u8; 16])).is_some());
        assert!(load_state(&path, &hex::encode([2u8; 16])).is_none());
        assert!(load_state(&path, "").is_none());
        fs::write(&path, b"{not json").unwrap();
        assert!(load_state(&path, &hex::encode([1u8; 16])).is_none());
        assert!(load_state(&path.with_extension("gone"), &hex::encode([1u8; 16])).is_none());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn key_layout_matches_abi() {
        // Key<KeyData> = u32 prefixlen + KeyData must equal struct rk_net_key.
        assert_eq!(
            4 + std::mem::size_of::<KeyData>(),
            std::mem::size_of::<rk_ebpf_common::rk_net_key>()
        );
        assert_eq!(
            std::mem::size_of::<NetRule>(),
            std::mem::size_of::<rk_net_rule>()
        );
    }

    #[test]
    fn trie_key_encodes_slot_profile_and_prefix() {
        let entry = Entry {
            profile: 5,
            prefix_len: 120,
            addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 1, 2, 0],
            ranges: vec![],
        };
        let (len, data) = trie_key(1, &entry);
        assert_eq!(len, 152);
        assert_eq!(data.scope, (1 << 31) | 5);
        assert_eq!(data.addr, entry.addr);
    }

    #[test]
    fn trie_value_copies_ranges_in_order() {
        let entry = Entry {
            profile: 0,
            prefix_len: 128,
            addr: [0; 16],
            ranges: vec![
                CompiledRange {
                    rule_id: 7,
                    lo: 443,
                    hi: 443,
                    proto: 1,
                },
                CompiledRange {
                    rule_id: 3,
                    lo: 0,
                    hi: 65535,
                    proto: 7,
                },
            ],
        };
        let v = trie_value(&entry);
        assert_eq!(v.nranges, 2);
        assert_eq!(
            (
                v.ranges[0].rule_id,
                v.ranges[0].port_lo,
                v.ranges[0].proto_mask
            ),
            (7, 443, 1)
        );
        assert_eq!((v.ranges[1].rule_id, v.ranges[1].port_hi), (3, 65535));
        assert_eq!(v.ranges[2].rule_id, 0);
    }

    fn file_rule(path: &str, mask: u32, rule_id: u32, optional: bool) -> CompiledFile {
        CompiledFile {
            profile: 0,
            rule_id,
            path: path.to_string(),
            target: FileTarget::Path {
                subtree: true,
                optional,
            },
            deny_mask: mask,
        }
    }

    #[test]
    fn resolve_files_merges_skips_and_fails_correctly() {
        let dir = std::env::temp_dir().join(format!("rk_resolve_files_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("secret");
        fs::write(&file, b"x").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let file_s = file.to_str().unwrap();
        let link_s = link.to_str().unwrap();
        let dir_s = dir.to_str().unwrap();

        // The file and a symlink to it are one object: masks merge, first rule wins,
        // and the subtree flag only sticks to directories.
        let (out, skipped) = resolve_files(&[
            file_rule(file_s, 1, 10, false),
            file_rule(link_s, 2, 11, false),
            file_rule(dir_s, 4, 12, false),
            file_rule("/nonexistent/rk/optional", 8, 13, true),
        ])
        .unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].starts_with("/nonexistent/rk/optional"));
        let f = out.iter().find(|r| r.rule_id == 10).unwrap();
        assert_eq!(f.deny_mask, 1 | 2);
        assert!(!f.subtree);
        let d = out.iter().find(|r| r.rule_id == 12).unwrap();
        assert!(d.subtree);

        // A missing path that is not from a built-in list fails the apply.
        assert!(resolve_files(&[file_rule("/nonexistent/rk/required", 1, 14, false)]).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    fn scratch_cgroupfs(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("rk-cgfs-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn ino(path: &Path) -> u64 {
        fs::metadata(path).unwrap().ino()
    }

    /// Bindings found in the kernel are matched to their cgroup by walking
    /// the cgroup filesystem; only a definitely removed cgroup counts as gone.
    #[test]
    fn cgroup_paths_and_liveness_come_from_the_cgroup_filesystem() {
        let root = scratch_cgroupfs("walk");
        let agent = root.join("rk.slice/agent-1");
        let pod = root.join("kubepods.slice/pod-a/cri-containerd-x.scope");
        fs::create_dir_all(&agent).unwrap();
        fs::create_dir_all(&pod).unwrap();
        let ids: BTreeSet<u64> = [ino(&agent), ino(&pod), u64::MAX].into();
        let found = cgroup_paths(&root, &ids);
        assert_eq!(found.len(), 2);
        assert_eq!(found[&ino(&agent)], "rk.slice/agent-1");
        assert_eq!(
            found[&ino(&pod)],
            "kubepods.slice/pod-a/cri-containerd-x.scope"
        );

        assert!(cgroup_alive(&root, "rk.slice/agent-1", ino(&agent)));
        // Same path, different cgroup: the bound one is gone.
        assert!(!cgroup_alive(&root, "rk.slice/agent-1", ino(&agent) + 1));
        assert!(!cgroup_alive(&root, "rk.slice/agent-gone", 7));
        // Unknown path: kept.
        assert!(cgroup_alive(&root, "", 7));
        fs::remove_dir_all(&root).unwrap();
    }

    /// A restart without a usable state file must not unbind running
    /// workloads: adopted bindings stay in what an apply writes until their
    /// cgroup is gone or the policy binds the cgroup itself. A dynamic
    /// binding whose cgroup is gone no longer blocks removing its profile.
    #[test]
    fn runtime_bindings_survive_unless_their_cgroup_is_gone() {
        let root = scratch_cgroupfs("runtime");
        let live_agent = root.join("rk.slice/agent-live");
        let adopted_pod = root.join("kubepods.slice/cri-containerd-y.scope");
        let static_cg = root.join("rk.slice/static");
        for d in [&live_agent, &adopted_pod, &static_cg] {
            fs::create_dir_all(d).unwrap();
        }
        let mut engine = PolicyEngine::new(root.clone());
        engine.dynamic.insert(
            ino(&live_agent),
            ("rk.slice/agent-live".into(), "agent".into()),
        );
        // The agent exited while its unbind was lost: its cgroup is gone.
        engine
            .dynamic
            .insert(u64::MAX - 1, ("rk.slice/agent-gone".into(), "old".into()));
        engine.adopted.insert(
            ino(&adopted_pod),
            ("kubepods.slice/cri-containerd-y.scope".into(), 5),
        );
        engine.adopted.insert(u64::MAX - 2, (String::new(), 6)); // path unknown
        engine
            .adopted
            .insert(u64::MAX - 3, ("rk.slice/agent-removed".into(), 6));
        engine
            .adopted
            .insert(ino(&static_cg), ("rk.slice/static".into(), 6));

        // The policy drops `old` and binds `rk.slice/static` itself.
        let text = "[profiles.agent]\nmode = \"audit\"\n[profiles.agent.files]\ninclude = []\n\
                    [[bindings]]\ncgroup = \"rk.slice/static\"\nprofile = \"agent\"\n";
        let policy = rk_policy::net::parse(text, &mut ProfileIds::default()).unwrap();
        let mut wanted = engine.resolve_bindings(&policy, false).unwrap();
        let (stale, kept) = engine.add_runtime_bindings(&policy, &mut wanted).unwrap();
        assert_eq!(stale, vec![u64::MAX - 1]);
        assert_eq!(kept, BTreeSet::from([ino(&adopted_pod), u64::MAX - 2]));
        assert!(wanted.contains_key(&ino(&live_agent)));
        assert_eq!(wanted[&ino(&adopted_pod)].1, 5, "adopted binding unchanged");
        assert_ne!(wanted[&ino(&static_cg)].1, 6, "the static binding wins");
        assert!(!wanted.contains_key(&(u64::MAX - 3)));
        assert!(
            engine.dry_run(text).is_ok(),
            "a stale binding blocked the apply"
        );

        // A live agent still protects its profile.
        let without_agent =
            "[profiles.other]\nmode = \"audit\"\n[profiles.other.files]\ninclude = []\n";
        let e = engine.dry_run(without_agent).unwrap_err().to_string();
        assert!(e.contains("used by running agent"), "{e}");
        fs::remove_dir_all(&root).unwrap();
    }

    /// An apply that does not fit the maps is refused before the flip, and
    /// the dry run refuses it the same way.
    #[test]
    fn capacity_is_checked_before_anything_is_written() {
        let mut live = SlotContents::default();
        assert!(check_capacity(&live, CAP_NET, 0, 0, 0, CAP_BINDINGS).is_ok());
        live.deny.push((
            0,
            KeyData {
                scope: 0,
                addr: [0; 16],
            },
        ));
        let e = check_capacity(&live, CAP_NET, 0, 0, 0, 0)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("network deny") && e.contains("Nothing was changed"),
            "{e}"
        );
        assert!(check_capacity(&live, 0, 0, CAP_EXEC + 1, 0, 0).is_err());
        assert!(check_capacity(&live, 0, 0, 0, CAP_FILE + 1, 0).is_err());
        assert!(check_capacity(&live, 0, 0, 0, 0, CAP_BINDINGS + 1).is_err());
    }

    /// The capacities above must match the maps' `max_entries` in rk-bpf.
    #[test]
    fn map_capacities_match_the_bpf_sources() {
        fn max_entries(src: &str, map: &str) -> usize {
            let end = src.find(&format!("}} {map} SEC(")).expect(map);
            let decl = &src[src[..end].rfind("struct {").expect(map)..end];
            let n = decl.split("max_entries, ").nth(1).expect(map);
            n[..n.find(')').expect(map)].trim().parse().expect(map)
        }
        let common = include_str!("../../rk-bpf/src/common.bpf.h");
        let net = include_str!("../../rk-bpf/src/net.bpf.c");
        let exec = include_str!("../../rk-bpf/src/exec.bpf.c");
        let file = include_str!("../../rk-bpf/src/file.bpf.c");
        assert_eq!(max_entries(common, MAP_BINDINGS), CAP_BINDINGS);
        assert_eq!(max_entries(net, MAP_DENY), CAP_NET);
        assert_eq!(max_entries(net, MAP_ALLOW), CAP_NET);
        assert_eq!(max_entries(exec, MAP_EXEC), CAP_EXEC);
        assert_eq!(max_entries(file, MAP_FILE), CAP_FILE);
    }

    #[test]
    fn dry_run_touches_nothing_and_reports_changes() {
        let root = std::env::temp_dir().join(format!("rk_dry_run_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let engine = PolicyEngine::new(root.clone());
        let text = "[profiles.a]\nmode = \"audit\"\n[profiles.a.files]\ninclude = []\n\
                    [[bindings]]\ncgroup = \"rk.slice/agent-x\"\nprofile = \"a\"\n";

        let d = engine.dry_run(text).unwrap();
        assert_eq!(d.generation, 1);
        assert_eq!(d.cgroups_to_create, vec!["rk.slice/agent-x".to_string()]);
        assert!(
            !root.join("rk.slice").exists(),
            "a dry run must not create cgroups"
        );
        assert!(
            d.changes.contains(&"+ profile a".to_string()),
            "{:#?}",
            d.changes
        );
        assert!(engine
            .diff_text(text)
            .unwrap()
            .contains(&"+ binding rk.slice/agent-x -> a".to_string()));

        // A dry run fails exactly where an apply would.
        assert!(engine.dry_run("[profiles.a]\nmode = \"block\"\n").is_err());
        assert!(engine
            .dry_run("[profiles.a]\nmode = \"audit\"\n[[profiles.a.files.deny]]\npath = \"/nonexistent/rk\"\naccess = [\"read\"]\n")
            .is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    /// Phase 5b §6: without BPF LSM, exec and file rules are refused, and
    /// network-only profiles still apply.
    #[test]
    fn lsm_rules_refused_without_bpf_lsm() {
        let mut engine = PolicyEngine::new(std::env::temp_dir());
        engine.set_lsm_active(false);
        let network_only = "[profiles.a]\nmode = \"enforce\"\nnetwork.deny_raw_sockets = false\n\
                            [profiles.a.files]\ninclude = []\n";
        assert!(engine.dry_run(network_only).is_ok());
        for text in [
            // The built-in credentials list and raw-socket denial are on by default.
            "[profiles.a]\nmode = \"enforce\"\n",
            "[profiles.a]\nmode = \"enforce\"\n[profiles.a.files]\ninclude = []\n",
            "[profiles.a]\nmode = \"enforce\"\nnetwork.deny_raw_sockets = false\n\
             [profiles.a.exec]\ndefault = \"deny\"\n[profiles.a.files]\ninclude = []\n",
        ] {
            let e = engine.dry_run(text).unwrap_err().to_string();
            assert!(e.contains("BPF LSM is not active"), "{e}");
        }
        engine.set_lsm_active(true);
        assert!(engine.dry_run("[profiles.a]\nmode = \"enforce\"\n").is_ok());
    }

    #[test]
    fn profile_index_separates_slots() {
        assert_eq!(profile_index(0, 3), 3);
        assert_eq!(profile_index(1, 3), RK_MAX_PROFILES + 3);
    }

    #[test]
    fn link_pin_replaces_dots_and_slashes_for_bpffs() {
        let dir = Path::new("/sys/fs/bpf/rk/links");
        let pin = link_pin(
            Some(dir),
            "rk_net_connect4",
            Some(Path::new("/sys/fs/cgroup/rk.slice")),
        )
        .unwrap();
        let fname = pin.file_name().unwrap().to_string_lossy();
        assert!(!fname.contains('.'));
        assert_eq!(fname, "rk_net_connect4@rk_slice");
    }
}
