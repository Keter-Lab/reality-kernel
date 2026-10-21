//! Network hook attachment and atomic policy apply (docs/design/phase-2.md §4).
//!
//! An apply writes the *inactive* generation slot (profiles plus deny and allow
//! trie entries), then flips `rk_active_slot` with one 4-byte array update: that
//! update is the commit point. A slot is cleared only at the start of the next
//! apply, and never within [`SLOT_GRACE`] of the flip that retired it, so no
//! running decision (which reads the slot once and lasts microseconds) can
//! observe a slot being rewritten. A failed apply never touches the active slot.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, HashMap as BpfHashMap};
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

/// Host-wide LSM programs.
pub const LSM_PROGRAMS: [&str; 1] = ["rk_net_socket_create"];

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
/// the first rule id is kept. A missing path from a built-in list is skipped;
/// any other resolution failure fails the apply before the kernel changes.
fn resolve_files(entries: &[CompiledFile]) -> Result<Vec<ResolvedFile>> {
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
                Err(err) if optional && err.kind() == std::io::ErrorKind::NotFound => {}
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
    Ok(merged.into_values().collect())
}

/// Attaches the exec programs (already loaded): the host-wide LSM exec check
/// and the `sched_process_exec` record. Links detach when `ebpf` drops.
pub fn attach_exec(ebpf: &mut Ebpf) -> Result<Vec<String>> {
    let program = ebpf
        .program_mut(EXEC_LSM_PROGRAM)
        .with_context(|| format!("program `{EXEC_LSM_PROGRAM}` missing from rk.bpf.o"))?;
    let program: &mut Lsm = program.try_into()?;
    program
        .attach()
        .with_context(|| format!("attach LSM program `{EXEC_LSM_PROGRAM}`"))?;

    let program = ebpf
        .program_mut(EXEC_RECORD_PROGRAM)
        .with_context(|| format!("program `{EXEC_RECORD_PROGRAM}` missing from rk.bpf.o"))?;
    let program: &mut BtfTracePoint = program.try_into()?;
    program
        .attach()
        .with_context(|| format!("attach `{EXEC_RECORD_PROGRAM}`"))?;

    Ok(vec![
        format!("{EXEC_LSM_PROGRAM} (lsm)"),
        format!("{EXEC_RECORD_PROGRAM} (tp_btf/sched_process_exec)"),
    ])
}

/// Attaches every enforcement program: network hooks on `cgroup_root` plus the
/// exec programs.
pub fn attach_all(ebpf: &mut Ebpf, cgroup_root: &Path) -> Result<Vec<String>> {
    let mut attached = attach_network(ebpf, cgroup_root)?;
    attached.extend(attach_exec(ebpf)?);
    Ok(attached)
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
/// it if needed, and the LSM programs host-wide. Links detach when `ebpf` drops.
pub fn attach_network(ebpf: &mut Ebpf, cgroup_root: &Path) -> Result<Vec<String>> {
    fs::create_dir_all(cgroup_root).with_context(|| format!("create {}", cgroup_root.display()))?;
    let cgroup =
        fs::File::open(cgroup_root).with_context(|| format!("open {}", cgroup_root.display()))?;

    let mut attached = Vec::new();
    for name in SOCK_ADDR_PROGRAMS {
        let program = ebpf
            .program_mut(name)
            .with_context(|| format!("program `{name}` missing from rk.bpf.o"))?;
        let program: &mut CgroupSockAddr = program.try_into()?;
        // bpf_link based cgroup attachments take no flags and are always multi-attach.
        program
            .attach(&cgroup, CgroupAttachMode::Single)
            .with_context(|| format!("attach `{name}` to {}", cgroup_root.display()))?;
        attached.push(format!("{name} -> {}", cgroup_root.display()));
    }
    for name in LSM_PROGRAMS {
        let program = ebpf
            .program_mut(name)
            .with_context(|| format!("program `{name}` missing from rk.bpf.o"))?;
        let program: &mut Lsm = program.try_into()?;
        program
            .attach()
            .with_context(|| format!("attach LSM program `{name}`"))?;
        attached.push(format!("{name} (lsm)"));
    }
    Ok(attached)
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
    pub bindings: usize,
}

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
    policy: Option<Policy>,
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
            policy: None,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn policy(&self) -> Option<&Policy> {
        self.policy.as_ref()
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
        let generation = self.generation + 1;
        let compiled = net::compile(&policy, generation)?;
        let bindings = self.resolve_bindings(&policy)?;
        let exec = resolve_exec(&compiled.exec)?;
        let files = resolve_files(&compiled.files)?;

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

        // Profile ids are stable, so (re)binding after the flip is safe.
        self.sync_bindings(ebpf, bindings)?;

        let report = ApplyReport {
            generation,
            slot,
            profiles: compiled.profiles.len(),
            deny_entries: compiled.deny.len(),
            allow_entries: compiled.allow.len(),
            exec_entries: exec.len(),
            file_entries: files.len(),
            bindings: self.bindings.len(),
        };
        self.policy = Some(policy);
        Ok(report)
    }

    fn resolve_bindings(&self, policy: &Policy) -> Result<BTreeMap<u64, (String, u32)>> {
        let mut out = BTreeMap::new();
        for b in &policy.bindings {
            let path = self.cgroup_fs.join(&b.cgroup);
            fs::create_dir_all(&path)
                .with_context(|| format!("create cgroup {}", path.display()))?;
            let id = fs::metadata(&path)
                .with_context(|| format!("stat cgroup {}", path.display()))?
                .ino();
            out.insert(id, (b.cgroup.clone(), b.profile));
        }
        Ok(out)
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
        for (id, (_, profile)) in &wanted {
            if self.bindings.get(id).map(|(_, p)| p) != Some(profile) {
                let value = rk_binding {
                    profile: *profile,
                    ..rk_binding::zeroed()
                };
                bindings.insert(id, Binding(value), 0)?;
            }
        }
        for id in self.bindings.keys() {
            if !wanted.contains_key(id) {
                let _ = bindings.remove(id);
            }
        }
        self.bindings = wanted;
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
        Ok(())
    }

    /// Restores a quarantined cgroup to the profile its policy binds it to.
    pub fn release(&mut self, ebpf: &mut Ebpf, cgroup: &str) -> Result<()> {
        let id = self
            .cgroup_id(cgroup)
            .with_context(|| format!("`{cgroup}` is not bound to a profile"))?;
        let profile = self
            .policy
            .as_ref()
            .and_then(|p| p.bindings.iter().find(|b| b.cgroup == cgroup))
            .map(|b| b.profile)
            .with_context(|| format!("`{cgroup}` has no binding in the active policy"))?;
        self.quarantined.remove(&id);
        self.set_binding(ebpf, id, profile)
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
        let out = resolve_files(&[
            file_rule(file_s, 1, 10, false),
            file_rule(link_s, 2, 11, false),
            file_rule(dir_s, 4, 12, false),
            file_rule("/nonexistent/rk/optional", 8, 13, true),
        ])
        .unwrap();
        assert_eq!(out.len(), 2);
        let f = out.iter().find(|r| r.rule_id == 10).unwrap();
        assert_eq!(f.deny_mask, 1 | 2);
        assert!(!f.subtree);
        let d = out.iter().find(|r| r.rule_id == 12).unwrap();
        assert!(d.subtree);

        // A missing path that is not from a built-in list fails the apply.
        assert!(resolve_files(&[file_rule("/nonexistent/rk/required", 1, 14, false)]).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn profile_index_separates_slots() {
        assert_eq!(profile_index(0, 3), 3);
        assert_eq!(profile_index(1, 3), RK_MAX_PROFILES + 3);
    }
}
