//! Network hook attachment and atomic policy apply (docs/design/phase-2.md §4).
//!
//! An apply writes the *inactive* generation slot (profiles plus deny and allow
//! trie entries), then flips `rk_active_slot` with one 4-byte array update: that
//! update is the commit point. A slot is cleared only at the start of the next
//! apply, and never within [`SLOT_GRACE`] of the flip that retired it, so no
//! running decision (which reads the slot once and lasts microseconds) can
//! observe a slot being rewritten. A failed apply never touches the active slot.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, HashMap as BpfHashMap};
use aya::programs::{CgroupAttachMode, CgroupSockAddr, Lsm};
use aya::Ebpf;
use bytemuck::Zeroable;
use rk_ebpf_common::{rk_binding, rk_net_range, rk_net_rule, rk_profile, RK_MAX_PROFILES};
use rk_policy::net::{self, Action, Compiled, Entry, Mode, Policy, ProfileIds};

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

/// Attaches the network programs (already loaded) to `cgroup_root`, creating
/// it if needed, and the LSM programs host-wide. Links detach when `ebpf` drops.
pub fn attach_network(ebpf: &mut Ebpf, cgroup_root: &Path) -> Result<Vec<String>> {
    fs::create_dir_all(cgroup_root)
        .with_context(|| format!("create {}", cgroup_root.display()))?;
    let cgroup = fs::File::open(cgroup_root)
        .with_context(|| format!("open {}", cgroup_root.display()))?;

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReport {
    pub generation: u64,
    pub slot: u32,
    pub profiles: usize,
    pub deny_entries: usize,
    pub allow_entries: usize,
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

        if let Some(flip) = self.last_flip {
            let elapsed = flip.elapsed();
            if elapsed < SLOT_GRACE {
                std::thread::sleep(SLOT_GRACE - elapsed);
            }
        }

        let slot = self.active_slot ^ 1;
        self.clear_slot(ebpf, slot)?;
        self.write_slot(ebpf, slot, &compiled)?;

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
            bindings: self.bindings.len(),
        };
        self.policy = Some(policy);
        Ok(report)
    }

    fn resolve_bindings(&self, policy: &Policy) -> Result<BTreeMap<u64, (String, u32)>> {
        let mut out = BTreeMap::new();
        for b in &policy.bindings {
            let path = self.cgroup_fs.join(&b.cgroup);
            fs::create_dir_all(&path).with_context(|| format!("create cgroup {}", path.display()))?;
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
            let map = ebpf.map_mut(map_name).with_context(|| format!("{map_name} missing"))?;
            let mut trie = LpmTrie::<_, KeyData, NetRule>::try_from(map)?;
            for (prefix_len, data) in keys {
                // Already-absent keys are fine: the goal is an empty slot.
                let _ = trie.remove(&Key::new(*prefix_len, *data));
            }
        }
        let map = ebpf.map_mut(MAP_PROFILES).context("rk_profiles missing")?;
        let mut profiles = Array::<_, Profile>::try_from(map)?;
        for id in &contents.profiles {
            profiles.set(profile_index(slot, *id), Profile(rk_profile::zeroed()), 0)?;
        }
        Ok(())
    }

    fn write_slot(&mut self, ebpf: &mut Ebpf, slot: u32, compiled: &Compiled) -> Result<()> {
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
            let map = ebpf.map_mut(map_name).with_context(|| format!("{map_name} missing"))?;
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
                    .with_context(|| format!("write {map_name} entry for profile {}", entry.profile))?;
            }
        }
        Ok(())
    }

    fn sync_bindings(&mut self, ebpf: &mut Ebpf, wanted: BTreeMap<u64, (String, u32)>) -> Result<()> {
        let map = ebpf.map_mut(MAP_BINDINGS).context("rk_cgroup_profile missing")?;
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
        assert_eq!(std::mem::size_of::<NetRule>(), std::mem::size_of::<rk_net_rule>());
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
                CompiledRange { rule_id: 7, lo: 443, hi: 443, proto: 1 },
                CompiledRange { rule_id: 3, lo: 0, hi: 65535, proto: 7 },
            ],
        };
        let v = trie_value(&entry);
        assert_eq!(v.nranges, 2);
        assert_eq!((v.ranges[0].rule_id, v.ranges[0].port_lo, v.ranges[0].proto_mask), (7, 443, 1));
        assert_eq!((v.ranges[1].rule_id, v.ranges[1].port_hi), (3, 65535));
        assert_eq!(v.ranges[2].rule_id, 0);
    }

    #[test]
    fn profile_index_separates_slots() {
        assert_eq!(profile_index(0, 3), 3);
        assert_eq!(profile_index(1, 3), RK_MAX_PROFILES + 3);
    }
}
