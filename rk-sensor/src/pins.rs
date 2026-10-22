//! Pinning and adoption (docs/design/phase-6.md §3).
//!
//! Every map of the production object is pinned under `<root>/maps` and every
//! link under `<root>/links`, so protection outlives the process. A restarted
//! sensor whose object matches `rk_meta` reuses the pinned maps (aya opens a
//! pinned map instead of creating one) and adopts the pinned links; the
//! attach helpers in `policy` skip any link that is already pinned.
//!
//! A different object (a new release) is not adopted. It is loaded beside the
//! running one under `<root>.next`, and the old pin set is removed only after
//! the new programs are attached and hold the policy: make-before-break, so
//! there is never a moment with nothing attached (docs/design/phase-10.md §3).

use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use aya::maps::{Array, Map, MapData};
use aya::{Ebpf, EbpfLoader};
use bytemuck::Zeroable;
use rk_ebpf_common::{rk_meta, RK_ABI_VERSION};
use sha2::{Digest, Sha256};

/// Default pin root.
pub const PIN_ROOT: &str = "/sys/fs/bpf/rk";

const BPF_FS_MAGIC: u64 = 0xcafe_4a11;

/// Every map of rk.bpf.o. [`open`] refuses an object with a map missing here,
/// so a new map can never silently be left unpinned.
pub const PINNED_MAPS: &[&str] = &[
    "events_ringbuf",
    "scratch_map",
    "rk_counters",
    "monitored_cgroups",
    "rk_cgroup_profile",
    "rk_profiles",
    "rk_active_slot",
    "rk_heartbeat",
    "rk_config",
    "rk_guard",
    "rk_meta",
    "rk_net_deny",
    "rk_net_allow",
    "rk_exec_allow",
    "rk_exec_decided",
    "rk_file_protect",
];

#[derive(Clone, Copy)]
#[repr(transparent)]
struct Meta(rk_meta);
// SAFETY: rk_meta is a bindgen Pod (no padding, any bit pattern valid).
unsafe impl aya::Pod for Meta {}

/// How the pin set was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adoption {
    /// No pins existed: everything was created.
    Fresh,
    /// Pins of the same object existed and were adopted: no gap.
    Adopted,
    /// Pins of a different object (ABI or build) exist and stay attached; the
    /// new object was loaded under `<root>.next`. The caller attaches the new
    /// programs, moves the policy over, then calls [`finish_replacement`].
    Replacing,
}

/// The pin set being replaced, while [`Adoption::Replacing`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Previous {
    pub root: PathBuf,
    /// Epoch of the old pin set, to read its engine state file.
    pub epoch: [u8; 16],
}

/// The production object opened with pinned maps.
pub struct Pinned {
    pub ebpf: Ebpf,
    pub adoption: Adoption,
    /// Random per pin set; ties the engine state file to these pins.
    pub epoch: [u8; 16],
    /// Directory for link pins, passed to the `policy::attach_*` helpers.
    pub links: PathBuf,
    /// Set while replacing: the old pin set, still attached.
    pub previous: Option<Previous>,
}

/// `<root>.next`, where a replacing object is pinned.
pub fn next_root(root: &Path) -> PathBuf {
    let mut p = root.as_os_str().to_owned();
    p.push(".next");
    PathBuf::from(p)
}

/// Puts the pin directories in a consistent state after a sensor that died
/// mid-replacement: with both `root` and `<root>.next`, the replacement had
/// not switched yet, so the partial `.next` is dropped (the old set is still
/// attached); with only `.next`, the old set was already removed, so `.next`
/// becomes `root`. Returns what it did, for the log.
pub fn reconcile(root: &Path) -> Result<Option<&'static str>> {
    let next = next_root(root);
    if !next.exists() {
        return Ok(None);
    }
    if root.exists() {
        fs::remove_dir_all(&next).with_context(|| format!("remove {}", next.display()))?;
        Ok(Some("removed an unfinished replacement; the running object stays attached"))
    } else {
        fs::rename(&next, root)
            .with_context(|| format!("rename {} to {}", next.display(), root.display()))?;
        Ok(Some("completed an interrupted replacement"))
    }
}

/// Ends a replacement: removes the old pin set (its links detach, nothing
/// else holds them) and moves the new one to `root`. Call only once the new
/// programs are attached and the new maps hold the policy.
pub fn finish_replacement(root: &Path) -> Result<()> {
    fs::remove_dir_all(root).with_context(|| format!("remove {}", root.display()))?;
    let next = next_root(root);
    fs::rename(&next, root)
        .with_context(|| format!("rename {} to {}", next.display(), root.display()))
}

/// Abandons a replacement that could not be completed: the new pin set is
/// removed and the old one, never touched, keeps enforcing.
pub fn abort_replacement(root: &Path) -> Result<()> {
    let next = next_root(root);
    if next.exists() {
        fs::remove_dir_all(&next).with_context(|| format!("remove {}", next.display()))?;
    }
    Ok(())
}

fn maps_dir(root: &Path) -> PathBuf {
    root.join("maps")
}

fn links_dir(root: &Path) -> PathBuf {
    root.join("links")
}

/// Mounts bpffs at the parent of `root` when nothing is mounted there.
fn ensure_bpffs(mount_point: &Path) -> Result<()> {
    let c_path = CString::new(mount_point.as_os_str().as_bytes())?;
    // SAFETY: valid NUL-terminated path and an out-pointer to a statfs struct.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c_path.as_ptr(), &mut st) } == 0
        && (st.f_type as u64 & 0xffff_ffff) == BPF_FS_MAGIC
    {
        return Ok(());
    }
    fs::create_dir_all(mount_point).with_context(|| format!("create {}", mount_point.display()))?;
    let fstype = CString::new("bpf")?;
    // SAFETY: valid NUL-terminated strings; no mount data.
    let rc = unsafe {
        libc::mount(
            fstype.as_ptr(),
            c_path.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("mount bpffs at {}", mount_point.display()));
    }
    Ok(())
}

fn create_layout(root: &Path) -> Result<()> {
    for dir in [root.to_path_buf(), maps_dir(root), links_dir(root)] {
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod {}", dir.display()))?;
    }
    Ok(())
}

fn read_meta(root: &Path) -> Result<rk_meta> {
    let data = MapData::from_pin(maps_dir(root).join("rk_meta"))?;
    let array: Array<MapData, Meta> = Array::try_from(Map::Array(data))?;
    Ok(array.get(&0, 0)?.0)
}

/// Opens `bytes` (the production object) with every map pinned under `root`,
/// adopting an existing pin set when it was created by the same object.
/// `ring_bytes` sizes a newly created ring buffer and sets the adaptive
/// wakeup threshold to an eighth of it (docs/design/phase-7.md §4); an adopted
/// ring keeps the size it was created with.
pub fn open(bytes: &[u8], root: &Path, ring_bytes: u32) -> Result<Pinned> {
    let mount_point = root.parent().context("pin root has no parent")?;
    ensure_bpffs(mount_point)?;

    if let Some(what) = reconcile(root)? {
        tracing::warn!(root = %root.display(), "{what}");
    }

    let sha: [u8; 32] = Sha256::digest(bytes).into();
    let mut adoption = Adoption::Fresh;
    let mut epoch = *uuid::Uuid::new_v4().as_bytes();
    let mut previous = None;
    if root.exists() {
        match read_meta(root) {
            Ok(meta) if meta.abi == RK_ABI_VERSION && meta.object_sha256 == sha => {
                adoption = Adoption::Adopted;
                epoch = meta.epoch;
            }
            Ok(meta) => {
                tracing::info!(
                    root = %root.display(),
                    "pins were created by a different object: replacing them without a gap \
                     (the new object loads beside the running one)"
                );
                adoption = Adoption::Replacing;
                previous = Some(Previous {
                    root: root.to_path_buf(),
                    epoch: meta.epoch,
                });
            }
            Err(e) => {
                // No readable rk_meta: nothing to adopt or migrate from.
                // Its links (if any) are still attached, so make-before-break
                // applies all the same; there is just no state to carry over.
                tracing::warn!(
                    root = %root.display(),
                    error = %format!("{e:#}"),
                    "pins without a readable rk_meta: replacing them"
                );
                adoption = Adoption::Replacing;
                previous = Some(Previous {
                    root: root.to_path_buf(),
                    epoch: [0; 16],
                });
            }
        }
    }
    let pin_root = match adoption {
        Adoption::Replacing => next_root(root),
        _ => root.to_path_buf(),
    };
    create_layout(&pin_root)?;

    let maps = maps_dir(&pin_root);
    let wakeup_threshold = u64::from(ring_bytes / 8);
    let mut loader = EbpfLoader::new();
    loader
        .map_max_entries("events_ringbuf", ring_bytes)
        .override_global("rk_wakeup_threshold", &wakeup_threshold, true);
    for &name in PINNED_MAPS {
        loader.map_pin_path(name, maps.join(name));
    }
    let mut ebpf = loader
        .load(bytes)
        .context("load rk.bpf.o with pinned maps")?;

    let unpinned: Vec<&str> = ebpf
        .maps()
        .map(|(name, _)| name)
        .filter(|name| !name.starts_with('.') && !PINNED_MAPS.contains(name))
        .collect();
    if !unpinned.is_empty() {
        bail!("maps {unpinned:?} are not in pins::PINNED_MAPS and would not survive a restart");
    }

    if adoption != Adoption::Adopted {
        let mut meta = rk_meta::zeroed();
        meta.abi = RK_ABI_VERSION;
        meta.object_sha256 = sha;
        meta.epoch = epoch;
        let map = ebpf.map_mut("rk_meta").context("rk_meta missing")?;
        let mut array: Array<&mut MapData, Meta> = Array::try_from(map)?;
        array.set(0, Meta(meta), 0).context("write rk_meta")?;
    }

    Ok(Pinned {
        ebpf,
        adoption,
        epoch,
        links: links_dir(&pin_root),
        previous,
    })
}

/// Removes the pin set, which detaches every pinned link once no process
/// holds it. Returns whether anything was removed.
pub fn uninstall(root: &Path) -> Result<bool> {
    let mut removed = false;
    // `.next` too: a replacement interrupted mid-way is attached as well.
    for dir in [next_root(root), root.to_path_buf()] {
        if dir.exists() {
            fs::remove_dir_all(&dir).with_context(|| format!("remove {}", dir.display()))?;
            removed = true;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_maps_are_unique_and_cover_userspace_maps() {
        let mut names = PINNED_MAPS.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), PINNED_MAPS.len());
        for name in [
            "events_ringbuf",
            "rk_cgroup_profile",
            "rk_heartbeat",
            "rk_config",
            "rk_guard",
            "rk_meta",
        ] {
            assert!(PINNED_MAPS.contains(&name), "{name}");
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let root = std::env::temp_dir()
            .join(format!("rk-pins-{}-{name}", std::process::id()))
            .join("rk");
        let _ = fs::remove_dir_all(root.parent().unwrap());
        fs::create_dir_all(root.parent().unwrap()).unwrap();
        root
    }

    fn mark(dir: &Path, tag: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("tag"), tag).unwrap();
    }

    fn tag(dir: &Path) -> String {
        fs::read_to_string(dir.join("tag")).unwrap()
    }

    /// Phase 10 §3: a replacement interrupted before the switch keeps the
    /// running set and drops the partial new one.
    #[test]
    fn reconcile_drops_an_unfinished_replacement() {
        let root = scratch("unfinished");
        mark(&root, "old");
        mark(&next_root(&root), "new");
        assert!(reconcile(&root).unwrap().is_some());
        assert_eq!(tag(&root), "old");
        assert!(!next_root(&root).exists());
    }

    /// Interrupted after the old set was removed: the new one takes its place.
    #[test]
    fn reconcile_completes_an_interrupted_switch() {
        let root = scratch("switch");
        mark(&next_root(&root), "new");
        assert!(reconcile(&root).unwrap().is_some());
        assert_eq!(tag(&root), "new");
        assert!(!next_root(&root).exists());
        assert_eq!(reconcile(&root).unwrap(), None);
    }

    #[test]
    fn finish_replacement_swaps_and_abort_keeps_the_old_set() {
        let root = scratch("finish");
        mark(&root, "old");
        mark(&next_root(&root), "new");
        abort_replacement(&root).unwrap();
        assert_eq!(tag(&root), "old");
        assert!(!next_root(&root).exists());

        mark(&next_root(&root), "new");
        finish_replacement(&root).unwrap();
        assert_eq!(tag(&root), "new");
        assert!(!next_root(&root).exists());
    }

    #[test]
    fn uninstall_of_missing_root_is_a_no_op() {
        let root = std::env::temp_dir().join(format!("rk-pins-{}", std::process::id()));
        assert!(!uninstall(&root).unwrap());
    }
}
