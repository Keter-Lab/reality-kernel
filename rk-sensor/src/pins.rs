//! Pinning and adoption (docs/design/phase-6.md §3).
//!
//! Every map of the production object is pinned under `<root>/maps` and every
//! link under `<root>/links`, so protection outlives the process. A restarted
//! sensor whose object matches `rk_meta` reuses the pinned maps (aya opens a
//! pinned map instead of creating one) and adopts the pinned links; the
//! attach helpers in `policy` skip any link that is already pinned.

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
    /// Pins of a different object (ABI or build) were removed and recreated:
    /// a gap of one load-and-attach.
    Replaced,
}

/// The production object opened with pinned maps.
pub struct Pinned {
    pub ebpf: Ebpf,
    pub adoption: Adoption,
    /// Random per pin set; ties the engine state file to these pins.
    pub epoch: [u8; 16],
    /// Directory for link pins, passed to the `policy::attach_*` helpers.
    pub links: PathBuf,
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
pub fn open(bytes: &[u8], root: &Path) -> Result<Pinned> {
    let mount_point = root.parent().context("pin root has no parent")?;
    ensure_bpffs(mount_point)?;

    let sha: [u8; 32] = Sha256::digest(bytes).into();
    let mut adoption = Adoption::Fresh;
    let mut epoch = *uuid::Uuid::new_v4().as_bytes();
    if root.exists() {
        match read_meta(root) {
            Ok(meta) if meta.abi == RK_ABI_VERSION && meta.object_sha256 == sha => {
                adoption = Adoption::Adopted;
                epoch = meta.epoch;
            }
            _ => {
                tracing::warn!(
                    root = %root.display(),
                    "pins were created by a different object: replacing them \
                     (protection pauses for one load-and-attach)"
                );
                fs::remove_dir_all(root).with_context(|| format!("remove {}", root.display()))?;
                adoption = Adoption::Replaced;
            }
        }
    }
    create_layout(root)?;

    let maps = maps_dir(root);
    let mut loader = EbpfLoader::new();
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
        links: links_dir(root),
    })
}

/// Removes the pin set, which detaches every pinned link once no process
/// holds it. Returns whether anything was removed.
pub fn uninstall(root: &Path) -> Result<bool> {
    if !root.exists() {
        return Ok(false);
    }
    fs::remove_dir_all(root).with_context(|| format!("remove {}", root.display()))?;
    Ok(true)
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

    #[test]
    fn uninstall_of_missing_root_is_a_no_op() {
        let root = std::env::temp_dir().join(format!("rk-pins-{}", std::process::id()));
        assert!(!uninstall(&root).unwrap());
    }
}
