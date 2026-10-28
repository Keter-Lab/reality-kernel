//! The device the kernel hooks compare for a file: its superblock's
//! (`inode->i_sb->s_dev`), which audit records carry. `stat(2)` does not
//! always report it: on btrfs subvolumes and snapshots `st_dev` is the
//! subvolume's anonymous device, so a file looked up by `st_dev` never
//! matches the record of its execution. Same method as rk-sensor's
//! `identity` module: open the path with `O_PATH`, read its mount id from
//! `/proc/self/fdinfo`, and that mount's `major:minor` (the superblock
//! device) from `/proc/self/mountinfo`.

use std::collections::HashMap;
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

/// The superblock device of the file at `path` (symlinks followed), in the
/// kernel encoding `MAJOR << 20 | MINOR`; `None` when it cannot be read.
pub fn superblock_dev(path: &Path) -> Option<u64> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH)
        .open(path)
        .ok()?;
    let fdinfo = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd())).ok()?;
    mount_dev(parse_fdinfo_mnt_id(&fdinfo)?)
}

/// Mount id -> superblock device, read once and again when an id is missing
/// (a mount that appeared since).
fn mount_dev(mnt_id: u64) -> Option<u64> {
    static TABLE: OnceLock<Mutex<HashMap<u64, u64>>> = OnceLock::new();
    let mut table = TABLE.get_or_init(Default::default).lock().ok()?;
    if !table.contains_key(&mnt_id) {
        let text = fs::read_to_string("/proc/self/mountinfo").ok()?;
        *table = text.lines().filter_map(parse_mountinfo_line).collect();
    }
    table.get(&mnt_id).copied()
}

/// `mount_id parent_id major:minor ...`: (mount id, `MAJOR << 20 | MINOR`).
fn parse_mountinfo_line(line: &str) -> Option<(u64, u64)> {
    let mut fields = line.split_whitespace();
    let id = fields.next()?.parse().ok()?;
    let _parent = fields.next()?;
    let (major, minor) = fields.next()?.split_once(':')?;
    let major: u64 = major.parse().ok()?;
    let minor: u64 = minor.parse().ok()?;
    Some((id, (major << 20) | minor))
}

/// The `mnt_id:` line of a `/proc/<pid>/fdinfo/<fd>` file (Linux 3.15+).
fn parse_fdinfo_mnt_id(text: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.strip_prefix("mnt_id:"))
        .and_then(|v| v.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn suggest_identity_parses_mountinfo_and_fdinfo() {
        let line = "36 35 98:3 /mnt1 /mnt/parent rw,noatime master:1 - btrfs /dev/root rw";
        assert_eq!(parse_mountinfo_line(line), Some((36, (98 << 20) | 3)));
        assert_eq!(parse_mountinfo_line("garbage"), None);
        let fdinfo = "pos:\t0\nflags:\t010000000\nmnt_id:\t29\nino:\t1234\n";
        assert_eq!(parse_fdinfo_mnt_id(fdinfo), Some(29));
        assert_eq!(parse_fdinfo_mnt_id("pos:\t0\n"), None);
    }

    /// On the CI filesystems (not btrfs) the superblock device is the one
    /// `stat` reports.
    #[test]
    fn suggest_identity_resolves_a_live_file() {
        let exe = std::env::current_exe().unwrap();
        let dev = superblock_dev(&exe).expect("superblock device of the test binary");
        let m = fs::metadata(&exe).unwrap();
        let fstype = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        if !fstype.contains(" - btrfs ") && !fstype.contains(" - overlay ") {
            assert_eq!(dev, crate::suggest::kernel_dev(m.dev()));
        }
    }
}
