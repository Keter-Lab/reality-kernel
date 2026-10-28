//! The identity the kernel hooks compare for a file: `(i_sb->s_dev, i_ino)`.
//!
//! File and exec rules are keyed on the superblock device of the inode
//! (`exec.bpf.c` and `file.bpf.c` read `inode->i_sb->s_dev`). `stat(2)` does
//! not always report that device: btrfs's `getattr` returns the subvolume's
//! anonymous device (`BTRFS_I(inode)->root->anon_dev`), which differs from
//! the superblock's for every subvolume and snapshot, including the top-level
//! one. A rule resolved from `st_dev` then silently never matches.
//!
//! The superblock device is what `/proc/self/mountinfo` prints in its third
//! field (`MAJOR(sb->s_dev):MINOR(sb->s_dev)`, `show_mountinfo` in
//! `fs/proc_namespace.c`). The mount a path resolves to is found by opening it
//! with `O_PATH` (no read access, no side effects on FIFOs or devices) and
//! reading `mnt_id` from `/proc/self/fdinfo/<fd>`; `st_ino` from the same
//! descriptor is the inode number (`generic_fillattr` copies `i_ino`).

use std::collections::HashMap;
use std::fs::{self, Metadata};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use anyhow::{Context, Result};

use crate::selftest::kernel_dev;

const MOUNTINFO: &str = "/proc/self/mountinfo";

/// One line of `/proc/self/mountinfo`, reduced to what identity needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// `sb->s_dev` in the kernel encoding (`MAJOR << 20 | MINOR`).
    pub dev: u64,
    pub fstype: String,
}

/// A file as the hooks see it.
#[derive(Debug, Clone)]
pub struct FileIdentity {
    /// Superblock device, kernel encoding: the value the hooks compare.
    pub dev: u64,
    pub ino: u64,
    /// `st_dev` in the kernel encoding; differs from `dev` on btrfs.
    pub stat_dev: u64,
    pub fstype: String,
    pub meta: Metadata,
}

/// Mount id -> superblock device, read once per apply and re-read once when a
/// path resolves to a mount that appeared after the read.
#[derive(Debug, Default)]
pub struct MountTable {
    by_id: HashMap<u64, Mount>,
    loaded: bool,
}

impl MountTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses mountinfo text. Lines that do not parse are skipped; a path on
    /// such a mount then fails to resolve, which is an error, not a guess.
    pub fn parse(text: &str) -> Self {
        let by_id = text.lines().filter_map(parse_mountinfo_line).collect();
        Self {
            by_id,
            loaded: true,
        }
    }

    fn reload(&mut self) -> Result<()> {
        let text = fs::read_to_string(MOUNTINFO).with_context(|| format!("read {MOUNTINFO}"))?;
        *self = Self::parse(&text);
        Ok(())
    }

    /// The mount with id `mnt_id`, re-reading mountinfo once on a miss.
    fn mount(&mut self, mnt_id: u64) -> Result<&Mount> {
        if !self.loaded || !self.by_id.contains_key(&mnt_id) {
            self.reload()?;
        }
        self.by_id
            .get(&mnt_id)
            .with_context(|| format!("mount id {mnt_id} is not in {MOUNTINFO}"))
    }

    /// Resolves `path` (following symlinks) to the identity the kernel
    /// compares. Fails when the superblock device cannot be determined: a
    /// rule keyed on a guessed device could silently never match.
    pub fn identity(&mut self, path: &Path) -> std::io::Result<FileIdentity> {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(path)?;
        let meta = file.metadata()?;
        let fdinfo = fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
        let mnt_id = parse_fdinfo_mnt_id(&fdinfo).ok_or_else(|| {
            std::io::Error::other(format!(
                "{}: no mnt_id in /proc/self/fdinfo",
                path.display()
            ))
        })?;
        let mount = self
            .mount(mnt_id)
            .map_err(|e| std::io::Error::other(format!("{}: {e:#}", path.display())))?;
        Ok(FileIdentity {
            dev: mount.dev,
            ino: meta.ino(),
            stat_dev: kernel_dev(meta.dev()),
            fstype: mount.fstype.clone(),
            meta,
        })
    }
}

/// `mount_id parent_id major:minor root mount_point options [optional...] -
/// fstype source super_options`. Returns (mount id, mount).
pub fn parse_mountinfo_line(line: &str) -> Option<(u64, Mount)> {
    let mut fields = line.split_whitespace();
    let id = fields.next()?.parse().ok()?;
    let _parent = fields.next()?;
    let (major, minor) = fields.next()?.split_once(':')?;
    let major: u64 = major.parse().ok()?;
    let minor: u64 = minor.parse().ok()?;
    // Optional fields end at the lone "-" separator; the type follows it.
    let fstype = fields.skip_while(|f| *f != "-").nth(1)?.to_string();
    Some((
        id,
        Mount {
            dev: (major << 20) | minor,
            fstype,
        },
    ))
}

/// The `mnt_id:` line of a `/proc/<pid>/fdinfo/<fd>` file (Linux 3.15+).
pub fn parse_fdinfo_mnt_id(text: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.strip_prefix("mnt_id:"))
        .and_then(|v| v.trim().parse().ok())
}

/// Logs a rule whose stat device differs from the superblock device on a
/// filesystem other than btrfs (whose inode numbers are known to match):
/// on overlayfs, for instance, `st_ino` may not be the overlay inode's
/// `i_ino`, so the rule may not match. Not an error: the identity used is the
/// one the kernel compares, and only the inode number is uncertain.
pub fn warn_if_uncertain(what: &str, path: &str, id: &FileIdentity) {
    if id.dev != id.stat_dev && id.fstype != "btrfs" {
        tracing::warn!(
            rule = what,
            path,
            fstype = %id.fstype,
            superblock_dev = id.dev,
            stat_dev = id.stat_dev,
            "rule path is on a filesystem whose stat(2) identity differs from the \
             superblock identity the kernel compares; the rule may not match"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_parses_mountinfo_lines() {
        let ext4 =
            "36 35 98:0 /mnt1 /mnt/parent rw,noatime master:1 - ext3 /dev/root rw,errors=continue";
        assert_eq!(
            parse_mountinfo_line(ext4),
            Some((
                36,
                Mount {
                    dev: 98 << 20,
                    fstype: "ext3".into()
                }
            ))
        );
        // No optional fields; btrfs subvolume mount with an anonymous device.
        let btrfs =
            "29 1 0:26 /@home /home rw,relatime - btrfs /dev/vda2 rw,subvolid=257,subvol=/@home";
        assert_eq!(
            parse_mountinfo_line(btrfs),
            Some((
                29,
                Mount {
                    dev: 26,
                    fstype: "btrfs".into()
                }
            ))
        );
        // Several optional fields, escaped space in the mount point.
        let shared = "120 29 259:3 / /mnt/a\\040b rw shared:5 master:2 - xfs /dev/nvme0n1p3 rw";
        let (id, m) = parse_mountinfo_line(shared).unwrap();
        assert_eq!(
            (id, m.dev, m.fstype.as_str()),
            (120, (259 << 20) | 3, "xfs")
        );
        // Malformed lines are skipped, not misread.
        assert_eq!(parse_mountinfo_line(""), None);
        assert_eq!(parse_mountinfo_line("1 2 nodev / / rw - ext4 x rw"), None);
        assert_eq!(parse_mountinfo_line("1 2 8:1 / / rw shared:1"), None);
    }

    #[test]
    fn identity_mount_table_indexes_by_id() {
        let t = MountTable::parse(
            "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
             garbage\n\
             23 22 0:30 /@snap /snap rw - btrfs /dev/sda2 rw\n",
        );
        assert_eq!(t.by_id.len(), 2);
        assert_eq!(t.by_id[&22].dev, (8 << 20) | 1);
        assert_eq!(t.by_id[&23].dev, 30);
    }

    #[test]
    fn identity_parses_fdinfo_mnt_id() {
        assert_eq!(
            parse_fdinfo_mnt_id("pos:\t0\nflags:\t012100000\nmnt_id:\t26\nino:\t1234\n"),
            Some(26)
        );
        assert_eq!(parse_fdinfo_mnt_id("pos:\t0\nflags:\t0\n"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn identity_resolves_a_live_path_and_keeps_the_inode() {
        let dir = std::env::temp_dir().join(format!("rk_identity_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("f");
        fs::write(&file, b"x").unwrap();
        let mut table = MountTable::new();
        let id = table.identity(&file).unwrap();
        let meta = fs::metadata(&file).unwrap();
        assert_eq!(id.ino, meta.ino());
        assert_eq!(id.stat_dev, kernel_dev(meta.dev()));
        assert!(id.meta.is_file());
        // A directory resolves too (O_PATH needs no read permission).
        assert!(table.identity(&dir).unwrap().meta.is_dir());
        assert!(table.identity(&dir.join("missing")).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
