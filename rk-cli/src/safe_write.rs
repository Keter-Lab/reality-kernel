//! Files root writes in directories other users may control: `rk init`'s
//! policy and backup, `rk policy suggest --out`. Run under sudo, a plain
//! `fs::write` follows a symbolic link the user or the governed agent
//! planted at the destination and overwrites whatever it points to.
//!
//! Here nothing is ever opened through a link: new files are created with
//! `O_CREAT | O_EXCL | O_NOFOLLOW` (which fails on any existing name, links
//! included), and a replacement is staged under a fresh, unpredictable name
//! and renamed over the destination (rename replaces the name itself and
//! never follows a link there). Every step happens relative to one open
//! descriptor of the parent directory, so swapping a directory in the path
//! midway changes nothing.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Write as _};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

/// The open parent directory of `path`, and the file name in it.
fn open_parent(path: &Path) -> io::Result<(File, CString)> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{}: not a file name", path.display()),
        )
    })?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let dir = File::open(dir)?;
    if !dir.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{}: parent is not a directory", path.display()),
        ));
    }
    let name = CString::new(name.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok((dir, name))
}

/// Creates `name` in `dir`: fails if anything (a link included) is there.
fn create_at(dir: &File, name: &CStr, mode: libc::c_uint) -> io::Result<File> {
    // SAFETY: `name` is NUL-terminated and outlives the call; `dir` is an
    // open descriptor.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a new descriptor that nothing else owns.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn unlink_at(dir: &File, name: &CStr) {
    // SAFETY: as in `create_at`. Best effort: the name is ours.
    unsafe {
        libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0);
    }
}

fn rename_at(dir: &File, from: &CStr, to: &CStr) -> io::Result<()> {
    // SAFETY: as in `create_at`.
    let rc =
        unsafe { libc::renameat(dir.as_raw_fd(), from.as_ptr(), dir.as_raw_fd(), to.as_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn write_all_synced(mut file: File, contents: &[u8]) -> io::Result<()> {
    file.write_all(contents)?;
    file.sync_all()
}

/// Creates `path` with `contents`. Fails with [`io::ErrorKind::AlreadyExists`]
/// if anything is at `path`, a symbolic link included; never writes through
/// one.
pub fn create_new(path: &Path, contents: &[u8], mode: libc::c_uint) -> io::Result<()> {
    let (dir, name) = open_parent(path)?;
    let file = create_at(&dir, &name, mode)?;
    if let Err(e) = write_all_synced(file, contents) {
        unlink_at(&dir, &name);
        return Err(e);
    }
    let _ = dir.sync_all();
    Ok(())
}

/// Writes `contents` to `path`, replacing a regular file there atomically.
/// Refuses when `path` is a symbolic link or not a regular file. The new
/// file is staged under a fresh name next to `path` and renamed over it, so
/// a reader sees the old or the new file, never a partial one, and the
/// replaced file's owner and mode are not kept (the new one has `mode`).
pub fn replace(path: &Path, contents: &[u8], mode: libc::c_uint) -> Result<()> {
    // Only for a clear message: renameat never follows a link at the
    // destination, so a link planted after this check is replaced, not
    // written through.
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => bail!(
            "{} is a symbolic link; refusing to write through it (remove it or choose another path)",
            path.display()
        ),
        Ok(m) if !m.is_file() => bail!("{} exists and is not a regular file", path.display()),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("inspect {}", path.display())),
    }
    let (dir, name) = open_parent(path).with_context(|| format!("write {}", path.display()))?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    for attempt in 0..16u32 {
        let mut staged = b".".to_vec();
        staged.extend_from_slice(name.as_bytes());
        staged.extend_from_slice(
            format!(".rk-{}-{nanos:x}-{attempt}", std::process::id()).as_bytes(),
        );
        let staged = CString::new(staged).context("staging name")?;
        let file = match create_at(&dir, &staged, mode) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).with_context(|| format!("stage a new {}", path.display()));
            }
        };
        let written =
            write_all_synced(file, contents).and_then(|()| rename_at(&dir, &staged, &name));
        if let Err(e) = written {
            unlink_at(&dir, &staged);
            return Err(e).with_context(|| format!("write {}", path.display()));
        }
        let _ = dir.sync_all();
        return Ok(());
    }
    bail!(
        "write {}: could not create a staging file next to it",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("rk-safe-write-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// A link planted at the destination is refused, and its target (the
    /// file root would have overwritten) is untouched.
    #[test]
    fn root_writes_never_follow_a_planted_symlink() {
        let dir = scratch("link");
        let victim = dir.join("victim");
        fs::write(&victim, "precious\n").unwrap();
        let out = dir.join("agent.toml");
        symlink(&victim, &out).unwrap();

        let err = replace(&out, b"policy\n", 0o644).unwrap_err().to_string();
        assert!(err.contains("symbolic link"), "{err}");
        let err = create_new(&out, b"policy\n", 0o600).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        // A dangling link is not followed either (O_CREAT would create its target).
        let dangling = dir.join("dangling");
        symlink(dir.join("created-through-link"), &dangling).unwrap();
        assert!(create_new(&dangling, b"x", 0o600).is_err());
        assert!(replace(&dangling, b"x", 0o644).is_err());
        assert!(!dir.join("created-through-link").exists());

        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious\n");
        let _ = fs::remove_dir_all(&dir);
    }

    /// An existing regular file is replaced whole, and no staging file is
    /// left behind.
    #[test]
    fn replace_overwrites_a_regular_file_atomically() {
        let dir = scratch("replace");
        let out = dir.join("agent.toml");
        replace(&out, b"one\n", 0o644).unwrap();
        fs::write(&out, "old and longer\n").unwrap();
        replace(&out, b"two\n", 0o644).unwrap();
        assert_eq!(fs::read_to_string(&out).unwrap(), "two\n");
        let names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [std::ffi::OsString::from("agent.toml")]);
        assert!(
            replace(&dir, b"x", 0o644).is_err(),
            "a directory is refused"
        );

        create_new(&dir.join("new"), b"n\n", 0o600).unwrap();
        assert_eq!(fs::read_to_string(dir.join("new")).unwrap(), "n\n");
        let err = create_new(&dir.join("new"), b"again", 0o600).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        let _ = fs::remove_dir_all(&dir);
    }
}
