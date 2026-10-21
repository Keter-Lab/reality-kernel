//! Agent cgroup management in cgroupfs.

use std::ffi::CString;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::{FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rk_policy::net;

/// Construct the relative cgroup path for an agent id under `rk.slice/`.
pub fn agent_cgroup_rel(uuid: &str) -> String {
    format!("{}/agent-{}", net::CGROUP_ROOT, uuid)
}

/// Create an agent cgroup directory directly in cgroupfs under `rk.slice/`.
///
/// Ensures root ownership (`0:0`) and mode `0o755`, preventing unprivileged
/// agents from modifying cgroup settings or delegating sub-cgroups.
pub fn create_agent_cgroup(cgroup_fs: &Path, uuid: &str) -> Result<(PathBuf, u64)> {
    let rel = agent_cgroup_rel(uuid);
    let path = cgroup_fs.join(&rel);

    // Ensure parent rk.slice directory exists and is traversable: agents run
    // unprivileged and must be able to reach their own cgroup. Its mode is
    // set explicitly because a daemon umask of 077 would otherwise make it 0700.
    let parent = cgroup_fs.join(net::CGROUP_ROOT);
    if !parent.exists() {
        fs::create_dir_all(&parent)
            .with_context(|| format!("failed to create parent cgroup {}", parent.display()))?;
    }
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("failed to chmod parent cgroup {}", parent.display()))?;

    fs::create_dir(&path)
        .with_context(|| format!("failed to create agent cgroup {}", path.display()))?;

    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("failed to chmod agent cgroup {}", path.display()))?;

    let meta = fs::metadata(&path)
        .with_context(|| format!("failed to stat agent cgroup {}", path.display()))?;
    let cgroup_id = meta.ino();

    Ok((path, cgroup_id))
}

/// Open an agent cgroup directory file descriptor for use with `clone3(CLONE_INTO_CGROUP)`.
pub fn open_cgroup_dir(path: &Path) -> Result<OwnedFd> {
    let c_path = CString::new(path.to_string_lossy().as_bytes())?;
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to open cgroup dir {}", path.display()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Kill all processes in the agent cgroup.
///
/// Uses `cgroup.kill` (Linux 5.14+). If `cgroup.kill` is absent, falls back to
/// reading `cgroup.procs` and sending `SIGKILL` to each process.
pub fn kill_cgroup(path: &Path) -> Result<()> {
    let kill_file = path.join("cgroup.kill");
    if kill_file.exists() {
        if let Err(e) = fs::write(&kill_file, b"1\n") {
            // If already empty or failed, proceed to procs fallback
            tracing::debug!(path = %kill_file.display(), error = %e, "cgroup.kill write failed");
        }
    }

    // Fallback or belt-and-suspenders: kill any remaining procs
    let procs_file = path.join("cgroup.procs");
    if procs_file.exists() {
        if let Ok(content) = fs::read_to_string(&procs_file) {
            for line in content.lines() {
                if let Ok(pid) = line.trim().parse::<i32>() {
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Wait for all processes in the cgroup to exit, then remove the directory.
pub fn drain_and_remove_cgroup(path: &Path, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    let events_file = path.join("cgroup.events");
    let procs_file = path.join("cgroup.procs");

    while start.elapsed() < timeout {
        let is_empty = if events_file.exists() {
            if let Ok(content) = fs::read_to_string(&events_file) {
                content.lines().any(|l| l.trim() == "populated 0")
            } else {
                false
            }
        } else if procs_file.exists() {
            if let Ok(content) = fs::read_to_string(&procs_file) {
                content.trim().is_empty()
            } else {
                false
            }
        } else {
            true
        };

        if is_empty {
            break;
        }

        // Send SIGKILL again if still populated after 50ms
        if start.elapsed() > Duration::from_millis(50) {
            let _ = kill_cgroup(path);
        }

        sleep(Duration::from_millis(10));
    }

    if path.exists() {
        fs::remove_dir(path)
            .with_context(|| format!("failed to remove agent cgroup {}", path.display()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_rel_formatting() {
        assert_eq!(agent_cgroup_rel("1234-abcd"), "rk.slice/agent-1234-abcd");
        assert!(net::validate_cgroup(&agent_cgroup_rel("uuid")).is_ok());
    }

    #[test]
    fn mock_cgroup_kill_and_drain() {
        let tmp = std::env::temp_dir().join(format!("rk-test-{}", std::process::id()));
        let cgroup_dir = tmp.join("rk.slice/agent-mock");
        fs::create_dir_all(&cgroup_dir).unwrap();

        let kill_file = cgroup_dir.join("cgroup.kill");
        fs::write(&kill_file, b"0\n").unwrap();

        let events_file = cgroup_dir.join("cgroup.events");
        fs::write(&events_file, b"populated 0\n").unwrap();

        kill_cgroup(&cgroup_dir).unwrap();
        assert_eq!(fs::read_to_string(&kill_file).unwrap(), "1\n");

        // Still populated: drain must give up with an error and leave the
        // cgroup in place, never report success.
        fs::write(&events_file, b"populated 1\n").unwrap();
        assert!(drain_and_remove_cgroup(&cgroup_dir, Duration::from_millis(50)).is_err());
        assert!(cgroup_dir.exists());

        // In cgroupfs the interface files vanish with the directory, but a plain
        // temp directory cannot be removed while it holds files. Remove the mock
        // files to model an emptied cgroup, then drain must remove it.
        fs::remove_file(&kill_file).unwrap();
        fs::remove_file(&events_file).unwrap();
        drain_and_remove_cgroup(&cgroup_dir, Duration::from_millis(100)).unwrap();
        assert!(!cgroup_dir.exists());
        let _ = fs::remove_dir_all(&tmp);
    }
}
