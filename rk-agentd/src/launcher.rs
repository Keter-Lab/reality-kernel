//! Unprivileged process launcher using `clone3(CLONE_INTO_CGROUP)`.

use std::ffi::CString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::protocol::AgentPrivilegeChecks;

pub const CLONE_PIDFD: u64 = 0x00001000;
pub const CLONE_INTO_CGROUP: u64 = 0x00000200;

const SYS_CLONE3: libc::c_long = 435;
const SYS_CLOSE_RANGE: libc::c_long = 436;
const SYS_CAPSET: libc::c_long = 126;

const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct CapUserHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[repr(C)]
#[derive(Debug, Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

/// Spawns the agent process directly inside `cgroup_fd`.
///
/// In the child before `execve`:
/// 1. Stdio file descriptors are redirected (`dup2`).
/// 2. `no_new_privs` is enabled.
/// 3. All capabilities are cleared.
/// 4. Privilege is dropped to `target_uid` and `target_gid`.
///
/// Returns `(child_pid, optional_pidfd)`.
pub fn spawn_in_cgroup(
    cgroup_fd: RawFd,
    cgroup_path: &Path,
    target_uid: u32,
    target_gid: u32,
    stdio_fds: Option<[RawFd; 3]>,
    cmd: &[String],
    env: &[(String, String)],
) -> Result<(i32, Option<OwnedFd>)> {
    if cmd.is_empty() {
        bail!("empty command");
    }

    // Resolve binary path (absolute or via PATH)
    let binary_str = &cmd[0];
    let resolved_path = if binary_str.contains('/') {
        binary_str.clone()
    } else {
        find_in_path(binary_str).unwrap_or_else(|| binary_str.clone())
    };

    let c_path = CString::new(resolved_path.as_str())
        .with_context(|| format!("invalid binary path `{resolved_path}`"))?;

    let mut c_argv = Vec::with_capacity(cmd.len());
    for arg in cmd {
        c_argv.push(
            CString::new(arg.as_str())
                .with_context(|| format!("invalid argument `{arg}`"))?,
        );
    }
    let mut c_argv_ptrs: Vec<*const libc::c_char> = c_argv.iter().map(|s| s.as_ptr()).collect();
    c_argv_ptrs.push(std::ptr::null());

    let mut c_env = Vec::with_capacity(env.len());
    for (k, v) in env {
        c_env.push(
            CString::new(format!("{k}={v}"))
                .with_context(|| format!("invalid environment `{k}={v}`"))?,
        );
    }
    let mut c_envp_ptrs: Vec<*const libc::c_char> = c_env.iter().map(|s| s.as_ptr()).collect();
    c_envp_ptrs.push(std::ptr::null());

    // Prepare clone3 arguments
    let mut pidfd: i32 = -1;
    let mut args = CloneArgs {
        flags: CLONE_PIDFD | CLONE_INTO_CGROUP,
        pidfd: &mut pidfd as *mut i32 as u64,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: cgroup_fd as u64,
    };

    let clone_res = unsafe {
        libc::syscall(
            SYS_CLONE3,
            &mut args as *mut CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        )
    };

    if clone_res == 0 {
        // --- CHILD PROCESS ---
        // Async-signal-safe code only. No allocations, no mutexes.
        unsafe {
            child_pre_exec(stdio_fds, target_uid, target_gid, &c_path, &c_argv_ptrs, &c_envp_ptrs);
        }
    }

    if clone_res > 0 {
        // --- PARENT PROCESS ---
        let child_pid = clone_res as i32;
        let opt_pidfd = if pidfd >= 0 {
            Some(unsafe { OwnedFd::from_raw_fd(pidfd) })
        } else {
            None
        };
        return Ok((child_pid, opt_pidfd));
    }

    // If clone3 failed with ENOSYS, fall back to pipe handshake + fork
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOSYS) {
        return spawn_fallback_pipe(
            cgroup_path,
            target_uid,
            target_gid,
            stdio_fds,
            &c_path,
            &c_argv_ptrs,
            &c_envp_ptrs,
        );
    }

    Err(err).context("clone3 syscall failed")
}

/// Async-signal-safe setup in child process before execve.
unsafe fn child_pre_exec(
    stdio_fds: Option<[RawFd; 3]>,
    target_uid: u32,
    target_gid: u32,
    c_path: &CString,
    c_argv_ptrs: &[*const libc::c_char],
    c_envp_ptrs: &[*const libc::c_char],
) -> ! {
    // 1. Stdio redirection
    if let Some([in_fd, out_fd, err_fd]) = stdio_fds {
        libc::dup2(in_fd, libc::STDIN_FILENO);
        libc::dup2(out_fd, libc::STDOUT_FILENO);
        libc::dup2(err_fd, libc::STDERR_FILENO);
    }

    // 2. Close file descriptors >= 3
    let _ = libc::syscall(
        SYS_CLOSE_RANGE,
        3 as libc::c_uint,
        !0 as libc::c_uint,
        0 as libc::c_uint,
    );
    for fd in 3..256 {
        libc::close(fd);
    }

    // 3. Set no_new_privs
    libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

    // 4. Clear all capabilities
    let cap_hdr = CapUserHeader {
        version: 0x20080522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    let cap_data = [
        CapUserData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapUserData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    libc::syscall(SYS_CAPSET, &cap_hdr, &cap_data[0]);
    libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);

    // 5. Drop privileges
    if target_gid != 0 {
        libc::setgroups(0, std::ptr::null());
        libc::setresgid(target_gid, target_gid, target_gid);
    }
    if target_uid != 0 {
        libc::setresuid(target_uid, target_uid, target_uid);
    }

    // 6. Execute command
    libc::execve(c_path.as_ptr(), c_argv_ptrs.as_ptr(), c_envp_ptrs.as_ptr());

    // If execve failed:
    libc::_exit(127);
}

/// Fallback fork + pipe handshake if clone3 is unavailable.
fn spawn_fallback_pipe(
    cgroup_path: &Path,
    target_uid: u32,
    target_gid: u32,
    stdio_fds: Option<[RawFd; 3]>,
    c_path: &CString,
    c_argv_ptrs: &[*const libc::c_char],
    c_envp_ptrs: &[*const libc::c_char],
) -> Result<(i32, Option<OwnedFd>)> {
    let mut c2p = [0; 2];
    let mut p2c = [0; 2];
    unsafe {
        if libc::pipe2(c2p.as_mut_ptr(), libc::O_CLOEXEC) < 0
            || libc::pipe2(p2c.as_mut_ptr(), libc::O_CLOEXEC) < 0
        {
            return Err(std::io::Error::last_os_error()).context("pipe2 failed");
        }
    }

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error()).context("fork failed");
    }

    if pid == 0 {
        // Child
        unsafe {
            libc::close(c2p[0]);
            libc::close(p2c[1]);

            // Signal parent that we are ready to be attached to cgroup
            let dummy = [1u8];
            libc::write(c2p[1], dummy.as_ptr() as *const _, 1);
            libc::close(c2p[1]);

            // Wait for parent confirmation
            let mut buf = [0u8; 1];
            libc::read(p2c[0], buf.as_mut_ptr() as *mut _, 1);
            libc::close(p2c[0]);

            child_pre_exec(stdio_fds, target_uid, target_gid, c_path, c_argv_ptrs, c_envp_ptrs);
        }
    }

    // Parent
    unsafe {
        libc::close(c2p[1]);
        libc::close(p2c[0]);

        // Wait for child signal
        let mut buf = [0u8; 1];
        libc::read(c2p[0], buf.as_mut_ptr() as *mut _, 1);
        libc::close(c2p[0]);

        // Move child into cgroup
        let procs = cgroup_path.join("cgroup.procs");
        fs::write(&procs, format!("{pid}\n"))
            .with_context(|| format!("failed to attach child to {}", procs.display()))?;

        // Release child
        let dummy = [1u8];
        libc::write(p2c[1], dummy.as_ptr() as *const _, 1);
        libc::close(p2c[1]);
    }

    Ok((pid, None))
}

/// Locate a command in `$PATH`.
fn find_in_path(cmd: &str) -> Option<String> {
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(cmd);
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().to_string());
            }
        }
    }
    None
}

/// Verify the unprivileged posture of a running agent process.
pub fn verify_agent_privileges(pid: u32, cgroup_path: &Path) -> AgentPrivilegeChecks {
    let mut no_new_privs = false;
    let mut empty_capabilities = false;
    let mut caller_uid = 0;
    let mut caller_gid = 0;

    let status_path = format!("/proc/{pid}/status");
    if let Ok(content) = fs::read_to_string(&status_path) {
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("NoNewPrivs:\t") {
                no_new_privs = rest.trim() == "1";
            } else if let Some(rest) = line.strip_prefix("CapEff:\t") {
                empty_capabilities = rest.trim() == "0000000000000000";
            } else if let Some(rest) = line.strip_prefix("Uid:\t") {
                if let Some(first) = rest.split_whitespace().next() {
                    caller_uid = first.parse().unwrap_or(0);
                }
            } else if let Some(rest) = line.strip_prefix("Gid:\t") {
                if let Some(first) = rest.split_whitespace().next() {
                    caller_gid = first.parse().unwrap_or(0);
                }
            }
        }
    }

    let mut cgroup_not_delegated = false;
    if let Ok(meta) = fs::metadata(cgroup_path) {
        // Must be owned by root and not writable by non-root (0o755 or 0o555)
        let mode = meta.mode() & 0o777;
        cgroup_not_delegated = meta.uid() == 0 && (mode & 0o022 == 0);
    }

    AgentPrivilegeChecks {
        unprivileged_user: caller_uid != 0,
        caller_uid,
        caller_gid,
        no_new_privs,
        empty_capabilities,
        cgroup_not_delegated,
    }
}
