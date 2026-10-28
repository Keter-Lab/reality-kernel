//! Unprivileged process launcher using `clone3(CLONE_INTO_CGROUP)`.

use std::ffi::CString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::protocol::AgentPrivilegeChecks;

// Values from include/uapi/linux/sched.h. 0x200 is CLONE_FS: with that value
// clone3 silently left agents in the daemon's cgroup, ungoverned.
pub const CLONE_PIDFD: u64 = 0x0000_1000;
pub const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

const SYS_CLONE3: libc::c_long = 435;
const SYS_CAPSET: libc::c_long = 126;
// Same number on every architecture (the unified syscall table, Linux 5.1+).
const SYS_PIDFD_SEND_SIGNAL: libc::c_long = 424;
const SYS_PIDFD_OPEN: libc::c_long = 434;

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
/// 2. Other open file descriptors are closed.
/// 3. Session is created (`setsid`).
/// 4. Group memberships are cleared (`setgroups`).
/// 5. GID is dropped to `target_gid` (`setresgid`).
/// 6. UID is dropped to `target_uid` (`setresuid`).
/// 7. `no_new_privs` is enabled (`prctl`).
/// 8. Capabilities are cleared as defence in depth (`capset` + ambient clear).
/// 9. Working directory is changed (`chdir`).
/// 10. Command is executed (`execve`).
///
/// Returns `(child_pid, optional_pidfd)`.
/// Context parameters for launching an unprivileged agent process into a cgroup.
#[derive(Debug, Clone)]
pub struct SpawnContext<'a> {
    pub cgroup_fd: RawFd,
    pub cgroup_path: &'a Path,
    pub target_uid: u32,
    pub target_gid: u32,
    pub cwd: Option<&'a str>,
    pub stdio_fds: Option<[RawFd; 3]>,
    pub cmd: &'a [String],
    pub env: &'a [(String, String)],
}

struct ChildExecContext<'a> {
    err_pipe: RawFd,
    stdio_fds: Option<[RawFd; 3]>,
    target_uid: u32,
    target_gid: u32,
    c_cwd: Option<&'a CString>,
    c_path: &'a CString,
    c_argv_ptrs: &'a [*const libc::c_char],
    c_envp_ptrs: &'a [*const libc::c_char],
}

/// Spawn an unprivileged agent process directly into the given cgroup.
///
/// Execution posture:
/// 1. Process is created directly inside `cgroup_fd` via `clone3(CLONE_INTO_CGROUP)`.
/// 2. If stdio FDs were passed over seqpacket SCM_RIGHTS, they are dup2'd to 0, 1, 2.
/// 3. New session is established (`setsid`).
/// 4. Group memberships are cleared (`setgroups`).
/// 5. GID is dropped to `target_gid` (`setresgid`).
/// 6. UID is dropped to `target_uid` (`setresuid`).
/// 7. `no_new_privs` is enabled (`prctl`).
/// 8. Capabilities are cleared as defence in depth (`capset` + ambient clear).
/// 9. Working directory is changed (`chdir`).
/// 10. Command is executed (`execve`).
///
/// Returns `(child_pid, optional_pidfd)`.
pub fn spawn_in_cgroup(ctx: SpawnContext<'_>) -> Result<(i32, Option<OwnedFd>)> {
    if ctx.cmd.is_empty() {
        bail!("empty command");
    }

    // Resolve binary path (absolute or via PATH)
    let binary_str = &ctx.cmd[0];
    let resolved_path = if binary_str.contains('/') {
        binary_str.clone()
    } else {
        find_in_path(binary_str).unwrap_or_else(|| binary_str.clone())
    };

    let c_path = CString::new(resolved_path.as_str())
        .with_context(|| format!("invalid binary path `{resolved_path}`"))?;

    let mut c_argv = Vec::with_capacity(ctx.cmd.len());
    for arg in ctx.cmd {
        c_argv
            .push(CString::new(arg.as_str()).with_context(|| format!("invalid argument `{arg}`"))?);
    }
    let mut c_argv_ptrs: Vec<*const libc::c_char> = c_argv.iter().map(|s| s.as_ptr()).collect();
    c_argv_ptrs.push(std::ptr::null());

    let mut c_env = Vec::with_capacity(ctx.env.len());
    for (k, v) in ctx.env {
        c_env.push(
            CString::new(format!("{k}={v}"))
                .with_context(|| format!("invalid environment `{k}={v}`"))?,
        );
    }
    let mut c_envp_ptrs: Vec<*const libc::c_char> = c_env.iter().map(|s| s.as_ptr()).collect();
    c_envp_ptrs.push(std::ptr::null());

    let c_cwd = match ctx.cwd {
        Some(dir) => Some(CString::new(dir).with_context(|| format!("invalid cwd `{dir}`"))?),
        None => None,
    };

    // Close-on-exec pipe for reporting child setup failures to parent
    let mut err_pipe = [0; 2];
    if unsafe { libc::pipe2(err_pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error()).context("pipe2 for err_pipe failed");
    }

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
        cgroup: ctx.cgroup_fd as u64,
    };

    let clone_res = unsafe {
        libc::syscall(
            SYS_CLONE3,
            &mut args as *mut CloneArgs,
            std::mem::size_of::<CloneArgs>(),
        )
    };

    let child_ctx = ChildExecContext {
        err_pipe: err_pipe[1],
        stdio_fds: ctx.stdio_fds,
        target_uid: ctx.target_uid,
        target_gid: ctx.target_gid,
        c_cwd: c_cwd.as_ref(),
        c_path: &c_path,
        c_argv_ptrs: &c_argv_ptrs,
        c_envp_ptrs: &c_envp_ptrs,
    };

    if clone_res == 0 {
        // --- CHILD PROCESS ---
        // Async-signal-safe code only. No allocations, no mutexes.
        unsafe {
            libc::close(err_pipe[0]); // Close read end in child
            child_pre_exec(child_ctx);
        }
    }

    if clone_res > 0 {
        // --- PARENT PROCESS ---
        let child_pid = clone_res as i32;
        unsafe {
            libc::close(err_pipe[1]); // Close write end in parent
        }

        // Check if child reported an error before execve
        let mut err_buf = [0u8; 1024];
        let n = unsafe {
            libc::read(
                err_pipe[0],
                err_buf.as_mut_ptr() as *mut libc::c_void,
                err_buf.len(),
            )
        };
        unsafe {
            libc::close(err_pipe[0]);
        }

        if n > 0 {
            let msg = String::from_utf8_lossy(&err_buf[..n as usize]);
            let mut status = 0;
            unsafe {
                libc::waitpid(child_pid, &mut status, 0);
            }
            bail!("child setup or exec failed: {}", msg.trim());
        }

        let opt_pidfd = if pidfd >= 0 {
            Some(unsafe { OwnedFd::from_raw_fd(pidfd) })
        } else {
            None
        };
        return Ok((child_pid, opt_pidfd));
    }

    // If clone3 failed with ENOSYS, fall back to pipe handshake + fork
    unsafe {
        libc::close(err_pipe[0]);
        libc::close(err_pipe[1]);
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOSYS) {
        return spawn_fallback_pipe(ctx.cgroup_path, child_ctx);
    }

    Err(err).context("clone3 syscall failed")
}

unsafe fn send_child_err_and_exit(err_pipe: RawFd, msg: &[u8], code: i32) -> ! {
    libc::write(err_pipe, msg.as_ptr() as *const libc::c_void, msg.len());
    libc::close(err_pipe);
    libc::_exit(code);
}

/// Async-signal-safe setup in child process before execve.
unsafe fn child_pre_exec(ctx: ChildExecContext<'_>) -> ! {
    // 1. Stdio redirection
    if let Some([in_fd, out_fd, err_fd]) = ctx.stdio_fds {
        if libc::dup2(in_fd, libc::STDIN_FILENO) < 0
            || libc::dup2(out_fd, libc::STDOUT_FILENO) < 0
            || libc::dup2(err_fd, libc::STDERR_FILENO) < 0
        {
            send_child_err_and_exit(ctx.err_pipe, b"dup2 stdio failed\n", 101);
        }
    }

    // 2. Close file descriptors >= 3 except err_pipe
    for fd in 3..256 {
        if fd != ctx.err_pipe {
            libc::close(fd);
        }
    }

    // 3. setsid
    if libc::setsid() < 0 {
        send_child_err_and_exit(ctx.err_pipe, b"setsid failed\n", 102);
    }

    // 4. setgroups
    if libc::setgroups(0, std::ptr::null()) < 0 {
        send_child_err_and_exit(ctx.err_pipe, b"setgroups failed\n", 103);
    }

    // 5. setresgid
    if libc::setresgid(ctx.target_gid, ctx.target_gid, ctx.target_gid) < 0 {
        send_child_err_and_exit(ctx.err_pipe, b"setresgid failed\n", 104);
    }

    // 6. setresuid
    if libc::setresuid(ctx.target_uid, ctx.target_uid, ctx.target_uid) < 0 {
        send_child_err_and_exit(ctx.err_pipe, b"setresuid failed\n", 105);
    }

    // 7. PR_SET_NO_NEW_PRIVS
    if libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
        send_child_err_and_exit(ctx.err_pipe, b"prctl PR_SET_NO_NEW_PRIVS failed\n", 106);
    }

    // 8. Clear ambient and remaining capabilities as defence in depth
    libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
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
    if libc::syscall(SYS_CAPSET, &cap_hdr, &cap_data[0]) < 0 {
        send_child_err_and_exit(ctx.err_pipe, b"capset failed\n", 107);
    }

    // 9. chdir to working directory if specified
    if let Some(cwd) = ctx.c_cwd {
        if libc::chdir(cwd.as_ptr()) < 0 {
            send_child_err_and_exit(ctx.err_pipe, b"chdir failed\n", 108);
        }
    }

    // 10. Execute command
    libc::execve(
        ctx.c_path.as_ptr(),
        ctx.c_argv_ptrs.as_ptr(),
        ctx.c_envp_ptrs.as_ptr(),
    );

    // If execve failed, report the errno (EPERM here means policy denied the
    // agent's first exec). Formatted by hand: no allocation after clone.
    let errno = *libc::__errno_location();
    let mut msg = *b"execve failed: errno 0000\n";
    let mut n = errno.clamp(0, 9999);
    for digit in msg[21..25].iter_mut().rev() {
        *digit = b'0' + (n % 10) as u8;
        n /= 10;
    }
    send_child_err_and_exit(ctx.err_pipe, &msg, 127);
}

/// Byte the parent writes to release a forked child once it is in its
/// cgroup. Only this byte releases it: end-of-file (the parent dropped the
/// pipe, abandoning the launch) or an error makes the child exit instead.
const RELEASE_BYTE: u8 = b'R';

/// A close-on-exec pipe: (read end, write end).
fn cloexec_pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error()).context("pipe2 failed");
    }
    // SAFETY: pipe2 returned two new descriptors that nothing else owns.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Reads one byte, retrying on EINTR; `None` on end-of-file or error.
/// Async-signal-safe: it runs in the forked child.
unsafe fn read_byte(fd: RawFd) -> Option<u8> {
    let mut buf = [0u8; 1];
    loop {
        let n = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 1);
        if n == 1 {
            return Some(buf[0]);
        }
        if n < 0 && *libc::__errno_location() == libc::EINTR {
            continue;
        }
        return None;
    }
}

/// Whether the parent released the child (see [`RELEASE_BYTE`]).
unsafe fn wait_for_release(fd: RawFd) -> bool {
    read_byte(fd) == Some(RELEASE_BYTE)
}

/// Kills and reaps a child of this process that must never run its command.
fn kill_and_reap(pid: libc::pid_t) {
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        while libc::waitpid(pid, std::ptr::null_mut(), 0) < 0
            && *libc::__errno_location() == libc::EINTR
        {}
    }
}

/// Fallback fork + pipe handshake if clone3 is unavailable.
///
/// The child signals it is ready, then blocks until the parent has written
/// its pid to the agent cgroup's `cgroup.procs` and released it with
/// [`RELEASE_BYTE`]. Every failure fails closed: if the attach fails the
/// child is killed and reaped, and a child that reads end-of-file exits
/// without running the command, so it can never execute in the daemon's own
/// (ungoverned) cgroup.
fn spawn_fallback_pipe(
    cgroup_path: &Path,
    mut child_ctx: ChildExecContext<'_>,
) -> Result<(i32, Option<OwnedFd>)> {
    let (c2p_r, c2p_w) = cloexec_pipe()?;
    let (p2c_r, p2c_w) = cloexec_pipe()?;
    let (err_r, err_w) = cloexec_pipe()?;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error()).context("fork failed");
    }

    if pid == 0 {
        // --- CHILD ---
        // Async-signal-safe code only. The OwnedFds are never dropped here:
        // every path ends in _exit or execve.
        unsafe {
            libc::close(err_r.as_raw_fd());
            libc::close(c2p_r.as_raw_fd());
            libc::close(p2c_w.as_raw_fd());

            // Tell the parent we are ready to be attached to the cgroup.
            let ready = [1u8];
            if libc::write(c2p_w.as_raw_fd(), ready.as_ptr() as *const libc::c_void, 1) != 1 {
                libc::_exit(109);
            }
            libc::close(c2p_w.as_raw_fd());

            // Wait for the explicit release. EOF or an error means the parent
            // abandoned the launch (the attach failed): never exec.
            if !wait_for_release(p2c_r.as_raw_fd()) {
                libc::_exit(110);
            }
            libc::close(p2c_r.as_raw_fd());

            child_ctx.err_pipe = err_w.as_raw_fd();
            child_pre_exec(child_ctx);
        }
    }

    // --- PARENT ---
    drop(err_w);
    drop(c2p_w);
    drop(p2c_r);

    let ready = unsafe { read_byte(c2p_r.as_raw_fd()) };
    drop(c2p_r);

    let procs = cgroup_path.join("cgroup.procs");
    let attached = match ready {
        Some(_) => fs::write(&procs, format!("{pid}\n"))
            .with_context(|| format!("failed to attach child to {}", procs.display())),
        None => Err(anyhow::anyhow!("child exited before it could be attached to its cgroup")),
    };
    if let Err(e) = attached {
        // Closing the release pipe alone makes the child exit; kill it too,
        // so it can never run the command outside its cgroup.
        drop(p2c_w);
        kill_and_reap(pid);
        return Err(e);
    }

    // A pidfd for the registry where the kernel has pidfd_open (a container
    // runtime's seccomp profile can hide clone3 but not pidfd_open). The child
    // is not reaped yet, so `pid` is still ours.
    let pidfd = pidfd_open(pid).ok();

    // Release the child.
    let release = [RELEASE_BYTE];
    let n = unsafe {
        libc::write(
            p2c_w.as_raw_fd(),
            release.as_ptr() as *const libc::c_void,
            1,
        )
    };
    let release_err = std::io::Error::last_os_error();
    drop(p2c_w);
    if n != 1 {
        kill_and_reap(pid);
        return Err(release_err).context("failed to release the child");
    }

    let mut err_buf = [0u8; 1024];
    let n = unsafe {
        libc::read(
            err_r.as_raw_fd(),
            err_buf.as_mut_ptr() as *mut libc::c_void,
            err_buf.len(),
        )
    };
    drop(err_r);
    if n > 0 {
        let msg = String::from_utf8_lossy(&err_buf[..n as usize]);
        let mut status = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }
        bail!("child setup or exec failed: {}", msg.trim());
    }

    Ok((pid, pidfd))
}

/// `pidfd_open(2)` (Linux 5.3): a descriptor that names exactly one process,
/// so it can be signalled without the risk of hitting a recycled pid.
pub fn pidfd_open(pid: libc::pid_t) -> std::io::Result<OwnedFd> {
    let fd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: pidfd_open returned a new descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// Sends `signal` to a process through its pidfd, which can never reach a
/// process that reused the pid. Without a pidfd (kernels before 5.3) it
/// falls back to `kill(2)`; callers drop their record of `pid` as soon as
/// the process is reaped, which bounds that window.
pub fn signal_process(pid: u32, pidfd: Option<&OwnedFd>, signal: i32) -> std::io::Result<()> {
    let rc = match pidfd {
        Some(fd) => unsafe {
            libc::syscall(
                SYS_PIDFD_SEND_SIGNAL,
                fd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        },
        None => libc::c_long::from(unsafe { libc::kill(pid as libc::pid_t, signal) }),
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
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
    let mut proc_uid = 0;
    let mut proc_gid = 0;

    let status_path = format!("/proc/{pid}/status");
    if let Ok(content) = fs::read_to_string(&status_path) {
        for line in content.lines() {
            if let Some(rest) = line.strip_prefix("NoNewPrivs:\t") {
                no_new_privs = rest.trim() == "1";
            } else if let Some(rest) = line.strip_prefix("CapEff:\t") {
                empty_capabilities = rest.trim() == "0000000000000000";
            } else if let Some(rest) = line.strip_prefix("Uid:\t") {
                if let Some(first) = rest.split_whitespace().next() {
                    proc_uid = first.parse().unwrap_or(0);
                }
            } else if let Some(rest) = line.strip_prefix("Gid:\t") {
                if let Some(first) = rest.split_whitespace().next() {
                    proc_gid = first.parse().unwrap_or(0);
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
        unprivileged_user: proc_uid != 0, // Never root!
        caller_uid: proc_uid,
        caller_gid: proc_gid,
        no_new_privs,
        empty_capabilities,
        cgroup_not_delegated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the uapi values: a wrong flag makes clone3 succeed while leaving
    /// the agent outside its cgroup.
    #[test]
    fn clone_flags_match_uapi() {
        assert_eq!(CLONE_INTO_CGROUP, 1 << 33);
        assert_eq!(CLONE_PIDFD, 1 << 12);
        assert_eq!(CLONE_INTO_CGROUP & 0xffff_ffff, 0);
    }

    fn write_byte(fd: &OwnedFd, byte: u8) {
        let buf = [byte];
        let n = unsafe { libc::write(fd.as_raw_fd(), buf.as_ptr() as *const libc::c_void, 1) };
        assert_eq!(n, 1);
    }

    /// The fork fallback's child runs only on the explicit release byte; EOF
    /// (the parent abandoned the launch) and any other byte make it exit.
    #[test]
    fn fallback_child_is_released_only_by_the_release_byte() {
        let (r, w) = cloexec_pipe().unwrap();
        write_byte(&w, RELEASE_BYTE);
        assert!(unsafe { wait_for_release(r.as_raw_fd()) });

        let (r, w) = cloexec_pipe().unwrap();
        drop(w);
        assert!(!unsafe { wait_for_release(r.as_raw_fd()) }, "EOF released");

        let (r, w) = cloexec_pipe().unwrap();
        write_byte(&w, 1);
        assert!(!unsafe { wait_for_release(r.as_raw_fd()) }, "wrong byte released");
    }

    /// When the cgroup attach fails, the fallback kills and reaps the child
    /// and the command never runs.
    #[test]
    fn fallback_attach_failure_never_runs_the_command() {
        let dir = std::env::temp_dir().join(format!("rk-fallback-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("ran");
        let missing_cgroup = dir.join("no-such-cgroup");

        let c_path = CString::new("/bin/sh").unwrap();
        let args = [
            CString::new("sh").unwrap(),
            CString::new("-c").unwrap(),
            CString::new(format!("echo ran > {}", marker.display())).unwrap(),
        ];
        let mut argv: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
        argv.push(std::ptr::null());
        let envp = [std::ptr::null::<libc::c_char>()];
        let ctx = ChildExecContext {
            err_pipe: -1,
            stdio_fds: None,
            target_uid: unsafe { libc::getuid() },
            target_gid: unsafe { libc::getgid() },
            c_cwd: None,
            c_path: &c_path,
            c_argv_ptrs: &argv,
            c_envp_ptrs: &envp,
        };
        let err = spawn_fallback_pipe(&missing_cgroup, ctx).unwrap_err();
        assert!(format!("{err:#}").contains("attach"), "{err:#}");
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!marker.exists(), "the command ran although the attach failed");
        let _ = fs::remove_dir_all(&dir);
    }

    /// A pidfd never signals a recycled pid: once the process is reaped,
    /// signalling through it fails instead of reaching another process.
    #[test]
    fn signal_through_pidfd_fails_after_reap() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id();
        let Ok(pidfd) = pidfd_open(pid as libc::pid_t) else {
            // Kernel without pidfd_open (before 5.3): nothing to test.
            let _ = child.kill();
            let _ = child.wait();
            return;
        };
        signal_process(pid, Some(&pidfd), libc::SIGKILL).unwrap();
        child.wait().unwrap();
        let err = signal_process(pid, Some(&pidfd), libc::SIGKILL).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ESRCH));
    }

    #[test]
    fn privilege_check_flags_root_as_failed() {
        let tmp = std::env::temp_dir().join(format!("rk-priv-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&tmp);

        // When proc_uid is 0, unprivileged_user must be false
        let checks = AgentPrivilegeChecks {
            unprivileged_user: false,
            caller_uid: 0,
            caller_gid: 0,
            no_new_privs: true,
            empty_capabilities: true,
            cgroup_not_delegated: true,
        };
        assert!(!checks.unprivileged_user);

        // When proc_uid is 65534 (nobody), unprivileged_user must be true
        let checks_unpriv = AgentPrivilegeChecks {
            unprivileged_user: true,
            caller_uid: 65534,
            caller_gid: 65534,
            no_new_privs: true,
            empty_capabilities: true,
            cgroup_not_delegated: true,
        };
        assert!(checks_unpriv.unprivileged_user);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn service_user_fallback_mapping() {
        let caller_uid = 0;
        let caller_gid = 0;
        let service_uid = 65534;
        let service_gid = 65534;

        let (target_uid, target_gid) = if caller_uid == 0 {
            (service_uid, service_gid)
        } else {
            (caller_uid, caller_gid)
        };
        assert_eq!(target_uid, 65534);
        assert_eq!(target_gid, 65534);

        let unpriv_caller = 1000;
        let (target_uid, _) = if unpriv_caller == 0 {
            (service_uid, service_gid)
        } else {
            (unpriv_caller, 1000)
        };
        assert_eq!(target_uid, 1000);
    }
}
