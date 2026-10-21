//! Unix domain socket server handling CLI client requests.

use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rk_policy::net::Profile;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::auth::{check_launchable_by, check_policy_admin, get_peer_cred, PeerCred};
use crate::cgroup::{create_agent_cgroup, drain_and_remove_cgroup, kill_cgroup, open_cgroup_dir};
use crate::launcher::spawn_in_cgroup;
use crate::protocol::{
    recv_request, send_response, ApplyReportData, CapabilityStatus, DryRunData, Request, Response,
    MAX_MESSAGE_SIZE,
};
use crate::registry::{ActiveAgent, AgentRegistry};

/// Trait implemented by `rk-sensor` daemon to drive policy operations.
pub trait PolicyHandler: Send + Sync {
    fn apply(&mut self, text: &str) -> Result<ApplyReportData>;
    fn dry_run(&self, text: &str) -> Result<DryRunData>;
    fn diff(&self, text: &str) -> Result<Vec<String>>;
    fn rollback(&mut self) -> Result<ApplyReportData>;
    fn bind_dynamic(&mut self, cgroup: &str, profile: &str) -> Result<u64>;
    fn unbind_dynamic(&mut self, cgroup_id: u64) -> Result<()>;
    fn get_profile(&self, name: &str) -> Result<Profile>;
    fn active_profiles(&self) -> Vec<String>;
    fn generation(&self) -> u64;
    fn capabilities(&self) -> Vec<CapabilityStatus>;
}

/// Server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub socket_path: PathBuf,
    pub cgroup_fs: PathBuf,
    pub service_uid: u32,
    pub service_gid: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from(crate::protocol::DEFAULT_SOCKET_PATH),
            cgroup_fs: PathBuf::from("/sys/fs/cgroup"),
            service_uid: 65534, // nobody
            service_gid: 65534, // nogroup / nobody
        }
    }
}

/// Start the agent daemon socket server.
pub async fn run_server(
    config: ServerConfig,
    handler: Arc<Mutex<dyn PolicyHandler>>,
    registry: Arc<AgentRegistry>,
) -> Result<()> {
    if let Some(parent) = config.socket_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create socket dir {}", parent.display()))?;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o755));
        }
    }

    if config.socket_path.exists() {
        let _ = fs::remove_file(&config.socket_path);
    }

    let sock_fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if sock_fd < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to create SOCK_SEQPACKET");
    }
    let listener = unsafe { OwnedFd::from_raw_fd(sock_fd) };

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path_bytes = config.socket_path.as_os_str().as_bytes();
    if path_bytes.len() >= addr.sun_path.len() {
        bail!("socket path is too long: {}", config.socket_path.display());
    }
    unsafe {
        std::ptr::copy_nonoverlapping(
            path_bytes.as_ptr() as *const libc::c_char,
            addr.sun_path.as_mut_ptr(),
            path_bytes.len(),
        );
    }

    let addr_len =
        (std::mem::size_of::<libc::sa_family_t>() + path_bytes.len() + 1) as libc::socklen_t;

    let bind_res = unsafe {
        libc::bind(
            listener.as_raw_fd(),
            &addr as *const _ as *const libc::sockaddr,
            addr_len,
        )
    };
    if bind_res != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("bind failed on {}", config.socket_path.display()));
    }

    // Set socket permissions to 0666 so local users can connect and run agents
    let c_path = CString::new(path_bytes)?;
    unsafe {
        libc::chmod(c_path.as_ptr(), 0o666);
    }

    let listen_res = unsafe { libc::listen(listener.as_raw_fd(), 128) };
    if listen_res != 0 {
        return Err(std::io::Error::last_os_error()).context("listen failed");
    }

    info!(
        socket = %config.socket_path.display(),
        "agentd socket server listening"
    );

    let raw_listener = listener.as_raw_fd();
    // Keep listener alive by not dropping it
    let _listener_keepalive = listener;

    loop {
        // Poll for incoming connection
        let mut pollfd = libc::pollfd {
            fd: raw_listener,
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_res = unsafe { libc::poll(&mut pollfd, 1, 500) };
        if poll_res < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            error!(error = %err, "poll on socket failed");
            break;
        }
        if poll_res == 0 || (pollfd.revents & libc::POLLIN) == 0 {
            tokio::task::yield_now().await;
            continue;
        }

        let client_fd = unsafe {
            libc::accept4(
                raw_listener,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if client_fd < 0 {
            continue;
        }

        let client = unsafe { OwnedFd::from_raw_fd(client_fd) };
        let handler_clone = handler.clone();
        let registry_clone = registry.clone();
        let config_clone = Arc::new(config.clone());

        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(client, handler_clone, registry_clone, config_clone).await
            {
                warn!(error = %e, "error handling client connection");
            }
        });
    }

    Ok(())
}

async fn handle_connection(
    client: OwnedFd,
    handler: Arc<Mutex<dyn PolicyHandler>>,
    registry: Arc<AgentRegistry>,
    config: Arc<ServerConfig>,
) -> Result<()> {
    let cred = get_peer_cred(client.as_raw_fd())?;
    debug!(?cred, "accepted client connection");

    let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
    let (req, fds) = match recv_request(client.as_raw_fd(), &mut buf)? {
        Some(pair) => pair,
        None => return Ok(()),
    };

    match req {
        Request::Run {
            profile,
            session,
            cwd,
            cmd,
            env,
        } => {
            let run_ctx = RunContext {
                client,
                cred,
                profile_name: profile,
                session,
                cwd,
                cmd,
                env,
                passed_fds: fds,
            };
            handle_run(run_ctx, handler, registry, config).await
        }
        Request::Apply {
            policy_text,
            dry_run,
        } => {
            if let Err(e) = check_policy_admin(&cred) {
                let resp = Response::Error {
                    message: e.to_string(),
                };
                return send_response(client.as_raw_fd(), &resp);
            }

            if dry_run {
                let handler_lock = handler.lock().await;
                match handler_lock.dry_run(&policy_text) {
                    Ok(dry_run_data) => send_response(
                        client.as_raw_fd(),
                        &Response::DryRunSuccess {
                            dry_run: dry_run_data,
                        },
                    ),
                    Err(e) => send_response(
                        client.as_raw_fd(),
                        &Response::Error {
                            message: format!("{e:#}"),
                        },
                    ),
                }
            } else {
                let mut handler_lock = handler.lock().await;
                match handler_lock.apply(&policy_text) {
                    Ok(report) => {
                        send_response(client.as_raw_fd(), &Response::ApplySuccess { report })
                    }
                    Err(e) => send_response(
                        client.as_raw_fd(),
                        &Response::Error {
                            message: format!("{e:#}"),
                        },
                    ),
                }
            }
        }
        Request::Diff { policy_text } => {
            let handler_lock = handler.lock().await;
            match handler_lock.diff(&policy_text) {
                Ok(diff) => send_response(client.as_raw_fd(), &Response::DiffSuccess { diff }),
                Err(e) => send_response(
                    client.as_raw_fd(),
                    &Response::Error {
                        message: format!("{e:#}"),
                    },
                ),
            }
        }
        Request::Rollback => {
            if let Err(e) = check_policy_admin(&cred) {
                let resp = Response::Error {
                    message: e.to_string(),
                };
                return send_response(client.as_raw_fd(), &resp);
            }
            let mut handler_lock = handler.lock().await;
            match handler_lock.rollback() {
                Ok(report) => {
                    send_response(client.as_raw_fd(), &Response::RollbackSuccess { report })
                }
                Err(e) => send_response(
                    client.as_raw_fd(),
                    &Response::Error {
                        message: format!("{e:#}"),
                    },
                ),
            }
        }
        Request::Status => {
            let handler_lock = handler.lock().await;
            let status = registry.build_status(
                true,
                handler_lock.generation(),
                handler_lock.active_profiles(),
                handler_lock.capabilities(),
            );
            send_response(client.as_raw_fd(), &Response::StatusSuccess { status })
        }
        Request::Signal { agent_id, signal } => {
            if let Some(agent) = registry.get(&agent_id) {
                // Authorised if root, in group rk, or owner
                if cred.uid == 0
                    || cred.uid == agent.caller_uid
                    || check_policy_admin(&cred).is_ok()
                {
                    unsafe {
                        libc::kill(agent.pid as i32, signal);
                    }
                    send_response(client.as_raw_fd(), &Response::SignalSuccess)
                } else {
                    send_response(
                        client.as_raw_fd(),
                        &Response::Error {
                            message: format!("not authorised to signal agent {agent_id}"),
                        },
                    )
                }
            } else {
                send_response(
                    client.as_raw_fd(),
                    &Response::Error {
                        message: format!("agent `{agent_id}` not found"),
                    },
                )
            }
        }
    }
}

struct RunContext {
    client: OwnedFd,
    cred: PeerCred,
    profile_name: String,
    session: Option<String>,
    cwd: Option<String>,
    cmd: Vec<String>,
    env: Vec<(String, String)>,
    passed_fds: Vec<OwnedFd>,
}

async fn handle_run(
    ctx: RunContext,
    handler: Arc<Mutex<dyn PolicyHandler>>,
    registry: Arc<AgentRegistry>,
    config: Arc<ServerConfig>,
) -> Result<()> {
    // 1. Authorisation and validation
    let (_profile_def, rel_cgroup, cgroup_path, cgroup_id, cgroup_dir_fd) = {
        let mut handler_lock = handler.lock().await;
        let profile_def = match handler_lock.get_profile(&ctx.profile_name) {
            Ok(p) => p,
            Err(e) => {
                let resp = Response::Error {
                    message: format!("{e:#}"),
                };
                send_response(ctx.client.as_raw_fd(), &resp)?;
                return Ok(());
            }
        };

        if let Err(e) = check_launchable_by(&ctx.cred, &profile_def) {
            let resp = Response::Error {
                message: format!("{e:#}"),
            };
            send_response(ctx.client.as_raw_fd(), &resp)?;
            return Ok(());
        }

        // 2. Create agent cgroup directly in cgroupfs
        let uuid = Uuid::new_v4().to_string();
        let rel_cgroup = crate::cgroup::agent_cgroup_rel(&uuid);
        let (cgroup_path, _) = match create_agent_cgroup(&config.cgroup_fs, &uuid) {
            Ok(pair) => pair,
            Err(e) => {
                let resp = Response::Error {
                    message: format!("failed to create cgroup: {e:#}"),
                };
                send_response(ctx.client.as_raw_fd(), &resp)?;
                return Ok(());
            }
        };

        // 3. Bind cgroup to profile before process exists
        let cgroup_id = match handler_lock.bind_dynamic(&rel_cgroup, &ctx.profile_name) {
            Ok(id) => id,
            Err(e) => {
                let _ = fs::remove_dir(&cgroup_path);
                let resp = Response::Error {
                    message: format!("failed to bind profile: {e:#}"),
                };
                send_response(ctx.client.as_raw_fd(), &resp)?;
                return Ok(());
            }
        };

        let cgroup_dir_fd = match open_cgroup_dir(&cgroup_path) {
            Ok(fd) => fd,
            Err(e) => {
                let _ = handler_lock.unbind_dynamic(cgroup_id);
                let _ = fs::remove_dir(&cgroup_path);
                let resp = Response::Error {
                    message: format!("failed to open cgroup dir: {e:#}"),
                };
                send_response(ctx.client.as_raw_fd(), &resp)?;
                return Ok(());
            }
        };

        (
            profile_def,
            rel_cgroup,
            cgroup_path,
            cgroup_id,
            cgroup_dir_fd,
        )
    };

    // 4. Extract stdio file descriptors if passed
    let stdio_fds = if ctx.passed_fds.len() >= 3 {
        Some([
            ctx.passed_fds[0].as_raw_fd(),
            ctx.passed_fds[1].as_raw_fd(),
            ctx.passed_fds[2].as_raw_fd(),
        ])
    } else {
        None
    };

    // 5. Never run agents as root: map root caller to configured service user
    let (target_uid, target_gid) = if ctx.cred.uid == 0 {
        (config.service_uid, config.service_gid)
    } else {
        (ctx.cred.uid, ctx.cred.gid)
    };

    // 6. Spawn unprivileged process directly into cgroup
    let spawn_res = spawn_in_cgroup(crate::launcher::SpawnContext {
        cgroup_fd: cgroup_dir_fd.as_raw_fd(),
        cgroup_path: &cgroup_path,
        target_uid,
        target_gid,
        cwd: ctx.cwd.as_deref(),
        stdio_fds,
        cmd: &ctx.cmd,
        env: &ctx.env,
    });

    let (pid, _pidfd) = match spawn_res {
        Ok(res) => res,
        Err(e) => {
            let mut handler_lock = handler.lock().await;
            let _ = handler_lock.unbind_dynamic(cgroup_id);
            let _ = fs::remove_dir(&cgroup_path);
            let resp = Response::Error {
                message: format!("failed to spawn agent: {e:#}"),
            };
            send_response(ctx.client.as_raw_fd(), &resp)?;
            return Ok(());
        }
    };

    // Fail closed: an agent seen outside its cgroup is ungoverned. clone3
    // guarantees placement, so this only fires on a launcher bug. A child that
    // already exited cannot be checked and is not treated as misplaced.
    if let Ok(cg) = fs::read_to_string(format!("/proc/{pid}/cgroup")) {
        let expected = format!("/{rel_cgroup}");
        if let Some(actual) = cg.lines().find_map(|l| l.strip_prefix("0::")) {
            if actual != expected {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, std::ptr::null_mut(), 0);
                }
                let mut handler_lock = handler.lock().await;
                let _ = handler_lock.unbind_dynamic(cgroup_id);
                let _ = fs::remove_dir(&cgroup_path);
                error!(pid, actual, %expected, "agent started outside its cgroup; killed");
                let resp = Response::Error {
                    message: format!("agent started in cgroup {actual}, not {expected}; killed it"),
                };
                send_response(ctx.client.as_raw_fd(), &resp)?;
                return Ok(());
            }
        }
    }

    let agent_id = rel_cgroup
        .split('/')
        .next_back()
        .unwrap_or("agent")
        .to_string();

    let agent = ActiveAgent {
        agent_id: agent_id.clone(),
        pid: pid as u32,
        profile: ctx.profile_name,
        session_id: ctx.session,
        cgroup_rel: rel_cgroup.clone(),
        cgroup_path: cgroup_path.clone(),
        cgroup_id,
        caller_uid: ctx.cred.uid,
        caller_gid: ctx.cred.gid,
        target_uid,
        target_gid,
    };
    registry.register(agent);

    // 6. Notify client that agent has started
    let resp = Response::RunStarted {
        agent_id: agent_id.clone(),
        pid: pid as u32,
        cgroup_id,
    };
    send_response(ctx.client.as_raw_fd(), &resp)?;

    // 7. Wait for process exit or incoming signal requests. The waiter owns the
    // connection: it must stay open until `RunExited` is sent, and a closed fd
    // number could otherwise be reused by another client.
    let client = ctx.client;
    let handler_clone = handler.clone();
    let registry_clone = registry.clone();
    let cgroup_path_clone = cgroup_path.clone();

    // Background waiter task for process termination
    tokio::task::spawn_blocking(move || {
        let client_fd = client.as_raw_fd();
        let mut status = 0;
        let mut exit_code = 1;

        // Loop waitpid while checking for incoming client signals
        loop {
            let wait_res = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if wait_res == pid {
                // Main agent process exited
                if libc::WIFEXITED(status) {
                    exit_code = libc::WEXITSTATUS(status);
                } else if libc::WIFSIGNALED(status) {
                    exit_code = 128 + libc::WTERMSIG(status);
                }
                break;
            } else if wait_res < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EINTR) {
                    break;
                }
            }

            // Check if client sent a signal request or disconnected
            let mut pollfd = libc::pollfd {
                fd: client_fd,
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            };
            let poll_res = unsafe { libc::poll(&mut pollfd, 1, 10) };
            if poll_res > 0 && (pollfd.revents & libc::POLLIN) != 0 {
                let mut buf = vec![0u8; 4096];
                if let Ok(Some((Request::Signal { signal, .. }, _))) =
                    recv_request(client_fd, &mut buf)
                {
                    unsafe {
                        libc::kill(pid, signal);
                    }
                }
            }
            if poll_res > 0 && (pollfd.revents & libc::POLLHUP) != 0 {
                // Client disconnected -> kill agent
                let _ = kill_cgroup(&cgroup_path_clone);
            }

            std::thread::sleep(Duration::from_millis(5));
        }

        // Cleanup sequence:
        // a. Kill any remaining processes in cgroup
        let _ = kill_cgroup(&cgroup_path_clone);

        // b. Unbind dynamic cgroup from eBPF map
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let mut lock = handler_clone.lock().await;
            let _ = lock.unbind_dynamic(cgroup_id);
        });

        // c. Drain and remove cgroup directory
        let _ = drain_and_remove_cgroup(&cgroup_path_clone, Duration::from_secs(2));

        // d. Unregister from active registry
        registry_clone.unregister(&agent_id);

        // e. Send exit notification to client
        let exit_resp = Response::RunExited { exit_code };
        let _ = send_response(client_fd, &exit_resp);
        drop(client);
    });

    Ok(())
}
