//! Unix domain socket server handling CLI client requests.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rk_policy::net::{Profile, K8S_PROFILE_ANNOTATION, K8S_SESSION_ANNOTATION};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::auth::{check_launchable_by, check_policy_admin, get_peer_cred, launch_refusal, PeerCred};
use crate::cgroup::{create_agent_cgroup, drain_and_remove_cgroup, kill_cgroup, open_cgroup_dir};
use crate::launcher::{pidfd_open, signal_process, spawn_in_cgroup};
use crate::protocol::{
    recv_request, send_response, ApplyReportData, CapabilityStatus, DryRunData, Request, Response,
    MAX_MESSAGE_SIZE,
};
use crate::registry::{ActiveAgent, AgentRegistry};

/// What the blocking receive stage hands back: the connection (moved through the
/// blocking task and returned), the peer credentials, and the decoded request
/// with any passed descriptors (`None` if the peer sent nothing).
type ReceivedConnection = (OwnedFd, PeerCred, Option<(Request, Vec<OwnedFd>)>);

/// Maximum time the daemon waits for a client to send its request before the
/// connection is dropped. Legitimate clients send immediately after connecting;
/// this only bounds idle or slow-loris connections so they cannot pin a handler
/// indefinitely.
const RECV_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of connections being handled at once. A slot is taken when a
/// connection is accepted and held while its request is received and
/// dispatched, until its response is sent (for `Run`, until `RunStarted`, which
/// includes waiting for the policy lock and spawning the agent). Beyond this,
/// new connections are shed until a slot frees. This bounds the blocking-pool
/// threads and descriptors a local flood can tie up; it does not limit
/// long-lived agents, whose waiters run as separate tasks after the slot is
/// released.
const MAX_CONCURRENT_RECEIVES: usize = 128;

/// Bounds any single blocking `recvmsg` on `fd` with `SO_RCVTIMEO`. Best-effort:
/// a failure only forgoes the timeout, so it is not treated as fatal.
fn set_recv_timeout(fd: RawFd, timeout: Duration) {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
}

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
    /// Profile for a pod's containers (docs/design/phase-5b.md §4).
    fn resolve_pod_profile(
        &self,
        namespace: &str,
        annotation: Option<&str>,
    ) -> Result<Option<String>>;
    /// Binds a Kubernetes container cgroup (relative to the cgroupfs root).
    fn bind_container(&mut self, cgroup: &str, profile: &str) -> Result<u64>;
    /// Event pipeline counters for `rk status` (Phase 7 §5).
    fn counters(&self) -> BTreeMap<String, u64> {
        BTreeMap::new()
    }
}

/// Server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub socket_path: PathBuf,
    pub cgroup_fs: PathBuf,
    pub service_uid: u32,
    pub service_gid: u32,
    /// Kubernetes cgroup root relative to `cgroup_fs` (Phase 5b). Container
    /// bindings are refused when unset or outside it.
    pub k8s_cgroup_root: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from(crate::protocol::DEFAULT_SOCKET_PATH),
            cgroup_fs: PathBuf::from("/sys/fs/cgroup"),
            service_uid: 65534, // nobody
            service_gid: 65534, // nogroup / nobody
            k8s_cgroup_root: None,
        }
    }
}

/// The container's cgroup, relative to the cgroupfs root, from the text of
/// `/proc/<pid>/cgroup`. It must lie under the Kubernetes cgroup `root`.
pub fn container_cgroup(proc_cgroup: &str, root: &str) -> Result<String> {
    let path = proc_cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .context("no cgroup v2 entry in /proc/<pid>/cgroup")?;
    let rel = path.trim_start_matches('/');
    let root = root.trim_matches('/');
    if root.is_empty()
        || !rel.starts_with(&format!("{root}/"))
        || rel
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
    {
        bail!("container cgroup `{path}` is not under the Kubernetes cgroup root `{root}`");
    }
    Ok(rel.to_string())
}

/// Whether a container's cgroup (relative to the cgroupfs root, under the
/// Kubernetes `root`) names `container_id`: some segment below the root is
/// the id itself (cgroupfs driver) or contains it as `-<id>` followed by the
/// end or a `.` (systemd driver: `cri-containerd-<id>.scope`,
/// `crio-<id>.scope`, `docker-<id>.scope`). This ties a binding to the
/// container NRI asked about: a pid recycled into another workload resolves to
/// a cgroup that does not name this container, and is refused.
pub fn cgroup_names_container(cgroup: &str, root: &str, container_id: &str) -> bool {
    if container_id.is_empty() {
        return false;
    }
    let Some(below) = cgroup.strip_prefix(root.trim_matches('/')) else {
        return false;
    };
    below.split('/').any(|segment| {
        segment.match_indices(container_id).any(|(i, _)| {
            let before = segment[..i].chars().next_back();
            let after = segment[i + container_id.len()..].chars().next();
            matches!(before, None | Some('-')) && matches!(after, None | Some('.'))
        })
    })
}

/// Why a just-spawned agent's placement is not confirmed, from the text of its
/// `/proc/<pid>/cgroup` (`None` when it could not be read), or `None` when it
/// is in `expected`. Anything but a positive match fails the launch.
pub fn placement_problem(proc_cgroup: Option<&str>, expected: &str) -> Option<String> {
    let Some(text) = proc_cgroup else {
        return Some("its /proc/<pid>/cgroup is unreadable".into());
    };
    match text.lines().find_map(|l| l.strip_prefix("0::")) {
        Some(actual) if actual == expected => None,
        Some(actual) => Some(format!("it is in cgroup {actual}, not {expected}")),
        None => Some("its /proc/<pid>/cgroup has no cgroup v2 entry".into()),
    }
}

async fn bind_container(
    handler: &Arc<Mutex<dyn PolicyHandler>>,
    registry: &AgentRegistry,
    config: &ServerConfig,
    pid: u32,
    namespace: &str,
    annotations: &BTreeMap<String, String>,
    container_id: &str,
) -> Result<Option<(u64, String)>> {
    let mut h = handler.lock().await;
    let annotation = annotations.get(K8S_PROFILE_ANNOTATION).map(String::as_str);
    let Some(profile) = h.resolve_pod_profile(namespace, annotation)? else {
        return Ok(None);
    };
    if pid == 0 {
        bail!("container has no process yet (pid 0); refusing to start it ungoverned");
    }
    let root = config
        .k8s_cgroup_root
        .as_deref()
        .context("this daemon has no Kubernetes cgroup root (start it with --k8s-cgroup-root)")?;
    if container_id.is_empty() {
        bail!("container has no id; refusing to start it ungoverned");
    }
    // The pid comes from the runtime and may have been recycled by now. Hold
    // the process with a pidfd while its cgroup is read (checked below), and
    // require the cgroup to name the container: together they refuse binding
    // whatever workload now owns the pid. Without pidfd_open (before Linux
    // 5.3) only the name check applies.
    let pidfd = pidfd_open(pid as libc::pid_t);
    if let Err(e) = &pidfd {
        if e.raw_os_error() == Some(libc::ESRCH) {
            bail!("container process {pid} has exited; refusing to start it ungoverned");
        }
    }
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .with_context(|| format!("read /proc/{pid}/cgroup"))?;
    let cgroup = container_cgroup(&text, root)?;
    if !cgroup_names_container(&cgroup, root, container_id) {
        bail!(
            "process {pid} is in cgroup `{cgroup}`, which does not name container \
             {container_id} (pid reused?); refusing to bind it"
        );
    }
    if let Ok(fd) = &pidfd {
        if signal_process(pid, Some(fd), 0).is_err() {
            bail!("container process {pid} exited while its cgroup was read; refusing to bind it");
        }
    }
    let id = h.bind_container(&cgroup, &profile)?;
    registry.register_container(
        container_id,
        id,
        annotations.get(K8S_SESSION_ANNOTATION).cloned(),
    );
    Ok(Some((id, profile)))
}

/// Start the agent daemon socket server.
pub async fn run_server(
    config: ServerConfig,
    handler: Arc<Mutex<dyn PolicyHandler>>,
    registry: Arc<AgentRegistry>,
) -> Result<()> {
    if let Some(parent) = config.socket_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create socket dir {}", parent.display()))?;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o755));
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

    // The accept loop blocks in poll(2), so it runs on a blocking thread and
    // hands each connection to the runtime with Handle::spawn, which any idle
    // worker picks up at once. Spawning from inside a worker that then blocks
    // parks the new task in that worker's LIFO slot, which other workers
    // cannot steal: every request used to wait for the poll timeout (~500 ms,
    // half of rk-nri's budget per NRI call).
    // Cap how many connections may be in flight at once (see the accept loop).
    let recv_slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_RECEIVES));

    let rt = tokio::runtime::Handle::current();
    let accept_loop = tokio::task::spawn_blocking(move || -> Result<()> {
        let raw_listener = listener.as_raw_fd();
        loop {
            let mut pollfd = libc::pollfd {
                fd: raw_listener,
                events: libc::POLLIN,
                revents: 0,
            };
            let poll_res = unsafe { libc::poll(&mut pollfd, 1, 1000) };
            if poll_res < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err).context("poll on the agentd socket failed");
            }
            if poll_res == 0 || (pollfd.revents & libc::POLLIN) == 0 {
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

            // Bound the initial blocking receive so a slow or idle client cannot
            // pin a handler indefinitely (control-plane DoS).
            set_recv_timeout(client.as_raw_fd(), RECV_TIMEOUT);

            // Shed load: cap how many connections may be in flight at once, so a
            // flood of idle connections cannot exhaust the blocking pool or the
            // descriptor table. The permit covers the whole request, not just
            // the receive: it is held until the response is sent (for Run, until
            // RunStarted), and released before a long-lived Run's waiter task.
            let permit = match recv_slots.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!("agentd receive slots exhausted; shedding a connection");
                    continue;
                }
            };

            let handler_clone = handler.clone();
            let registry_clone = registry.clone();
            let config_clone = Arc::new(config.clone());

            rt.spawn(async move {
                let _permit = permit;
                if let Err(e) =
                    handle_connection(client, handler_clone, registry_clone, config_clone).await
                {
                    warn!(error = %e, "error handling client connection");
                }
            });
        }
    });
    accept_loop.await.context("agentd accept loop panicked")?
}

async fn handle_connection(
    client: OwnedFd,
    handler: Arc<Mutex<dyn PolicyHandler>>,
    registry: Arc<AgentRegistry>,
    config: Arc<ServerConfig>,
) -> Result<()> {
    // Read the peer credentials and the request on the blocking pool (bounded by
    // SO_RCVTIMEO), so a slow or idle client blocks a short-lived blocking-pool
    // thread rather than an async runtime worker.
    let (client, cred, received) =
        tokio::task::spawn_blocking(move || -> Result<ReceivedConnection> {
            let cred = get_peer_cred(client.as_raw_fd())?;
            let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
            let received = recv_request(client.as_raw_fd(), &mut buf)?;
            Ok((client, cred, received))
        })
        .await
        .context("agentd receive task panicked")??;

    debug!(?cred, "accepted client connection");

    let (req, fds) = match received {
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
            if let Err(e) = check_policy_admin(&cred) {
                return send_response(
                    client.as_raw_fd(),
                    &Response::Error {
                        message: e.to_string(),
                    },
                );
            }
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
            if let Err(e) = check_policy_admin(&cred) {
                return send_response(
                    client.as_raw_fd(),
                    &Response::Error {
                        message: e.to_string(),
                    },
                );
            }
            let handler_lock = handler.lock().await;
            let mut status = registry.build_status(
                true,
                handler_lock.generation(),
                handler_lock.active_profiles(),
                handler_lock.capabilities(),
            );
            status.counters = handler_lock.counters();
            send_response(client.as_raw_fd(), &Response::StatusSuccess { status })
        }
        Request::Signal { agent_id, signal } => {
            if let Some(agent) = registry.get(&agent_id) {
                // Authorised if root, in group rk, or owner
                if cred.uid == 0
                    || cred.uid == agent.caller_uid
                    || check_policy_admin(&cred).is_ok()
                {
                    // Through the agent's pidfd: once it is reaped the signal
                    // fails, rather than reaching whatever reused its pid.
                    match signal_process(agent.pid, agent.pidfd.as_deref(), signal) {
                        Ok(()) => send_response(client.as_raw_fd(), &Response::SignalSuccess),
                        Err(e) => send_response(
                            client.as_raw_fd(),
                            &Response::Error {
                                message: format!("cannot signal agent {agent_id}: {e}"),
                            },
                        ),
                    }
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
        Request::BindContainer {
            pid,
            namespace,
            pod,
            pod_uid: _,
            container,
            container_id,
            annotations,
        } => {
            let resp = if cred.uid != 0 {
                Response::Error {
                    message: format!(
                        "caller uid {} may not bind containers (root only)",
                        cred.uid
                    ),
                }
            } else {
                match bind_container(
                    &handler,
                    &registry,
                    &config,
                    pid,
                    &namespace,
                    &annotations,
                    &container_id,
                )
                .await
                {
                    Ok(Some((cgroup_id, profile))) => {
                        info!(%namespace, %pod, %container, %profile, cgroup_id, "container bound");
                        Response::ContainerBound { cgroup_id, profile }
                    }
                    Ok(None) => Response::NotGoverned,
                    Err(e) => {
                        warn!(%namespace, %pod, %container, error = %format!("{e:#}"), "container refused");
                        Response::Error {
                            message: format!("{e:#}"),
                        }
                    }
                }
            };
            send_response(client.as_raw_fd(), &resp)
        }
        Request::UnbindContainer { container_id } => {
            let resp = if cred.uid != 0 {
                Response::Error {
                    message: format!(
                        "caller uid {} may not unbind containers (root only)",
                        cred.uid
                    ),
                }
            } else {
                if let Some(id) = registry.unregister_container(&container_id) {
                    let _ = handler.lock().await.unbind_dynamic(id);
                    info!(%container_id, cgroup_id = id, "container unbound");
                }
                Response::ContainerUnbound
            };
            send_response(client.as_raw_fd(), &resp)
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
    mut ctx: RunContext,
    handler: Arc<Mutex<dyn PolicyHandler>>,
    registry: Arc<AgentRegistry>,
    config: Arc<ServerConfig>,
) -> Result<()> {
    // 1. Authorisation and validation
    let (_profile_def, rel_cgroup, cgroup_path, cgroup_id, cgroup_dir_fd) = {
        let mut handler_lock = handler.lock().await;
        // An unknown profile and one the caller may not launch are refused
        // with the same message, so a caller cannot probe which profiles
        // exist (see `launch_refusal`).
        let profile_def = match handler_lock
            .get_profile(&ctx.profile_name)
            .and_then(|p| check_launchable_by(&ctx.cred, &p).map(|()| p))
        {
            Ok(p) => p,
            Err(e) => {
                let resp = Response::Error {
                    message: launch_refusal(&ctx.cred, &ctx.profile_name, &e),
                };
                send_response(ctx.client.as_raw_fd(), &resp)?;
                return Ok(());
            }
        };

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

    // The session's trace context (docs/design/phase-9.md §3.6), so an
    // instrumented agent's spans join the trace of its kernel decisions.
    // A TRACEPARENT the caller set is kept.
    if let Some(session) = &ctx.session {
        if !ctx.env.iter().any(|(k, _)| k == "TRACEPARENT") {
            ctx.env
                .push(("TRACEPARENT".into(), crate::trace::traceparent(session)));
        }
    }

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

    let (pid, pidfd) = match spawn_res {
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
    let pidfd = pidfd.map(Arc::new);

    // Fail closed: an agent that cannot be shown to be in its cgroup may be
    // ungoverned. clone3 guarantees placement, so a mismatch means a launcher
    // bug. The child is not reaped yet, so even one that already exited still
    // has a readable /proc/<pid>/cgroup: an unreadable one is a failed launch.
    let expected = format!("/{rel_cgroup}");
    let placement = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok();
    if let Some(problem) = placement_problem(placement.as_deref(), &expected) {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        let mut handler_lock = handler.lock().await;
        let _ = handler_lock.unbind_dynamic(cgroup_id);
        let _ = fs::remove_dir(&cgroup_path);
        error!(pid, %problem, %expected, "agent placement not confirmed; killed");
        let resp = Response::Error {
            message: format!("agent placement not confirmed ({problem}); killed it"),
        };
        send_response(ctx.client.as_raw_fd(), &resp)?;
        return Ok(());
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
        pidfd: pidfd.clone(),
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
                    let _ = signal_process(pid as u32, pidfd.as_deref(), signal);
                }
            }
            if poll_res > 0 && (pollfd.revents & libc::POLLHUP) != 0 {
                // Client disconnected -> kill agent
                let _ = kill_cgroup(&cgroup_path_clone);
            }

            std::thread::sleep(Duration::from_millis(5));
        }

        // The agent is reaped: its pid may be reused from now on, so drop the
        // registry entry at once, before the slower cleanup below, and no
        // Signal request can be aimed at the pid any more.
        registry_clone.unregister(&agent_id);

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

        // d. Send exit notification to client
        let exit_resp = Response::RunExited { exit_code };
        let _ = send_response(client_fd, &exit_resp);
        drop(client);
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_cgroup_must_be_under_root() {
        let root = "kubepods.slice";
        let ok = "0::/kubepods.slice/kubepods-besteffort.slice/cri-containerd-abc.scope\n";
        assert_eq!(
            container_cgroup(ok, root).unwrap(),
            "kubepods.slice/kubepods-besteffort.slice/cri-containerd-abc.scope"
        );
        // cgroup v1 lines before the v2 one are skipped.
        let mixed = format!("12:cpu:/x\n{ok}");
        assert!(container_cgroup(&mixed, "/kubepods.slice/").is_ok());
        for bad in [
            "0::/\n",                               // root cgroup
            "0::/kubepods.slice\n",                 // the root itself, not a container
            "0::/system.slice/evil.scope\n",        // elsewhere
            "0::/kubepods.slicex/c\n",              // prefix trick
            "0::/../../kubepods.slice/c\n",         // outside our cgroup namespace
            "0::/kubepods.slice/../system.slice\n", // traversal
            "12:cpu:/kubepods.slice/c\n",           // no v2 entry
        ] {
            assert!(container_cgroup(bad, root).is_err(), "{bad:?}");
        }
        assert!(container_cgroup(ok, "").is_err());
    }

    /// A binding is accepted only for a cgroup that names the container, so
    /// a recycled pid in another workload's cgroup is refused.
    #[test]
    fn container_cgroup_must_name_the_container() {
        let root = "kubepods.slice";
        let id = "4f1c0a9b7e2d";
        for ok in [
            "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod1.slice/cri-containerd-4f1c0a9b7e2d.scope",
            "kubepods.slice/kubepods-pod1.slice/crio-4f1c0a9b7e2d.scope",
            "kubepods.slice/kubepods-pod1.slice/docker-4f1c0a9b7e2d.scope/init",
            "kubepods.slice/besteffort/pod1/4f1c0a9b7e2d",
        ] {
            assert!(cgroup_names_container(ok, root, id), "{ok}");
        }
        for bad in [
            // Another container: the pid was recycled.
            "kubepods.slice/kubepods-pod1.slice/cri-containerd-0123456789ab.scope",
            // The id only as part of a longer one.
            "kubepods.slice/kubepods-pod1.slice/cri-containerd-x4f1c0a9b7e2d.scope",
            "kubepods.slice/kubepods-pod1.slice/cri-containerd-4f1c0a9b7e2dff.scope",
            // Only in the root, not below it.
            "kubepods.slice",
        ] {
            assert!(!cgroup_names_container(bad, root, id), "{bad}");
        }
        assert!(!cgroup_names_container(
            "kubepods.slice/kubepods-pod1.slice/cri-containerd-.scope",
            root,
            ""
        ));
    }

    /// The post-spawn check fails closed: only a positive match passes.
    #[test]
    fn placement_check_fails_closed() {
        let expected = "/rk.slice/agent-1";
        assert_eq!(placement_problem(Some("0::/rk.slice/agent-1\n"), expected), None);
        assert_eq!(
            placement_problem(Some("12:cpu:/x\n0::/rk.slice/agent-1\n"), expected),
            None
        );
        for bad in [
            Some("0::/system.slice/rk-sensor.service\n"),
            Some("0::/rk.slice/agent-1/child\n"),
            Some("12:cpu:/rk.slice/agent-1\n"),
            Some(""),
            None,
        ] {
            assert!(placement_problem(bad, expected).is_some(), "{bad:?}");
        }
    }
}
