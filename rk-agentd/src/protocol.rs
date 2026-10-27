//! Protocol types and socket transport for `rk-agentd`.

use std::collections::BTreeMap;
use std::fmt;
use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// Default Unix domain socket path for communication with `rk-sensor`.
pub const DEFAULT_SOCKET_PATH: &str = "/run/rk/agentd.sock";

/// Maximum datagram payload size in bytes (1 MB).
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Requests sent from `rk` CLI (or other clients) to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Request {
    /// Launch an agent under the given profile and optional session id.
    Run {
        profile: String,
        session: Option<String>,
        cwd: Option<String>,
        cmd: Vec<String>,
        env: Vec<(String, String)>,
    },
    /// Apply policy text atomically, or perform dry-run validation.
    Apply { policy_text: String, dry_run: bool },
    /// Diff policy text against currently active policy.
    Diff { policy_text: String },
    /// Rollback policy to previous generation.
    Rollback,
    /// Query status of daemon, active policy, running agents, and capabilities.
    Status,
    /// Forward a signal to a running agent.
    Signal { agent_id: String, signal: i32 },
    /// Bind a Kubernetes container to its pod's profile, sent by `rk-nri` from
    /// NRI `StartContainer`: the task exists and its command has not run.
    /// Root only. Wire format is shared with the Go plugin (rk-nri/protocol.go).
    BindContainer {
        pid: u32,
        namespace: String,
        pod: String,
        pod_uid: String,
        container: String,
        container_id: String,
        annotations: BTreeMap<String, String>,
    },
    /// Remove a container's binding (NRI `StopContainer` / `RemoveContainer`).
    UnbindContainer { container_id: String },
}

/// Responses sent from the daemon to the client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Response {
    /// Agent launched successfully into its cgroup.
    RunStarted {
        agent_id: String,
        pid: u32,
        cgroup_id: u64,
    },
    /// Agent main process has exited.
    RunExited { exit_code: i32 },
    /// Policy applied successfully.
    ApplySuccess { report: ApplyReportData },
    /// Dry run completed successfully.
    DryRunSuccess { dry_run: DryRunData },
    /// Policy diff completed successfully.
    DiffSuccess { diff: Vec<String> },
    /// Policy rolled back successfully.
    RollbackSuccess { report: ApplyReportData },
    /// Daemon status query result.
    StatusSuccess { status: DaemonStatus },
    /// Signal delivered successfully.
    SignalSuccess,
    /// Container bound; its command may start.
    ContainerBound { cgroup_id: u64, profile: String },
    /// The pod has no profile; the container starts ungoverned.
    NotGoverned,
    /// Container binding removed (or there was none).
    ContainerUnbound,
    /// Operation failed.
    Error { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApplyReportData {
    pub generation: u64,
    pub slot: u32,
    pub profiles: usize,
    pub deny_entries: usize,
    pub allow_entries: usize,
    pub exec_entries: usize,
    pub file_entries: usize,
    pub skipped_files: Vec<String>,
    pub bindings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DryRunData {
    pub generation: u64,
    pub profiles: usize,
    pub deny_entries: usize,
    pub allow_entries: usize,
    pub exec_entries: usize,
    pub file_entries: usize,
    pub skipped_files: Vec<String>,
    pub cgroups_to_create: Vec<String>,
    pub diff: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonStatus {
    pub health: bool,
    pub generation: u64,
    pub active_profiles: Vec<String>,
    pub agents: Vec<AgentStatusInfo>,
    pub capabilities: Vec<CapabilityStatus>,
    /// Event pipeline counters (Phase 7 §5): kernel drops summed over CPUs,
    /// records drained, userspace drops, decoder outcomes.
    #[serde(default)]
    pub counters: BTreeMap<String, u64>,
    /// Bound Kubernetes containers (Phase 5b).
    #[serde(default)]
    pub containers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityStatus {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentStatusInfo {
    pub agent_id: String,
    pub pid: u32,
    pub profile: String,
    pub session_id: Option<String>,
    pub cgroup_rel: String,
    pub cgroup_id: u64,
    pub privilege_checks: AgentPrivilegeChecks,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentPrivilegeChecks {
    pub unprivileged_user: bool,
    pub caller_uid: u32,
    pub caller_gid: u32,
    pub no_new_privs: bool,
    pub empty_capabilities: bool,
    pub cgroup_not_delegated: bool,
}

impl fmt::Display for AgentPrivilegeChecks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "uid={}, gid={}, no_new_privs={}, empty_caps={}, cgroup_root_owned={}",
            self.caller_uid,
            self.caller_gid,
            self.no_new_privs,
            self.empty_capabilities,
            self.cgroup_not_delegated
        )
    }
}

/// Send a raw message over a Unix socket with optional file descriptor passing (`SCM_RIGHTS`).
pub fn send_message(sock: RawFd, data: &[u8], fds: &[RawFd]) -> Result<()> {
    unsafe {
        let mut iov = libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        };
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;

        let mut cmsg_buf = Vec::new();
        if !fds.is_empty() {
            let fds_bytes = std::mem::size_of_val(fds);
            let cmsg_space = libc::CMSG_SPACE(fds_bytes as u32) as usize;
            cmsg_buf.resize(cmsg_space, 0u8);

            msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
            // size_t on glibc, socklen_t on musl (release target).
            msg.msg_controllen = cmsg_space as _;

            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            if cmsg.is_null() {
                return Err(anyhow!("CMSG_FIRSTHDR returned null pointer"));
            }
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(fds_bytes as u32) as _;

            let data_ptr = libc::CMSG_DATA(cmsg) as *mut RawFd;
            std::ptr::copy_nonoverlapping(fds.as_ptr(), data_ptr, fds.len());
        }

        let res = libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL);
        if res < 0 {
            return Err(std::io::Error::last_os_error()).context("sendmsg failed");
        }
        Ok(())
    }
}

/// Receive a raw message from a Unix socket along with any passed file descriptors (`SCM_RIGHTS`).
pub fn recv_message(sock: RawFd, buf: &mut [u8]) -> Result<(usize, Vec<OwnedFd>)> {
    unsafe {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let cmsg_space = libc::CMSG_SPACE((8 * std::mem::size_of::<RawFd>()) as u32) as usize;
        let mut cmsg_buf = vec![0u8; cmsg_space];

        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_space as _;

        // CLOEXEC: a descriptor passed to the daemon must never leak into an agent.
        let res = libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC);
        if res < 0 {
            return Err(std::io::Error::last_os_error()).context("recvmsg failed");
        }

        // Collect any SCM_RIGHTS descriptors into OwnedFds *before* inspecting
        // `res`. The kernel installs passed descriptors into our table during
        // recvmsg, even on a zero-length datagram; returning early on res == 0
        // without wrapping them would leak one set per message and let any local
        // peer exhaust the daemon's descriptor table (denial of service).
        let mut received_fds = Vec::new();
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let data_ptr = libc::CMSG_DATA(cmsg) as *const RawFd;
                let cmsg_len: usize = (*cmsg).cmsg_len as _;
                let base_len = libc::CMSG_LEN(0) as usize;
                if cmsg_len >= base_len {
                    let num_fds = (cmsg_len - base_len) / std::mem::size_of::<RawFd>();
                    for i in 0..num_fds {
                        let fd = *data_ptr.add(i);
                        received_fds.push(OwnedFd::from_raw_fd(fd));
                    }
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }

        Ok((res as usize, received_fds))
    }
}

/// Serialise and send a [`Request`] with optional attached file descriptors.
pub fn send_request(sock: RawFd, req: &Request, fds: &[RawFd]) -> Result<()> {
    let bytes = serde_json::to_vec(req).context("failed to serialize Request")?;
    send_message(sock, &bytes, fds)
}

/// Receive and deserialise a [`Request`] with any attached file descriptors.
pub fn recv_request(sock: RawFd, buf: &mut [u8]) -> Result<Option<(Request, Vec<OwnedFd>)>> {
    let (n, fds) = recv_message(sock, buf)?;
    if n == 0 {
        return Ok(None);
    }
    let req: Request =
        serde_json::from_slice(&buf[..n]).context("failed to parse Request payload")?;
    Ok(Some((req, fds)))
}

/// Serialise and send a [`Response`].
pub fn send_response(sock: RawFd, resp: &Response) -> Result<()> {
    let bytes = serde_json::to_vec(resp).context("failed to serialize Response")?;
    send_message(sock, &bytes, &[])
}

/// Receive and deserialise a [`Response`].
pub fn recv_response(sock: RawFd, buf: &mut [u8]) -> Result<Option<Response>> {
    let (n, _) = recv_message(sock, buf)?;
    if n == 0 {
        return Ok(None);
    }
    let resp: Response =
        serde_json::from_slice(&buf[..n]).context("failed to parse Response payload")?;
    Ok(Some(resp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;

    #[test]
    fn request_serde_roundtrip() {
        let req = Request::Run {
            profile: "test-profile".into(),
            session: Some("sess-123".into()),
            cwd: Some("/home/agent/workspace".into()),
            cmd: vec!["python".into(), "agent.py".into()],
            env: vec![("KEY".into(), "VAL".into())],
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(req, decoded);

        let req = Request::Apply {
            policy_text: "[profiles.a]\nmode = \"enforce\"\n".into(),
            dry_run: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(req, decoded);

        let req = Request::Rollback;
        let json = serde_json::to_string(&req).unwrap();
        let decoded: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn response_serde_roundtrip() {
        let resp = Response::RunStarted {
            agent_id: "agent-1".into(),
            pid: 1234,
            cgroup_id: 5678,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, decoded);

        let resp = Response::RunExited { exit_code: 0 };
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, decoded);

        let resp = Response::Error {
            message: "permission denied".into(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let decoded: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, decoded);
    }

    /// The exact JSON exchanged with rk-nri. rk-nri/protocol_test.go asserts
    /// the same strings, so a change on either side fails a test.
    #[test]
    fn nri_wire_contract() {
        let bind = r#"{"BindContainer":{"pid":42,"namespace":"agents","pod":"p","pod_uid":"u","container":"c","container_id":"id1","annotations":{"realitykernel.dev/profile":"strict"}}}"#;
        let req: Request = serde_json::from_str(bind).unwrap();
        assert_eq!(
            req,
            Request::BindContainer {
                pid: 42,
                namespace: "agents".into(),
                pod: "p".into(),
                pod_uid: "u".into(),
                container: "c".into(),
                container_id: "id1".into(),
                annotations: [(
                    "realitykernel.dev/profile".to_string(),
                    "strict".to_string()
                )]
                .into(),
            }
        );
        let unbind = r#"{"UnbindContainer":{"container_id":"id1"}}"#;
        assert_eq!(
            serde_json::from_str::<Request>(unbind).unwrap(),
            Request::UnbindContainer {
                container_id: "id1".into()
            }
        );
        let cases = [
            (
                Response::ContainerBound {
                    cgroup_id: 7,
                    profile: "strict".into(),
                },
                r#"{"ContainerBound":{"cgroup_id":7,"profile":"strict"}}"#,
            ),
            (Response::NotGoverned, r#""NotGoverned""#),
            (Response::ContainerUnbound, r#""ContainerUnbound""#),
            (
                Response::Error {
                    message: "m".into(),
                },
                r#"{"Error":{"message":"m"}}"#,
            ),
        ];
        for (resp, json) in cases {
            assert_eq!(serde_json::to_string(&resp).unwrap(), json);
        }
    }

    /// A zero-length datagram carrying a descriptor must still have that
    /// descriptor collected (and therefore closed on drop), not leaked. This is
    /// the control-plane descriptor-exhaustion DoS regression test.
    #[test]
    fn zero_length_datagram_with_fds_is_not_leaked() {
        let mut sv = [0; 2];
        let rc =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, sv.as_mut_ptr()) };
        assert_eq!(rc, 0);
        let sender = unsafe { OwnedFd::from_raw_fd(sv[0]) };
        let receiver = unsafe { OwnedFd::from_raw_fd(sv[1]) };

        let mut pipefd = [0; 2];
        assert_eq!(unsafe { libc::pipe(pipefd.as_mut_ptr()) }, 0);
        let pipe_r = unsafe { OwnedFd::from_raw_fd(pipefd[0]) };
        let pipe_w = unsafe { OwnedFd::from_raw_fd(pipefd[1]) };

        // Zero-length payload, one attached descriptor: recvmsg returns 0 but the
        // kernel has already installed the descriptor in our table.
        send_message(sender.as_raw_fd(), &[], &[pipe_r.as_raw_fd()]).unwrap();

        let mut buf = vec![0u8; 64];
        let (n, fds) = recv_message(receiver.as_raw_fd(), &mut buf).unwrap();
        assert_eq!(n, 0);
        assert_eq!(fds.len(), 1, "passed descriptor must be collected, not leaked");
        // `fds` dropping here closes the received descriptor.
        drop(pipe_w);
    }

    #[test]
    fn socketpair_message_and_fd_passing() {
        let mut sv = [0; 2];
        let rc =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0, sv.as_mut_ptr()) };
        assert_eq!(rc, 0);

        let sender = unsafe { OwnedFd::from_raw_fd(sv[0]) };
        let receiver = unsafe { OwnedFd::from_raw_fd(sv[1]) };

        // Create a dummy pipe to get a file descriptor to send
        let mut pipefd = [0; 2];
        let rc = unsafe { libc::pipe(pipefd.as_mut_ptr()) };
        assert_eq!(rc, 0);
        let pipe_r = unsafe { OwnedFd::from_raw_fd(pipefd[0]) };
        let pipe_w = unsafe { OwnedFd::from_raw_fd(pipefd[1]) };

        let req = Request::Status;
        send_request(sender.as_raw_fd(), &req, &[pipe_r.as_raw_fd()]).unwrap();

        let mut buf = vec![0u8; 4096];
        let (received_req, received_fds) = recv_request(receiver.as_raw_fd(), &mut buf)
            .unwrap()
            .unwrap();
        assert_eq!(received_req, req);
        assert_eq!(received_fds.len(), 1);

        // Write to pipe_w and read from received_fds[0]
        let msg = b"reality-kernel";
        unsafe {
            libc::write(pipe_w.as_raw_fd(), msg.as_ptr() as *const _, msg.len());
            let mut read_buf = [0u8; 14];
            let n = libc::read(
                received_fds[0].as_raw_fd(),
                read_buf.as_mut_ptr() as *mut _,
                read_buf.len(),
            );
            assert_eq!(n, 14);
            assert_eq!(&read_buf, msg);
        }
    }
}
