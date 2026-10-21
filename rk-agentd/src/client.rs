//! Client library for communicating with `rk-sensor`'s agentd socket.

use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};

use crate::protocol::{
    recv_response, send_request, ApplyReportData, DaemonStatus, DryRunData, Request, Response,
    DEFAULT_SOCKET_PATH, MAX_MESSAGE_SIZE,
};

/// Client connection to the agent daemon socket.
pub struct Client {
    sock: OwnedFd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied(ApplyReportData),
    DryRun(DryRunData),
}

impl Client {
    /// Connect to the agent daemon socket (or the default `/run/rk/agentd.sock`).
    pub fn connect(socket_path: Option<&Path>) -> Result<Self> {
        let path = socket_path.unwrap_or_else(|| Path::new(DEFAULT_SOCKET_PATH));

        let sock_fd =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
        if sock_fd < 0 {
            return Err(std::io::Error::last_os_error()).context("failed to create socket");
        }
        let sock = unsafe { OwnedFd::from_raw_fd(sock_fd) };

        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let path_bytes = path.to_string_lossy().as_bytes();
        if path_bytes.len() >= addr.sun_path.len() {
            bail!("socket path is too long: {}", path.display());
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

        let conn_res = unsafe {
            libc::connect(
                sock.as_raw_fd(),
                &addr as *const _ as *const libc::sockaddr,
                addr_len,
            )
        };
        if conn_res != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to connect to daemon at {}", path.display()));
        }

        Ok(Self { sock })
    }

    /// Launch a governed agent, forward signals, and wait for its exit code.
    pub fn run(
        &self,
        profile: &str,
        session: Option<&str>,
        cmd: &[String],
        env: &[(String, String)],
    ) -> Result<i32> {
        let req = Request::Run {
            profile: profile.to_string(),
            session: session.map(str::to_string),
            cmd: cmd.to_vec(),
            env: env.to_vec(),
        };

        // Pass current process stdin, stdout, and stderr
        let stdio_fds = [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO];

        send_request(self.sock.as_raw_fd(), &req, &stdio_fds)?;

        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        let resp = match recv_response(self.sock.as_raw_fd(), &mut buf)? {
            Some(r) => r,
            None => bail!("daemon closed connection unexpectedly"),
        };

        let agent_id = match resp {
            Response::RunStarted { agent_id, .. } => agent_id,
            Response::Error { message } => bail!("{message}"),
            other => bail!("unexpected daemon response: {other:?}"),
        };

        // Forward SIGINT and SIGTERM while waiting for exit
        let raw_sock = self.sock.as_raw_fd();
        let agent_id_for_sig = agent_id.clone();
        let exited = Arc::new(AtomicBool::new(false));
        let exited_clone = exited.clone();

        // Install signal handler thread
        let signal_thread = std::thread::spawn(move || {
            unsafe {
                // Handle signals via polling on signalfd
                let mut mask: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut mask);
                libc::sigaddset(&mut mask, libc::SIGINT);
                libc::sigaddset(&mut mask, libc::SIGTERM);
                libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut());

                let sfd = libc::signalfd(-1, &mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC);
                if sfd >= 0 {
                    while !exited_clone.load(Ordering::Relaxed) {
                        let mut fds = libc::pollfd {
                            fd: sfd,
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        let poll_res = libc::poll(&mut fds, 1, 100);
                        if poll_res > 0 && (fds.revents & libc::POLLIN) != 0 {
                            let mut fdsi: libc::signalfd_siginfo = std::mem::zeroed();
                            let n = libc::read(
                                sfd,
                                &mut fdsi as *mut _ as *mut libc::c_void,
                                std::mem::size_of::<libc::signalfd_siginfo>(),
                            );
                            if n > 0 {
                                let sig = fdsi.ssi_signo as i32;
                                let sig_req = Request::Signal {
                                    agent_id: agent_id_for_sig.clone(),
                                    signal: sig,
                                };
                                let _ = send_request(raw_sock, &sig_req, &[]);
                            }
                        }
                    }
                    libc::close(sfd);
                }
            }
        });

        // Wait for RunExited message
        loop {
            match recv_response(self.sock.as_raw_fd(), &mut buf)? {
                Some(Response::RunExited { exit_code }) => {
                    exited.store(true, Ordering::Relaxed);
                    let _ = signal_thread.join();
                    return Ok(exit_code);
                }
                Some(Response::Error { message }) => {
                    exited.store(true, Ordering::Relaxed);
                    let _ = signal_thread.join();
                    bail!("{message}");
                }
                Some(other) => {
                    tracing::debug!(?other, "ignored intermediate response");
                }
                None => {
                    exited.store(true, Ordering::Relaxed);
                    let _ = signal_thread.join();
                    bail!("connection closed by daemon before exit code received");
                }
            }
        }
    }

    /// Apply a policy file atomically, or perform dry-run.
    pub fn apply(&self, policy_text: &str, dry_run: bool) -> Result<ApplyOutcome> {
        let req = Request::Apply {
            policy_text: policy_text.to_string(),
            dry_run,
        };
        send_request(self.sock.as_raw_fd(), &req, &[])?;

        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        match recv_response(self.sock.as_raw_fd(), &mut buf)? {
            Some(Response::ApplySuccess { report }) => Ok(ApplyOutcome::Applied(report)),
            Some(Response::DryRunSuccess { dry_run }) => Ok(ApplyOutcome::DryRun(dry_run)),
            Some(Response::Error { message }) => bail!("{message}"),
            other => bail!("unexpected response: {other:?}"),
        }
    }

    /// Diff a policy file against the active policy.
    pub fn diff(&self, policy_text: &str) -> Result<Vec<String>> {
        let req = Request::Diff {
            policy_text: policy_text.to_string(),
        };
        send_request(self.sock.as_raw_fd(), &req, &[])?;

        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        match recv_response(self.sock.as_raw_fd(), &mut buf)? {
            Some(Response::DiffSuccess { diff }) => Ok(diff),
            Some(Response::Error { message }) => bail!("{message}"),
            other => bail!("unexpected response: {other:?}"),
        }
    }

    /// Roll back policy to previous generation.
    pub fn rollback(&self) -> Result<ApplyReportData> {
        let req = Request::Rollback;
        send_request(self.sock.as_raw_fd(), &req, &[])?;

        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        match recv_response(self.sock.as_raw_fd(), &mut buf)? {
            Some(Response::RollbackSuccess { report }) => Ok(report),
            Some(Response::Error { message }) => bail!("{message}"),
            other => bail!("unexpected response: {other:?}"),
        }
    }

    /// Query daemon status.
    pub fn status(&self) -> Result<DaemonStatus> {
        let req = Request::Status;
        send_request(self.sock.as_raw_fd(), &req, &[])?;

        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        match recv_response(self.sock.as_raw_fd(), &mut buf)? {
            Some(Response::StatusSuccess { status }) => Ok(status),
            Some(Response::Error { message }) => bail!("{message}"),
            other => bail!("unexpected response: {other:?}"),
        }
    }
}
