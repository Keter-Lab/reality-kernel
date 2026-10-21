//! `rk-agentd`: Agent governance daemon library for Reality Kernel.
//!
//! Provides the socket API, dynamic cgroup lifecycle management, unprivileged
//! agent launching (`clone3(CLONE_INTO_CGROUP)`), policy pipeline commands
//! (dry-run, diff, rollback), and session linkage.

pub mod auth;
pub mod cgroup;
pub mod client;
pub mod launcher;
pub mod protocol;
pub mod registry;
pub mod server;

pub use auth::{check_launchable_by, check_policy_admin, get_peer_cred, PeerCred};
pub use client::{ApplyOutcome, Client};
pub use protocol::{
    AgentPrivilegeChecks, AgentStatusInfo, ApplyReportData, CapabilityStatus, DaemonStatus,
    DryRunData, Request, Response, DEFAULT_SOCKET_PATH,
};
pub use registry::{ActiveAgent, AgentRegistry};
pub use server::{run_server, PolicyHandler, ServerConfig};
