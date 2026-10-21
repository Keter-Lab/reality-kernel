//! Registry tracking active agents and session linkages.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::launcher;
use crate::protocol::{AgentStatusInfo, CapabilityStatus, DaemonStatus};

/// Details of a currently governed agent running in a cgroup.
#[derive(Debug, Clone)]
pub struct ActiveAgent {
    pub agent_id: String,
    pub pid: u32,
    pub profile: String,
    pub session_id: Option<String>,
    pub cgroup_rel: String,
    pub cgroup_path: PathBuf,
    pub cgroup_id: u64,
    pub caller_uid: u32,
    pub caller_gid: u32,
    pub target_uid: u32,
    pub target_gid: u32,
}

/// Session mappings kept after their agent exits, so events still queued in
/// the ring buffer keep their session id. Cgroup ids are never reused within
/// a boot, so a retained mapping cannot mislabel a later agent.
const RETAINED_SESSIONS: usize = 4096;

/// Registry of running agents and session ID mappings.
#[derive(Debug, Default)]
pub struct AgentRegistry {
    agents: RwLock<HashMap<String, ActiveAgent>>,
    cgroup_sessions: RwLock<HashMap<u64, String>>,
    retired: RwLock<VecDeque<u64>>,
}

impl AgentRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register a newly spawned agent.
    pub fn register(&self, agent: ActiveAgent) {
        if let Some(ref session) = agent.session_id {
            self.cgroup_sessions
                .write()
                .unwrap()
                .insert(agent.cgroup_id, session.clone());
        }
        self.agents
            .write()
            .unwrap()
            .insert(agent.agent_id.clone(), agent);
    }

    /// Unregister an exited agent. Its session mapping is retired, not
    /// dropped: the newest `RETAINED_SESSIONS` stay resolvable.
    pub fn unregister(&self, agent_id: &str) -> Option<ActiveAgent> {
        let removed = self.agents.write().unwrap().remove(agent_id);
        if let Some(ref agent) = removed {
            if agent.session_id.is_some() {
                let mut retired = self.retired.write().unwrap();
                retired.push_back(agent.cgroup_id);
                if retired.len() > RETAINED_SESSIONS {
                    if let Some(old) = retired.pop_front() {
                        self.cgroup_sessions.write().unwrap().remove(&old);
                    }
                }
            }
        }
        removed
    }

    /// Retrieve an agent by ID.
    pub fn get(&self, agent_id: &str) -> Option<ActiveAgent> {
        self.agents.read().unwrap().get(agent_id).cloned()
    }

    /// Retrieve all currently active agents.
    pub fn list(&self) -> Vec<ActiveAgent> {
        self.agents.read().unwrap().values().cloned().collect()
    }

    /// Look up session ID for a given cgroup ID. Fast O(1) read for ring buffer events.
    pub fn session_for_cgroup(&self, cgroup_id: u64) -> Option<String> {
        self.cgroup_sessions
            .read()
            .unwrap()
            .get(&cgroup_id)
            .cloned()
    }

    /// Snapshot status information for all running agents.
    pub fn snapshot_agents(&self) -> Vec<AgentStatusInfo> {
        let agents = self.list();
        let mut infos = Vec::with_capacity(agents.len());
        for a in agents {
            let privs = launcher::verify_agent_privileges(a.pid, &a.cgroup_path);
            infos.push(AgentStatusInfo {
                agent_id: a.agent_id,
                pid: a.pid,
                profile: a.profile,
                session_id: a.session_id,
                cgroup_rel: a.cgroup_rel,
                cgroup_id: a.cgroup_id,
                privilege_checks: privs,
            });
        }
        infos
    }

    /// Build a complete `DaemonStatus` report.
    pub fn build_status(
        &self,
        health: bool,
        generation: u64,
        active_profiles: Vec<String>,
        capabilities: Vec<CapabilityStatus>,
    ) -> DaemonStatus {
        DaemonStatus {
            health,
            generation,
            active_profiles,
            agents: self.snapshot_agents(),
            capabilities,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(n: u64, session: Option<&str>) -> ActiveAgent {
        ActiveAgent {
            agent_id: format!("agent-{n}"),
            pid: 1,
            profile: "p".into(),
            session_id: session.map(str::to_string),
            cgroup_rel: format!("rk.slice/agent-{n}"),
            cgroup_path: PathBuf::from(format!("/sys/fs/cgroup/rk.slice/agent-{n}")),
            cgroup_id: n,
            caller_uid: 0,
            caller_gid: 0,
            target_uid: 65534,
            target_gid: 65534,
        }
    }

    #[test]
    fn session_outlives_agent_within_bound() {
        let reg = AgentRegistry::new();
        reg.register(agent(1, Some("s1")));
        assert!(reg.unregister("agent-1").is_some());
        assert!(reg.get("agent-1").is_none());
        // Late events from the exited agent still resolve their session.
        assert_eq!(reg.session_for_cgroup(1).as_deref(), Some("s1"));

        for n in 2..=(RETAINED_SESSIONS as u64 + 1) {
            reg.register(agent(n, Some("s")));
            reg.unregister(&format!("agent-{n}"));
        }
        // The oldest retired mapping is evicted once the bound is exceeded.
        assert_eq!(reg.session_for_cgroup(1), None);
        assert_eq!(reg.session_for_cgroup(2).as_deref(), Some("s"));
        assert_eq!(reg.retired.read().unwrap().len(), RETAINED_SESSIONS);
    }
}
