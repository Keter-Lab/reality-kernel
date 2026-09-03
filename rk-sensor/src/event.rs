use rk_ebpf_common::{ExecEvent, FileOpenEvent, NetConnectEvent, UnlinkEvent};

#[derive(Debug, Clone)]
pub enum RkEvent {
    Exec(ExecEvent),
    FileOpen(FileOpenEvent),
    NetConnect(NetConnectEvent),
    Unlink(UnlinkEvent),
}

#[derive(Debug, Clone)]
pub struct EnrichedEvent {
    pub base: RkEvent,
    pub cmdline: Option<String>,
    pub cgroup: Option<String>,
    pub exe_path: Option<String>,
}

impl RkEvent {
    pub fn pid(&self) -> u32 {
        match self {
            RkEvent::Exec(v) => v.pid,
            RkEvent::FileOpen(v) => v.pid,
            RkEvent::NetConnect(v) => v.pid,
            RkEvent::Unlink(v) => v.pid,
        }
    }
}
