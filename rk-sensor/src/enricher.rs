use tokio::fs;
use tracing::debug;

use crate::event::{EnrichedEvent, RkEvent};

pub async fn enrich_event(event: RkEvent) -> EnrichedEvent {
    let pid = event.pid();

    let cmdline = read_proc_field(pid, "cmdline").await;
    let cgroup = read_proc_field(pid, "cgroup").await;
    let exe_path = read_proc_exe(pid).await;

    EnrichedEvent {
        base: event,
        cmdline,
        cgroup,
        exe_path,
    }
}

async fn read_proc_field(pid: u32, field: &str) -> Option<String> {
    let path = format!("/proc/{pid}/{field}");
    match fs::read(path).await {
        Ok(mut bytes) => {
            if field == "cmdline" {
                for b in &mut bytes {
                    if *b == 0 {
                        *b = b' ';
                    }
                }
            }
            Some(String::from_utf8_lossy(&bytes).trim().to_string())
        }
        Err(err)
            if err.kind() == std::io::ErrorKind::NotFound
                || err.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            debug!(pid, field, "proc read race/permission: {err}");
            None
        }
        Err(err) => {
            debug!(pid, field, "proc read failed: {err}");
            None
        }
    }
}

async fn read_proc_exe(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/exe");
    match fs::read_link(path).await {
        Ok(link) => Some(link.display().to_string()),
        Err(err)
            if err.kind() == std::io::ErrorKind::NotFound
                || err.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            debug!(pid, "proc exe race/permission: {err}");
            None
        }
        Err(err) => {
            debug!(pid, "proc exe read failed: {err}");
            None
        }
    }
}
