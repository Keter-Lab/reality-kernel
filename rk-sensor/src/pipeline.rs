use tracing::info;

pub async fn process_event(event_bytes: &[u8]) {
    // Migration: In Phase 0/1, event bytes are validated via the new decoder.
    // Legacy /proc reading and ungrounded sys_enter_execve analysis are disabled
    // until Phase 3 lands with sched_process_exec.
    let mut str_buf = [""; 16];
    match crate::decoder::decode_event(event_bytes, &mut str_buf) {
        Ok(decoded) => {
            info!(
                event_type = decoded.hdr.type_,
                cgroup_id = decoded.hdr.cgroup_id,
                pid = decoded.hdr.pid,
                verdict = decoded.hdr.verdict,
                "decoded valid BPF ringbuffer event"
            );
        }
        Err(err) => {
            tracing::warn!(?err, "failed to decode ringbuffer event envelope");
        }
    }
}

pub async fn emit_overflow_marker(count: u64) {
    info!(
        overflow_count = count,
        marker = "RINGBUF_OVERFLOW",
        "synthetic audit marker emitted"
    );
}
