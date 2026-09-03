use rk_engine_core::analyse;
use tracing::info;

use crate::enricher;
use crate::event::RkEvent;

pub async fn process_event(event: RkEvent) {
    let enriched = enricher::enrich_event(event).await;

    if let RkEvent::Exec(exec) = &enriched.base {
        let command = if let Some(cmdline) = enriched.cmdline.clone() {
            cmdline
        } else {
            decode_c_string(&exec.argv_summary)
        };

        let result = analyse(&command, "kernel_exec_event", 5);
        info!(
            pid = exec.pid,
            verdict = result.verdict,
            confidence = result.confidence,
            action_id = result.action_id,
            max_divergence = result.max_divergence,
            "exec event analysed by rk-engine-core"
        );
    }

    info!(?enriched, "processed enriched kernel event");
}

fn decode_c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

pub async fn emit_overflow_marker(count: u64) {
    info!(
        overflow_count = count,
        marker = "RINGBUF_OVERFLOW",
        "synthetic audit marker emitted"
    );
}
