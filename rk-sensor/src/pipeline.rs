//! Per-record processing. Decoding failures are counted and logged, never fatal.

use tracing::{info, warn};

use crate::decoder::{self, DecodeStats};

pub fn process_record(bytes: &[u8], stats: &DecodeStats) {
    let result = decoder::decode(bytes);
    stats.record(&result);
    match result {
        Ok(event) => info!(
            event_type = event.hdr.type_,
            verdict = event.hdr.verdict,
            rule_id = event.hdr.rule_id,
            policy_gen = event.hdr.policy_gen,
            cgroup_id = event.hdr.cgroup_id,
            pid = event.hdr.pid,
            "event"
        ),
        Err(e) => warn!(error = %e, kind = e.kind(), "rejected malformed ring buffer record"),
    }
}
