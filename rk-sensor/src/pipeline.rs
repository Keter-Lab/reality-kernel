//! Per-record processing. Decoding failures are counted and logged, never fatal.

use std::sync::Arc;
use tracing::{info, warn};

use crate::decoder::{self, DecodeStats};
use rk_agentd::registry::AgentRegistry;

pub fn process_record(bytes: &[u8], stats: &DecodeStats) {
    process_record_with_registry(bytes, stats, None);
}

pub fn process_record_with_registry(
    bytes: &[u8],
    stats: &DecodeStats,
    registry: Option<&Arc<AgentRegistry>>,
) {
    let result = decoder::decode(bytes);
    stats.record(&result);
    match result {
        Ok(event) => {
            let session_id = registry.and_then(|r| r.session_for_cgroup(event.hdr.cgroup_id));
            if let Some(session_id) = session_id {
                info!(
                    event_type = event.hdr.type_,
                    verdict = event.hdr.verdict,
                    rule_id = event.hdr.rule_id,
                    policy_gen = event.hdr.policy_gen,
                    cgroup_id = event.hdr.cgroup_id,
                    session_id = session_id.as_str(),
                    pid = event.hdr.pid,
                    "event"
                );
            } else {
                info!(
                    event_type = event.hdr.type_,
                    verdict = event.hdr.verdict,
                    rule_id = event.hdr.rule_id,
                    policy_gen = event.hdr.policy_gen,
                    cgroup_id = event.hdr.cgroup_id,
                    pid = event.hdr.pid,
                    "event"
                );
            }
        }
        Err(e) => warn!(error = %e, kind = e.kind(), "rejected malformed ring buffer record"),
    }
}
