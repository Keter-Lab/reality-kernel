//! Per-record processing. Decoding failures are counted and logged, never fatal.
//!
//! The per-decision line is debug level (docs/design/phase-10.md §9): the
//! signed audit log is the record of every decision, and one INFO line per
//! decision floods the system journal on a busy host (journald then drops
//! messages, including the sensor's own). Enable it with
//! `RUST_LOG=info,rk_sensor::pipeline=debug`.

use std::sync::Arc;
use tracing::{debug, warn};

use crate::decoder::{self, DecodeStats, Event};
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
        Ok(event) => log_event(&event, registry),
        Err(e) => warn!(error = %e, kind = e.kind(), "rejected malformed ring buffer record"),
    }
}

/// The per-event log line (debug level), with the agent session when the
/// cgroup has one.
pub fn log_event(event: &Event<'_>, registry: Option<&Arc<AgentRegistry>>) {
    let session_id = registry.and_then(|r| r.session_for_cgroup(event.hdr.cgroup_id));
    if let Some(session_id) = session_id {
        debug!(
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
        debug!(
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
