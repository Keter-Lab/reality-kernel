//! W3C trace context for agent sessions (docs/design/phase-9.md §3.6).
//!
//! Each agent session is one trace. Its ids are derived from the session id,
//! so the launcher (which hands the agent a `TRACEPARENT`) and the sensor
//! (which exports kernel decisions as spans) agree without talking.

use sha2::{Digest as _, Sha256};

/// `(trace id, session span id)` of a session.
pub fn session_trace(session: &str) -> ([u8; 16], [u8; 8]) {
    let h = Sha256::digest(format!("rk-trace-v1:{session}").as_bytes());
    let mut trace = [0u8; 16];
    let mut span = [0u8; 8];
    trace.copy_from_slice(&h[..16]);
    span.copy_from_slice(&h[16..24]);
    (trace, span)
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The `TRACEPARENT` value for a session's agent (version 00, sampled).
pub fn traceparent(session: &str) -> String {
    let (trace, span) = session_trace(session);
    format!("00-{}-{}-01", to_hex(&trace), to_hex(&span))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traceparent_is_w3c_shaped_and_stable() {
        let tp = traceparent("sess-1");
        let parts: Vec<&str> = tp.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(
            (parts[0], parts[1].len(), parts[2].len(), parts[3]),
            ("00", 32, 16, "01")
        );
        assert_eq!(tp, traceparent("sess-1"));
        assert_ne!(tp, traceparent("sess-2"));
        assert_ne!(parts[1], "0".repeat(32));
    }
}
