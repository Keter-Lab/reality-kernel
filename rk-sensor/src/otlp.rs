//! OpenTelemetry export of decisions (docs/design/phase-9.md §3.6).
//!
//! OTLP over HTTP with the JSON encoding the OTLP specification defines, so
//! neither an OpenTelemetry SDK nor a gRPC stack is needed. Each agent
//! session is a trace (ids from [`rk_agentd::trace::session_trace`]); every
//! decision in it becomes a short span under the session span. The queue is
//! bounded: overflow and failed requests are counted, never retried, and
//! never touch the audit log, which is the durable record.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc;

use crate::metrics::Metrics;

/// Spans queued for export before new ones are dropped.
pub const QUEUE: usize = 4096;
const BATCH: usize = 256;
const FLUSH: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, PartialEq)]
pub struct Span {
    pub trace_id: [u8; 16],
    pub parent_id: [u8; 8],
    pub span_id: [u8; 8],
    pub name: String,
    pub time_ns: u64,
    pub denied: bool,
    pub attributes: Vec<(&'static str, Value)>,
}

static NEXT_SPAN: AtomicU64 = AtomicU64::new(0);

/// A decision span from its OCSF audit record, for a decision in `session`.
pub fn span_from_record(session: &str, record: &Value) -> Span {
    let (trace_id, parent_id) = rk_agentd::trace::session_trace(session);
    let n = NEXT_SPAN.fetch_add(1, Ordering::Relaxed);
    let time_ms = record["time"].as_i64().unwrap_or(0);
    let mut h = Sha256::new();
    h.update(trace_id);
    h.update(time_ms.to_be_bytes());
    h.update(n.to_be_bytes());
    let mut span_id = [0u8; 8];
    span_id.copy_from_slice(&h.finalize()[..8]);

    let rk = crate::observe::rk(record);
    let mut attributes: Vec<(&'static str, Value)> = vec![
        ("rk.session", json!(session)),
        ("rk.verdict", rk["verdict"].clone()),
        ("rk.rule_id", rk["rule_id"].clone()),
        ("rk.policy_gen", rk["policy_gen"].clone()),
        ("rk.cgroup_id", rk["cgroup_id"].clone()),
        ("ocsf.class_uid", record["class_uid"].clone()),
        ("ocsf.activity", record["activity_name"].clone()),
    ];
    let extra: [(&'static str, &str); 6] = [
        ("rk.profile", "/policy/name"),
        ("process.pid", "/actor/process/pid"),
        ("process.executable.path", "/actor/process/file/path"),
        ("network.peer.address", "/dst_endpoint/ip"),
        ("network.peer.port", "/dst_endpoint/port"),
        ("file.path", "/file/path"),
    ];
    for (key, pointer) in extra {
        if let Some(v) = record.pointer(pointer) {
            attributes.push((key, v.clone()));
        }
    }
    Span {
        trace_id,
        parent_id,
        span_id,
        name: format!(
            "rk.decision {}",
            record["activity_name"].as_str().unwrap_or("")
        ),
        time_ns: u64::try_from(time_ms)
            .unwrap_or(0)
            .saturating_mul(1_000_000),
        denied: rk["verdict"] == "deny",
        attributes,
    }
}

fn any_value(v: &Value) -> Value {
    match v {
        Value::Bool(b) => json!({ "boolValue": b }),
        // OTLP/JSON encodes 64-bit integers as strings.
        Value::Number(n) if n.is_i64() || n.is_u64() => json!({ "intValue": n.to_string() }),
        Value::Number(n) => json!({ "doubleValue": n.as_f64() }),
        Value::String(s) => json!({ "stringValue": s }),
        other => json!({ "stringValue": other.to_string() }),
    }
}

fn hex(bytes: &[u8]) -> String {
    rk_agentd::trace::to_hex(bytes)
}

/// The `ExportTraceServiceRequest` body for `spans`, OTLP/JSON encoded.
pub fn payload(spans: &[Span], hostname: &str, version: &str) -> Value {
    let spans: Vec<Value> = spans
        .iter()
        .map(|s| {
            let attributes: Vec<Value> = s
                .attributes
                .iter()
                .map(|(k, v)| json!({ "key": k, "value": any_value(v) }))
                .collect();
            json!({
                "traceId": hex(&s.trace_id),
                "spanId": hex(&s.span_id),
                "parentSpanId": hex(&s.parent_id),
                "name": s.name,
                "kind": 1,
                "startTimeUnixNano": s.time_ns.to_string(),
                "endTimeUnixNano": s.time_ns.to_string(),
                "attributes": attributes,
                // STATUS_CODE_ERROR for an enforced deny, else unset.
                "status": if s.denied { json!({ "code": 2, "message": "denied by policy" }) } else { json!({}) },
            })
        })
        .collect();
    json!({
        "resourceSpans": [{
            "resource": { "attributes": [
                { "key": "service.name", "value": { "stringValue": "rk-sensor" } },
                { "key": "service.version", "value": { "stringValue": version } },
                { "key": "host.name", "value": { "stringValue": hostname } },
            ]},
            "scopeSpans": [{
                "scope": { "name": "rk-sensor", "version": version },
                "spans": spans,
            }],
        }]
    })
}

/// Hands spans to the export task without blocking.
#[derive(Clone)]
pub struct Exporter {
    tx: mpsc::Sender<Span>,
    metrics: Arc<Metrics>,
}

impl Exporter {
    /// Queues a span; a full queue drops it and counts the loss.
    pub fn offer(&self, span: Span) {
        if self.tx.try_send(span).is_err() {
            self.metrics.otlp_lost.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Checks an `--otlp-endpoint`: `http://host:port`. TLS to the backend is
/// the node-local collector's job, so the sensor carries no TLS stack.
pub fn validate_endpoint(endpoint: &str) -> Result<(), String> {
    match endpoint.split_once("://") {
        Some(("http", rest)) if !rest.is_empty() => Ok(()),
        Some(("https", _)) => Err(
            "--otlp-endpoint must be plain http:// to a node-local OpenTelemetry Collector, \
             which handles TLS to the backend"
                .into(),
        ),
        _ => Err(format!(
            "--otlp-endpoint `{endpoint}` is not an http:// URL"
        )),
    }
}

/// Starts the export task on the current tokio runtime, posting to
/// `<endpoint>/v1/traces`.
pub fn start(endpoint: &str, hostname: String, version: String, metrics: Arc<Metrics>) -> Exporter {
    let (tx, rx) = mpsc::channel(QUEUE);
    let url = format!("{}/v1/traces", endpoint.trim_end_matches('/'));
    tokio::spawn(run(url, hostname, version, metrics.clone(), rx));
    Exporter { tx, metrics }
}

/// An exporter whose queue nothing drains, for tests of the overflow path.
#[cfg(test)]
fn detached(capacity: usize, metrics: Arc<Metrics>) -> (Exporter, mpsc::Receiver<Span>) {
    let (tx, rx) = mpsc::channel(capacity);
    (Exporter { tx, metrics }, rx)
}

async fn run(
    url: String,
    hostname: String,
    version: String,
    metrics: Arc<Metrics>,
    mut rx: mpsc::Receiver<Span>,
) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "OTLP export disabled: cannot build an HTTP client");
            return;
        }
    };
    let mut batch = Vec::with_capacity(BATCH);
    loop {
        // Wait for the first span, then gather more for up to FLUSH.
        match rx.recv().await {
            Some(span) => batch.push(span),
            None => return,
        }
        let deadline = tokio::time::sleep(FLUSH);
        tokio::pin!(deadline);
        while batch.len() < BATCH {
            tokio::select! {
                span = rx.recv() => match span {
                    Some(span) => batch.push(span),
                    None => break,
                },
                _ = &mut deadline => break,
            }
        }
        let n = batch.len() as u64;
        let body = payload(&batch, &hostname, &version);
        batch.clear();
        match client.post(&url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => {
                metrics.otlp_exported.fetch_add(n, Ordering::Relaxed);
            }
            Ok(resp) => {
                metrics.otlp_errors.fetch_add(1, Ordering::Relaxed);
                metrics.otlp_lost.fetch_add(n, Ordering::Relaxed);
                tracing::warn!(status = %resp.status(), spans = n, "OTLP collector refused the export");
            }
            Err(e) => {
                metrics.otlp_errors.fetch_add(1, Ordering::Relaxed);
                metrics.otlp_lost.fetch_add(n, Ordering::Relaxed);
                tracing::warn!(error = %e, spans = n, "OTLP export failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Value {
        json!({
            "time": 1_760_000_000_123i64,
            "class_uid": 4001,
            "activity_name": "Open",
            "policy": { "name": "agent" },
            "actor": { "process": { "pid": 42, "file": { "path": "/usr/bin/curl" } } },
            "dst_endpoint": { "ip": "10.0.0.5", "port": 443 },
            "unmapped": { "rk": { "verdict": "deny", "rule_id": 7, "policy_gen": 3, "cgroup_id": 9 } },
        })
    }

    #[test]
    fn spans_join_the_session_trace() {
        let span = span_from_record("sess-1", &record());
        let (trace, parent) = rk_agentd::trace::session_trace("sess-1");
        assert_eq!((span.trace_id, span.parent_id), (trace, parent));
        assert_eq!(span.time_ns, 1_760_000_000_123_000_000);
        assert!(span.denied);
        assert_ne!(span.span_id, span_from_record("sess-1", &record()).span_id);
        let body = payload(&[span], "node-a", "0.1.0");
        let s = &body["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(s["traceId"].as_str().unwrap().len(), 32);
        assert_eq!(s["parentSpanId"], rk_agentd::trace::to_hex(&parent));
        assert_eq!(s["status"]["code"], 2);
        let attrs = s["attributes"].as_array().unwrap();
        assert!(attrs.contains(&json!({ "key": "rk.rule_id", "value": { "intValue": "7" } })));
        assert!(attrs.contains(
            &json!({ "key": "network.peer.address", "value": { "stringValue": "10.0.0.5" } })
        ));
    }

    #[test]
    fn endpoints_must_be_plain_http() {
        assert!(validate_endpoint("http://127.0.0.1:4318").is_ok());
        assert!(validate_endpoint("https://collector:4318").is_err());
        assert!(validate_endpoint("collector:4318").is_err());
        assert!(validate_endpoint("http://").is_err());
    }

    #[test]
    fn a_full_queue_counts_the_loss() {
        let metrics = Arc::new(Metrics::default());
        let (exporter, _rx) = detached(1, metrics.clone());
        exporter.offer(span_from_record("s", &record()));
        exporter.offer(span_from_record("s", &record()));
        assert_eq!(metrics.otlp_lost.load(Ordering::Relaxed), 1);
    }

    /// End to end against an in-process OTLP/HTTP collector.
    #[tokio::test]
    async fn exports_to_a_collector() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let collector = std::thread::spawn(move || {
            use std::io::{BufRead as _, BufReader, Read as _, Write as _};
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut length = 0;
            loop {
                let mut h = String::new();
                reader.read_line(&mut h).unwrap();
                if h == "\r\n" {
                    break;
                }
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let mut stream = stream;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}")
                .unwrap();
            (request_line, body)
        });
        let metrics = Arc::new(Metrics::default());
        let exporter = start(
            &format!("http://{addr}"),
            "node-a".into(),
            "0.1.0".into(),
            metrics.clone(),
        );
        exporter.offer(span_from_record("sess-1", &record()));
        let (line, body) = tokio::task::spawn_blocking(move || collector.join().unwrap())
            .await
            .unwrap();
        assert!(line.starts_with("POST /v1/traces "), "{line}");
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body["resourceSpans"][0]["scopeSpans"][0]["spans"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        for _ in 0..50 {
            if metrics.otlp_exported.load(Ordering::Relaxed) == 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("export not counted");
    }
}
