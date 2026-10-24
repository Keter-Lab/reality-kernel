//! Prometheus metrics (docs/design/phase-9.md §3.5).
//!
//! Counters the worker keeps ([`Metrics`]) are combined at scrape time with
//! values read from the kernel and the policy engine ([`Snapshot`]) and
//! rendered in the Prometheus text exposition format.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;

/// Hook classes, indexed like `enum rk_hook`.
pub const HOOKS: [&str; 9] = [
    "connect4",
    "connect6",
    "sendmsg4",
    "sendmsg6",
    "sock_create",
    "exec",
    "file",
    "guard",
    "tun",
];
const _: () = assert!(HOOKS.len() == rk_ebpf_common::rk_hook::RK_HOOK_MAX as usize);

/// Verdicts, indexed like `enum rk_verdict`.
pub const VERDICTS: [&str; 3] = ["allow", "deny", "audit_would_deny"];

/// Key of a kernel decision counter in the engine's counter map.
pub fn decision_key(hook: &str, verdict: &str) -> String {
    format!("decisions.{hook}.{verdict}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditInfo {
    pub key_id: String,
    pub head_hash: String,
}

/// Counters kept by the worker and the exporters.
#[derive(Debug, Default)]
pub struct Metrics {
    /// (rule id, verdict, profile) -> decisions, for deny and audit only.
    rule_hits: Mutex<BTreeMap<(u32, &'static str, String), u64>>,
    pub audit_records: AtomicU64,
    pub audit_batches: AtomicU64,
    pub audit_write_errors: AtomicU64,
    /// Sequence number the next audit batch gets.
    pub audit_head_seq: AtomicU64,
    audit_info: Mutex<Option<AuditInfo>>,
    pub otlp_exported: AtomicU64,
    pub otlp_lost: AtomicU64,
    pub otlp_errors: AtomicU64,
}

impl Metrics {
    pub fn hit(&self, rule_id: u32, verdict: &'static str, profile: Option<&str>) {
        let key = (rule_id, verdict, profile.unwrap_or("").to_string());
        *self.rule_hits.lock().unwrap().entry(key).or_insert(0) += 1;
    }

    pub fn set_audit_head(&self, next_seq: u64, info: AuditInfo) {
        self.audit_head_seq.store(next_seq, Ordering::Relaxed);
        *self.audit_info.lock().unwrap() = Some(info);
    }

    pub fn audit_info(&self) -> Option<AuditInfo> {
        self.audit_info.lock().unwrap().clone()
    }
}

/// Values read from the kernel and the engine when scraped.
#[derive(Debug, Default, Clone)]
pub struct Snapshot {
    /// The engine's counter map (kernel counters, pipeline counters).
    pub counters: BTreeMap<String, u64>,
    pub decoder_errors: Vec<(&'static str, u64)>,
    pub policy_generation: u64,
    pub heartbeat_age_seconds: Option<f64>,
    /// Capability name (as in `rk status`) -> available.
    pub capabilities: Vec<(String, bool)>,
}

fn escape(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

pub fn render(m: &Metrics, s: &Snapshot) -> String {
    let mut out = String::new();
    let c = |k: &str| s.counters.get(k).copied().unwrap_or(0);

    family(
        &mut out,
        "rk_decisions_total",
        "counter",
        "Governed decisions by hook and verdict, counted in the kernel.",
    );
    for hook in HOOKS {
        for verdict in VERDICTS {
            let _ = writeln!(
                out,
                "rk_decisions_total{{hook=\"{hook}\",verdict=\"{verdict}\"}} {}",
                c(&decision_key(hook, verdict))
            );
        }
    }

    family(
        &mut out,
        "rk_rule_hits_total",
        "counter",
        "Deny and audit-would-deny decisions by rule, from events.",
    );
    for ((rule, verdict, profile), n) in m.rule_hits.lock().unwrap().iter() {
        let _ = writeln!(
            out,
            "rk_rule_hits_total{{rule_id=\"{rule}\",verdict=\"{verdict}\",profile=\"{}\"}} {n}",
            escape(profile)
        );
    }

    family(
        &mut out,
        "rk_events_lost_total",
        "counter",
        "Decision events lost before the audit log, by stage.",
    );
    let lost = [
        ("kernel", c("ringbuf_drops") + c("scratch_misses")),
        ("channel", c("userspace_drops")),
        ("otlp", m.otlp_lost.load(Ordering::Relaxed)),
    ];
    for (stage, n) in lost {
        let _ = writeln!(out, "rk_events_lost_total{{stage=\"{stage}\"}} {n}");
    }

    family(
        &mut out,
        "rk_decoder_errors_total",
        "counter",
        "Ring buffer records rejected by the decoder, by kind.",
    );
    for (kind, n) in &s.decoder_errors {
        let _ = writeln!(out, "rk_decoder_errors_total{{kind=\"{kind}\"}} {n}");
    }

    family(
        &mut out,
        "rk_policy_generation",
        "gauge",
        "Generation of the active policy.",
    );
    let _ = writeln!(out, "rk_policy_generation {}", s.policy_generation);

    if let Some(age) = s.heartbeat_age_seconds {
        family(
            &mut out,
            "rk_heartbeat_age_seconds",
            "gauge",
            "Seconds since the sensor last renewed the kernel heartbeat.",
        );
        let _ = writeln!(out, "rk_heartbeat_age_seconds {age:.3}");
    }

    family(
        &mut out,
        "rk_enforcement_available",
        "gauge",
        "Whether enforcement of each rule family is available on this node.",
    );
    for (capability, name) in [("network", "cgroup_v2"), ("lsm", "bpf_lsm")] {
        let ok = s.capabilities.iter().any(|(n, ok)| n == name && *ok);
        let _ = writeln!(
            out,
            "rk_enforcement_available{{capability=\"{capability}\"}} {}",
            u8::from(ok)
        );
    }

    let counters = [
        (
            "rk_audit_records_total",
            "Records written to the audit log.",
            &m.audit_records,
        ),
        (
            "rk_audit_batches_total",
            "Audit batches sealed.",
            &m.audit_batches,
        ),
        (
            "rk_audit_write_errors_total",
            "Failed audit log writes.",
            &m.audit_write_errors,
        ),
        (
            "rk_otlp_spans_exported_total",
            "Decision spans accepted by the OTLP collector.",
            &m.otlp_exported,
        ),
        (
            "rk_otlp_export_errors_total",
            "Failed OTLP export requests.",
            &m.otlp_errors,
        ),
    ];
    for (name, help, v) in counters {
        family(&mut out, name, "counter", help);
        let _ = writeln!(out, "{name} {}", v.load(Ordering::Relaxed));
    }

    if let Some(info) = m.audit_info() {
        family(
            &mut out,
            "rk_audit_head_seq",
            "gauge",
            "Sequence number of the next audit batch (the chain head).",
        );
        let _ = writeln!(
            out,
            "rk_audit_head_seq {}",
            m.audit_head_seq.load(Ordering::Relaxed)
        );
        family(
            &mut out,
            "rk_audit_info",
            "gauge",
            "Audit signing key and chain head hash.",
        );
        let _ = writeln!(
            out,
            "rk_audit_info{{key_id=\"{}\",head_hash=\"{}\"}} 1",
            escape(&info.key_id),
            escape(&info.head_hash)
        );
    }
    out
}

/// Produces a [`Snapshot`] on each scrape.
pub type SnapshotFn = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Snapshot> + Send>> + Send + Sync>;

struct ServerState {
    metrics: Arc<Metrics>,
    snapshot: SnapshotFn,
}

async fn scrape(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    let snapshot = (state.snapshot)().await;
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        render(&state.metrics, &snapshot),
    )
}

/// Serves `GET /metrics` on `listener` until the task is dropped.
pub async fn serve_on(
    listener: tokio::net::TcpListener,
    metrics: Arc<Metrics>,
    snapshot: SnapshotFn,
) -> Result<()> {
    let app = Router::new()
        .route("/metrics", get(scrape))
        .with_state(Arc::new(ServerState { metrics, snapshot }));
    axum::serve(listener, app).await.context("metrics server")
}

pub async fn serve(addr: SocketAddr, metrics: Arc<Metrics>, snapshot: SnapshotFn) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind metrics address {addr}"))?;
    serve_on(listener, metrics, snapshot).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> Snapshot {
        let mut counters = BTreeMap::new();
        counters.insert(decision_key("connect4", "deny"), 3);
        counters.insert("ringbuf_drops".into(), 2);
        counters.insert("scratch_misses".into(), 1);
        Snapshot {
            counters,
            decoder_errors: vec![("too_short", 4)],
            policy_generation: 9,
            heartbeat_age_seconds: Some(0.25),
            capabilities: vec![("cgroup_v2".into(), true), ("bpf_lsm".into(), false)],
        }
    }

    #[test]
    fn renders_every_family() {
        let m = Metrics::default();
        m.hit(7, "deny", Some("agent \"x\""));
        m.set_audit_head(
            12,
            AuditInfo {
                key_id: "abcd".into(),
                head_hash: "ff".into(),
            },
        );
        let text = render(&m, &snapshot());
        for line in [
            "rk_decisions_total{hook=\"connect4\",verdict=\"deny\"} 3",
            "rk_decisions_total{hook=\"guard\",verdict=\"allow\"} 0",
            "rk_rule_hits_total{rule_id=\"7\",verdict=\"deny\",profile=\"agent \\\"x\\\"\"} 1",
            "rk_events_lost_total{stage=\"kernel\"} 3",
            "rk_decoder_errors_total{kind=\"too_short\"} 4",
            "rk_policy_generation 9",
            "rk_heartbeat_age_seconds 0.250",
            "rk_enforcement_available{capability=\"network\"} 1",
            "rk_enforcement_available{capability=\"lsm\"} 0",
            "rk_audit_head_seq 12",
            "rk_audit_info{key_id=\"abcd\",head_hash=\"ff\"} 1",
        ] {
            assert!(
                text.lines().any(|l| l == line),
                "missing `{line}` in:\n{text}"
            );
        }
        // Every sample belongs to a declared family.
        let declared: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix("# TYPE "))
            .filter_map(|l| l.split(' ').next())
            .collect();
        for l in text.lines().filter(|l| !l.starts_with('#')) {
            let name = l.split(['{', ' ']).next().unwrap();
            assert!(declared.contains(&name), "{name} has no # TYPE");
        }
    }

    #[tokio::test]
    async fn serves_metrics_over_http() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let snap: SnapshotFn = Arc::new(|| -> Pin<Box<dyn Future<Output = Snapshot> + Send>> {
            Box::pin(async { snapshot() })
        });
        let server = tokio::spawn(serve_on(listener, Arc::new(Metrics::default()), snap));
        let body = tokio::task::spawn_blocking(move || {
            use std::io::{Read as _, Write as _};
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).unwrap();
            out
        })
        .await
        .unwrap();
        server.abort();
        assert!(body.starts_with("HTTP/1.1 200"), "{body}");
        assert!(body.contains("text/plain; version=0.0.4"));
        assert!(body.contains("rk_policy_generation 9"));
    }
}
