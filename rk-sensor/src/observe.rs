//! The worker-side observer (docs/design/phase-9.md §3.1): turns decoded
//! events into audit records, metrics and OTLP spans, and records losses.
//!
//! By default the audit log holds every deny, audit-would-deny and tamper
//! decision; allows (network allows, committed execs) are added with
//! `include_allow`. Committed exec records always feed the process table.

use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use rk_agentd::registry::AgentRegistry;
use rk_audit::chain::Writer;
use rk_audit::ocsf::{self, Activity, Decision, Verdict};
use rk_ebpf_common::{rk_event_type, rk_exec_flag};
use serde_json::Value;
use tracing::{error, info, warn};

use crate::consumer::{PipelineStats, RecordHandler};
use crate::decoder::{self, DecodeStats, Event, Payload, Strings};
use crate::metrics::{AuditInfo, Metrics};
use crate::otlp::{self, Exporter};
use crate::policy::AuditContext;
use crate::proctable::ProcTable;
use crate::resilience::boottime_ns;

/// The active policy's audit context, republished by the engine's owner.
pub type SharedContext = Arc<RwLock<Arc<AuditContext>>>;

/// `unmapped.rk` of a record (`Null` when absent).
pub fn rk(record: &Value) -> &Value {
    &record["unmapped"]["rk"]
}

/// Kernel-side event losses (ring buffer drops plus scratch misses), kept
/// current by whoever owns the BPF maps.
#[derive(Debug, Default)]
pub struct KernelLosses(pub AtomicU64);

pub struct Observer {
    pub registry: Option<Arc<AgentRegistry>>,
    pub context: SharedContext,
    pub writer: Option<Writer>,
    pub include_allow: bool,
    pub metrics: Arc<Metrics>,
    pub procs: ProcTable,
    pub kernel_losses: Arc<KernelLosses>,
    pub pipeline: Arc<PipelineStats>,
    pub otlp: Option<Exporter>,
    pub hostname: String,
    pub version: String,
    /// Losses already recorded in the audit log.
    recorded_kernel: u64,
    recorded_channel: u64,
    /// The last audit write failed (to log the first failure only).
    failing: bool,
}

/// UTF-8 (lossy) of a kernel string.
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Milliseconds since the epoch at which an event with boot-time stamp
/// `ts_ns` happened.
fn wall_ms(ts_ns: u64) -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let age_ns = boottime_ns().saturating_sub(ts_ns);
    let ms = now.as_nanos().saturating_sub(u128::from(age_ns)) / 1_000_000;
    i64::try_from(ms).unwrap_or(i64::MAX)
}

pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

impl Observer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: Option<Arc<AgentRegistry>>,
        context: SharedContext,
        writer: Option<Writer>,
        include_allow: bool,
        metrics: Arc<Metrics>,
        kernel_losses: Arc<KernelLosses>,
        pipeline: Arc<PipelineStats>,
        otlp: Option<Exporter>,
    ) -> Self {
        let mut o = Self {
            registry,
            context,
            writer,
            include_allow,
            metrics,
            procs: ProcTable::new(crate::proctable::DEFAULT_CAPACITY, PathBuf::from("/proc")),
            recorded_kernel: kernel_losses.0.load(Ordering::Relaxed),
            recorded_channel: pipeline.userspace_drops(),
            kernel_losses,
            pipeline,
            otlp,
            hostname: hostname(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            failing: false,
        };
        o.publish_head();
        o
    }

    fn publish_head(&mut self) {
        if let Some(w) = &self.writer {
            let head = w.head();
            self.metrics.set_audit_head(
                head.next_seq,
                AuditInfo {
                    key_id: w.key_id(),
                    head_hash: hex::encode(head.hash),
                },
            );
        }
    }

    fn write(&mut self, record: &Value) {
        let Some(w) = self.writer.as_mut() else {
            return;
        };
        let before = w.head().next_seq;
        match w.append(record) {
            Ok(()) => {
                self.metrics.audit_records.fetch_add(1, Ordering::Relaxed);
                self.failing = false;
            }
            Err(e) => {
                self.metrics
                    .audit_write_errors
                    .fetch_add(1, Ordering::Relaxed);
                if !self.failing {
                    error!(error = %format!("{e:#}"), "audit log write failed");
                    self.failing = true;
                }
            }
        }
        self.after_write(before);
    }

    fn after_write(&mut self, before: u64) {
        let Some(w) = &self.writer else {
            return;
        };
        let sealed = w.head().next_seq.saturating_sub(before);
        if sealed > 0 {
            self.metrics
                .audit_batches
                .fetch_add(sealed, Ordering::Relaxed);
            self.publish_head();
        }
    }

    fn on_event(&mut self, event: &Event<'_>) {
        let hdr = &event.hdr;
        // Committed exec: process table first, audit only with allows.
        if let Payload::Exec { body, strings } = &event.payload {
            if body.flags & rk_exec_flag::RK_EXEC_DECISION == 0 {
                let mut names = *strings;
                if let Some(path) = names.next() {
                    self.procs.record_exec(hdr.tgid, text(path), hdr.ts_ns);
                }
                if !self.include_allow {
                    return;
                }
            }
        }
        let Some(verdict) = Verdict::from_abi(hdr.verdict) else {
            return;
        };
        if verdict == Verdict::Allow && !self.include_allow {
            return;
        }
        let Some(activity_owned) = OwnedActivity::from_event(event) else {
            return;
        };

        let context = self.context.read().unwrap().clone();
        let (profile, origin) = context.describe(hdr.rule_id, hdr.cgroup_id);
        if verdict != Verdict::Allow {
            self.metrics.hit(hdr.rule_id, verdict.as_str(), profile);
        }
        let session = self
            .registry
            .as_ref()
            .and_then(|r| r.session_for_cgroup(hdr.cgroup_id));
        let proc_info = self.procs.lookup(hdr.tgid, hdr.ts_ns);
        let record = ocsf::decision(&Decision {
            time_ms: wall_ms(hdr.ts_ns),
            activity: activity_owned.as_activity(),
            verdict,
            rule_id: hdr.rule_id,
            policy_gen: hdr.policy_gen,
            profile,
            rule_origin: origin,
            cgroup_id: hdr.cgroup_id,
            session: session.as_deref(),
            process: ocsf::Process {
                pid: hdr.tgid,
                tid: hdr.pid,
                uid: hdr.uid,
                gid: hdr.gid,
                exe: proc_info.exe.as_deref(),
                ppid: proc_info.ppid,
                enrichment: proc_info.source.as_str(),
            },
            hostname: &self.hostname,
            version: &self.version,
        });
        self.write(&record);
        if let (Some(exporter), Some(session)) = (&self.otlp, session.as_deref()) {
            exporter.offer(otlp::span_from_record(session, &record));
        }
    }

    /// Appends a loss record when either loss counter advanced.
    fn record_losses(&mut self) {
        let kernel = self.kernel_losses.0.load(Ordering::Relaxed);
        let channel = self.pipeline.userspace_drops();
        let (dk, dc) = (
            kernel.saturating_sub(self.recorded_kernel),
            channel.saturating_sub(self.recorded_channel),
        );
        if dk == 0 && dc == 0 {
            return;
        }
        warn!(
            kernel = dk,
            channel = dc,
            "decision events lost before the audit log"
        );
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0);
        let record = ocsf::loss(now, &self.hostname, &self.version, dk, dc);
        self.write(&record);
        self.recorded_kernel = kernel;
        self.recorded_channel = channel;
    }
}

impl RecordHandler for Observer {
    fn record(&mut self, bytes: &[u8], stats: &DecodeStats) {
        let result = decoder::decode(bytes);
        stats.record(&result);
        match result {
            Ok(event) => {
                // The per-event log line stays: operators and the Phase 6
                // suite read it. The audit log is the durable, signed record.
                crate::pipeline::log_event(&event, self.registry.as_ref());
                self.on_event(&event);
            }
            Err(e) => warn!(error = %e, kind = e.kind(), "rejected malformed ring buffer record"),
        }
    }

    fn tick(&mut self) {
        self.record_losses();
        if let Some(w) = self.writer.as_mut() {
            let before = w.head().next_seq;
            if let Err(e) = w.tick() {
                self.metrics
                    .audit_write_errors
                    .fetch_add(1, Ordering::Relaxed);
                error!(error = %format!("{e:#}"), "audit batch seal failed");
            }
            self.after_write(before);
        }
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        self.record_losses();
        if let Some(mut w) = self.writer.take() {
            let before = w.head().next_seq;
            match w.seal() {
                Ok(()) => info!(next_batch = w.head().next_seq, "audit log sealed"),
                Err(e) => error!(error = %format!("{e:#}"), "final audit seal failed"),
            }
            let sealed = w.head().next_seq.saturating_sub(before);
            self.metrics
                .audit_batches
                .fetch_add(sealed, Ordering::Relaxed);
        }
    }
}

/// An [`Activity`] with owned strings, built from a decoded event.
enum OwnedActivity {
    Connect {
        addr: IpAddr,
        port: u16,
        protocol: u8,
        sendmsg: bool,
    },
    SocketCreate {
        family: u16,
        sock_type: u32,
        protocol: u32,
    },
    Tun {
        op: u32,
    },
    Exec {
        path: Option<String>,
        argv: Option<String>,
        dev: u64,
        ino: u64,
        committed: bool,
    },
    File {
        path: Option<String>,
        hook: u16,
        access: u32,
        dev: u64,
        ino: u64,
    },
    Tamper {
        hook: u16,
        target_tgid: u32,
        detail: u64,
    },
}

fn first(strings: &Strings<'_>) -> Option<String> {
    let mut it = *strings;
    it.next().map(text)
}

impl OwnedActivity {
    fn from_event(event: &Event<'_>) -> Option<Self> {
        Some(match &event.payload {
            Payload::Net { body } => Self::Connect {
                addr: IpAddr::V6(Ipv6Addr::from(body.daddr_v6)),
                port: body.dport,
                protocol: body.protocol,
                sendmsg: u32::from(event.hdr.type_) == rk_event_type::RK_EV_SENDMSG,
            },
            Payload::Sock { body } => Self::SocketCreate {
                family: body.family,
                sock_type: body.type_,
                protocol: body.protocol,
            },
            Payload::Tun { body } => Self::Tun { op: body.op },
            Payload::Exec { body, strings } => {
                let committed = body.flags & rk_exec_flag::RK_EXEC_DECISION == 0;
                let mut it = *strings;
                let path = it.next().map(text);
                // The argument area is NUL-separated.
                let argv = it
                    .next()
                    .map(|a| text(a).trim_end_matches('\0').replace('\0', " "));
                Self::Exec {
                    path,
                    argv,
                    dev: body.file_dev,
                    ino: body.file_ino,
                    committed,
                }
            }
            Payload::FileDeny { body, strings } => Self::File {
                path: first(strings),
                hook: body.hook,
                access: body.access,
                dev: body.file_dev,
                ino: body.file_ino,
            },
            Payload::File { body, strings } => Self::File {
                path: first(strings),
                hook: 1,
                access: 1,
                dev: body.file_dev,
                ino: body.file_ino,
            },
            Payload::Tamper { body } => Self::Tamper {
                hook: body.hook,
                target_tgid: body.target_tgid,
                detail: body.detail,
            },
            Payload::Raw { .. } => return None,
        })
    }

    fn as_activity(&self) -> Activity<'_> {
        match self {
            Self::Connect {
                addr,
                port,
                protocol,
                sendmsg,
            } => Activity::Connect {
                addr: *addr,
                port: *port,
                protocol: *protocol,
                sendmsg: *sendmsg,
            },
            Self::SocketCreate {
                family,
                sock_type,
                protocol,
            } => Activity::SocketCreate {
                family: *family,
                sock_type: *sock_type,
                protocol: *protocol,
            },
            Self::Tun { op } => Activity::Tun { op: *op },
            Self::Exec {
                path,
                argv,
                dev,
                ino,
                committed,
            } => Activity::Exec {
                path: path.as_deref(),
                argv: argv.as_deref(),
                dev: *dev,
                ino: *ino,
                committed: *committed,
            },
            Self::File {
                path,
                hook,
                access,
                dev,
                ino,
            } => Activity::File {
                path: path.as_deref(),
                hook: *hook,
                access: *access,
                dev: *dev,
                ino: *ino,
            },
            Self::Tamper {
                hook,
                target_tgid,
                detail,
            } => Activity::Tamper {
                hook: *hook,
                target_tgid: *target_tgid,
                detail: *detail,
            },
        }
    }
}
