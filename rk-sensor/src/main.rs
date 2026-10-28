//! `rk-sensor` entry point.

// Release builds must carry their BPF objects; there is no runtime path override.
#[cfg(all(not(debug_assertions), not(feature = "embedded-bpf")))]
compile_error!(
    "release builds of rk-sensor must embed the BPF objects: build with `--features embedded-bpf`"
);

use std::collections::BTreeMap;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rk_agentd::protocol::{ApplyReportData, CapabilityStatus, DryRunData};
use rk_agentd::registry::AgentRegistry;
use rk_agentd::server::{self, PolicyHandler, ServerConfig};
use rk_ebpf_common::rk_counter;
use rk_sensor::consumer::RecordHandler as _;
use rk_sensor::loader::{self, Object};
use rk_sensor::metrics::{self, Metrics, Snapshot, SnapshotFn};
use rk_sensor::observe::{KernelLosses, Observer, SharedContext};
use rk_sensor::policy::{self, PolicyEngine};
use rk_sensor::resilience::{self, Heartbeat};
use rk_sensor::{consumer, otlp, pins, selftest};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

const USAGE: &str = "usage: rk-sensor [--policy FILE] [--watch-policy] \
                     [--k8s-cgroup-root auto|DIR] [--heartbeat-timeout SECS] \
                     [--state-file FILE] [--ring-size-mb N] \
                     [--audit-dir DIR|off] [--audit-key FILE] [--audit-allow] \
                     [--metrics-addr ADDR|off] [--otlp-endpoint http://HOST:PORT] \
                     | --uninstall | --selftest | --version | --help";

/// Longest time a replacement spends draining the old ring buffer
/// (docs/design/phase-10.md §3).
const OLD_RING_DRAIN: Duration = Duration::from_secs(1);

/// Where the metrics endpoint listens by default (docs/design/phase-9.md §3.5).
const DEFAULT_METRICS_ADDR: &str = "127.0.0.1:9464";

/// Policy file read at start and on SIGHUP when `--policy` is not given.
const DEFAULT_POLICY: &str = "/etc/rk/policy.toml";

/// Engine state kept across restarts (docs/design/phase-6.md §3.3).
const DEFAULT_STATE_FILE: &str = "/run/rk/engine-state.json";

/// Default heartbeat timeout (docs/design/phase-6.md §4).
const DEFAULT_HEARTBEAT_SECS: u64 = 10;

/// Kubernetes cgroup roots probed by `--k8s-cgroup-root auto`, relative to
/// the cgroupfs root: systemd driver, cgroupfs driver, and kubelet's
/// `--cgroup-root=/kubelet` layout (used by kind) for each.
const K8S_ROOTS: &[&str] = &[
    "kubepods.slice",
    "kubepods",
    "kubelet.slice/kubelet-kubepods.slice",
    "kubelet/kubepods",
];

/// How often `--watch-policy` checks the policy file.
const WATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// How often the pipeline counters are logged (Phase 7 §5).
const STATS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Debug, Default, PartialEq, Eq)]
struct RunOpts {
    policy: Option<String>,
    /// Re-apply the policy file whenever its content changes (Phase 5b §7).
    watch: bool,
    /// `auto` or a directory relative to the cgroupfs root (Phase 5b §5).
    k8s_root: Option<String>,
    /// Seconds without a heartbeat before governed ENFORCE workloads are
    /// denied (Phase 6 §4); `None` means the default.
    heartbeat_secs: Option<u64>,
    state_file: Option<String>,
    /// Ring buffer size in MiB; default scales with CPUs (Phase 7 §4).
    ring_mb: Option<u32>,
    /// Audit log directory, or `off` (Phase 9 §3.3).
    audit_dir: Option<String>,
    audit_key: Option<String>,
    /// Also record allowed decisions in the audit log.
    audit_allow: bool,
    /// Metrics listen address, or `off` (Phase 9 §3.5).
    metrics_addr: Option<String>,
    /// OTLP/HTTP collector, e.g. `http://127.0.0.1:4318` (Phase 9 §3.6).
    otlp_endpoint: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Run(RunOpts),
    /// Remove the pin set: the only way to end protection without waiting
    /// for the heartbeat to fail closed (Phase 6 §3.5).
    Uninstall,
    Selftest,
    SelftestChild(Vec<String>),
    Version,
    Help,
}

fn parse_args(args: &[String]) -> Result<Mode, String> {
    match args {
        [flag] if flag == "--selftest" => return Ok(Mode::Selftest),
        [flag] if flag == "--uninstall" => return Ok(Mode::Uninstall),
        [flag] if flag == "--version" || flag == "-V" => return Ok(Mode::Version),
        [flag] if flag == "--help" || flag == "-h" => return Ok(Mode::Help),
        [flag, rest @ ..] if flag == selftest::CHILD_FLAG => {
            return Ok(Mode::SelftestChild(rest.to_vec()))
        }
        _ => {}
    }
    let unrecognised = || format!("unrecognised arguments: {}\n{USAGE}", args.join(" "));
    let mut opts = RunOpts::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--policy" => opts.policy = Some(it.next().ok_or_else(unrecognised)?.clone()),
            "--k8s-cgroup-root" => {
                opts.k8s_root = Some(it.next().ok_or_else(unrecognised)?.clone())
            }
            "--watch-policy" => opts.watch = true,
            "--heartbeat-timeout" => {
                let secs: u64 = it
                    .next()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(unrecognised)?;
                if secs == 0 {
                    return Err(format!("--heartbeat-timeout must be at least 1\n{USAGE}"));
                }
                opts.heartbeat_secs = Some(secs);
            }
            "--state-file" => opts.state_file = Some(it.next().ok_or_else(unrecognised)?.clone()),
            "--ring-size-mb" => {
                opts.ring_mb = Some(
                    it.next()
                        .and_then(|s| s.parse().ok())
                        .ok_or_else(unrecognised)?,
                )
            }
            "--audit-dir" => opts.audit_dir = Some(it.next().ok_or_else(unrecognised)?.clone()),
            "--audit-key" => opts.audit_key = Some(it.next().ok_or_else(unrecognised)?.clone()),
            "--audit-allow" => opts.audit_allow = true,
            "--metrics-addr" => {
                let addr = it.next().ok_or_else(unrecognised)?;
                if addr != "off" && addr.parse::<std::net::SocketAddr>().is_err() {
                    return Err(format!(
                        "--metrics-addr `{addr}` is not HOST:PORT or off\n{USAGE}"
                    ));
                }
                opts.metrics_addr = Some(addr.clone());
            }
            "--otlp-endpoint" => {
                let endpoint = it.next().ok_or_else(unrecognised)?;
                otlp::validate_endpoint(endpoint).map_err(|e| format!("{e}\n{USAGE}"))?;
                opts.otlp_endpoint = Some(endpoint.clone());
            }
            _ => return Err(unrecognised()),
        }
    }
    Ok(Mode::Run(opts))
}

fn exit_code(code: i32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = match parse_args(&args) {
        Ok(mode) => mode,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(64);
        }
    };

    match mode {
        Mode::Uninstall => {
            let root = Path::new(pins::PIN_ROOT);
            match pins::uninstall(root) {
                Ok(true) => {
                    println!("removed {}: protection ended", root.display());
                    ExitCode::SUCCESS
                }
                Ok(false) => {
                    println!("nothing pinned at {}", root.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("rk-sensor: {e:#}");
                    ExitCode::FAILURE
                }
            }
        }
        Mode::Help => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Mode::Version => {
            println!(
                "rk-sensor {} (abi {})",
                env!("CARGO_PKG_VERSION"),
                rk_ebpf_common::RK_ABI_VERSION
            );
            ExitCode::SUCCESS
        }
        Mode::SelftestChild(rest) => exit_code(selftest::run_child(&rest)),
        Mode::Selftest => {
            let report = selftest::run();
            match serde_json::to_string_pretty(&report) {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    eprintln!("failed to serialise selftest report: {e}");
                    return ExitCode::from(1);
                }
            }
            exit_code(report.exit_code)
        }
        Mode::Run(opts) => match run_daemon(&opts) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("rk-sensor: {e:#}");
                ExitCode::FAILURE
            }
        },
    }
}

struct SensorPolicyHandler {
    ebpf: aya::Ebpf,
    engine: PolicyEngine,
    lsm_active: bool,
    k8s_root: Option<String>,
    pipeline: Arc<consumer::PipelineStats>,
    /// Rule and binding names for the audit log, republished on every change.
    audit_ctx: SharedContext,
    metrics: Arc<Metrics>,
    audit_dir: Option<String>,
    metrics_addr: Option<String>,
}

impl SensorPolicyHandler {
    fn publish(&self) {
        *self.audit_ctx.write().unwrap() = Arc::new(self.engine.audit_context());
    }

    /// Kernel decision counters by hook and verdict (Phase 9 §3.4).
    fn decision_counters(&self, out: &mut BTreeMap<String, u64>) {
        let Some(map) = self.ebpf.map("rk_counters") else {
            return;
        };
        let Ok(per_cpu) = aya::maps::PerCpuArray::<_, u64>::try_from(map) else {
            return;
        };
        for (h, hook) in metrics::HOOKS.iter().enumerate() {
            for (v, verdict) in metrics::VERDICTS.iter().enumerate() {
                let index = rk_counter::RK_CNT_DECISION_BASE
                    + h as u32 * rk_ebpf_common::RK_VERDICTS
                    + v as u32;
                if let Ok(values) = per_cpu.get(&index, 0) {
                    out.insert(metrics::decision_key(hook, verdict), values.iter().sum());
                }
            }
        }
    }
}

impl PolicyHandler for SensorPolicyHandler {
    fn apply(&mut self, text: &str) -> Result<ApplyReportData> {
        let rep = self.engine.apply_text(&mut self.ebpf, text)?;
        self.publish();
        Ok(to_report_data(&rep))
    }

    fn dry_run(&self, text: &str) -> Result<DryRunData> {
        let dr = self.engine.dry_run(text)?;
        Ok(DryRunData {
            generation: dr.generation,
            profiles: dr.profiles,
            deny_entries: dr.deny_entries,
            allow_entries: dr.allow_entries,
            exec_entries: dr.exec_entries,
            file_entries: dr.file_entries,
            skipped_files: dr.skipped_files,
            cgroups_to_create: dr.cgroups_to_create,
            diff: dr.changes,
        })
    }

    fn diff(&self, text: &str) -> Result<Vec<String>> {
        self.engine.diff_text(text)
    }

    fn rollback(&mut self) -> Result<ApplyReportData> {
        let rep = self.engine.rollback(&mut self.ebpf)?;
        self.publish();
        Ok(to_report_data(&rep))
    }

    fn bind_dynamic(&mut self, cgroup: &str, profile: &str) -> Result<u64> {
        let id = self.engine.bind_dynamic(&mut self.ebpf, cgroup, profile)?;
        self.publish();
        Ok(id)
    }

    fn unbind_dynamic(&mut self, cgroup_id: u64) -> Result<()> {
        self.engine.unbind_dynamic(&mut self.ebpf, cgroup_id)?;
        self.publish();
        Ok(())
    }

    fn get_profile(&self, name: &str) -> Result<rk_policy::net::Profile> {
        self.engine
            .policy()
            .context("no policy applied yet")?
            .profiles
            .iter()
            .find(|p| p.name == name)
            .cloned()
            .with_context(|| format!("profile `{name}` not found"))
    }

    fn active_profiles(&self) -> Vec<String> {
        self.engine
            .policy()
            .map(|p| p.profiles.iter().map(|prof| prof.name.clone()).collect())
            .unwrap_or_default()
    }

    fn generation(&self) -> u64 {
        self.engine.generation()
    }

    fn capabilities(&self) -> Vec<CapabilityStatus> {
        vec![
            CapabilityStatus {
                name: "bpf_lsm".into(),
                ok: self.lsm_active,
                detail: if self.lsm_active {
                    "active: exec, file and raw-socket rules enforced".into()
                } else {
                    "inactive (`bpf` not in /sys/kernel/security/lsm): network rules only; \
                     boot with lsm=...,bpf"
                        .into()
                },
            },
            CapabilityStatus {
                name: "cgroup_v2".into(),
                ok: Path::new(policy::CGROUP_FS)
                    .join("cgroup.controllers")
                    .exists(),
                detail: policy::CGROUP_FS.into(),
            },
            CapabilityStatus {
                name: "kubernetes".into(),
                ok: self.k8s_root.is_some(),
                detail: match &self.k8s_root {
                    Some(root) => format!("container bindings under {root}"),
                    None => "not enabled (--k8s-cgroup-root)".into(),
                },
            },
            CapabilityStatus {
                name: "audit_log".into(),
                ok: self.metrics.audit_info().is_some(),
                detail: match (&self.audit_dir, self.metrics.audit_info()) {
                    (Some(dir), Some(info)) => format!(
                        "{dir}: key {}, next batch {}",
                        info.key_id,
                        self.metrics
                            .audit_head_seq
                            .load(std::sync::atomic::Ordering::Relaxed)
                    ),
                    (Some(dir), None) => format!("{dir}: not writable (see the sensor log)"),
                    (None, _) => "disabled (--audit-dir off)".into(),
                },
            },
            CapabilityStatus {
                name: "metrics".into(),
                ok: self.metrics_addr.is_some(),
                detail: match &self.metrics_addr {
                    Some(addr) => format!("http://{addr}/metrics"),
                    None => "disabled (--metrics-addr off)".into(),
                },
            },
        ]
    }

    fn resolve_pod_profile(
        &self,
        namespace: &str,
        annotation: Option<&str>,
    ) -> Result<Option<String>> {
        self.engine
            .policy()
            .context("no policy applied yet")?
            .resolve_pod_profile(namespace, annotation)
            .map_err(anyhow::Error::msg)
    }

    fn bind_container(&mut self, cgroup: &str, profile: &str) -> Result<u64> {
        let id = self
            .engine
            .bind_container(&mut self.ebpf, cgroup, profile)?;
        self.publish();
        Ok(id)
    }

    fn counters(&self) -> BTreeMap<String, u64> {
        let mut out = BTreeMap::new();
        if let Some(map) = self.ebpf.map("rk_counters") {
            if let Ok(per_cpu) = aya::maps::PerCpuArray::<_, u64>::try_from(map) {
                for (name, index) in [
                    ("ringbuf_drops", rk_counter::RK_CNT_RINGBUF_DROP),
                    ("scratch_misses", rk_counter::RK_CNT_SCRATCH_MISS),
                ] {
                    if let Ok(values) = per_cpu.get(&index, 0) {
                        out.insert(name.to_string(), values.iter().sum());
                    }
                }
            }
        }
        self.decision_counters(&mut out);
        out.insert("records_drained".into(), self.pipeline.drained());
        out.insert("userspace_drops".into(), self.pipeline.userspace_drops());
        out.insert("decoded".into(), self.pipeline.decode.decoded());
        out.insert("decode_rejected".into(), self.pipeline.decode.rejected());
        out
    }
}

/// Events the kernel could not emit: ring buffer drops plus scratch misses.
fn kernel_lost(ebpf: &aya::Ebpf) -> u64 {
    let Some(map) = ebpf.map("rk_counters") else {
        return 0;
    };
    let Ok(per_cpu) = aya::maps::PerCpuArray::<_, u64>::try_from(map) else {
        return 0;
    };
    [
        rk_counter::RK_CNT_RINGBUF_DROP,
        rk_counter::RK_CNT_SCRATCH_MISS,
    ]
    .iter()
    .filter_map(|i| per_cpu.get(i, 0).ok())
    .map(|values| values.iter().sum::<u64>())
    .sum()
}

/// `--audit-dir`/`--metrics-addr` style option: `off`, a value, or the default.
fn on_or_off(value: Option<&str>, default: &str) -> Option<String> {
    match value {
        Some("off") => None,
        other => Some(other.unwrap_or(default).to_string()),
    }
}

fn to_report_data(rep: &policy::ApplyReport) -> ApplyReportData {
    ApplyReportData {
        generation: rep.generation,
        slot: rep.slot,
        profiles: rep.profiles,
        deny_entries: rep.deny_entries,
        allow_entries: rep.allow_entries,
        exec_entries: rep.exec_entries,
        file_entries: rep.file_entries,
        skipped_files: rep.skipped_files.clone(),
        bindings: rep.bindings,
    }
}

/// Moves this thread into PID 1's cgroup namespace, so `/proc/<pid>/cgroup`
/// of containers reads as paths from the host cgroupfs root. A DaemonSet pod
/// has a private cgroup namespace; needs `hostPID` and CAP_SYS_ADMIN. Must
/// run before any other thread exists: setns changes only the calling thread,
/// and threads created afterwards inherit it.
fn enter_host_cgroup_namespace() -> Result<()> {
    let ns = std::fs::File::open("/proc/1/ns/cgroup").context("open /proc/1/ns/cgroup")?;
    // SAFETY: plain syscall on a valid fd that outlives the call.
    if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWCGROUP) } != 0 {
        return Err(std::io::Error::last_os_error()).context("setns(CLONE_NEWCGROUP)");
    }
    Ok(())
}

/// Resolves `--k8s-cgroup-root`. `auto` prefers the candidate in
/// [`K8S_ROOTS`] that contains this process's own cgroup (the DaemonSet pod
/// is itself under the root), then the first one that exists. Anything else
/// must be an existing directory relative to the cgroupfs root.
fn resolve_k8s_root(arg: &str) -> Result<String> {
    let fs_root = Path::new(policy::CGROUP_FS);
    if arg == "auto" {
        let own = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
        let own = own
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .unwrap_or("")
            .trim_start_matches('/');
        return pick_k8s_root(own, |r| fs_root.join(r).is_dir())
            .map(str::to_string)
            .with_context(|| format!("no Kubernetes cgroup root found (tried {K8S_ROOTS:?})"));
    }
    let root = arg.trim_matches('/');
    if root.is_empty() || root.split('/').any(|s| s == ".." || s == ".") {
        bail!("invalid --k8s-cgroup-root `{arg}`");
    }
    if !fs_root.join(root).is_dir() {
        bail!(
            "--k8s-cgroup-root `{root}` does not exist under {}",
            policy::CGROUP_FS
        );
    }
    Ok(root.to_string())
}

/// The [`K8S_ROOTS`] entry containing `own_cgroup`, else the first that
/// `exists`.
fn pick_k8s_root(own_cgroup: &str, exists: impl Fn(&str) -> bool) -> Option<&'static str> {
    K8S_ROOTS
        .iter()
        .find(|r| own_cgroup.starts_with(&format!("{r}/")))
        .or_else(|| K8S_ROOTS.iter().find(|r| exists(r)))
        .copied()
}

fn log_report(path: &str, report: &ApplyReportData, how: &str) {
    if !report.skipped_files.is_empty() {
        warn!(
            path,
            skipped = ?report.skipped_files,
            "built-in file rules not active on this host (missing or inaccessible)"
        );
    }
    info!(path, ?report, how, "policy applied");
}

fn run_daemon(opts: &RunOpts) -> Result<()> {
    let policy_path = opts.policy.as_deref().unwrap_or(DEFAULT_POLICY);
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    // Before the runtime starts any thread (see enter_host_cgroup_namespace).
    if opts.k8s_root.is_some() {
        enter_host_cgroup_namespace()?;
    }
    let k8s_root = opts.k8s_root.as_deref().map(resolve_k8s_root).transpose()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to start the tokio runtime")?;

    let result = runtime.block_on(async {
        // Pinned maps first (docs/design/phase-6.md §3). An adopted pin set
        // has run on a stale heartbeat for as long as the sensor was down, so
        // beat before anything slow.
        let bytes = loader::object_bytes(Object::Production)?;
        let pin_root = Path::new(pins::PIN_ROOT);
        let pins::Pinned {
            mut ebpf,
            adoption,
            epoch,
            links,
            previous,
        } = pins::open(
            bytes,
            pin_root,
            consumer::ring_size(
                std::thread::available_parallelism().map_or(1, usize::from),
                opts.ring_mb,
            ),
        )?;
        let timeout = Duration::from_secs(opts.heartbeat_secs.unwrap_or(DEFAULT_HEARTBEAT_SECS));
        let heartbeat = Heartbeat::start(&mut ebpf, timeout)?;
        resilience::protect_self(&mut ebpf)?;
        info!(
            ?adoption,
            heartbeat_timeout_s = timeout.as_secs(),
            "pin set ready"
        );

        let btf = aya::Btf::from_sys_fs().ok();
        let programs = loader::load_programs(Object::Production, &mut ebpf, btf.as_ref());
        if let Some(failed) = programs.iter().find(|p| !p.probe && !p.loaded) {
            bail!(
                "program `{}` failed to load: {}",
                failed.name,
                failed.error.as_deref().unwrap_or("unknown error")
            );
        }

        // LSM programs attach even where BPF LSM is inactive, but are never
        // called there. Attach them only where they work, and let the engine
        // refuse rules that need them (docs/design/phase-5b.md §6). Links
        // already pinned by an earlier sensor are adopted, not re-attached.
        let lsm_active = policy::bpf_lsm_active();
        let links = Some(links.as_path());
        let cgroup_root = Path::new(policy::CGROUP_FS).join(rk_policy::net::CGROUP_ROOT);
        let mut attached = policy::attach_sock_addr(&mut ebpf, &cgroup_root, links)?;
        if lsm_active {
            attached.extend(policy::attach_network_lsm(&mut ebpf, links)?);
            attached.extend(policy::attach_exec(&mut ebpf, links)?);
            attached.extend(policy::attach_file(&mut ebpf, links)?);
            attached.extend(policy::attach_guard(&mut ebpf, links)?);
        } else {
            warn!("BPF LSM is not active: exec, file and raw-socket rules will be refused");
        }
        if let Some(root) = &k8s_root {
            attached.extend(policy::attach_sock_addr(
                &mut ebpf,
                &Path::new(policy::CGROUP_FS).join(root),
                links,
            )?);
            info!(
                root = root.as_str(),
                "network programs attached at the Kubernetes cgroup root"
            );
        }
        info!(?attached, lsm_active, "enforcement programs attached");

        let mut engine = PolicyEngine::default();
        engine.set_lsm_active(lsm_active);
        engine.set_state_file(
            PathBuf::from(opts.state_file.as_deref().unwrap_or(DEFAULT_STATE_FILE)),
            &epoch,
        );
        if adoption == pins::Adoption::Adopted {
            let restored = engine.adopt(&mut ebpf)?;
            info!(
                restored,
                generation = engine.generation(),
                "adopted the running policy"
            );
        }

        // Replacing a different object (docs/design/phase-10.md §3): both
        // generations are attached now. The new maps must hold the policy
        // before the old pin set may go; otherwise the old one keeps
        // enforcing and this sensor stops.
        let mut old_ring = None;
        if let Some(prev) = &previous {
            let carried = (|| -> Result<&'static str> {
                if engine.migrate(&mut ebpf, &prev.epoch)? {
                    return Ok("the replaced pin set's state");
                }
                let text = std::fs::read_to_string(policy_path)
                    .with_context(|| format!("no state to carry over and cannot read {policy_path}"))?;
                engine.apply_text(&mut ebpf, &text)?;
                Ok("the policy file")
            })();
            match carried {
                Ok(from) => info!(from, generation = engine.generation(), "policy carried into the new object"),
                Err(e) => {
                    pins::abort_replacement(pin_root)?;
                    return Err(e.context(
                        "cannot replace the running object; it stays attached and keeps enforcing",
                    ));
                }
            }
            old_ring = aya::maps::MapData::from_pin(prev.root.join("maps").join("events_ringbuf"))
                .ok()
                .and_then(|data| aya::maps::RingBuf::try_from(aya::maps::Map::RingBuf(data)).ok());
        }
        let ring = consumer::take_ring(&mut ebpf)?;
        let registry = AgentRegistry::new();

        // Phase 9: audit log, metrics and OTLP behind the worker. Telemetry
        // never gates enforcement: a log that cannot be opened is reported
        // (rk status, metrics) and the sensor carries on.
        let metrics = Arc::new(Metrics::default());
        let audit_ctx: SharedContext =
            Arc::new(std::sync::RwLock::new(Arc::new(engine.audit_context())));
        let audit_dir = on_or_off(opts.audit_dir.as_deref(), rk_audit::DEFAULT_DIR);
        let writer = audit_dir.as_deref().and_then(|dir| {
            let key_path = opts.audit_key.as_deref().unwrap_or(rk_audit::DEFAULT_KEY);
            let opened = rk_audit::key::AuditKey::load_or_create(Path::new(key_path)).and_then(
                |key| rk_audit::chain::Writer::open(Path::new(dir), key, Default::default()),
            );
            match opened {
                Ok(w) => {
                    info!(dir, key_id = %w.key_id(), next_batch = w.head().next_seq, "audit log open");
                    for d in w.discarded() {
                        warn!(
                            file = %d.path.display(),
                            lines = d.lines,
                            bytes = d.bytes,
                            "audit log: lines after the last sealed batch (a crash mid-batch, or \
                             written by someone else) were set aside unsigned, not sealed"
                        );
                    }
                    Some(w)
                }
                Err(e) => {
                    error!(dir, error = %format!("{e:#}"), "audit log disabled: cannot open it");
                    None
                }
            }
        });
        let metrics_addr = on_or_off(opts.metrics_addr.as_deref(), DEFAULT_METRICS_ADDR);
        let exporter = opts.otlp_endpoint.as_deref().map(|endpoint| {
            otlp::start(
                endpoint,
                rk_sensor::observe::hostname(),
                env!("CARGO_PKG_VERSION").to_string(),
                metrics.clone(),
            )
        });
        // Losses before this start (pins adopted from an earlier sensor) are
        // the baseline: only new losses become loss records.
        let kernel_losses = Arc::new(KernelLosses(std::sync::atomic::AtomicU64::new(
            kernel_lost(&ebpf),
        )));
        let pipeline_stats = Arc::new(consumer::PipelineStats::default());
        let mut observer = Observer::new(
            Some(registry.clone()),
            audit_ctx.clone(),
            writer,
            opts.audit_allow,
            metrics.clone(),
            kernel_losses.clone(),
            pipeline_stats.clone(),
            exporter,
        );
        if let Some(mut old) = old_ring.take() {
            // Decisions the old programs made since the old sensor stopped.
            // They are still attached and still writing, so the drain is
            // bounded in time; anything after the deadline is only in the
            // old ring, which is about to go.
            let deadline = std::time::Instant::now() + OLD_RING_DRAIN;
            let mut drained = 0u64;
            while std::time::Instant::now() < deadline {
                let Some(item) = old.next() else {
                    break;
                };
                observer.record(&item, &pipeline_stats.decode);
                drained += 1;
            }
            drop(old);
            pins::finish_replacement(pin_root)?;
            info!(
                drained,
                "replaced the running object without a gap: old programs detached after the new ones took over"
            );
        } else if previous.is_some() {
            pins::finish_replacement(pin_root)?;
            info!("replaced the running object without a gap (old ring buffer not readable)");
        }
        let consumer = consumer::Consumer::start_with(
            ring,
            Box::new(observer),
            pipeline_stats,
            consumer::Config::default(),
        )?;

        let mut handler_inner = SensorPolicyHandler {
            ebpf,
            engine,
            lsm_active,
            k8s_root: k8s_root.clone(),
            pipeline: consumer.stats(),
            audit_ctx,
            metrics: metrics.clone(),
            audit_dir,
            metrics_addr: metrics_addr.clone(),
        };
        // Last policy text seen on disk, applied or not, so the watcher acts
        // (and logs a rejection) once per change.
        let mut last_seen: Option<String> = None;
        match std::fs::read_to_string(policy_path) {
            Ok(text) => {
                match handler_inner.apply(&text) {
                    Ok(report) => log_report(policy_path, &report, "start"),
                    Err(e) => error!(
                        path = policy_path,
                        error = %format!("{e:#}"),
                        "policy rejected; active policy unchanged"
                    ),
                }
                last_seen = Some(text);
            }
            Err(_) => warn!(
                path = policy_path,
                "policy file not readable; active policy unchanged"
            ),
        }

        let handler: Arc<Mutex<dyn PolicyHandler>> = Arc::new(Mutex::new(handler_inner));

        let server_cfg = ServerConfig {
            socket_path: PathBuf::from(rk_agentd::protocol::DEFAULT_SOCKET_PATH),
            cgroup_fs: PathBuf::from(policy::CGROUP_FS),
            service_uid: 65534,
            service_gid: 65534,
            k8s_cgroup_root: k8s_root,
        };

        let server_handler = handler.clone();
        let server_registry = registry.clone();
        let _server = tokio::spawn(async move {
            if let Err(e) = server::run_server(server_cfg, server_handler, server_registry).await {
                error!(error = %e, "agentd server stopped with error");
            }
        });

        if let Some(addr) = &metrics_addr {
            let addr: std::net::SocketAddr = addr
                .parse()
                .with_context(|| format!("--metrics-addr `{addr}`"))?;
            let snapshot_handler = handler.clone();
            let stats = consumer.stats();
            let last_beat = heartbeat.last_beat();
            let snapshot: SnapshotFn =
                Arc::new(move || -> Pin<Box<dyn Future<Output = Snapshot> + Send>> {
                    let handler = snapshot_handler.clone();
                    let stats = stats.clone();
                    let last_beat = last_beat.clone();
                    Box::pin(async move {
                        let h = handler.lock().await;
                        Snapshot {
                            counters: h.counters(),
                            decoder_errors: stats.decode.rejected_by_kind().collect(),
                            policy_generation: h.generation(),
                            heartbeat_age_seconds: Some(
                                resilience::heartbeat_age(&last_beat).as_secs_f64(),
                            ),
                            capabilities: h
                                .capabilities()
                                .into_iter()
                                .map(|c| (c.name, c.ok))
                                .collect(),
                        }
                    })
                });
            let served = metrics.clone();
            tokio::spawn(async move {
                if let Err(e) = metrics::serve(addr, served, snapshot).await {
                    error!(error = %format!("{e:#}"), "metrics endpoint stopped");
                }
            });
            info!(%addr, "metrics endpoint listening");
        }

        let mut hangup = signal(SignalKind::hangup()).context("install SIGHUP handler")?;
        let mut terminate = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
        let mut watch = tokio::time::interval(WATCH_INTERVAL);
        let mut stats_tick = tokio::time::interval(STATS_INTERVAL);
        // Kernel losses feed the audit log's loss records (Phase 9 §3.4).
        let mut loss_tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = hangup.recv() => {
                    match std::fs::read_to_string(policy_path) {
                        Ok(text) => {
                            match handler.lock().await.apply(&text) {
                                Ok(report) => log_report(policy_path, &report, "SIGHUP"),
                                Err(e) => error!(
                                    path = policy_path,
                                    error = %format!("{e:#}"),
                                    "policy rejected on SIGHUP; active policy unchanged"
                                ),
                            }
                            last_seen = Some(text);
                        }
                        Err(e) => warn!(
                            path = policy_path,
                            error = %e,
                            "policy file not readable on SIGHUP; active policy unchanged"
                        ),
                    }
                }
                _ = watch.tick(), if opts.watch => {
                    // ConfigMap volumes are updated by an atomic symlink swap,
                    // so a read sees either the old or the new file, never half.
                    if let Ok(text) = std::fs::read_to_string(policy_path) {
                        if last_seen.as_deref() != Some(text.as_str()) {
                            match handler.lock().await.apply(&text) {
                                Ok(report) => log_report(policy_path, &report, "watch"),
                                Err(e) => error!(
                                    path = policy_path,
                                    error = %format!("{e:#}"),
                                    "changed policy rejected; active policy unchanged"
                                ),
                            }
                            last_seen = Some(text);
                        }
                    }
                }
                _ = stats_tick.tick() => {
                    let counters = handler.lock().await.counters();
                    info!(?counters, "pipeline stats");
                }
                _ = loss_tick.tick() => {
                    let counters = handler.lock().await.counters();
                    let lost = ["ringbuf_drops", "scratch_misses"]
                        .iter()
                        .map(|k| counters.get(*k).copied().unwrap_or(0))
                        .sum::<u64>();
                    kernel_losses.0.store(lost, Ordering::Relaxed);
                }
                _ = terminate.recv() => break,
                _ = tokio::signal::ctrl_c() => break,
            }
        }

        consumer.stop();
        info!("rk-sensor stopped");
        Ok(())
    });
    // The agentd accept loop blocks in poll(2) on a blocking thread, which a
    // plain runtime drop waits for forever: SIGTERM must end the process.
    // Everything that needs a clean stop (consumer drain, final audit seal,
    // heartbeat thread) has finished inside the block above.
    runtime.shutdown_timeout(Duration::from_secs(2));
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_known_modes() {
        assert_eq!(parse_args(&args(&[])), Ok(Mode::Run(RunOpts::default())));
        assert_eq!(
            parse_args(&args(&["--policy", "/etc/rk/p.toml"])),
            Ok(Mode::Run(RunOpts {
                policy: Some("/etc/rk/p.toml".into()),
                ..RunOpts::default()
            }))
        );
        assert_eq!(
            parse_args(&args(&[
                "--watch-policy",
                "--k8s-cgroup-root",
                "auto",
                "--policy",
                "/p"
            ])),
            Ok(Mode::Run(RunOpts {
                policy: Some("/p".into()),
                watch: true,
                k8s_root: Some("auto".into()),
                ..RunOpts::default()
            }))
        );
        assert!(parse_args(&args(&["--policy"])).is_err());
        assert!(parse_args(&args(&["--k8s-cgroup-root"])).is_err());
        assert_eq!(
            parse_args(&args(&[
                "--heartbeat-timeout",
                "3",
                "--state-file",
                "/s.json"
            ])),
            Ok(Mode::Run(RunOpts {
                heartbeat_secs: Some(3),
                state_file: Some("/s.json".into()),
                ..RunOpts::default()
            }))
        );
        for bad in [["--heartbeat-timeout", "0"], ["--heartbeat-timeout", "x"]] {
            assert!(parse_args(&args(&bad)).is_err(), "{bad:?}");
        }
        assert_eq!(parse_args(&args(&["--uninstall"])), Ok(Mode::Uninstall));
        assert_eq!(
            parse_args(&args(&["--ring-size-mb", "8"])),
            Ok(Mode::Run(RunOpts {
                ring_mb: Some(8),
                ..RunOpts::default()
            }))
        );
        assert!(parse_args(&args(&["--ring-size-mb", "x"])).is_err());
        assert_eq!(parse_args(&args(&["--selftest"])), Ok(Mode::Selftest));
        assert_eq!(parse_args(&args(&["-V"])), Ok(Mode::Version));
        assert_eq!(
            parse_args(&args(&[selftest::CHILD_FLAG, "a", "b"])),
            Ok(Mode::SelftestChild(args(&["a", "b"])))
        );
    }

    #[test]
    fn parses_observability_flags() {
        assert_eq!(
            parse_args(&args(&[
                "--audit-dir",
                "/a",
                "--audit-key",
                "/k",
                "--audit-allow",
                "--metrics-addr",
                "0.0.0.0:9464",
                "--otlp-endpoint",
                "http://127.0.0.1:4318",
            ])),
            Ok(Mode::Run(RunOpts {
                audit_dir: Some("/a".into()),
                audit_key: Some("/k".into()),
                audit_allow: true,
                metrics_addr: Some("0.0.0.0:9464".into()),
                otlp_endpoint: Some("http://127.0.0.1:4318".into()),
                ..RunOpts::default()
            }))
        );
        assert!(parse_args(&args(&["--metrics-addr", "off"])).is_ok());
        assert!(parse_args(&args(&["--metrics-addr", "nonsense"])).is_err());
        assert!(parse_args(&args(&["--otlp-endpoint", "https://collector:4318"])).is_err());
        assert_eq!(on_or_off(Some("off"), "d"), None);
        assert_eq!(on_or_off(None, "d").as_deref(), Some("d"));
        assert_eq!(on_or_off(Some("/x"), "d").as_deref(), Some("/x"));
    }

    #[test]
    fn k8s_root_prefers_the_one_containing_the_daemon() {
        let kind = "kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/p/c";
        // kubepods.slice exists too, but the daemon's own pod is elsewhere.
        assert_eq!(
            pick_k8s_root(kind, |_| true),
            Some("kubelet.slice/kubelet-kubepods.slice")
        );
        // Not in a pod (systemd service): first existing candidate.
        assert_eq!(
            pick_k8s_root("system.slice/rk.service", |r| r == "kubepods"),
            Some("kubepods")
        );
        assert_eq!(pick_k8s_root("", |_| false), None);
        // A prefix that is not a whole path segment does not count.
        assert_eq!(pick_k8s_root("kubepods.slicex/c", |_| false), None);
    }

    /// Plan Phase 0: release builds contain no runtime override for the BPF
    /// object path. No flag accepts a path; unknown flags are rejected.
    #[test]
    fn no_object_path_flag() {
        for flag in ["--bpf-object", "--object", "--bpf", "--bpf-path", "--obj"] {
            assert!(parse_args(&args(&[flag, "/tmp/evil.o"])).is_err(), "{flag}");
        }
        assert!(!USAGE.contains("path"));
    }
}
