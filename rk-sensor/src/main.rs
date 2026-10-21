//! `rk-sensor` entry point.

// Release builds must carry their BPF objects; there is no runtime path override.
#[cfg(all(not(debug_assertions), not(feature = "embedded-bpf")))]
compile_error!(
    "release builds of rk-sensor must embed the BPF objects: build with `--features embedded-bpf`"
);

use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rk_agentd::protocol::{ApplyReportData, CapabilityStatus, DryRunData};
use rk_agentd::registry::AgentRegistry;
use rk_agentd::server::{self, PolicyHandler, ServerConfig};
use rk_sensor::loader::{self, Object};
use rk_sensor::policy::{self, PolicyEngine};
use rk_sensor::{consumer, selftest};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

const USAGE: &str = "usage: rk-sensor [--policy FILE] [--watch-policy] \
                     [--k8s-cgroup-root auto|DIR] | --selftest | --version | --help";

/// Policy file read at start and on SIGHUP when `--policy` is not given.
const DEFAULT_POLICY: &str = "/etc/rk/policy.toml";

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

#[derive(Debug, Default, PartialEq, Eq)]
struct RunOpts {
    policy: Option<String>,
    /// Re-apply the policy file whenever its content changes (Phase 5b §7).
    watch: bool,
    /// `auto` or a directory relative to the cgroupfs root (Phase 5b §5).
    k8s_root: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Run(RunOpts),
    Selftest,
    SelftestChild(Vec<String>),
    Version,
    Help,
}

fn parse_args(args: &[String]) -> Result<Mode, String> {
    match args {
        [flag] if flag == "--selftest" => return Ok(Mode::Selftest),
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
}

impl PolicyHandler for SensorPolicyHandler {
    fn apply(&mut self, text: &str) -> Result<ApplyReportData> {
        let rep = self.engine.apply_text(&mut self.ebpf, text)?;
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
        Ok(to_report_data(&rep))
    }

    fn bind_dynamic(&mut self, cgroup: &str, profile: &str) -> Result<u64> {
        self.engine.bind_dynamic(&mut self.ebpf, cgroup, profile)
    }

    fn unbind_dynamic(&mut self, cgroup_id: u64) -> Result<()> {
        self.engine.unbind_dynamic(&mut self.ebpf, cgroup_id)
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
        self.engine.bind_container(&mut self.ebpf, cgroup, profile)
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

/// Resolves `--k8s-cgroup-root`: `auto` probes [`K8S_ROOTS`]; anything else
/// must be an existing directory relative to the cgroupfs root.
fn resolve_k8s_root(arg: &str) -> Result<String> {
    let fs_root = Path::new(policy::CGROUP_FS);
    if arg == "auto" {
        return K8S_ROOTS
            .iter()
            .find(|r| fs_root.join(r).is_dir())
            .map(|r| r.to_string())
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

    runtime.block_on(async {
        let mut ebpf = loader::open(Object::Production)?;
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
        // refuse rules that need them (docs/design/phase-5b.md §6).
        let lsm_active = policy::bpf_lsm_active();
        let cgroup_root = Path::new(policy::CGROUP_FS).join(rk_policy::net::CGROUP_ROOT);
        let mut attached = policy::attach_network(&mut ebpf, &cgroup_root)?;
        if lsm_active {
            attached.extend(policy::attach_exec(&mut ebpf)?);
            attached.extend(policy::attach_file(&mut ebpf)?);
        } else {
            warn!("BPF LSM is not active: exec, file and raw-socket rules will be refused");
        }
        if let Some(root) = &k8s_root {
            attached.extend(policy::attach_network(
                &mut ebpf,
                &Path::new(policy::CGROUP_FS).join(root),
            )?);
            info!(
                root = root.as_str(),
                "network programs attached at the Kubernetes cgroup root"
            );
        }
        info!(?attached, lsm_active, "enforcement programs attached");

        let mut engine = PolicyEngine::default();
        engine.set_lsm_active(lsm_active);
        let stop = Arc::new(AtomicBool::new(false));
        let ring = consumer::take_ring(&mut ebpf)?;

        let registry = AgentRegistry::new();
        let consumer = tokio::spawn(consumer::consume_loop_with_registry(
            ring,
            stop.clone(),
            Some(registry.clone()),
        ));

        let mut handler_inner = SensorPolicyHandler {
            ebpf,
            engine,
            lsm_active,
            k8s_root: k8s_root.clone(),
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

        let mut hangup = signal(SignalKind::hangup()).context("install SIGHUP handler")?;
        let mut terminate = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
        let mut watch = tokio::time::interval(WATCH_INTERVAL);
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
                _ = terminate.recv() => break,
                _ = tokio::signal::ctrl_c() => break,
            }
        }

        stop.store(true, Ordering::Relaxed);
        consumer.await.context("consumer task panicked")??;
        info!("rk-sensor stopped");
        Ok(())
    })
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
            }))
        );
        assert!(parse_args(&args(&["--policy"])).is_err());
        assert!(parse_args(&args(&["--k8s-cgroup-root"])).is_err());
        assert_eq!(parse_args(&args(&["--selftest"])), Ok(Mode::Selftest));
        assert_eq!(parse_args(&args(&["-V"])), Ok(Mode::Version));
        assert_eq!(
            parse_args(&args(&[selftest::CHILD_FLAG, "a", "b"])),
            Ok(Mode::SelftestChild(args(&["a", "b"])))
        );
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
