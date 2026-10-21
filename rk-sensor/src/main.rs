//! `rk-sensor` entry point.

// Release builds must carry their BPF objects; there is no runtime path override.
#[cfg(all(not(debug_assertions), not(feature = "embedded-bpf")))]
compile_error!(
    "release builds of rk-sensor must embed the BPF objects: build with `--features embedded-bpf`"
);

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

const USAGE: &str = "usage: rk-sensor [--policy FILE | --selftest | --version | --help]";

/// Policy file read at start and on SIGHUP when `--policy` is not given.
const DEFAULT_POLICY: &str = "/etc/rk/policy.toml";

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Run { policy: Option<String> },
    Selftest,
    SelftestChild(Vec<String>),
    Version,
    Help,
}

fn parse_args(args: &[String]) -> Result<Mode, String> {
    match args {
        [] => Ok(Mode::Run { policy: None }),
        [flag, file] if flag == "--policy" => Ok(Mode::Run {
            policy: Some(file.clone()),
        }),
        [flag] if flag == "--selftest" => Ok(Mode::Selftest),
        [flag] if flag == "--version" || flag == "-V" => Ok(Mode::Version),
        [flag] if flag == "--help" || flag == "-h" => Ok(Mode::Help),
        [flag, rest @ ..] if flag == selftest::CHILD_FLAG => Ok(Mode::SelftestChild(rest.to_vec())),
        _ => Err(format!(
            "unrecognised arguments: {}\n{USAGE}",
            args.join(" ")
        )),
    }
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
        Mode::Run { policy } => match run_daemon(policy.as_deref().unwrap_or(DEFAULT_POLICY)) {
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
                ok: true,
                detail: "active".into(),
            },
            CapabilityStatus {
                name: "cgroup_v2".into(),
                ok: true,
                detail: "/sys/fs/cgroup".into(),
            },
        ]
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

fn run_daemon(policy_path: &str) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

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
        let cgroup_root = Path::new(policy::CGROUP_FS).join(rk_policy::net::CGROUP_ROOT);
        let attached = policy::attach_all(&mut ebpf, &cgroup_root)?;
        info!(?attached, "enforcement programs attached");

        let engine = PolicyEngine::default();
        let stop = Arc::new(AtomicBool::new(false));
        let ring = consumer::take_ring(&mut ebpf)?;

        let registry = AgentRegistry::new();
        let consumer = tokio::spawn(consumer::consume_loop_with_registry(
            ring,
            stop.clone(),
            Some(registry.clone()),
        ));

        let mut handler_inner = SensorPolicyHandler { ebpf, engine };
        if let Ok(text) = std::fs::read_to_string(policy_path) {
            match handler_inner.apply(&text) {
                Ok(report) => {
                    if !report.skipped_files.is_empty() {
                        warn!(
                            path = policy_path,
                            skipped = ?report.skipped_files,
                            "built-in file rules not active on this host (missing or inaccessible)"
                        );
                    }
                    info!(path = policy_path, ?report, "policy applied");
                }
                Err(e) => {
                    error!(
                        path = policy_path,
                        error = %format!("{e:#}"),
                        "policy rejected; active policy unchanged"
                    );
                }
            }
        } else {
            warn!(
                path = policy_path,
                "policy file not readable; active policy unchanged"
            );
        }

        let handler: Arc<Mutex<dyn PolicyHandler>> = Arc::new(Mutex::new(handler_inner));

        let server_cfg = ServerConfig {
            socket_path: PathBuf::from(rk_agentd::protocol::DEFAULT_SOCKET_PATH),
            cgroup_fs: PathBuf::from(policy::CGROUP_FS),
            service_uid: 65534,
            service_gid: 65534,
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
        loop {
            tokio::select! {
                _ = hangup.recv() => {
                    let mut lock = handler.lock().await;
                    match std::fs::read_to_string(policy_path) {
                        Ok(text) => match lock.apply(&text) {
                            Ok(report) => {
                                if !report.skipped_files.is_empty() {
                                    warn!(
                                        path = policy_path,
                                        skipped = ?report.skipped_files,
                                        "built-in file rules not active on this host (missing or inaccessible)"
                                    );
                                }
                                info!(path = policy_path, ?report, "policy applied on SIGHUP");
                            }
                            Err(e) => {
                                error!(
                                    path = policy_path,
                                    error = %format!("{e:#}"),
                                    "policy rejected on SIGHUP; active policy unchanged"
                                );
                            }
                        },
                        Err(e) => {
                            warn!(
                                path = policy_path,
                                error = %e,
                                "policy file not readable on SIGHUP; active policy unchanged"
                            );
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
        assert_eq!(parse_args(&args(&[])), Ok(Mode::Run { policy: None }));
        assert_eq!(
            parse_args(&args(&["--policy", "/etc/rk/p.toml"])),
            Ok(Mode::Run {
                policy: Some("/etc/rk/p.toml".into())
            })
        );
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
