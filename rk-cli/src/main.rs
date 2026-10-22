use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use rk_agentd::client::{ApplyOutcome, Client};
use rk_agentd::protocol::{AgentStatusInfo, DaemonStatus};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MIN_KERNEL_MAJOR: u64 = 5;
const MIN_KERNEL_MINOR: u64 = 8;

#[derive(Parser, Debug)]
#[command(
    name = "rk",
    version,
    about = "Reality Kernel operations and agent CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Launch a governed agent under a profile
    Run {
        /// Profile to govern the agent under
        #[arg(long)]
        profile: String,
        /// Session id for audit and attestation linkage
        #[arg(long, env = "RK_SESSION_ID")]
        session: Option<String>,
        /// Command and arguments to execute
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },
    /// Policy management commands
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
    /// Query daemon status, active policy, running agents, and capabilities
    Status {
        /// Emit machine-readable JSON output
        #[arg(long)]
        json: bool,
    },
    /// Run deployment preflight checks (formerly rkctl preflight)
    #[command(alias = "preflight")]
    Doctor {
        /// Emit machine-readable JSON output
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyCommands {
    /// Apply a policy file atomically
    Apply {
        /// Path to policy TOML file
        file: PathBuf,
        /// Validate and report changes without touching the kernel
        #[arg(long)]
        dry_run: bool,
    },
    /// Show differences between a policy file and the active policy
    Diff {
        /// Path to policy TOML file
        file: PathBuf,
    },
    /// Re-apply the previous policy
    Rollback,
}

#[derive(Debug, Clone, Serialize)]
struct Capability {
    name: &'static str,
    ok: bool,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct PreflightReport {
    kernel_release: String,
    min_kernel: String,
    kernel_ok: bool,
    bpf_lsm_available: bool,
    kprobe_fallback_available: bool,
    ring_buffer_supported: bool,
    capabilities: Vec<Capability>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run {
            profile,
            session,
            cmd,
        } => run_agent(&profile, session.as_deref(), &cmd),
        Commands::Policy { command } => match run_policy(command) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("rk policy error: {e:#}");
                ExitCode::FAILURE
            }
        },
        Commands::Status { json } => match run_status(json) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("rk status error: {e:#}");
                ExitCode::FAILURE
            }
        },
        Commands::Doctor { json } => match run_preflight(json) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => ExitCode::from(2),
            Err(err) => {
                eprintln!("doctor error: {err:#}");
                ExitCode::from(1)
            }
        },
    }
}

fn run_agent(profile: &str, session: Option<&str>, cmd: &[String]) -> ExitCode {
    let client = match Client::connect(None) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("rk run: failed to connect to rk-sensor daemon: {e:#}");
            return ExitCode::FAILURE;
        }
    };

    let env = std::env::vars().collect::<Vec<_>>();
    let cwd_buf = std::env::current_dir().ok();
    let cwd_str = cwd_buf.as_deref().and_then(|p| p.to_str());
    match client.run(profile, session, cwd_str, cmd, &env) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(e) => {
            eprintln!("rk run error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run_policy(command: PolicyCommands) -> Result<()> {
    let client = Client::connect(None)
        .context("failed to connect to rk-sensor daemon (is rk-sensor running?)")?;

    match command {
        PolicyCommands::Apply { file, dry_run } => {
            let text = fs::read_to_string(&file)
                .with_context(|| format!("failed to read policy file {}", file.display()))?;
            match client.apply(&text, dry_run)? {
                ApplyOutcome::Applied(rep) => {
                    println!(
                        "Policy applied: generation {}, {} profiles, {} bindings",
                        rep.generation, rep.profiles, rep.bindings
                    );
                    if !rep.skipped_files.is_empty() {
                        eprintln!(
                            "Warning: skipped built-in file rules on this host: {:?}",
                            rep.skipped_files
                        );
                    }
                }
                ApplyOutcome::DryRun(dr) => {
                    println!(
                        "Dry run: generation {}, {} profiles, {} cgroups to create",
                        dr.generation,
                        dr.profiles,
                        dr.cgroups_to_create.len()
                    );
                    if !dr.diff.is_empty() {
                        println!("Changes:");
                        for line in &dr.diff {
                            println!("  {line}");
                        }
                    } else {
                        println!("No changes against active policy.");
                    }
                }
            }
        }
        PolicyCommands::Diff { file } => {
            let text = fs::read_to_string(&file)
                .with_context(|| format!("failed to read policy file {}", file.display()))?;
            let diff = client.diff(&text)?;
            if diff.is_empty() {
                println!("No changes against active policy.");
            } else {
                for line in &diff {
                    println!("{line}");
                }
            }
        }
        PolicyCommands::Rollback => {
            let rep = client.rollback()?;
            println!(
                "Policy rolled back: generation {}, {} profiles, {} bindings",
                rep.generation, rep.profiles, rep.bindings
            );
        }
    }
    Ok(())
}

fn run_status(as_json: bool) -> Result<()> {
    let client = Client::connect(None)
        .context("failed to connect to rk-sensor daemon (is rk-sensor running?)")?;
    let status = client.status()?;

    if as_json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        print_human_status(&status);
    }
    Ok(())
}

fn print_human_status(status: &DaemonStatus) {
    println!("Reality Kernel daemon status");
    println!(
        "  health     : {}",
        if status.health {
            "healthy"
        } else {
            "unhealthy"
        }
    );
    println!("  generation : {}", status.generation);
    println!("  containers : {} (Kubernetes)", status.containers);
    if !status.counters.is_empty() {
        let line: Vec<String> = status
            .counters
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        println!("  pipeline   : {}", line.join(" "));
    }
    println!(
        "  profiles   : {}",
        if status.active_profiles.is_empty() {
            "(none)".into()
        } else {
            status.active_profiles.join(", ")
        }
    );
    println!();
    println!("Running agents ({}):", status.agents.len());
    if status.agents.is_empty() {
        println!("  (none)");
    } else {
        for a in &status.agents {
            print_agent_status(a);
        }
    }
    println!();
    println!("Kernel capabilities:");
    for cap in &status.capabilities {
        println!(
            "  - {:22} {:3}  {}",
            cap.name,
            if cap.ok { "yes" } else { "no" },
            cap.detail
        );
    }
}

fn print_agent_status(a: &AgentStatusInfo) {
    println!("  - Agent {} (pid {}):", a.agent_id, a.pid);
    println!("    profile      : {}", a.profile);
    if let Some(ref sess) = a.session_id {
        println!("    session      : {}", sess);
    }
    println!("    cgroup       : {} (id {})", a.cgroup_rel, a.cgroup_id);
    println!("    privilege checks:");
    println!(
        "      unprivileged user   : {} (uid={}, gid={})",
        yes_no(a.privilege_checks.unprivileged_user),
        a.privilege_checks.caller_uid,
        a.privilege_checks.caller_gid
    );
    println!(
        "      no_new_privs        : {}",
        yes_no(a.privilege_checks.no_new_privs)
    );
    println!(
        "      empty capabilities  : {}",
        yes_no(a.privilege_checks.empty_capabilities)
    );
    println!(
        "      no cgroup delegation: {}",
        yes_no(a.privilege_checks.cgroup_not_delegated)
    );
}

fn run_preflight(as_json: bool) -> Result<bool> {
    let kernel_release = read_kernel_release()?;
    let (major, minor) = parse_kernel_semver(&kernel_release)
        .with_context(|| format!("could not parse kernel release '{kernel_release}'"))?;
    let kernel_ok =
        major > MIN_KERNEL_MAJOR || (major == MIN_KERNEL_MAJOR && minor >= MIN_KERNEL_MINOR);

    let lsm_list = read_optional_string("/sys/kernel/security/lsm");
    let bpf_lsm_available = lsm_list
        .as_deref()
        .map(|raw| raw.split(',').any(|v| v.trim() == "bpf"))
        .unwrap_or(false);

    let tracing_root = detect_tracing_root();
    let kprobe_events = tracing_root.as_ref().map(|root| root.join("kprobe_events"));
    let kprobe_fallback_available = kprobe_events.as_ref().map(|p| p.exists()).unwrap_or(false);

    let has_btf = Path::new("/sys/kernel/btf/vmlinux").exists();
    let ring_buffer_supported = kernel_ok && has_btf;

    let mut capabilities = Vec::new();
    capabilities.push(Capability {
        name: "kernel_minimum_5_8",
        ok: kernel_ok,
        detail: format!("detected={kernel_release}, required>=5.8"),
    });
    capabilities.push(Capability {
        name: "ring_buffer_support",
        ok: ring_buffer_supported,
        detail: if has_btf {
            "/sys/kernel/btf/vmlinux present".to_string()
        } else {
            "missing /sys/kernel/btf/vmlinux".to_string()
        },
    });
    capabilities.push(Capability {
        name: "bpf_lsm",
        ok: bpf_lsm_available,
        detail: lsm_list.unwrap_or_else(|| "unavailable".to_string()),
    });
    capabilities.push(Capability {
        name: "kprobe_fallback",
        ok: kprobe_fallback_available,
        detail: match kprobe_events {
            Some(path) => format!("kprobe_events={}", path.display()),
            None => "tracefs/debugfs tracing path unavailable".to_string(),
        },
    });
    capabilities.push(Capability {
        name: "bpffs_mounted",
        ok: Path::new("/sys/fs/bpf").exists(),
        detail: "/sys/fs/bpf".to_string(),
    });
    capabilities.push(Capability {
        name: "cgroup_v2",
        ok: Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
        detail: "/sys/fs/cgroup/cgroup.controllers".to_string(),
    });

    let report = PreflightReport {
        kernel_release,
        min_kernel: "5.8".to_string(),
        kernel_ok,
        bpf_lsm_available,
        kprobe_fallback_available,
        ring_buffer_supported,
        capabilities,
    };

    if as_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human_report(&report);
    }

    if !report.kernel_ok {
        bail!("kernel < 5.8 is unsupported for Reality Kernel production agent");
    }

    Ok(report.ring_buffer_supported
        && (report.bpf_lsm_available || report.kprobe_fallback_available))
}

fn print_human_report(report: &PreflightReport) {
    println!("Reality Kernel preflight");
    println!("  kernel release : {}", report.kernel_release);
    println!("  minimum kernel : {}", report.min_kernel);
    println!("  BPF LSM        : {}", yes_no(report.bpf_lsm_available));
    println!(
        "  kprobe fallback: {}",
        yes_no(report.kprobe_fallback_available)
    );
    println!(
        "  ring buffer    : {}",
        yes_no(report.ring_buffer_supported)
    );
    println!();
    println!("Capability matrix:");
    for cap in &report.capabilities {
        println!("  - {:22} {:3}  {}", cap.name, yes_no(cap.ok), cap.detail);
    }
}

fn yes_no(v: bool) -> &'static str {
    if v {
        "yes"
    } else {
        "no"
    }
}

fn read_kernel_release() -> Result<String> {
    let raw = fs::read_to_string("/proc/sys/kernel/osrelease")
        .context("failed to read /proc/sys/kernel/osrelease")?;
    Ok(raw.trim().to_string())
}

fn parse_kernel_semver(release: &str) -> Result<(u64, u64)> {
    let mut split = release.split('.');
    let major = split
        .next()
        .context("missing major version")?
        .parse::<u64>()
        .context("invalid major version")?;
    let minor_raw = split.next().context("missing minor version")?;
    let minor_digits: String = minor_raw
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let minor = minor_digits
        .parse::<u64>()
        .context("invalid minor version")?;
    Ok((major, minor))
}

fn read_optional_string(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn detect_tracing_root() -> Option<PathBuf> {
    let tracefs = PathBuf::from("/sys/kernel/tracing");
    if tracefs.exists() {
        return Some(tracefs);
    }

    let debugfs = PathBuf::from("/sys/kernel/debug/tracing");
    if debugfs.exists() {
        return Some(debugfs);
    }

    None
}
