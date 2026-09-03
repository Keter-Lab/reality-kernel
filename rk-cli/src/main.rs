use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MIN_KERNEL_MAJOR: u64 = 5;
const MIN_KERNEL_MINOR: u64 = 8;

#[derive(Parser, Debug)]
#[command(name = "rkctl", version, about = "Reality Kernel operations CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run deployment preflight checks
    Preflight {
        /// Emit machine-readable JSON output
        #[arg(long)]
        json: bool,
    },
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
    let result = match cli.command {
        Commands::Preflight { json } => run_preflight(json),
    };

    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(2),
        Err(err) => {
            eprintln!("preflight error: {err:#}");
            ExitCode::from(1)
        }
    }
}

fn run_preflight(as_json: bool) -> Result<bool> {
    let kernel_release = read_kernel_release()?;
    let (major, minor) = parse_kernel_semver(&kernel_release)
        .with_context(|| format!("could not parse kernel release '{kernel_release}'"))?;
    let kernel_ok = major > MIN_KERNEL_MAJOR || (major == MIN_KERNEL_MAJOR && minor >= MIN_KERNEL_MINOR);

    let lsm_list = read_optional_string("/sys/kernel/security/lsm");
    let bpf_lsm_available = lsm_list
        .as_deref()
        .map(|raw| raw.split(',').any(|v| v.trim() == "bpf"))
        .unwrap_or(false);

    let tracing_root = detect_tracing_root();
    let kprobe_events = tracing_root
        .as_ref()
        .map(|root| root.join("kprobe_events"));
    let kprobe_fallback_available = kprobe_events
        .as_ref()
        .map(|p| p.exists())
        .unwrap_or(false);

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

    Ok(report.ring_buffer_supported && (report.bpf_lsm_available || report.kprobe_fallback_available))
}

fn print_human_report(report: &PreflightReport) {
    println!("Reality Kernel preflight");
    println!("  kernel release : {}", report.kernel_release);
    println!("  minimum kernel : {}", report.min_kernel);
    println!("  BPF LSM        : {}", yes_no(report.bpf_lsm_available));
    println!("  kprobe fallback: {}", yes_no(report.kprobe_fallback_available));
    println!("  ring buffer    : {}", yes_no(report.ring_buffer_supported));
    println!();
    println!("Capability matrix:");
    for cap in &report.capabilities {
        println!("  - {:22} {:3}  {}", cap.name, yes_no(cap.ok), cap.detail);
    }
}

fn yes_no(v: bool) -> &'static str {
    if v { "yes" } else { "no" }
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
    let minor_digits: String = minor_raw.chars().take_while(|c| c.is_ascii_digit()).collect();
    let minor = minor_digits.parse::<u64>().context("invalid minor version")?;
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
