//! Workspace automation: `cargo xtask <command>`.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "xtask", about = "Reality Kernel workspace automation")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Build the CO-RE BPF objects with clang (rk-bpf/build/<arch>/).
    BuildBpf {
        /// x86, arm64, or all.
        #[arg(long, default_value = "all")]
        arch: String,
    },
    /// Build BPF objects for the host arch, then rk-sensor with them embedded.
    BuildSensor {
        #[arg(long)]
        release: bool,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::BuildBpf { arch } => build_bpf(&arch),
        Commands::BuildSensor { release } => build_sensor(release),
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("failed to run {cmd:?}"))?;
    if !status.success() {
        bail!("{cmd:?} failed with {status}");
    }
    Ok(())
}

fn build_bpf(arch: &str) -> Result<()> {
    let target = match arch {
        "all" => "all-arches".to_string(),
        "x86" | "arm64" => format!("ARCH={arch}"),
        other => bail!("unsupported arch `{other}`: expected x86, arm64 or all"),
    };
    run(Command::new("make")
        .arg("-C")
        .arg(workspace_root().join("rk-bpf"))
        .arg(target))
}

fn build_sensor(release: bool) -> Result<()> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86",
        "aarch64" => "arm64",
        other => bail!("unsupported host arch `{other}`"),
    };
    build_bpf(arch)?;
    let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.current_dir(workspace_root()).args([
        "build",
        "-p",
        "rk-sensor",
        "--features",
        "embedded-bpf",
    ]);
    if release {
        cmd.arg("--release");
    }
    run(&mut cmd)
}
