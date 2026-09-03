use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::process::Command;

#[derive(Parser, Debug)]
#[command(name = "xtask", version, about = "Workspace automation tasks")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Build eBPF probes using cargo
    BuildEbpf {
        /// Build in release mode
        #[arg(long)]
        release: bool,
        /// BPF compilation target triple
        #[arg(long, default_value = "bpfel-unknown-none")]
        target: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::BuildEbpf { release, target } => build_ebpf(&target, release),
    }
}

fn build_ebpf(target: &str, release: bool) -> Result<()> {
    println!("[xtask] building rk-ebpf-probes for target {target}");

    let mut cmd = Command::new("cargo");
    cmd.args(["build", "-p", "rk-ebpf-probes", "--target", target]);
    if release {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .context("failed to invoke cargo build for rk-ebpf-probes")?;

    if !status.success() {
        anyhow::bail!(
            "rk-ebpf-probes build failed (target={target}, release={release})"
        );
    }

    println!("[xtask] build-ebpf complete");
    Ok(())
}
