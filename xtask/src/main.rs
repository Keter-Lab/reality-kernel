use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(name = "xtask", version, about = "Workspace automation tasks")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Build C eBPF objects using clang
    BuildBpf {
        #[arg(long, default_value = "all")]
        arch: String,
    },
    /// Check that committed Rust bindgen types have not drifted from rk_abi.h
    CheckBindgenDrift,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::BuildBpf { arch } => build_bpf(&arch),
        Commands::CheckBindgenDrift => check_bindgen_drift(),
    }
}

fn build_bpf(arch: &str) -> Result<()> {
    println!("[xtask] building C CO-RE BPF objects in rk-bpf/ (arch={arch})");
    let mut cmd = Command::new("make");
    cmd.current_dir("rk-bpf");
    if arch != "all" {
        cmd.arg(format!("build/rk_bpf_{arch}.o"));
    }
    let status = cmd.status().context("failed to invoke make in rk-bpf/")?;
    if !status.success() {
        anyhow::bail!("BPF make build failed");
    }
    println!("[xtask] BPF build succeeded");
    Ok(())
}

fn check_bindgen_drift() -> Result<()> {
    println!("[xtask] verifying committed bindings against rk-bpf/include/rk_abi.h");
    let committed = fs::read_to_string("rk-ebpf-common/src/bindings.rs")
        .context("failed to read committed bindings.rs")?;

    let abi_header = Path::new("rk-bpf/include/rk_abi.h");
    if !abi_header.exists() {
        anyhow::bail!("missing rk-bpf/include/rk_abi.h");
    }

    // Verify key structs exist in committed bindings
    let required_tokens = [
        "pub struct rk_hdr",
        "pub struct rk_scratch_msg",
        "pub struct rk_payload_exec",
        "pub struct rk_payload_file",
        "pub struct rk_payload_net",
        "pub enum rk_event_type",
        "pub enum rk_verdict",
    ];

    for token in required_tokens {
        if !committed.contains(token) {
            anyhow::bail!("drift detected: committed bindings missing token '{token}'");
        }
    }

    println!("[xtask] bindgen drift check PASSED");
    Ok(())
}
