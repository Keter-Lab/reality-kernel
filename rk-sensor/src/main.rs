//! `rk-sensor` entry point.

// Release builds must carry their BPF objects; there is no runtime path override.
#[cfg(all(not(debug_assertions), not(feature = "embedded-bpf")))]
compile_error!(
    "release builds of rk-sensor must embed the BPF objects: build with `--features embedded-bpf`"
);

use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use rk_sensor::loader::{self, Object};
use rk_sensor::{consumer, selftest};
use tracing::info;

const USAGE: &str = "usage: rk-sensor [--selftest | --version | --help]";

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Run,
    Selftest,
    SelftestChild(Vec<String>),
    Version,
    Help,
}

fn parse_args(args: &[String]) -> Result<Mode, String> {
    match args {
        [] => Ok(Mode::Run),
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
        Mode::Run => match run_daemon() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("rk-sensor: {e:#}");
                ExitCode::FAILURE
            }
        },
    }
}

fn run_daemon() -> Result<()> {
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
        info!(
            programs = programs.len(),
            "rk-sensor started; this release has no enforcing hooks"
        );

        let stop = Arc::new(AtomicBool::new(false));
        let stop_on_signal = stop.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                stop_on_signal.store(true, Ordering::Relaxed);
            }
        });

        consumer::consume_loop(&mut ebpf, stop).await
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
        assert_eq!(parse_args(&args(&[])), Ok(Mode::Run));
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
