mod consumer;
mod enricher;
mod event;
mod loader;
mod pipeline;

use anyhow::{Context, Result};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,rk_sensor=info".into()),
        )
        .json()
        .init();

    let kernel = read_kernel_version().unwrap_or_else(|| "unknown".to_string());

    let mut loaded = loader::load_and_attach().context("failed to load and attach probes")?;

    info!(
        kernel_version = %kernel,
        hooks = ?loaded.attached_hooks,
        "rk-sensor startup complete"
    );

    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_signal = stop.clone();

    let signal_task = tokio::spawn(async move {
        if signal::ctrl_c().await.is_ok() {
            stop_for_signal.store(true, Ordering::Relaxed);
        }
    });

    let consume_result = consumer::consume_loop(&mut loaded.ebpf, stop.clone()).await;

    stop.store(true, Ordering::Relaxed);
    let _ = signal_task.await;

    if let Err(err) = consume_result {
        error!("consumer loop failed: {err:#}");
        return Err(err);
    }

    info!("rk-sensor shutdown complete");
    Ok(())
}

fn read_kernel_version() -> Option<String> {
    let output = Command::new("uname").arg("-r").output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
