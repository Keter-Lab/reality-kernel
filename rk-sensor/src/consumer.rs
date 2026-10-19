use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::Ebpf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

use crate::pipeline;

pub async fn consume_loop(ebpf: &mut Ebpf, stop: Arc<AtomicBool>) -> Result<()> {
    let mut ring = RingBuf::try_from(
        ebpf.take_map("events_ringbuf")
            .context("missing events_ringbuf ring buffer map")?,
    )
    .context("failed to open events_ringbuf ring buffer")?;

    while !stop.load(Ordering::Relaxed) {
        while let Some(item) = ring.next() {
            pipeline::process_event(item.as_ref()).await;
        }

        sleep(Duration::from_millis(10)).await;
    }

    Ok(())
}
