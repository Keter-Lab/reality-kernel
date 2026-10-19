//! Drains `events_ringbuf`. Phase 7 replaces the sleep-based poll with an
//! epoll-driven drain thread and a bounded channel.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::Ebpf;
use tokio::time::{sleep, Duration};
use tracing::info;

use crate::decoder::DecodeStats;
use crate::pipeline;

pub async fn consume_loop(ebpf: &mut Ebpf, stop: Arc<AtomicBool>) -> Result<()> {
    let map = ebpf
        .take_map("events_ringbuf")
        .context("missing events_ringbuf map")?;
    let mut ring = RingBuf::try_from(map).context("failed to open events_ringbuf")?;
    let stats = DecodeStats::default();

    while !stop.load(Ordering::Relaxed) {
        while let Some(item) = ring.next() {
            pipeline::process_record(&item, &stats);
        }
        sleep(Duration::from_millis(10)).await;
    }

    info!(
        decoded = stats.decoded(),
        rejected = stats.rejected(),
        "consumer stopped"
    );
    Ok(())
}
