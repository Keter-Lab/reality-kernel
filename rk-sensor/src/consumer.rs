//! Drains `events_ringbuf`. Phase 7 replaces the sleep-based poll with an
//! epoll-driven drain thread and a bounded channel.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::maps::{MapData, RingBuf};
use aya::Ebpf;
use tokio::time::{sleep, Duration};
use tracing::info;

use crate::decoder::DecodeStats;
use crate::pipeline;

/// Takes ownership of the ring buffer so the rest of `ebpf` stays usable (for
/// example by the policy engine).
pub fn take_ring(ebpf: &mut Ebpf) -> Result<RingBuf<MapData>> {
    let map = ebpf
        .take_map("events_ringbuf")
        .context("missing events_ringbuf map")?;
    RingBuf::try_from(map).context("failed to open events_ringbuf")
}

pub async fn consume_loop(mut ring: RingBuf<MapData>, stop: Arc<AtomicBool>) -> Result<()> {
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
