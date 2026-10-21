//! Drains `events_ringbuf`. Phase 7 replaces the sleep-based poll with an
//! epoll-driven drain thread and a bounded channel.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::maps::{MapData, RingBuf};
use aya::Ebpf;
use rk_agentd::registry::AgentRegistry;
use tokio::time::{sleep, Duration};
use tracing::info;

use crate::decoder::DecodeStats;
use crate::pipeline;

/// Takes ownership of the ring buffer so the rest of `ebpf` stays usable (for
/// example by the policy engine).
///
/// Open the ring buffer **once** per loaded object and keep that reader. With
/// aya 0.13, a second `RingBuf` opened on a partly consumed ring starts from a
/// stale producer-position cache and reads stale ring memory indefinitely.
pub fn take_ring(ebpf: &mut Ebpf) -> Result<RingBuf<MapData>> {
    let map = ebpf
        .take_map("events_ringbuf")
        .context("missing events_ringbuf map")?;
    RingBuf::try_from(map).context("failed to open events_ringbuf")
}

pub async fn consume_loop(ring: RingBuf<MapData>, stop: Arc<AtomicBool>) -> Result<()> {
    consume_loop_with_registry(ring, stop, None).await
}

pub async fn consume_loop_with_registry(
    mut ring: RingBuf<MapData>,
    stop: Arc<AtomicBool>,
    registry: Option<Arc<AgentRegistry>>,
) -> Result<()> {
    let stats = DecodeStats::default();

    while !stop.load(Ordering::Relaxed) {
        while let Some(item) = ring.next() {
            pipeline::process_record_with_registry(&item, &stats, registry.as_ref());
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
