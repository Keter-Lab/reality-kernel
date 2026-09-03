use anyhow::{Context, Result};
use aya::maps::{Array, RingBuf};
use aya::Ebpf;
use rk_ebpf_common::{
    ExecEvent, FileOpenEvent, NetConnectEvent, TaggedExecEvent, TaggedFileOpenEvent,
    TaggedNetConnectEvent, TaggedUnlinkEvent, UnlinkEvent, EVENT_TAG_EXEC, EVENT_TAG_FILE_OPEN,
    EVENT_TAG_NET_CONNECT, EVENT_TAG_UNLINK,
};
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{debug, error};

use crate::event::RkEvent;
use crate::pipeline;

pub async fn consume_loop(ebpf: &mut Ebpf, stop: Arc<AtomicBool>) -> Result<()> {
    let mut ring = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .context("missing EVENTS ring buffer map")?,
    )
    .context("failed to open EVENTS ring buffer")?;

    let mut drop_map = Array::<_, u64>::try_from(
        ebpf.map_mut("EVENT_DROPS")
            .context("missing EVENT_DROPS map")?,
    )
    .context("failed to open EVENT_DROPS map")?;

    let overflow_counter = AtomicU64::new(0);
    let mut last_drop_total = drop_map.get(&0, 0).unwrap_or(0);

    while !stop.load(Ordering::Relaxed) {
        while let Some(item) = ring.next() {
            match decode_event(item.as_ref()) {
                Some(event) => {
                    pipeline::process_event(event).await;
                }
                None => {
                    debug!("discarding unknown ringbuf event payload");
                }
            }
        }

        let current_drop_total = drop_map.get(&0, 0).unwrap_or(last_drop_total);
        if current_drop_total > last_drop_total {
            let delta = current_drop_total - last_drop_total;
            let count = overflow_counter.fetch_add(delta, Ordering::Relaxed) + delta;
            error!(
                overflow_count = count,
                delta,
                "ring buffer overflow detected via EVENT_DROPS"
            );
            pipeline::emit_overflow_marker(count).await;
            last_drop_total = current_drop_total;
        }

        sleep(Duration::from_millis(25)).await;
    }

    Ok(())
}

fn decode_event(bytes: &[u8]) -> Option<RkEvent> {
    if bytes.is_empty() {
        return None;
    }

    match bytes[0] {
        EVENT_TAG_EXEC if bytes.len() >= size_of::<TaggedExecEvent>() => {
            let payload = unsafe { (bytes.as_ptr() as *const TaggedExecEvent).read_unaligned() };
            Some(RkEvent::Exec(copy_exec(&payload.event)))
        }
        EVENT_TAG_FILE_OPEN if bytes.len() >= size_of::<TaggedFileOpenEvent>() => {
            let payload = unsafe { (bytes.as_ptr() as *const TaggedFileOpenEvent).read_unaligned() };
            Some(RkEvent::FileOpen(copy_file(&payload.event)))
        }
        EVENT_TAG_NET_CONNECT if bytes.len() >= size_of::<TaggedNetConnectEvent>() => {
            let payload = unsafe { (bytes.as_ptr() as *const TaggedNetConnectEvent).read_unaligned() };
            Some(RkEvent::NetConnect(copy_net(&payload.event)))
        }
        EVENT_TAG_UNLINK if bytes.len() >= size_of::<TaggedUnlinkEvent>() => {
            let payload = unsafe { (bytes.as_ptr() as *const TaggedUnlinkEvent).read_unaligned() };
            Some(RkEvent::Unlink(copy_unlink(&payload.event)))
        }
        _ => None,
    }
}

fn copy_exec(v: &ExecEvent) -> ExecEvent {
    *v
}

fn copy_file(v: &FileOpenEvent) -> FileOpenEvent {
    *v
}

fn copy_net(v: &NetConnectEvent) -> NetConnectEvent {
    *v
}

fn copy_unlink(v: &UnlinkEvent) -> UnlinkEvent {
    *v
}
