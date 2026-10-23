//! Event pipeline (docs/design/phase-7.md §3).
//!
//! A dedicated drain thread waits on the ring buffer with epoll, copies every
//! available record out, and hands batches to a worker over a bounded channel.
//! The worker decodes and writes them. The drain thread never decodes, logs or
//! waits on a sink: when the channel is full the batch is dropped and counted,
//! so a slow sink can never back the ring up into kernel-side loss.
//!
//! Stopping is bounded (docs/design/phase-10.md §9): the final drain reads
//! the ring for at most [`STOP_DRAIN`] (what is left stays in the pinned ring
//! for the next sensor), and the worker processes what is queued for at most
//! [`STOP_BUDGET`]; the rest is counted as dropped, which the audit observer
//! records as a loss.

use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::maps::{MapData, RingBuf};
use aya::Ebpf;
use rk_agentd::registry::AgentRegistry;
use tracing::{error, info};

use crate::decoder::DecodeStats;
use crate::pipeline;

/// Smallest and largest ring buffer, and the share per CPU (§4).
pub const MIN_RING_BYTES: u32 = 1 << 20;
pub const MAX_RING_BYTES: u32 = 64 << 20;
pub const RING_BYTES_PER_CPU: u32 = 256 << 10;

/// Records per batch handed to the worker.
const BATCH: usize = 512;

/// Longest final drain of the ring buffer after a stop request.
pub const STOP_DRAIN: Duration = Duration::from_millis(500);

/// Longest time the worker keeps processing queued records after a stop
/// request.
pub const STOP_BUDGET: Duration = Duration::from_secs(2);

/// Takes ownership of the ring buffer so the rest of `ebpf` stays usable (for
/// example by the policy engine). The pipeline opens it exactly once; aya
/// 0.14 fixed the stale-position bug that made a second reader unsafe, but one
/// reader per ring remains the design.
pub fn take_ring(ebpf: &mut Ebpf) -> Result<RingBuf<MapData>> {
    let map = ebpf
        .take_map("events_ringbuf")
        .context("missing events_ringbuf map")?;
    RingBuf::try_from(map).context("failed to open events_ringbuf")
}

/// Ring buffer size: `cpus × 256 KiB` rounded up to a power of two and clamped
/// to [1 MiB, 64 MiB], or `override_mb` MiB (also clamped) when given.
pub fn ring_size(cpus: usize, override_mb: Option<u32>) -> u32 {
    let want = match override_mb {
        Some(mb) => u64::from(mb.clamp(1, MAX_RING_BYTES >> 20)) << 20,
        None => (cpus.max(1) as u64).saturating_mul(u64::from(RING_BYTES_PER_CPU)),
    };
    let rounded = want.next_power_of_two();
    rounded.clamp(u64::from(MIN_RING_BYTES), u64::from(MAX_RING_BYTES)) as u32
}

/// Userspace counters of the pipeline. Kernel-side drops are the per-CPU
/// `rk_counters` map; `drained + kernel drops` is every event produced.
#[derive(Debug, Default)]
pub struct PipelineStats {
    /// Records copied out of the ring buffer.
    pub drained: AtomicU64,
    /// Records dropped because the channel to the worker was full.
    pub userspace_drops: AtomicU64,
    /// Decoder outcomes, counted by the worker.
    pub decode: DecodeStats,
}

impl PipelineStats {
    pub fn drained(&self) -> u64 {
        self.drained.load(Ordering::Relaxed)
    }

    pub fn userspace_drops(&self) -> u64 {
        self.userspace_drops.load(Ordering::Relaxed)
    }
}

/// What the worker does with each record (Phase 9: the audit observer).
pub trait RecordHandler: Send + 'static {
    fn record(&mut self, bytes: &[u8], stats: &DecodeStats);
    /// Called after every batch and at least every `Config::poll_timeout`
    /// while idle, so time-based work (sealing audit batches) happens.
    fn tick(&mut self) {}
}

/// The pre-Phase 9 handler: decode and log.
struct LogHandler {
    registry: Option<Arc<AgentRegistry>>,
}

impl RecordHandler for LogHandler {
    fn record(&mut self, bytes: &[u8], stats: &DecodeStats) {
        pipeline::process_record_with_registry(bytes, stats, self.registry.as_ref());
    }
}

/// Pipeline tuning.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// Batches the channel holds before the drain thread starts dropping.
    pub channel_batches: usize,
    /// Upper bound on event latency when no wakeup arrives (§4): data below
    /// the kernel's wakeup threshold is picked up after at most this long.
    pub poll_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            channel_batches: 1024,
            poll_timeout: Duration::from_millis(100),
        }
    }
}

/// Drain thread, channel and worker. Stopping drains what is left first.
pub struct Consumer {
    stop: Arc<AtomicBool>,
    wake: OwnedFd,
    drain: Option<JoinHandle<()>>,
    worker: Option<JoinHandle<()>>,
    stats: Arc<PipelineStats>,
}

fn owned(fd: RawFd, what: &str) -> Result<OwnedFd> {
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context(what.to_string());
    }
    // SAFETY: a freshly created descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn epoll_add(epoll: &OwnedFd, fd: RawFd, token: u64) -> Result<()> {
    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: token,
    };
    // SAFETY: valid epoll and target descriptors, valid event pointer.
    if unsafe { libc::epoll_ctl(epoll.as_raw_fd(), libc::EPOLL_CTL_ADD, fd, &mut ev) } != 0 {
        return Err(std::io::Error::last_os_error()).context("epoll_ctl");
    }
    Ok(())
}

impl Consumer {
    /// Starts the drain thread and a worker that decodes and logs.
    pub fn start(
        ring: RingBuf<MapData>,
        registry: Option<Arc<AgentRegistry>>,
        config: Config,
    ) -> Result<Self> {
        Self::start_with(
            ring,
            Box::new(LogHandler { registry }),
            Arc::new(PipelineStats::default()),
            config,
        )
    }

    /// Starts the drain thread and a worker that hands records to `handler`.
    /// `stats` is shared so the handler can see the pipeline's own losses.
    pub fn start_with(
        mut ring: RingBuf<MapData>,
        mut handler: Box<dyn RecordHandler>,
        stats: Arc<PipelineStats>,
        config: Config,
    ) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        // SAFETY: plain syscalls; results are checked by `owned`.
        let wake = owned(
            unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) },
            "eventfd",
        )?;
        let epoll = owned(
            unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) },
            "epoll_create1",
        )?;
        epoll_add(&epoll, ring.as_raw_fd(), 0)?;
        epoll_add(&epoll, wake.as_raw_fd(), 1)?;

        let (tx, rx) = sync_channel::<Vec<Vec<u8>>>(config.channel_batches.max(1));
        let timeout_ms = i32::try_from(config.poll_timeout.as_millis()).unwrap_or(i32::MAX);

        let drain_stats = stats.clone();
        let drain_stop = stop.clone();
        let drain = thread::Builder::new()
            .name("rk-drain".into())
            .spawn(move || {
                let send = |batch: Vec<Vec<u8>>| {
                    let n = batch.len() as u64;
                    drain_stats.drained.fetch_add(n, Ordering::Relaxed);
                    // Full or disconnected: count the loss, never block.
                    if tx.try_send(batch).is_err() {
                        drain_stats.userspace_drops.fetch_add(n, Ordering::Relaxed);
                    }
                };
                let mut events = [libc::epoll_event { events: 0, u64: 0 }; 2];
                loop {
                    // SAFETY: valid epoll fd and a buffer of `events.len()` entries.
                    let n = unsafe {
                        libc::epoll_wait(epoll.as_raw_fd(), events.as_mut_ptr(), 2, timeout_ms)
                    };
                    if n < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.raw_os_error() != Some(libc::EINTR) {
                            error!(error = %err, "epoll_wait on the ring buffer failed");
                            break;
                        }
                    }
                    // Read the flag before draining, so records written before
                    // a stop request are still delivered.
                    let stopping = drain_stop.load(Ordering::Relaxed);
                    // Producers keep writing while we read: bound the final
                    // drain, or a busy host could keep it going forever.
                    let deadline = stopping.then(|| Instant::now() + STOP_DRAIN);
                    let mut batch = Vec::with_capacity(BATCH);
                    while let Some(item) = ring.next() {
                        batch.push(item.to_vec());
                        if batch.len() == BATCH {
                            send(std::mem::replace(&mut batch, Vec::with_capacity(BATCH)));
                            if deadline.is_some_and(|d| Instant::now() >= d) {
                                break;
                            }
                        }
                    }
                    if !batch.is_empty() {
                        send(batch);
                    }
                    if stopping {
                        break;
                    }
                }
            })
            .context("spawn drain thread")?;

        let worker_stats = stats.clone();
        let worker_stop = stop.clone();
        let tick_every = config.poll_timeout;
        let worker = thread::Builder::new()
            .name("rk-worker".into())
            .spawn(move || {
                let mut stop_seen: Option<Instant> = None;
                loop {
                    match rx.recv_timeout(tick_every) {
                        Ok(batch) => {
                            if worker_stop.load(Ordering::Relaxed) {
                                let since = *stop_seen.get_or_insert_with(Instant::now);
                                if since.elapsed() >= STOP_BUDGET {
                                    worker_stats
                                        .userspace_drops
                                        .fetch_add(batch.len() as u64, Ordering::Relaxed);
                                    continue;
                                }
                            }
                            for record in &batch {
                                handler.record(record, &worker_stats.decode);
                            }
                            handler.tick();
                        }
                        Err(RecvTimeoutError::Timeout) => handler.tick(),
                        Err(RecvTimeoutError::Disconnected) => {
                            handler.tick();
                            break;
                        }
                    }
                }
            })
            .context("spawn worker thread")?;

        Ok(Self {
            stop,
            wake,
            drain: Some(drain),
            worker: Some(worker),
            stats,
        })
    }

    /// Live pipeline counters.
    pub fn stats(&self) -> Arc<PipelineStats> {
        self.stats.clone()
    }

    /// Stops the drain thread (after a final drain) and the worker (after it
    /// has written everything already queued).
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let one: u64 = 1;
        // SAFETY: writes 8 bytes from a valid u64 to our own eventfd.
        unsafe {
            libc::write(
                self.wake.as_raw_fd(),
                (&one as *const u64).cast(),
                std::mem::size_of::<u64>(),
            );
        }
        if let Some(drain) = self.drain.take() {
            let _ = drain.join();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
            info!(
                drained = self.stats.drained(),
                userspace_drops = self.stats.userspace_drops(),
                decoded = self.stats.decode.decoded(),
                rejected = self.stats.decode.rejected(),
                "consumer stopped"
            );
        }
    }
}

impl Drop for Consumer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_size_scales_with_cpus_and_is_clamped() {
        assert_eq!(ring_size(1, None), MIN_RING_BYTES);
        assert_eq!(ring_size(4, None), MIN_RING_BYTES);
        assert_eq!(ring_size(8, None), 2 << 20);
        assert_eq!(ring_size(12, None), 4 << 20); // 3 MiB rounds up
        assert_eq!(ring_size(1024, None), MAX_RING_BYTES);
        assert_eq!(ring_size(0, None), MIN_RING_BYTES);
        assert_eq!(ring_size(64, Some(3)), 4 << 20);
        assert_eq!(ring_size(64, Some(0)), MIN_RING_BYTES);
        assert_eq!(ring_size(1, Some(1000)), MAX_RING_BYTES);
        for cpus in 0..300 {
            assert!(ring_size(cpus, None).is_power_of_two());
        }
    }
}
