//! Heartbeat and self-identification (docs/design/phase-6.md §4, §5).
//!
//! Enforcing hooks treat a governed ENFORCE workload as denied once the
//! heartbeat is older than the configured timeout, so whoever attaches the
//! programs (the daemon, or a test harness) must keep a [`Heartbeat`] alive.

use std::os::fd::AsFd as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use aya::maps::{Array, Map, MapData};
use aya::Ebpf;
use bytemuck::Zeroable;
use rk_ebpf_common::{rk_config, rk_guard_target};

pub const MAP_HEARTBEAT: &str = "rk_heartbeat";
pub const MAP_CONFIG: &str = "rk_config";
pub const MAP_GUARD: &str = "rk_guard";

/// Shortest accepted heartbeat timeout.
pub const MIN_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy)]
#[repr(transparent)]
struct Config(rk_config);
// SAFETY: rk_config is a bindgen Pod (no padding, any bit pattern valid).
unsafe impl aya::Pod for Config {}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct GuardTarget(rk_guard_target);
// SAFETY: as above.
unsafe impl aya::Pod for GuardTarget {}

/// `CLOCK_BOOTTIME` in nanoseconds: what `bpf_ktime_get_boot_ns()` returns.
pub fn boottime_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid pointer to a timespec; CLOCK_BOOTTIME always exists on Linux.
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

/// An `Array` on its own duplicate of a map's fd, for use on another thread.
fn owned_array<V: aya::Pod>(ebpf: &Ebpf, name: &str) -> Result<Array<MapData, V>> {
    let fd = match ebpf.map(name) {
        Some(Map::Array(data)) => data
            .fd()
            .as_fd()
            .try_clone_to_owned()
            .with_context(|| format!("duplicate {name} fd"))?,
        Some(_) => bail!("{name} is not an array map"),
        None => bail!("{name} missing from rk.bpf.o"),
    };
    Ok(Array::try_from(Map::Array(MapData::from_fd(fd)?))?)
}

/// Writes the heartbeat every timeout/4 on a dedicated OS thread, so a busy
/// async runtime can never starve it. Beats stop when this is dropped.
pub struct Heartbeat {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Heartbeat {
    /// Stores `timeout`, beats once, then keeps beating. Call before the
    /// enforcement programs are attached (or adopted), so a governed workload
    /// never meets a stale heartbeat because of startup order.
    pub fn start(ebpf: &mut Ebpf, timeout: Duration) -> Result<Self> {
        if timeout < MIN_TIMEOUT {
            bail!(
                "heartbeat timeout {timeout:?} is below the minimum {MIN_TIMEOUT:?}"
            );
        }
        let mut config: Array<MapData, Config> = owned_array(ebpf, MAP_CONFIG)?;
        let mut cfg = rk_config::zeroed();
        cfg.heartbeat_timeout_ns = u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX);
        config.set(0, Config(cfg), 0).context("write rk_config")?;

        let mut beat: Array<MapData, u64> = owned_array(ebpf, MAP_HEARTBEAT)?;
        beat.set(0, boottime_ns(), 0)
            .context("write rk_heartbeat")?;

        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let interval = timeout / 4;
        let thread = thread::Builder::new()
            .name("rk-heartbeat".into())
            .spawn(move || {
                let mut failing = false;
                while !thread_stop.load(Ordering::Relaxed) {
                    thread::sleep(interval);
                    match beat.set(0, boottime_ns(), 0) {
                        Ok(()) => failing = false,
                        Err(e) if !failing => {
                            failing = true;
                            tracing::error!(error = %e, "heartbeat write failed");
                        }
                        Err(_) => {}
                    }
                }
            })
            .context("spawn heartbeat thread")?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for Heartbeat {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// `starttime` (field 22) from `/proc/<pid>/stat`, in clock ticks.
pub fn start_ticks(stat: &str) -> Option<u64> {
    // comm (field 2) may contain spaces and ')': fields resume after the last ')'.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Registers this process as the sensor the guard hooks protect.
pub fn protect_self(ebpf: &mut Ebpf) -> Result<()> {
    let stat = std::fs::read_to_string("/proc/self/stat").context("read /proc/self/stat")?;
    let mut target = rk_guard_target::zeroed();
    target.tgid = std::process::id();
    target.start_ticks = start_ticks(&stat).context("parse /proc/self/stat")?;
    let mut guard: Array<MapData, GuardTarget> = owned_array(ebpf, MAP_GUARD)?;
    guard
        .set(0, GuardTarget(target), 0)
        .context("write rk_guard")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_start_ticks_with_hostile_comm() {
        let stat = "4242 (rk) s) e(n) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 3 0 987654 1000 10";
        assert_eq!(start_ticks(stat), Some(987_654));
        assert_eq!(start_ticks("1 (init) S"), None);
        assert_eq!(start_ticks("garbage"), None);
    }

    #[test]
    fn boottime_is_monotonic() {
        let a = boottime_ns();
        let b = boottime_ns();
        assert!(a > 0 && b >= a);
    }
}
