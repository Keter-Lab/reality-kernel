//! Phase 7 benchmarks (docs/design/phase-7.md §6).
//!
//! Loads the production object in-process (like the verdict suite) so the
//! same workloads can be timed with no programs attached (baseline), attached
//! but ungoverned, and governed. Prints a JSON report between
//! `===RK_BENCH_BEGIN===` and `===RK_BENCH_END===`; `tests/bench/gate.py`
//! turns the reports of all kernels into the CI summary and the budget gate.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use aya::Btf;
use rk_ebpf_common::rk_counter;
use serde_json::{json, Value};

use crate::{get_counter, wait_with_deadline, workloads, CHILD_DEADLINE};

pub const BENCH_FLAG: &str = "--bench";

const GOVERNED: &str = "/sys/fs/cgroup/rk.slice/bench";
const UNGOVERNED: &str = "/sys/fs/cgroup/rk-bench-ungoverned";
const FILE_DIR: &str = "/run/rk-bench";

/// Hook exercised by each syscall loop, and its iteration count.
const OPS: &[(&str, &str, usize)] = &[
    ("open", "file_open", 20_000),
    ("connect", "connect4", 20_000),
    ("socket", "socket_create", 20_000),
    ("exec", "bprm_check_security", 1_000),
];

/// Each configuration runs this many times; the median is reported.
const REPEATS: usize = 3;

/// Default profile (built-in credentials file list included) plus one network
/// deny: the realistic cost of a governed process.
const POLICY: &str = r#"
[profiles.bench]
mode = "enforce"
network.default = "allow"

[[profiles.bench.network.deny]]
cidr = "10.99.0.1/32"
proto = ["tcp", "udp"]

[[bindings]]
cgroup = "rk.slice/bench"
profile = "bench"
"#;

/// Sustained-rate run: events per second asked of the workload, and length.
const SUSTAINED_RATE: u64 = 20_000;
const SUSTAINED_SECS: u64 = 10;

fn child(cgroup: &str, workload: &str, args: &[&str]) -> Result<String> {
    let exe = std::env::current_exe()?;
    let out = Command::new(exe)
        .arg(workloads::CHILD_FLAG)
        .arg(format!("{cgroup}/cgroup.procs"))
        .arg(workload)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn bench child")?;
    let out = wait_with_deadline(out, workload, CHILD_DEADLINE)?;
    if !out.status.success() {
        bail!(
            "{workload} {args:?} failed ({:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn median(mut v: Vec<u64>) -> u64 {
    v.sort_unstable();
    v[v.len() / 2]
}

/// p50 and p99 (ns) of one op in one cgroup: the median of `REPEATS` runs.
fn measure(cgroup: &str, op: &str, iters: usize) -> Result<(u64, u64)> {
    let (mut p50, mut p99) = (Vec::new(), Vec::new());
    for _ in 0..REPEATS {
        let out = child(cgroup, "bench", &[op, &iters.to_string()])?;
        let v: Value =
            serde_json::from_str(out.trim()).with_context(|| format!("parse {out:?}"))?;
        p50.push(v["p50"].as_u64().context("p50")?);
        p99.push(v["p99"].as_u64().context("p99")?);
    }
    Ok((median(p50), median(p99)))
}

fn measure_all(cgroup: &str) -> Result<Vec<(u64, u64)>> {
    OPS.iter()
        .map(|(op, _, n)| measure(cgroup, op, *n))
        .collect()
}

/// Average ns per run of each attached rk_* program, from bpf_stats.
fn bpf_stats(bpftool: &Path) -> Result<Value> {
    let out = Command::new(bpftool)
        .args(["-j", "prog", "show"])
        .output()
        .context("run bpftool")?;
    let progs: Value = serde_json::from_slice(&out.stdout).context("parse bpftool json")?;
    let mut stats = serde_json::Map::new();
    for p in progs.as_array().into_iter().flatten() {
        let name = p["name"].as_str().unwrap_or_default();
        let (Some(ns), Some(cnt)) = (p["run_time_ns"].as_u64(), p["run_cnt"].as_u64()) else {
            continue;
        };
        if name.starts_with("rk_") && cnt > 0 {
            stats.insert(name.to_string(), json!({ "avg_ns": ns / cnt, "runs": cnt }));
        }
    }
    Ok(Value::Object(stats))
}

/// Sends `count` governed datagrams `pace_us` apart; returns the counters
/// after the pipeline had time to drain.
fn rate_run(
    ebpf: &aya::Ebpf,
    pipeline: &rk_sensor::consumer::PipelineStats,
    count: u64,
    pace_us: u64,
) -> Result<Value> {
    let drops0 = get_counter(ebpf, rk_counter::RK_CNT_RINGBUF_DROP)?;
    let (drained0, user0) = (pipeline.drained(), pipeline.userspace_drops());
    let start = Instant::now();
    let out = child(
        GOVERNED,
        "paced_workload",
        &[
            "udp",
            "127.0.0.1:9",
            &count.to_string(),
            &pace_us.to_string(),
        ],
    )?;
    let secs = start.elapsed().as_secs_f64();
    // Longer than the drain thread's epoll timeout, so nothing is in flight.
    thread::sleep(Duration::from_millis(500));
    let v: Value = serde_json::from_str(out.trim()).with_context(|| format!("parse {out:?}"))?;
    let sent = v["ok"].as_u64().unwrap_or(0) + v["eperm"].as_u64().unwrap_or(0);
    Ok(json!({
        "sent": sent,
        "achieved_rate": (sent as f64 / secs) as u64,
        "drained": pipeline.drained() - drained0,
        "kernel_drops": get_counter(ebpf, rk_counter::RK_CNT_RINGBUF_DROP)? - drops0,
        "userspace_drops": pipeline.userspace_drops() - user0,
    }))
}

pub fn run(bpftool: Option<&Path>) -> Result<Value> {
    for dir in [GOVERNED, UNGOVERNED, FILE_DIR] {
        fs::create_dir_all(dir).with_context(|| format!("create {dir}"))?;
    }
    fs::write(format!("{FILE_DIR}/file"), b"rk").context("create bench file")?;

    // Load as the daemon does (pins aside): ring sized from the CPU count and
    // the adaptive wakeup threshold set, so the pipeline numbers are real.
    let bytes = crate::bpf::rk_bpf_bytes().context("built without embedded BPF objects")?;
    let ring_bytes = rk_sensor::consumer::ring_size(
        thread::available_parallelism().map_or(1, usize::from),
        None,
    );
    let wakeup_threshold = u64::from(ring_bytes / 8);
    let mut ebpf = aya::EbpfLoader::new()
        .set_max_entries("events_ringbuf", ring_bytes)
        .override_global("rk_wakeup_threshold", &wakeup_threshold, true)
        .load(bytes)
        .context("load rk.bpf.o")?;
    let btf = Btf::from_sys_fs().ok();
    for r in rk_sensor::loader::load_programs(
        rk_sensor::loader::Object::Production,
        &mut ebpf,
        btf.as_ref(),
    ) {
        if !r.loaded {
            bail!("{} failed to load: {:?}", r.name, r.error);
        }
    }

    // 1. Baseline: nothing attached.
    let baseline = measure_all(GOVERNED)?;

    // 2. Attach and govern. The heartbeat must stay fresh or every governed
    // ENFORCE action would be denied (docs/design/phase-6.md §4).
    let _heartbeat = rk_sensor::resilience::Heartbeat::start(&mut ebpf, Duration::from_secs(30))?;
    rk_sensor::policy::attach_all(&mut ebpf, Path::new("/sys/fs/cgroup/rk.slice"))?;
    let mut engine = rk_sensor::policy::PolicyEngine::default();
    engine.apply_text(&mut ebpf, POLICY)?;
    let ring = rk_sensor::consumer::take_ring(&mut ebpf)?;
    let consumer =
        rk_sensor::consumer::Consumer::start(ring, None, rk_sensor::consumer::Config::default())?;
    let pipeline = consumer.stats();

    let ungoverned = measure_all(UNGOVERNED)?;
    let stats_on = fs::write("/proc/sys/kernel/bpf_stats_enabled", b"1").is_ok();
    let governed = measure_all(GOVERNED)?;
    let per_program = match (stats_on, bpftool) {
        (true, Some(tool)) => {
            bpf_stats(tool).unwrap_or_else(|e| json!({ "error": format!("{e:#}") }))
        }
        _ => json!({ "error": "bpf_stats or bpftool unavailable" }),
    };
    let _ = fs::write("/proc/sys/kernel/bpf_stats_enabled", b"0");

    let mut hooks = serde_json::Map::new();
    for (i, (op, hook, iters)) in OPS.iter().enumerate() {
        let delta = |(p50, p99): (u64, u64)| {
            json!({
                "p50": p50.saturating_sub(baseline[i].0),
                "p99": p99.saturating_sub(baseline[i].1),
            })
        };
        hooks.insert(
            (*op).to_string(),
            json!({
                "hook": hook,
                "iterations": iters,
                "baseline": { "p50": baseline[i].0, "p99": baseline[i].1 },
                "ungoverned": { "p50": ungoverned[i].0, "p99": ungoverned[i].1 },
                "governed": { "p50": governed[i].0, "p99": governed[i].1 },
                "overhead": { "ungoverned": delta(ungoverned[i]), "governed": delta(governed[i]) },
            }),
        );
    }

    // 3. Event throughput through the Phase 7 pipeline.
    let pace = 1_000_000 / SUSTAINED_RATE;
    let sustained = rate_run(&ebpf, &pipeline, SUSTAINED_RATE * SUSTAINED_SECS, pace)?;
    let flood = rate_run(&ebpf, &pipeline, 500_000, 0)?;
    consumer.stop();

    let release = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    Ok(json!({
        "kernel": release.trim(),
        "ring_bytes": ring_bytes,
        "repeats": REPEATS,
        "hooks": hooks,
        "per_program": per_program,
        "sustained": { "target_rate": SUSTAINED_RATE, "seconds": SUSTAINED_SECS, "result": sustained },
        "flood": flood,
    }))
}
