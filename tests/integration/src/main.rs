//! rk-integration: Static integration test runner for Reality Kernel.
//!
//! Validates kernel network policy enforcement across all supported kernels.
//! Executes the full verdict suite against rk.bpf.o and rk_emitfail.bpf.o.

mod bpf;
mod workloads;

use std::collections::HashSet;
use std::fs;
use std::net::{TcpListener, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use aya::maps::{PerCpuArray, RingBuf};
use aya::Btf;
use rk_ebpf_common::rk_counter;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct TestCheck {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

impl TestCheck {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            passed: true,
            detail: detail.into(),
        }
    }

    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            passed: false,
            detail: detail.into(),
        }
    }
}

const POLICY_TEXT: &str = r#"
[profiles.enforce-profile]
mode = "enforce"
network.default = "deny"
network.include = ["cloud-metadata"]

[[profiles.enforce-profile.network.allow]]
cidr = "127.0.0.0/8"
proto = ["tcp", "udp"]

[[profiles.enforce-profile.network.allow]]
cidr = "::1/128"
proto = ["tcp", "udp"]

[[profiles.enforce-profile.network.deny]]
cidr = "10.99.0.0/24"
proto = ["tcp", "udp"]

[[profiles.enforce-profile.network.deny]]
cidr = "fd99::/64"
proto = ["tcp", "udp"]

[profiles.audit-profile]
mode = "audit"
network.default = "allow"

[[profiles.audit-profile.network.deny]]
cidr = "10.99.0.0/24"
proto = ["tcp", "udp"]

[[bindings]]
cgroup = "rk.slice/enforce"
profile = "enforce-profile"

[[bindings]]
cgroup = "rk.slice/audit"
profile = "audit-profile"
"#;

const POLICY_B: &str = r#"
[profiles.enforce-profile]
mode = "enforce"
network.default = "deny"
network.include = ["cloud-metadata"]

[[profiles.enforce-profile.network.allow]]
cidr = "127.0.0.0/8"
proto = ["tcp", "udp"]

[[profiles.enforce-profile.network.allow]]
cidr = "::1/128"
proto = ["tcp", "udp"]

[[profiles.enforce-profile.network.allow]]
cidr = "10.99.0.2/32"
proto = ["tcp", "udp"]

[[profiles.enforce-profile.network.deny]]
cidr = "10.99.0.1/32"
proto = ["tcp", "udp"]

[[profiles.enforce-profile.network.deny]]
cidr = "fd99::/64"
proto = ["tcp", "udp"]

[profiles.audit-profile]
mode = "audit"
network.default = "allow"

[[profiles.audit-profile.network.deny]]
cidr = "10.99.0.0/24"
proto = ["tcp", "udp"]

[[bindings]]
cgroup = "rk.slice/enforce"
profile = "enforce-profile"

[[bindings]]
cgroup = "rk.slice/audit"
profile = "audit-profile"
"#;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == workloads::CHILD_FLAG {
        let code = workloads::run_child(&args[2..]);
        std::process::exit(code);
    }

    let mut checks = Vec::new();

    #[cfg(not(target_os = "linux"))]
    {
        checks.push(TestCheck::fail("platform", "rk-integration requires Linux"));
        output_results(&checks);
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    {
        if bpf::rk_bpf_bytes().is_none() {
            checks.push(TestCheck::fail(
                "embedded_bpf",
                "binary built without --features embedded-bpf",
            ));
            output_results(&checks);
            std::process::exit(1);
        }

        run_suite(&mut checks);
        output_results(&checks);

        let failed = checks.iter().any(|c| !c.passed);
        std::process::exit(if failed { 1 } else { 0 });
    }
}

fn output_results(checks: &[TestCheck]) {
    println!("===RK_INTEGRATION_BEGIN===");
    if let Ok(json) = serde_json::to_string_pretty(checks) {
        println!("{}", json);
    }
    println!("===RK_INTEGRATION_END===");
}

#[cfg(target_os = "linux")]
fn run_suite(checks: &mut Vec<TestCheck>) {
    setup_environment();

    // 1. Run main verdict suite against rk.bpf.o
    let rk_bytes = match bpf::rk_bpf_bytes() {
        Some(b) => b,
        None => return,
    };

    let btf = Btf::from_sys_fs().ok();
    let cgroup_slice = Path::new("/sys/fs/cgroup/rk.slice");

    let mut ebpf = match rk_sensor::loader::open_bytes(rk_bytes, "rk.bpf.o") {
        Ok(e) => e,
        Err(e) => {
            checks.push(TestCheck::fail("bpf_open", format!("{e:#}")));
            return;
        }
    };

    let reports = rk_sensor::loader::load_programs(
        rk_sensor::loader::Object::Production,
        &mut ebpf,
        btf.as_ref(),
    );
    for r in &reports {
        if !r.loaded {
            checks.push(TestCheck::fail(
                "program_load",
                format!("{}: failed to load: {:?}", r.name, r.error),
            ));
            return;
        }
    }

    if let Err(e) = rk_sensor::policy::attach_network(&mut ebpf, cgroup_slice) {
        checks.push(TestCheck::fail("attach_network", format!("{e:#}")));
        return;
    }

    let mut engine = rk_sensor::policy::PolicyEngine::default();
    if let Err(e) = engine.apply_text(&mut ebpf, POLICY_TEXT) {
        checks.push(TestCheck::fail("policy_apply", format!("{e:#}")));
        return;
    }

    // Run each named test in §7
    run_test(checks, "net_enforce_tcp_v4", || {
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "tcp_connect",
            &["10.99.0.1:80", "eperm"],
        )?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "tcp_connect",
            &["127.0.0.1:8080", "ok"],
        )?;
        Ok("10.99.0.1 denied with EPERM, 127.0.0.1 allowed".into())
    });

    run_test(checks, "net_enforce_tcp_v6", || {
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "tcp_connect",
            &["[fd99::1]:80", "eperm"],
        )?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "tcp_connect",
            &["[::1]:8080", "ok"],
        )?;
        Ok("[fd99::1] denied with EPERM, [::1] allowed".into())
    });

    run_test(checks, "net_enforce_udp_connect_v4", || {
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "udp_connect",
            &["10.99.0.1:80", "eperm"],
        )?;
        Ok("udp connect to 10.99.0.1:80 denied with EPERM".into())
    });

    run_test(checks, "net_enforce_udp_connect_v6", || {
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "udp_connect",
            &["[fd99::1]:80", "eperm"],
        )?;
        Ok("udp connect to [fd99::1]:80 denied with EPERM".into())
    });

    run_test(checks, "net_enforce_udp_sendmsg_v4", || {
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "udp_sendmsg",
            &["10.99.0.1:80", "eperm"],
        )?;
        Ok("udp send_to to 10.99.0.1:80 denied with EPERM".into())
    });

    run_test(checks, "net_enforce_udp_sendmsg_v6", || {
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "udp_sendmsg",
            &["[fd99::1]:80", "eperm"],
        )?;
        Ok("udp send_to to [fd99::1]:80 denied with EPERM".into())
    });

    run_test(checks, "net_enforce_v4_mapped", || {
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "tcp_connect",
            &["[::ffff:10.99.0.1]:80", "eperm"],
        )?;
        Ok("connect to [::ffff:10.99.0.1]:80 denied with EPERM".into())
    });

    run_test(checks, "net_nat64_equivalence", || {
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "tcp_connect",
            &["[64:ff9b::10.99.0.1]:80", "eperm"],
        )?;
        Ok("NAT64 connect to [64:ff9b::10.99.0.1]:80 denied with EPERM".into())
    });

    run_test(checks, "net_raw_socket_denied", || {
        spawn_child("/sys/fs/cgroup/rk.slice/enforce", "raw_socket", &[])?;
        Ok("AF_INET and AF_INET6 raw sockets denied with EPERM".into())
    });

    run_test(checks, "net_packet_vnet_hdr_denied", || {
        spawn_child("/sys/fs/cgroup/rk.slice/enforce", "packet_socket", &[])?;
        Ok("AF_PACKET raw socket denied with EPERM".into())
    });

    run_test(checks, "net_tcp_fastopen_denied", || {
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "tcp_fastopen",
            &["10.99.0.1:80"],
        )?;
        Ok("TCP Fast Open sendto denied with EPERM".into())
    });

    run_test(checks, "net_io_uring_connect_denied", || {
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "io_uring_connect",
            &["10.99.0.1:80"],
        )?;
        Ok("io_uring IORING_OP_CONNECT denied with EPERM".into())
    });

    run_test(checks, "net_audit_reports_rule_id", || {
        let expected_rule_id = engine
            .policy()
            .and_then(|p| {
                p.origins
                    .iter()
                    .find(|o| o.profile == "audit-profile")
                    .map(|o| o.id)
            })
            .context("audit-profile rule not found in policy origins")?;

        let expected_cgroup_id = engine
            .cgroup_id("rk.slice/audit")
            .context("cgroup rk.slice/audit not bound in engine")?;

        // Drain ring buffer first to cleanly observe the audit event
        drain_ringbuf(&mut ebpf)?;

        // In audit mode, connect succeeds
        spawn_child(
            "/sys/fs/cgroup/rk.slice/audit",
            "tcp_connect",
            &["10.99.0.1:80", "ok"],
        )?;

        // Read ring buffer to verify audit event matches rule_id and cgroup_id
        let map = ebpf
            .map_mut("events_ringbuf")
            .context("missing events_ringbuf")?;
        let mut rb = RingBuf::try_from(map).context("open ringbuf")?;
        let mut found_audit = false;
        let mut matched_rule_id = 0;
        let mut matched_cgroup_id = 0;

        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_millis(500) {
            while let Some(item) = rb.next() {
                if let Ok(ev) = rk_sensor::decoder::decode(item.as_ref()) {
                    if ev.hdr.verdict
                        == rk_ebpf_common::rk_verdict::RK_VERDICT_AUDIT_WOULD_DENY as u8
                    {
                        matched_rule_id = ev.hdr.rule_id;
                        matched_cgroup_id = ev.hdr.cgroup_id;
                        if ev.hdr.rule_id == expected_rule_id
                            && ev.hdr.cgroup_id == expected_cgroup_id
                        {
                            found_audit = true;
                            break;
                        }
                    }
                }
            }
            if found_audit {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        if found_audit {
            Ok(format!(
                "audit allowed and emitted event with rule_id={expected_rule_id}, cgroup_id={expected_cgroup_id}"
            ))
        } else {
            anyhow::bail!(
                "audit event mismatch: expected rule_id={expected_rule_id}, cgroup_id={expected_cgroup_id}; got rule_id={matched_rule_id}, cgroup_id={matched_cgroup_id}"
            )
        }
    });

    run_test(checks, "net_ungoverned_untouched", || {
        spawn_child(
            "/sys/fs/cgroup/ungoverned",
            "tcp_connect",
            &["10.99.0.1:80", "ok"],
        )?;
        Ok("processes outside rk.slice can connect to 10.99.0.1:80 without hindrance".into())
    });

    run_test(checks, "net_unbound_sibling_untouched", || {
        spawn_child(
            "/sys/fs/cgroup/rk.slice/ungoverned-sibling",
            "tcp_connect",
            &["10.99.0.1:80", "ok"],
        )?;
        Ok("unbound sibling inside rk.slice can connect to 10.99.0.1:80 without hindrance".into())
    });

    run_test(checks, "net_reload_atomic", || {
        drain_ringbuf(&mut ebpf)?;
        let drops_start = get_counter(&ebpf, rk_counter::RK_CNT_RINGBUF_DROP)?;

        let mut deny_gens = HashSet::new();
        let mut allow_gens = HashSet::new();

        // Baseline active policy is POLICY_TEXT (A, deny)
        deny_gens.insert(engine.generation());

        let current_exe = std::env::current_exe().context("current_exe")?;
        let procs = "/sys/fs/cgroup/rk.slice/enforce/cgroup.procs";

        // Spawn child to perform 2,000 paced sends to 10.99.0.2:80
        let child = Command::new(&current_exe)
            .arg(workloads::CHILD_FLAG)
            .arg(procs)
            .arg("paced_workload")
            .arg("udp")
            .arg("10.99.0.2:80")
            .arg("2000")
            .arg("1000") // 1ms pace ~ 2-4s in guest VM
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("spawn paced_workload child")?;
        let child_pid = child.id();

        // Parent alternates A and B at least 6 times
        for i in 0..6 {
            if i % 2 == 0 {
                engine.apply_text(&mut ebpf, POLICY_B)?;
                allow_gens.insert(engine.generation());
            } else {
                engine.apply_text(&mut ebpf, POLICY_TEXT)?;
                deny_gens.insert(engine.generation());
            }
        }

        let output = child
            .wait_with_output()
            .context("wait for paced_workload child")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "child failed with exit {:?}: {}",
                output.status.code(),
                stderr.trim()
            );
        }

        #[derive(Deserialize)]
        struct ChildCounts {
            eperm: u64,
            ok: u64,
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let counts: ChildCounts = serde_json::from_str(stdout.trim())
            .with_context(|| format!("failed to parse child output: {stdout}"))?;

        if counts.eperm + counts.ok < 2000 {
            anyhow::bail!(
                "child performed {} sends, expected >= 2000",
                counts.eperm + counts.ok
            );
        }

        // Drain events from ring buffer
        let map = ebpf
            .map_mut("events_ringbuf")
            .context("missing events_ringbuf")?;
        let mut rb = RingBuf::try_from(map).context("open ringbuf")?;
        let mut deny_events = 0u64;
        let mut allow_events = 0u64;

        while let Some(item) = rb.next() {
            if let Ok(ev) = rk_sensor::decoder::decode(item.as_ref()) {
                if ev.hdr.tgid == child_pid {
                    let gen = ev.hdr.policy_gen;
                    let verdict = ev.hdr.verdict;
                    if deny_gens.contains(&gen) {
                        if verdict != rk_ebpf_common::rk_verdict::RK_VERDICT_DENY as u8 {
                            anyhow::bail!(
                                "event for deny gen {gen} had non-deny verdict {verdict}"
                            );
                        }
                        deny_events += 1;
                    } else if allow_gens.contains(&gen) {
                        if verdict != rk_ebpf_common::rk_verdict::RK_VERDICT_ALLOW as u8 {
                            anyhow::bail!(
                                "event for allow gen {gen} had non-allow verdict {verdict}"
                            );
                        }
                        allow_events += 1;
                    } else {
                        anyhow::bail!("event has unexpected policy_gen {gen}");
                    }
                }
            }
        }

        let drops_end = get_counter(&ebpf, rk_counter::RK_CNT_RINGBUF_DROP)?;
        let drops = drops_end.saturating_sub(drops_start);
        if drops > 0 {
            anyhow::bail!("expected zero drops during atomic reload, got {drops}");
        }

        if counts.eperm != deny_events {
            anyhow::bail!(
                "child EPERM count ({}) != deny events count ({})",
                counts.eperm,
                deny_events
            );
        }
        if counts.ok != allow_events {
            anyhow::bail!(
                "child OK count ({}) != allow events count ({})",
                counts.ok,
                allow_events
            );
        }
        if deny_events == 0 || allow_events == 0 {
            anyhow::bail!(
                "did not observe both generations (deny={}, allow={})",
                deny_events,
                allow_events
            );
        }

        Ok(format!(
            "2000 sends over 6 flips: {} denied, {} allowed; 1:1 match with events, 0 drops",
            deny_events, allow_events
        ))
    });

    run_test(checks, "net_verdicts_independent_of_telemetry", || {
        // Don't drain the ring buffer; flood it until it drops
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "flood_ringbuf",
            &["10.99.0.1:80"],
        )?;

        let drops = get_counter(&ebpf, rk_counter::RK_CNT_RINGBUF_DROP)?;
        if drops == 0 {
            anyhow::bail!("expected RK_CNT_RINGBUF_DROP > 0 after flood, got 0");
        }

        // Assert denied connects still get EPERM
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "tcp_connect",
            &["10.99.0.1:80", "eperm"],
        )?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "udp_connect",
            &["10.99.0.1:80", "eperm"],
        )?;

        Ok(format!(
            "ring buffer overflowed with {drops} drops; denied connects still return EPERM"
        ))
    });

    // Drop rk.bpf.o instance before loading rk_emitfail.bpf.o
    drop(ebpf);

    // 2. Run verdict suite against rk_emitfail.bpf.o
    run_test(checks, "net_verdicts_with_emit_failing", || {
        let emitfail_bytes = match bpf::rk_emitfail_bytes() {
            Some(b) => b,
            None => anyhow::bail!("rk_emitfail.bpf.o not embedded"),
        };

        let mut ebpf_fail = rk_sensor::loader::open_bytes(emitfail_bytes, "rk_emitfail.bpf.o")?;
        let reports = rk_sensor::loader::load_programs(
            rk_sensor::loader::Object::Production,
            &mut ebpf_fail,
            btf.as_ref(),
        );
        for r in &reports {
            if !r.loaded {
                anyhow::bail!("{}: failed to load: {:?}", r.name, r.error);
            }
        }

        rk_sensor::policy::attach_network(&mut ebpf_fail, cgroup_slice)?;
        let mut engine_fail = rk_sensor::policy::PolicyEngine::default();
        engine_fail.apply_text(&mut ebpf_fail, POLICY_TEXT)?;

        // Run the same full verdict list as the normal suite
        run_verdict_suite()?;

        // Assert RK_CNT_SCRATCH_MISS > 0
        let scratch_miss = get_counter(&ebpf_fail, rk_counter::RK_CNT_SCRATCH_MISS)?;
        if scratch_miss == 0 {
            anyhow::bail!("expected RK_CNT_SCRATCH_MISS > 0, got 0");
        }

        // Assert no events reached the ring buffer
        let map = ebpf_fail
            .map_mut("events_ringbuf")
            .context("missing events_ringbuf")?;
        let mut rb = RingBuf::try_from(map).context("open ringbuf")?;
        if rb.next().is_some() {
            anyhow::bail!(
                "expected no events in ring buffer with emit failing, but found at least one"
            );
        }

        Ok(format!(
            "all verdicts enforced with emit failing; {scratch_miss} scratch misses recorded and 0 events reached ringbuf"
        ))
    });
}

#[cfg(target_os = "linux")]
fn get_counter(ebpf: &aya::Ebpf, key: u32) -> Result<u64> {
    let map = ebpf.map("rk_counters").context("rk_counters map missing")?;
    let counters =
        PerCpuArray::<_, u64>::try_from(map).context("open rk_counters as PerCpuArray")?;
    let per_cpu = counters.get(&key, 0).context("get counter key")?;
    Ok(per_cpu.iter().sum::<u64>())
}

#[cfg(target_os = "linux")]
fn drain_ringbuf(ebpf: &mut aya::Ebpf) -> Result<()> {
    let map = ebpf
        .map_mut("events_ringbuf")
        .context("missing events_ringbuf")?;
    let mut rb = RingBuf::try_from(map).context("open ringbuf")?;
    while rb.next().is_some() {}
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_verdict_suite() -> Result<()> {
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "tcp_connect",
        &["10.99.0.1:80", "eperm"],
    )?;
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "tcp_connect",
        &["127.0.0.1:8080", "ok"],
    )?;
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "tcp_connect",
        &["[fd99::1]:80", "eperm"],
    )?;
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "tcp_connect",
        &["[::1]:8080", "ok"],
    )?;
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "udp_connect",
        &["10.99.0.1:80", "eperm"],
    )?;
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "udp_connect",
        &["[fd99::1]:80", "eperm"],
    )?;
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "udp_sendmsg",
        &["10.99.0.1:80", "eperm"],
    )?;
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "udp_sendmsg",
        &["[fd99::1]:80", "eperm"],
    )?;
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "tcp_connect",
        &["[::ffff:10.99.0.1]:80", "eperm"],
    )?;
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "tcp_connect",
        &["[64:ff9b::10.99.0.1]:80", "eperm"],
    )?;
    spawn_child("/sys/fs/cgroup/rk.slice/enforce", "raw_socket", &[])?;
    spawn_child("/sys/fs/cgroup/rk.slice/enforce", "packet_socket", &[])?;
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "tcp_fastopen",
        &["10.99.0.1:80"],
    )?;
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "io_uring_connect",
        &["10.99.0.1:80"],
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_test<F>(checks: &mut Vec<TestCheck>, name: &'static str, f: F)
where
    F: FnOnce() -> Result<String>,
{
    match f() {
        Ok(detail) => checks.push(TestCheck::pass(name, detail)),
        Err(e) => checks.push(TestCheck::fail(name, format!("{e:#}"))),
    }
}

#[cfg(target_os = "linux")]
fn spawn_child(cgroup_path: &str, workload: &str, extra_args: &[&str]) -> Result<()> {
    let procs = format!("{cgroup_path}/cgroup.procs");
    let current_exe = std::env::current_exe().context("current_exe")?;

    let mut cmd = Command::new(current_exe);
    cmd.arg(workloads::CHILD_FLAG).arg(&procs).arg(workload);

    for arg in extra_args {
        cmd.arg(arg);
    }

    let output = cmd.output().context("spawn child process")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "child workload '{}' failed (exit {:?}): {}",
            workload,
            output.status.code(),
            stderr.trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn setup_environment() {
    // Add loopback test addresses
    let _ = Command::new("ip")
        .args(["addr", "add", "10.99.0.1/24", "dev", "lo"])
        .status();
    let _ = Command::new("ip")
        .args(["addr", "add", "10.99.0.2/24", "dev", "lo"])
        .status();
    let _ = Command::new("ip")
        .args(["addr", "add", "fd99::1/64", "dev", "lo"])
        .status();
    let _ = Command::new("ip")
        .args(["addr", "add", "64:ff9b::10.99.0.1/128", "dev", "lo"])
        .status();

    // Create cgroups
    let _ = fs::create_dir_all("/sys/fs/cgroup/rk.slice/enforce");
    let _ = fs::create_dir_all("/sys/fs/cgroup/rk.slice/audit");
    let _ = fs::create_dir_all("/sys/fs/cgroup/rk.slice/ungoverned-sibling");
    let _ = fs::create_dir_all("/sys/fs/cgroup/ungoverned");

    // Spawn background TCP & UDP listeners
    start_tcp_listener("127.0.0.1:8080");
    start_tcp_listener("[::1]:8080");
    start_tcp_listener("10.99.0.1:80");
    start_tcp_listener("10.99.0.1:8080");
    start_tcp_listener("10.99.0.2:80");
    start_tcp_listener("[fd99::1]:80");
    start_tcp_listener("[fd99::1]:8080");

    start_udp_listener("127.0.0.1:8080");
    start_udp_listener("[::1]:8080");
    start_udp_listener("10.99.0.1:80");
    start_udp_listener("10.99.0.2:80");
    start_udp_listener("[fd99::1]:80");
}

fn start_tcp_listener(addr: &'static str) {
    thread::spawn(move || {
        if let Ok(listener) = TcpListener::bind(addr) {
            for mut s in listener.incoming().flatten() {
                use std::io::Write;
                let _ = s.write_all(b"OK\n");
            }
        }
    });
}

fn start_udp_listener(addr: &'static str) {
    thread::spawn(move || {
        if let Ok(socket) = UdpSocket::bind(addr) {
            let mut buf = [0u8; 1024];
            while socket.recv_from(&mut buf).is_ok() {}
        }
    });
}
