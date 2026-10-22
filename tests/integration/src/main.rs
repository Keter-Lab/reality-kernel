//! rk-integration: Static integration test runner for Reality Kernel.
//!
//! Validates kernel network policy enforcement across all supported kernels.
//! Executes the full verdict suite against rk.bpf.o and rk_emitfail.bpf.o.
//! With `--agent-suite`, drives the rk-sensor daemon through the `rk` CLI
//! instead (Phase 5, see agent.rs).

#[cfg(target_os = "linux")]
mod agent;
#[cfg(target_os = "linux")]
mod bench;
mod bpf;
#[cfg(target_os = "linux")]
mod conformance;
#[cfg(target_os = "linux")]
mod observability;
#[cfg(target_os = "linux")]
mod resilience;
mod workloads;

use std::collections::HashSet;
use std::fs;
use std::net::{TcpListener, UdpSocket};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::maps::{MapData, PerCpuArray, RingBuf};
use aya::Btf;
use rk_ebpf_common::{rk_counter, rk_exec_flag, rk_verdict};
use rk_sensor::decoder::Payload;
use serde::{Deserialize, Serialize};

/// A child that does not exit within this time is killed and fails its test,
/// so one stuck workload can never hang the whole suite.
const CHILD_DEADLINE: Duration = Duration::from_secs(60);
/// Upper bound for reading the ring buffer until it is empty.
const DRAIN_DEADLINE: Duration = Duration::from_secs(5);
/// Heartbeat timeout of the in-process suites. The heartbeat thread beats
/// every quarter of it, so it never goes stale during a run.
const HARNESS_HEARTBEAT: Duration = Duration::from_secs(30);

/// Progress goes to stderr so the CI log shows where a run stopped; stdout
/// carries only the JSON report.
macro_rules! progress {
    ($($arg:tt)*) => {{
        eprint!("[rk-integration] ");
        eprintln!($($arg)*);
    }};
}

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

[profiles.enforce-profile.exec]
default = "deny"
allow = [
    "/bin/true",
    "/bin/sh",
    "/run/rk-test/allowed_script.sh",
    "/run/rk-test/denied_interp_script.sh",
    "/run/rk-test/symlink_bin",
    "/run/rk-test/replaced_bin",
]

[profiles.enforce-profile.files]
protect_exec_allowlist = true

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_read_deny"
access = ["read"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_write_deny"
access = ["write"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_openat2_deny"
access = ["read"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_io_uring_deny"
access = ["read"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_o_trunc_deny"
access = ["truncate"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_truncate_deny"
access = ["truncate"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_ftruncate_deny"
access = ["truncate"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_unlink_deny"
access = ["delete"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_unlinkat_dir_deny"
access = ["delete"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_rename_src_deny"
access = ["rename"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_rename_replace_deny"
access = ["delete", "rename"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_rename_exchange_a"
access = ["rename"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_link_deny"
access = ["link"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/dir_create_deny"
access = ["create"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_chmod_deny"
access = ["setattr"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_hardlink_base"
access = ["read"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_bind_base"
access = ["read"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_symlink_base"
access = ["read"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_proc_fd_base"
access = ["write"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_relative_base"
access = ["read"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/subtree_dir"
subtree = true
access = ["read"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/deep"
subtree = true
access = ["read"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_reload_test"
access = ["read"]

[profiles.audit-profile]
mode = "audit"
network.default = "allow"

[[profiles.audit-profile.network.deny]]
cidr = "10.99.0.0/24"
proto = ["tcp", "udp"]

[profiles.audit-profile.exec]
default = "deny"

[profiles.audit-profile.files]
[[profiles.audit-profile.files.deny]]
path = "/run/rk-test/audit_file_deny"
access = ["read"]

[profiles.unlinked-profile]
mode = "enforce"
network.default = "allow"
exec.default = "allow"
exec.allow_unlinked = true

[[bindings]]
cgroup = "rk.slice/enforce"
profile = "enforce-profile"

[[bindings]]
cgroup = "rk.slice/audit"
profile = "audit-profile"

[[bindings]]
cgroup = "rk.slice/unlinked"
profile = "unlinked-profile"
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

[profiles.enforce-profile.exec]
default = "deny"
allow = [
    "/bin/true",
    "/bin/sh",
    "/run/rk-test/allowed_script.sh",
    "/run/rk-test/denied_interp_script.sh",
    "/run/rk-test/symlink_bin",
    "/run/rk-test/replaced_bin",
    "/run/rk-test/reload_bin",
]

[profiles.enforce-profile.files]
protect_exec_allowlist = true

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_read_deny"
access = ["read"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_write_deny"
access = ["write"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_openat2_deny"
access = ["read"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_io_uring_deny"
access = ["read"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_o_trunc_deny"
access = ["truncate"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_truncate_deny"
access = ["truncate"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_ftruncate_deny"
access = ["truncate"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_unlink_deny"
access = ["delete"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_unlinkat_dir_deny"
access = ["delete"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_rename_src_deny"
access = ["rename"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_rename_replace_deny"
access = ["delete", "rename"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_rename_exchange_a"
access = ["rename"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_link_deny"
access = ["link"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/dir_create_deny"
access = ["create"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_chmod_deny"
access = ["setattr"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_hardlink_base"
access = ["read"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_bind_base"
access = ["read"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_symlink_base"
access = ["read"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_proc_fd_base"
access = ["write"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/file_relative_base"
access = ["read"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/subtree_dir"
subtree = true
access = ["read"]

[[profiles.enforce-profile.files.deny]]
path = "/run/rk-test/deep"
subtree = true
access = ["read"]

[profiles.audit-profile]
mode = "audit"
network.default = "allow"

[[profiles.audit-profile.network.deny]]
cidr = "10.99.0.0/24"
proto = ["tcp", "udp"]

[profiles.audit-profile.exec]
default = "deny"

[profiles.audit-profile.files]
[[profiles.audit-profile.files.deny]]
path = "/run/rk-test/audit_file_deny"
access = ["read"]

[profiles.unlinked-profile]
mode = "enforce"
network.default = "allow"
exec.default = "allow"
exec.allow_unlinked = true

[[bindings]]
cgroup = "rk.slice/enforce"
profile = "enforce-profile"

[[bindings]]
cgroup = "rk.slice/audit"
profile = "audit-profile"

[[bindings]]
cgroup = "rk.slice/unlinked"
profile = "unlinked-profile"
"#;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == workloads::CHILD_FLAG {
        let code = workloads::run_child(&args[2..]);
        std::process::exit(code);
    }
    #[cfg(target_os = "linux")]
    if args.len() > 2 && args[1] == conformance::CONFORMANCE_FLAG {
        let mut checks = Vec::new();
        conformance::run(std::path::Path::new(&args[2]), &mut checks);
        output_results("RK_CONFORMANCE", &checks);
        std::process::exit(if checks.iter().all(|c| c.passed) {
            0
        } else {
            1
        });
    }
    #[cfg(target_os = "linux")]
    if args.len() > 1 && args[1] == bench::BENCH_FLAG {
        let bpftool = args.get(2).map(std::path::PathBuf::from);
        match bench::run(bpftool.as_deref()) {
            Ok(report) => {
                println!("===RK_BENCH_BEGIN===");
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_default()
                );
                println!("===RK_BENCH_END===");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("[rk-integration] bench failed: {e:#}");
                std::process::exit(1);
            }
        }
    }
    #[cfg(target_os = "linux")]
    if args.len() > 1 && args[1] == agent::PROBE_FLAG {
        std::process::exit(agent::run_probe(&args[2..]));
    }
    #[cfg(target_os = "linux")]
    if args.len() > 1 && args[1] == agent::SUITE_FLAG {
        let mut checks = Vec::new();
        agent::run_suite(&args[2..], &mut checks);
        output_results("RK_AGENT", &checks);
        std::process::exit(if checks.iter().all(|c| c.passed) {
            0
        } else {
            1
        });
    }
    #[cfg(target_os = "linux")]
    if args.len() > 1 && args[1] == observability::SUITE_FLAG {
        let mut checks = Vec::new();
        observability::run_suite(&args[2..], &mut checks);
        output_results("RK_OBSERVABILITY", &checks);
        std::process::exit(if checks.iter().all(|c| c.passed) {
            0
        } else {
            1
        });
    }
    #[cfg(target_os = "linux")]
    if args.len() > 1 && args[1] == resilience::SUITE_FLAG {
        let mut checks = Vec::new();
        resilience::run_suite(&args[2..], &mut checks);
        output_results("RK_RESILIENCE", &checks);
        std::process::exit(if checks.iter().all(|c| c.passed) {
            0
        } else {
            1
        });
    }

    let mut checks = Vec::new();

    #[cfg(not(target_os = "linux"))]
    {
        checks.push(TestCheck::fail("platform", "rk-integration requires Linux"));
        output_results("RK_INTEGRATION", &checks);
        std::process::exit(1);
    }

    #[cfg(target_os = "linux")]
    {
        if bpf::rk_bpf_bytes().is_none() {
            checks.push(TestCheck::fail(
                "embedded_bpf",
                "binary built without --features embedded-bpf",
            ));
            output_results("RK_INTEGRATION", &checks);
            std::process::exit(1);
        }

        run_suite(&mut checks);
        output_results("RK_INTEGRATION", &checks);

        let failed = checks.iter().any(|c| !c.passed);
        std::process::exit(if failed { 1 } else { 0 });
    }
}

fn output_results(marker: &str, checks: &[TestCheck]) {
    println!("==={marker}_BEGIN===");
    if let Ok(json) = serde_json::to_string_pretty(checks) {
        println!("{}", json);
    }
    println!("==={marker}_END===");
}

#[cfg(target_os = "linux")]
fn run_suite(checks: &mut Vec<TestCheck>) {
    progress!("setup: addresses, cgroups, listeners");
    setup_environment();
    progress!("setup: loading rk.bpf.o");

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

    // Kept alive for the whole run: a stale heartbeat denies every governed
    // ENFORCE action (docs/design/phase-6.md §4).
    let _heartbeat = match rk_sensor::resilience::Heartbeat::start(&mut ebpf, HARNESS_HEARTBEAT) {
        Ok(h) => h,
        Err(e) => {
            checks.push(TestCheck::fail("heartbeat_start", format!("{e:#}")));
            return;
        }
    };
    if let Err(e) = rk_sensor::policy::attach_all(&mut ebpf, cgroup_slice) {
        checks.push(TestCheck::fail("attach_all", format!("{e:#}")));
        return;
    }

    let mut engine = rk_sensor::policy::PolicyEngine::default();
    if let Err(e) = engine.apply_text(&mut ebpf, POLICY_TEXT) {
        checks.push(TestCheck::fail("policy_apply", format!("{e:#}")));
        return;
    }

    // Open the ring buffer exactly once and share the reader across tests. With
    // aya 0.13, a second RingBuf opened on a partly consumed ring starts from a
    // stale producer cache and reads stale ring memory forever (the cause of the
    // multi-hour hangs). rk-sensor's consumer also opens it once.
    let mut ring = match rk_sensor::consumer::take_ring(&mut ebpf) {
        Ok(ring) => ring,
        Err(e) => {
            checks.push(TestCheck::fail("ringbuf_open", format!("{e:#}")));
            return;
        }
    };

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
                    .find(|o| {
                        o.profile == "audit-profile" && o.origin.starts_with("network.deny[0]")
                    })
                    .map(|o| o.id)
            })
            .context("audit-profile rule not found in policy origins")?;

        let expected_cgroup_id = engine
            .cgroup_id("rk.slice/audit")
            .context("cgroup rk.slice/audit not bound in engine")?;

        // Drain ring buffer first to cleanly observe the audit event
        progress!("audit: draining ring buffer");
        drain_ringbuf(&mut ring)?;
        progress!("audit: drained; running audit child");

        // In audit mode, connect succeeds
        spawn_child(
            "/sys/fs/cgroup/rk.slice/audit",
            "tcp_connect",
            &["10.99.0.1:80", "ok"],
        )?;

        progress!("audit: child finished; reading events");
        // Read ring buffer to verify audit event matches rule_id and cgroup_id
        let rb = &mut ring;
        let mut found_audit = false;
        let mut matched_rule_id = 0;
        let mut matched_cgroup_id = 0;

        let start = std::time::Instant::now();
        // Diagnostics for a stream that never ends: how many records, a few
        // samples, and how many repeat an already-seen timestamp (which would
        // mean the consumer position is not advancing).
        let mut records = 0u64;
        let mut repeats = 0u64;
        let mut seen_ts = HashSet::new();
        let mut samples: Vec<String> = Vec::new();
        while start.elapsed() < Duration::from_millis(500) {
            while let Some(item) = rb.next() {
                records += 1;
                if start.elapsed() > DRAIN_DEADLINE {
                    anyhow::bail!(
                        "events never stopped while waiting for the audit event: {records} records \
                         ({repeats} repeated timestamps) in {}s; first records: {}",
                        DRAIN_DEADLINE.as_secs(),
                        samples.join("; ")
                    );
                }
                if let Ok(ev) = rk_sensor::decoder::decode(item.as_ref()) {
                    if !seen_ts.insert(ev.hdr.ts_ns) {
                        repeats += 1;
                    }
                    if samples.len() < 8 {
                        samples.push(format!(
                            "type={} verdict={} rule={} cgroup={} tgid={} gen={}",
                            ev.hdr.type_,
                            ev.hdr.verdict,
                            ev.hdr.rule_id,
                            ev.hdr.cgroup_id,
                            ev.hdr.tgid,
                            ev.hdr.policy_gen
                        ));
                    }
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
                "audit event mismatch: expected rule_id={expected_rule_id}, cgroup_id={expected_cgroup_id}; got rule_id={matched_rule_id}, cgroup_id={matched_cgroup_id}; {records} records seen: {}",
                samples.join("; ")
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
        drain_ringbuf(&mut ring)?;
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

        let output = wait_with_deadline(child, "paced_workload child", CHILD_DEADLINE)?;
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
        let rb = &mut ring;
        let mut deny_events = 0u64;
        let mut allow_events = 0u64;
        let drain_start = Instant::now();

        while let Some(item) = rb.next() {
            if drain_start.elapsed() > DRAIN_DEADLINE {
                anyhow::bail!(
                    "ring buffer still producing after {}s while reading reload events",
                    DRAIN_DEADLINE.as_secs()
                );
            }
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

    // ------------------------------------------------------------------------
    // Phase 3 process execution tests (docs/design/phase-3.md §7)
    // ------------------------------------------------------------------------

    run_test(checks, "exec_enforce_unlisted_denied", || {
        let enforce_cgroup_id = engine
            .cgroup_id("rk.slice/enforce")
            .context("cgroup rk.slice/enforce not bound")?;

        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "exec_cmd",
            &["eperm", "/run/rk-test/unlisted_bin"],
        )?;

        let ev = poll_exec_event(&mut ring, Duration::from_millis(500), |e| {
            e.cgroup_id == enforce_cgroup_id && e.verdict == rk_verdict::RK_VERDICT_DENY as u8
        })?;
        if ev.rule_id != 0 {
            anyhow::bail!("expected rule_id == 0, got {}", ev.rule_id);
        }
        if (ev.flags & rk_exec_flag::RK_EXEC_DECISION) == 0 {
            anyhow::bail!("expected RK_EXEC_DECISION flag set");
        }
        Ok("unlisted executable denied with EPERM; emitted decision deny event with rule 0".into())
    });

    run_test(checks, "exec_enforce_listed_runs", || {
        let enforce_cgroup_id = engine
            .cgroup_id("rk.slice/enforce")
            .context("cgroup rk.slice/enforce not bound")?;
        let expected_true_rule_id = engine
            .policy()
            .and_then(|p| {
                p.origins
                    .iter()
                    .find(|o| o.profile == "enforce-profile" && o.origin.contains("/bin/true"))
                    .map(|o| o.id)
            })
            .context("rule for /bin/true not found in origins")?;

        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "exec_cmd",
            &["ok", "/bin/true"],
        )?;

        let ev = poll_exec_event(&mut ring, Duration::from_millis(500), |e| {
            e.cgroup_id == enforce_cgroup_id
                && e.verdict == rk_verdict::RK_VERDICT_ALLOW as u8
                && (e.flags & rk_exec_flag::RK_EXEC_DECISION) == 0
        })?;
        if ev.rule_id != expected_true_rule_id {
            anyhow::bail!(
                "expected rule_id == {expected_true_rule_id}, got {}",
                ev.rule_id
            );
        }
        Ok(format!(
            "listed executable /bin/true ran successfully; emitted allow record with rule_id={expected_true_rule_id}"
        ))
    });

    run_test(checks, "exec_audit_reports_would_deny", || {
        let audit_cgroup_id = engine
            .cgroup_id("rk.slice/audit")
            .context("cgroup rk.slice/audit not bound")?;

        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/audit",
            "exec_cmd",
            &["ok", "/bin/true"],
        )?;

        let ev = poll_exec_event(&mut ring, Duration::from_millis(500), |e| {
            e.cgroup_id == audit_cgroup_id
                && e.verdict == rk_verdict::RK_VERDICT_AUDIT_WOULD_DENY as u8
        })?;
        if ev.rule_id != 0 {
            anyhow::bail!("expected rule_id == 0, got {}", ev.rule_id);
        }
        if !ev.filename.ends_with("/true") {
            anyhow::bail!("expected filename ending in /true, got {}", ev.filename);
        }
        if (ev.flags & rk_exec_flag::RK_EXEC_DECISION) == 0 {
            anyhow::bail!("expected RK_EXEC_DECISION flag set");
        }
        Ok(format!(
            "unlisted exec in audit mode ran successfully; emitted audit-would-deny event with rule_id=0, cgroup_id={audit_cgroup_id}, filename={}",
            ev.filename
        ))
    });

    run_test(checks, "exec_records_full_argv", || {
        let enforce_cgroup_id = engine
            .cgroup_id("rk.slice/enforce")
            .context("cgroup rk.slice/enforce not bound")?;
        let expected_sh_rule_id = engine
            .policy()
            .and_then(|p| {
                p.origins
                    .iter()
                    .find(|o| o.profile == "enforce-profile" && o.origin.contains("/bin/sh"))
                    .map(|o| o.id)
            })
            .context("rule for /bin/sh not found in origins")?;

        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "exec_cmd",
            &["ok", "/bin/sh", "-c", "echo a b"],
        )?;

        let ev = poll_exec_event(&mut ring, Duration::from_millis(500), |e| {
            e.cgroup_id == enforce_cgroup_id
                && e.verdict == rk_verdict::RK_VERDICT_ALLOW as u8
                && (e.flags & rk_exec_flag::RK_EXEC_DECISION) == 0
        })?;
        if ev.rule_id != expected_sh_rule_id {
            anyhow::bail!(
                "expected rule_id == {expected_sh_rule_id}, got {}",
                ev.rule_id
            );
        }
        let expected_argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo a b".to_string(),
        ];
        if ev.argv != expected_argv {
            anyhow::bail!(
                "argv mismatch: expected {:?}, got {:?}",
                expected_argv,
                ev.argv
            );
        }
        Ok(format!(
            "exec record carried exact argv {:?} with rule_id={expected_sh_rule_id}",
            ev.argv
        ))
    });

    run_test(checks, "exec_records_truncation_flag", || {
        let enforce_cgroup_id = engine
            .cgroup_id("rk.slice/enforce")
            .context("cgroup rk.slice/enforce not bound")?;
        let expected_true_rule_id = engine
            .policy()
            .and_then(|p| {
                p.origins
                    .iter()
                    .find(|o| o.profile == "enforce-profile" && o.origin.contains("/bin/true"))
                    .map(|o| o.id)
            })
            .context("rule for /bin/true not found in origins")?;

        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "exec_large_argv",
            &["/bin/true"],
        )?;

        let ev = poll_exec_event(&mut ring, Duration::from_millis(500), |e| {
            e.cgroup_id == enforce_cgroup_id
                && e.verdict == rk_verdict::RK_VERDICT_ALLOW as u8
                && (e.flags & rk_exec_flag::RK_EXEC_DECISION) == 0
        })?;
        if ev.rule_id != expected_true_rule_id {
            anyhow::bail!(
                "expected rule_id == {expected_true_rule_id}, got {}",
                ev.rule_id
            );
        }
        if (ev.flags & rk_exec_flag::RK_EXEC_ARGV_TRUNCATED) == 0 {
            anyhow::bail!(
                "expected RK_EXEC_ARGV_TRUNCATED flag set in flags={:#x}",
                ev.flags
            );
        }
        Ok(format!(
            "exec record with oversized argv set RK_EXEC_ARGV_TRUNCATED (flags={:#x})",
            ev.flags
        ))
    });

    run_test(checks, "exec_reload_atomic", || {
        let enforce_cgroup_id = engine
            .cgroup_id("rk.slice/enforce")
            .context("cgroup rk.slice/enforce not bound")?;

        drain_ringbuf(&mut ring)?;
        let drops_start = get_counter(&ebpf, rk_counter::RK_CNT_RINGBUF_DROP)?;

        let mut deny_gens = HashSet::new();
        let mut allow_gens = HashSet::new();

        deny_gens.insert(engine.generation());

        let current_exe = std::env::current_exe().context("current_exe")?;
        let procs = "/sys/fs/cgroup/rk.slice/enforce/cgroup.procs";

        let child = Command::new(&current_exe)
            .arg(workloads::CHILD_FLAG)
            .arg(procs)
            .arg("exec_reload_workload")
            .arg("/run/rk-test/reload_bin")
            .arg("250")
            .arg("25000") // 25ms pace ~ 6s in guest VM
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn exec_reload_workload child")?;

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

        let output = wait_with_deadline(child, "exec_reload_workload child", CHILD_DEADLINE)?;
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

        if counts.eperm + counts.ok < 200 {
            anyhow::bail!(
                "child performed {} execs, expected >= 200",
                counts.eperm + counts.ok
            );
        }

        let rb = &mut ring;
        let mut deny_events = 0u64;
        let mut allow_events = 0u64;
        let drain_start = Instant::now();

        while let Some(item) = rb.next() {
            if drain_start.elapsed() > DRAIN_DEADLINE {
                anyhow::bail!(
                    "ring buffer still producing after {}s while reading exec reload events",
                    DRAIN_DEADLINE.as_secs()
                );
            }
            if let Ok(ev) = rk_sensor::decoder::decode(item.as_ref()) {
                if ev.hdr.cgroup_id == enforce_cgroup_id
                    && ev.hdr.type_ == rk_ebpf_common::rk_event_type::RK_EV_EXEC as u16
                {
                    let gen = ev.hdr.policy_gen;
                    let verdict = ev.hdr.verdict;
                    if deny_gens.contains(&gen) {
                        if verdict != rk_verdict::RK_VERDICT_DENY as u8 {
                            anyhow::bail!(
                                "event for deny gen {gen} had non-deny verdict {verdict}"
                            );
                        }
                        deny_events += 1;
                    } else if allow_gens.contains(&gen) {
                        if verdict != rk_verdict::RK_VERDICT_ALLOW as u8 {
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
            anyhow::bail!("expected zero drops during exec atomic reload, got {drops}");
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
            "{} execs over 6 flips: {} denied, {} allowed; 1:1 match with events, 0 drops",
            counts.eperm + counts.ok,
            deny_events,
            allow_events
        ))
    });

    run_test(checks, "exec_script_requires_interpreter", || {
        // 1. Script is allowed, but interpreter is denied -> EPERM
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "exec_cmd",
            &["eperm", "/run/rk-test/denied_interp_script.sh"],
        )?;
        // 2. Interpreter is allowed, but script is unlisted -> EPERM
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "exec_cmd",
            &["eperm", "/run/rk-test/unlisted_script.sh"],
        )?;
        // 3. Both script and interpreter are allowed -> OK
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "exec_cmd",
            &["ok", "/run/rk-test/allowed_script.sh"],
        )?;
        Ok(
            "scripts require both script and interpreter allowed; denied if either is unlisted"
                .into(),
        )
    });

    run_test(checks, "exec_unlinked_denied", || {
        let enforce_cgroup_id = engine
            .cgroup_id("rk.slice/enforce")
            .context("cgroup rk.slice/enforce not bound")?;

        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "memfd_exec",
            &["eperm", "/bin/true"],
        )?;

        let ev = poll_exec_event(&mut ring, Duration::from_millis(500), |e| {
            e.cgroup_id == enforce_cgroup_id && e.verdict == rk_verdict::RK_VERDICT_DENY as u8
        })?;
        if (ev.flags & rk_exec_flag::RK_EXEC_UNLINKED) == 0 {
            anyhow::bail!("expected RK_EXEC_UNLINKED flag set");
        }
        Ok("unlinked executable (memfd) denied with EPERM in enforce mode; RK_EXEC_UNLINKED flag recorded".into())
    });

    run_test(checks, "exec_unlinked_override_allows", || {
        let unlinked_cgroup_id = engine
            .cgroup_id("rk.slice/unlinked")
            .context("cgroup rk.slice/unlinked not bound")?;

        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/unlinked",
            "memfd_exec",
            &["ok", "/bin/true"],
        )?;

        let ev = poll_exec_event(&mut ring, Duration::from_millis(500), |e| {
            e.cgroup_id == unlinked_cgroup_id
                && e.verdict == rk_verdict::RK_VERDICT_ALLOW as u8
                && (e.flags & rk_exec_flag::RK_EXEC_DECISION) == 0
        })?;
        if (ev.flags & rk_exec_flag::RK_EXEC_UNLINKED) == 0 {
            anyhow::bail!("expected RK_EXEC_UNLINKED flag set");
        }
        Ok("unlinked executable (memfd) allowed under exec.allow_unlinked=true; RK_EXEC_UNLINKED flag recorded".into())
    });

    run_test(checks, "exec_symlink_resolves_to_target", || {
        let enforce_cgroup_id = engine
            .cgroup_id("rk.slice/enforce")
            .context("cgroup rk.slice/enforce not bound")?;
        let expected_symlink_rule_id = engine
            .policy()
            .and_then(|p| {
                p.origins
                    .iter()
                    .find(|o| o.profile == "enforce-profile" && o.origin.contains("symlink_bin"))
                    .map(|o| o.id)
            })
            .context("rule for symlink_bin not found in origins")?;

        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "exec_cmd",
            &["ok", "/run/rk-test/symlink_bin"],
        )?;

        let ev = poll_exec_event(&mut ring, Duration::from_millis(500), |e| {
            e.cgroup_id == enforce_cgroup_id
                && e.verdict == rk_verdict::RK_VERDICT_ALLOW as u8
                && (e.flags & rk_exec_flag::RK_EXEC_DECISION) == 0
        })?;
        if ev.rule_id != expected_symlink_rule_id {
            anyhow::bail!(
                "expected rule_id == {expected_symlink_rule_id}, got {}",
                ev.rule_id
            );
        }
        Ok(format!(
            "symlink resolved to target at apply time and was permitted with rule_id={expected_symlink_rule_id}"
        ))
    });

    run_test(checks, "exec_replaced_binary_denied_until_reload", || {
        let enforce_cgroup_id = engine
            .cgroup_id("rk.slice/enforce")
            .context("cgroup rk.slice/enforce not bound")?;
        let expected_replaced_rule_id = engine
            .policy()
            .and_then(|p| {
                p.origins
                    .iter()
                    .find(|o| o.profile == "enforce-profile" && o.origin.contains("replaced_bin"))
                    .map(|o| o.id)
            })
            .context("rule for replaced_bin not found in origins")?;

        // 1. Initial binary runs OK
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "exec_cmd",
            &["ok", "/run/rk-test/replaced_bin"],
        )?;
        let ev = poll_exec_event(&mut ring, Duration::from_millis(500), |e| {
            e.cgroup_id == enforce_cgroup_id
                && e.verdict == rk_verdict::RK_VERDICT_ALLOW as u8
                && (e.flags & rk_exec_flag::RK_EXEC_DECISION) == 0
        })?;
        if ev.rule_id != expected_replaced_rule_id {
            anyhow::bail!(
                "expected rule_id == {expected_replaced_rule_id}, got {}",
                ev.rule_id
            );
        }

        // 2. Replace binary via atomic rename (new inode)
        fs::copy("/bin/true", "/run/rk-test/replaced_new")?;
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata("/run/rk-test/replaced_new")?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions("/run/rk-test/replaced_new", perms)?;
        fs::rename("/run/rk-test/replaced_new", "/run/rk-test/replaced_bin")?;

        // 3. Execution of replaced binary fails with EPERM (new inode not in map)
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "exec_cmd",
            &["eperm", "/run/rk-test/replaced_bin"],
        )?;
        let ev = poll_exec_event(&mut ring, Duration::from_millis(500), |e| {
            e.cgroup_id == enforce_cgroup_id && e.verdict == rk_verdict::RK_VERDICT_DENY as u8
        })?;
        if ev.rule_id != 0 {
            anyhow::bail!(
                "expected rule_id == 0 for replaced inode, got {}",
                ev.rule_id
            );
        }

        // 4. Policy reload re-resolves the new inode
        engine.apply_text(&mut ebpf, POLICY_TEXT)?;

        // 5. Execution succeeds again after reload
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "exec_cmd",
            &["ok", "/run/rk-test/replaced_bin"],
        )?;
        let ev = poll_exec_event(&mut ring, Duration::from_millis(500), |e| {
            e.cgroup_id == enforce_cgroup_id
                && e.verdict == rk_verdict::RK_VERDICT_ALLOW as u8
                && (e.flags & rk_exec_flag::RK_EXEC_DECISION) == 0
        })?;
        if ev.rule_id != expected_replaced_rule_id {
            anyhow::bail!(
                "expected rule_id == {expected_replaced_rule_id} after reload, got {}",
                ev.rule_id
            );
        }

        Ok("replaced binary denied due to inode change until policy reload re-resolved it".into())
    });

    run_test(checks, "exec_quarantine_blocks_exec_and_network", || {
        let enforce_cgroup_id = engine
            .cgroup_id("rk.slice/enforce")
            .context("cgroup rk.slice/enforce not bound")?;

        drain_ringbuf(&mut ring)?;
        // 1. Move enforce cgroup into quarantine
        engine.quarantine(&mut ebpf, "rk.slice/enforce")?;

        // 2. Previously allowed binary is denied with EPERM
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "exec_cmd",
            &["eperm", "/bin/true"],
        )?;
        let ev = poll_exec_event(&mut ring, Duration::from_millis(500), |e| {
            e.cgroup_id == enforce_cgroup_id && e.verdict == rk_verdict::RK_VERDICT_DENY as u8
        })?;
        if ev.rule_id != 0 {
            anyhow::bail!("expected rule_id == 0 in quarantine, got {}", ev.rule_id);
        }

        // 3. Previously allowed network connection is denied with EPERM
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "tcp_connect",
            &["127.0.0.1:8080", "eperm"],
        )?;

        // 4. Release enforce cgroup from quarantine
        engine.release(&mut ebpf, "rk.slice/enforce")?;

        // 5. Allowed binary runs again
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "exec_cmd",
            &["ok", "/bin/true"],
        )?;

        // 6. Allowed network connection succeeds again
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "tcp_connect",
            &["127.0.0.1:8080", "ok"],
        )?;

        Ok("quarantine immediately blocked exec and network; release restored them".into())
    });

    run_test(checks, "exec_ungoverned_untouched", || {
        spawn_child(
            "/sys/fs/cgroup/ungoverned",
            "exec_cmd",
            &["ok", "/run/rk-test/unlisted_bin"],
        )?;
        Ok("processes outside rk.slice can execute unlisted binaries without hindrance".into())
    });

    run_test(checks, "exec_unbound_sibling_untouched", || {
        spawn_child(
            "/sys/fs/cgroup/rk.slice/ungoverned-sibling",
            "exec_cmd",
            &["ok", "/run/rk-test/unlisted_bin"],
        )?;
        Ok(
            "unbound sibling inside rk.slice can execute unlisted binaries without hindrance"
                .into(),
        )
    });

    run_test(checks, "file_open_read_denied", || {
        let rule_id = file_rule_id(&engine, "enforce-profile", "/run/rk-test/file_read_deny")?;
        let cg_id = engine.cgroup_id("rk.slice/enforce").context("cgroup id")?;
        let (dev, ino) = file_identity("/run/rk-test/file_read_deny")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_open",
            &["/run/rk-test/file_read_deny", "r", "eperm"],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8 {
            anyhow::bail!("expected RK_VERDICT_DENY, got {}", ev.verdict);
        }
        if ev.rule_id != rule_id {
            anyhow::bail!("expected rule_id {rule_id}, got {}", ev.rule_id);
        }
        if ev.cgroup_id != cg_id {
            anyhow::bail!("expected cgroup_id {cg_id}, got {}", ev.cgroup_id);
        }
        if (ev.access & RK_FILE_READ) == 0 {
            anyhow::bail!("expected RK_FILE_READ in access, got {}", ev.access);
        }
        if ev.hook != RK_FILE_HOOK_OPEN {
            anyhow::bail!("expected RK_FILE_HOOK_OPEN, got {}", ev.hook);
        }
        Ok("file open for read denied with EPERM, event verified".into())
    });

    run_test(checks, "file_open_write_denied", || {
        let rule_id = file_rule_id(&engine, "enforce-profile", "/run/rk-test/file_write_deny")?;
        let cg_id = engine.cgroup_id("rk.slice/enforce").context("cgroup id")?;
        let (dev, ino) = file_identity("/run/rk-test/file_write_deny")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_open",
            &["/run/rk-test/file_write_deny", "w", "eperm"],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8
            || ev.rule_id != rule_id
            || ev.cgroup_id != cg_id
        {
            anyhow::bail!("header mismatch in file_open_write_denied: {ev:?}");
        }
        if (ev.access & RK_FILE_WRITE) == 0 || ev.hook != RK_FILE_HOOK_OPEN {
            anyhow::bail!("body mismatch in file_open_write_denied: {ev:?}");
        }
        Ok("file open for write denied with EPERM, event verified".into())
    });

    run_test(checks, "file_openat2_denied", || {
        let (dev, ino) = file_identity("/run/rk-test/file_openat2_deny")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_openat2",
            &["/run/rk-test/file_openat2_deny", "eperm"],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8 || ev.hook != RK_FILE_HOOK_OPEN {
            anyhow::bail!("event mismatch in file_openat2_denied: {ev:?}");
        }
        Ok("openat2 denied with EPERM, event verified".into())
    });

    run_test(checks, "file_io_uring_openat_denied", || {
        let (dev, ino) = file_identity("/run/rk-test/file_io_uring_deny")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_io_uring_openat",
            &["/run/rk-test/file_io_uring_deny"],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8 || ev.hook != RK_FILE_HOOK_OPEN {
            anyhow::bail!("event mismatch in file_io_uring_openat_denied: {ev:?}");
        }
        Ok("io_uring openat denied with EPERM, event verified".into())
    });

    run_test(checks, "file_o_trunc_denied", || {
        let (dev, ino) = file_identity("/run/rk-test/file_o_trunc_deny")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_open",
            &["/run/rk-test/file_o_trunc_deny", "o_trunc", "eperm"],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8 || (ev.access & RK_FILE_TRUNCATE) == 0 {
            anyhow::bail!("event mismatch in file_o_trunc_denied: {ev:?}");
        }
        Ok("O_TRUNC open denied with EPERM, event verified".into())
    });

    run_test(checks, "file_truncate_denied", || {
        let (dev, ino) = file_identity("/run/rk-test/file_truncate_deny")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_truncate",
            &["/run/rk-test/file_truncate_deny", "eperm"],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8
            || (ev.access & RK_FILE_TRUNCATE) == 0
            || ev.hook != RK_FILE_HOOK_SETATTR
        {
            anyhow::bail!("event mismatch in file_truncate_denied: {ev:?}");
        }
        Ok("truncate(2) denied with EPERM, event verified".into())
    });

    run_test(checks, "file_ftruncate_denied", || {
        let (dev, ino) = file_identity("/run/rk-test/file_ftruncate_deny")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_ftruncate",
            &["/run/rk-test/file_ftruncate_deny", "eperm"],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8
            || (ev.access & RK_FILE_TRUNCATE) == 0
            || ev.hook != RK_FILE_HOOK_SETATTR
        {
            anyhow::bail!("event mismatch in file_ftruncate_denied: {ev:?}");
        }
        Ok("ftruncate(2) denied with EPERM, event verified".into())
    });

    run_test(checks, "file_unlink_denied", || {
        let (dev, ino) = file_identity("/run/rk-test/file_unlink_deny")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_unlink",
            &["/run/rk-test/file_unlink_deny", "eperm"],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8
            || (ev.access & RK_FILE_DELETE) == 0
            || ev.hook != RK_FILE_HOOK_UNLINK
        {
            anyhow::bail!("event mismatch in file_unlink_denied: {ev:?}");
        }
        Ok("unlink(2) denied with EPERM, event verified".into())
    });

    run_test(checks, "file_unlinkat_dir_denied", || {
        let (dev, ino) = file_identity("/run/rk-test/file_unlinkat_dir_deny")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_rmdir",
            &["/run/rk-test/file_unlinkat_dir_deny", "eperm"],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8
            || (ev.access & RK_FILE_DELETE) == 0
            || ev.hook != RK_FILE_HOOK_UNLINK
        {
            anyhow::bail!("event mismatch in file_unlinkat_dir_denied: {ev:?}");
        }
        Ok("rmdir/unlinkat on directory denied with EPERM, event verified".into())
    });

    run_test(checks, "file_rename_source_denied", || {
        let (dev, ino) = file_identity("/run/rk-test/file_rename_src_deny")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_rename",
            &[
                "/run/rk-test/file_rename_src_deny",
                "/run/rk-test/renamed_target",
                "eperm",
            ],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8
            || (ev.access & RK_FILE_RENAME) == 0
            || ev.hook != RK_FILE_HOOK_RENAME
        {
            anyhow::bail!("event mismatch in file_rename_source_denied: {ev:?}");
        }
        Ok("rename source denied with EPERM, event verified".into())
    });

    run_test(checks, "file_rename_replace_target_denied", || {
        let (dev, ino) = file_identity("/run/rk-test/file_rename_replace_deny")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_rename",
            &[
                "/run/rk-test/file_rename_src_allowed",
                "/run/rk-test/file_rename_replace_deny",
                "eperm",
            ],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8 || ev.hook != RK_FILE_HOOK_RENAME {
            anyhow::bail!("event mismatch in file_rename_replace_target_denied: {ev:?}");
        }
        Ok("rename replace target denied with EPERM, event verified".into())
    });

    run_test(checks, "file_rename_exchange_denied", || {
        let (dev_a, ino_a) = file_identity("/run/rk-test/file_rename_exchange_a")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_rename_exchange",
            &[
                "/run/rk-test/file_rename_exchange_a",
                "/run/rk-test/file_rename_exchange_b",
                "eperm",
            ],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev_a && e.file_ino == ino_a
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8 || ev.hook != RK_FILE_HOOK_RENAME {
            anyhow::bail!("event mismatch in file_rename_exchange_denied: {ev:?}");
        }
        Ok("renameat2 RENAME_EXCHANGE denied with EPERM, event verified".into())
    });

    run_test(checks, "file_link_denied", || {
        let (dev, ino) = file_identity("/run/rk-test/file_link_deny")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_link",
            &[
                "/run/rk-test/file_link_deny",
                "/run/rk-test/file_link_new",
                "eperm",
            ],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8
            || (ev.access & RK_FILE_LINK) == 0
            || ev.hook != RK_FILE_HOOK_LINK
        {
            anyhow::bail!("event mismatch in file_link_denied: {ev:?}");
        }
        Ok("link(2) denied with EPERM, event verified".into())
    });

    run_test(checks, "file_create_in_protected_dir_denied", || {
        let (dev, ino) = file_identity("/run/rk-test/dir_create_deny")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_create",
            &["/run/rk-test/dir_create_deny/new_file", "eperm"],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8
            || (ev.access & RK_FILE_CREATE) == 0
            || ev.hook != RK_FILE_HOOK_CREATE
        {
            anyhow::bail!("event mismatch in file_create_in_protected_dir_denied: {ev:?}");
        }
        Ok("create in protected directory denied with EPERM, event verified".into())
    });

    run_test(checks, "file_chmod_denied", || {
        let (dev, ino) = file_identity("/run/rk-test/file_chmod_deny")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_chmod",
            &["/run/rk-test/file_chmod_deny", "eperm"],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8
            || (ev.access & RK_FILE_SETATTR) == 0
            || ev.hook != RK_FILE_HOOK_SETATTR
        {
            anyhow::bail!("event mismatch in file_chmod_denied: {ev:?}");
        }
        Ok("chmod(2) denied with EPERM, event verified".into())
    });

    run_test(checks, "file_hardlink_same_verdict", || {
        let (dev, ino) = file_identity("/run/rk-test/file_hardlink_base")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_open",
            &["/run/rk-test/file_hardlink_alias", "r", "eperm"],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8 {
            anyhow::bail!("event mismatch in file_hardlink_same_verdict: {ev:?}");
        }
        Ok("hardlink alias open denied with same verdict".into())
    });

    run_test(checks, "file_bind_mount_same_verdict", || {
        let (dev, ino) = file_identity("/run/rk-test/file_bind_base")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_open",
            &["/run/rk-test/file_bind_alias", "r", "eperm"],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8 {
            anyhow::bail!("event mismatch in file_bind_mount_same_verdict: {ev:?}");
        }
        Ok("bind mount open denied with same verdict".into())
    });

    run_test(checks, "file_symlink_same_verdict", || {
        let (dev, ino) = file_identity("/run/rk-test/file_symlink_base")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_open",
            &["/run/rk-test/file_symlink_alias", "r", "eperm"],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8 {
            anyhow::bail!("event mismatch in file_symlink_same_verdict: {ev:?}");
        }
        Ok("symlink alias open denied with same verdict".into())
    });

    run_test(checks, "file_proc_fd_reopen_same_verdict", || {
        let (dev, ino) = file_identity("/run/rk-test/file_proc_fd_base")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_proc_fd_reopen",
            &["/run/rk-test/file_proc_fd_base", "eperm"],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8 || (ev.access & RK_FILE_WRITE) == 0 {
            anyhow::bail!("event mismatch in file_proc_fd_reopen_same_verdict: {ev:?}");
        }
        Ok("/proc/self/fd reopen for write denied with same verdict".into())
    });

    run_test(checks, "file_relative_path_same_verdict", || {
        let (dev, ino) = file_identity("/run/rk-test/file_relative_base")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_relative_open",
            &["/run/rk-test", "file_relative_base", "eperm"],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8 {
            anyhow::bail!("event mismatch in file_relative_path_same_verdict: {ev:?}");
        }
        Ok("relative path open denied with same verdict".into())
    });

    run_test(checks, "file_ungoverned_untouched", || {
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/ungoverned",
            "file_open",
            &["/run/rk-test/file_read_deny", "r", "ok"],
        )?;
        thread::sleep(Duration::from_millis(50));
        if ring.next().is_some() {
            anyhow::bail!("unexpected event emitted for ungoverned file access");
        }
        Ok("ungoverned task opened protected file successfully without events".into())
    });

    run_test(checks, "file_subtree_rule_applies", || {
        let rule_id = file_rule_id(&engine, "enforce-profile", "/run/rk-test/subtree_dir")?;
        let (dev, ino) = file_identity("/run/rk-test/subtree_dir/nested/deep/file.txt")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_open",
            &[
                "/run/rk-test/subtree_dir/nested/deep/file.txt",
                "r",
                "eperm",
            ],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8
            || ev.rule_id != rule_id
            || (ev.flags & RK_FILE_EV_SUBTREE) == 0
        {
            anyhow::bail!("subtree event mismatch: {ev:?}");
        }
        Ok("subtree rule covered nested file and set RK_FILE_EV_SUBTREE".into())
    });

    run_test(checks, "file_deep_nesting_fails_closed", || {
        let mut deep_path = std::path::PathBuf::from("/run/rk-test/deep");
        for i in 1..=35 {
            deep_path.push(format!("d{i}"));
        }
        let deep_file = deep_path.join("file.txt");
        let (dev, ino) = file_identity(deep_file.to_str().unwrap())?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_open",
            &[deep_file.to_str().unwrap(), "r", "eperm"],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8
            || (ev.flags & RK_FILE_EV_DEPTH_EXCEEDED) == 0
        {
            anyhow::bail!("deep nesting event mismatch: {ev:?}");
        }
        Ok("access beyond 32 levels failed closed with RK_FILE_EV_DEPTH_EXCEEDED".into())
    });

    run_test(checks, "file_exec_allowlist_write_denied", || {
        let (dev, ino) = file_identity("/run/rk-test/allowed_script.sh")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_open",
            &["/run/rk-test/allowed_script.sh", "w", "eperm"],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8 || (ev.access & RK_FILE_WRITE) == 0 {
            anyhow::bail!("exec allowlist write deny event mismatch: {ev:?}");
        }
        Ok("write to allowlisted executable denied by protect_exec_allowlist".into())
    });

    run_test(checks, "file_exec_allowlist_replace_denied", || {
        let (dev, ino) = file_identity("/run/rk-test/allowed_script.sh")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/enforce",
            "file_rename",
            &[
                "/run/rk-test/file_rename_src_allowed",
                "/run/rk-test/allowed_script.sh",
                "eperm",
            ],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_DENY as u8 || ev.hook != RK_FILE_HOOK_RENAME {
            anyhow::bail!("exec allowlist replace deny event mismatch: {ev:?}");
        }
        Ok("replacing allowlisted executable via rename denied".into())
    });

    run_test(checks, "file_audit_reports_would_deny", || {
        let rule_id = file_rule_id(&engine, "audit-profile", "/run/rk-test/audit_file_deny")?;
        let cg_id = engine.cgroup_id("rk.slice/audit").context("cgroup id")?;
        let (dev, ino) = file_identity("/run/rk-test/audit_file_deny")?;
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/audit",
            "file_open",
            &["/run/rk-test/audit_file_deny", "r", "ok"],
        )?;
        let ev = poll_file_event(&mut ring, Duration::from_secs(2), |e| {
            e.file_dev == dev && e.file_ino == ino
        })?;
        if ev.verdict != rk_verdict::RK_VERDICT_AUDIT_WOULD_DENY as u8 {
            anyhow::bail!("expected RK_VERDICT_AUDIT_WOULD_DENY, got {}", ev.verdict);
        }
        if ev.rule_id != rule_id || ev.cgroup_id != cg_id {
            anyhow::bail!("audit header mismatch: {ev:?}");
        }
        Ok("audit profile allowed open and reported audit-would-deny".into())
    });

    run_test(checks, "file_reload_atomic", || {
        drain_ringbuf(&mut ring)?;
        let drops_start = get_counter(&ebpf, rk_counter::RK_CNT_RINGBUF_DROP)?;

        let mut deny_gens = HashSet::new();
        deny_gens.insert(engine.generation());

        let current_exe = std::env::current_exe().context("current_exe")?;
        let procs = "/sys/fs/cgroup/rk.slice/enforce/cgroup.procs";

        let child = Command::new(&current_exe)
            .arg(workloads::CHILD_FLAG)
            .arg(procs)
            .arg("file_reload_workload")
            .arg("/run/rk-test/file_reload_test")
            .arg("2000")
            .arg("500")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn file_reload_workload child")?;
        let child_pid = child.id();

        for i in 0..6 {
            if i % 2 == 0 {
                engine.apply_text(&mut ebpf, POLICY_B)?;
            } else {
                engine.apply_text(&mut ebpf, POLICY_TEXT)?;
                deny_gens.insert(engine.generation());
            }
        }

        let output = wait_with_deadline(child, "file_reload_workload child", CHILD_DEADLINE)?;
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
                "child performed {} opens, expected >= 2000",
                counts.eperm + counts.ok
            );
        }

        // Drain ring buffer
        let rb = &mut ring;
        let mut deny_events = 0u64;
        let drain_start = Instant::now();

        while let Some(item) = rb.next() {
            if drain_start.elapsed() > DRAIN_DEADLINE {
                anyhow::bail!(
                    "ring buffer still producing after {}s while reading file reload events",
                    DRAIN_DEADLINE.as_secs()
                );
            }
            if let Ok(ev) = rk_sensor::decoder::decode(item.as_ref()) {
                if ev.hdr.tgid == child_pid
                    && ev.hdr.type_ == rk_ebpf_common::rk_event_type::RK_EV_FILE_DENY as u16
                {
                    let gen = ev.hdr.policy_gen;
                    let verdict = ev.hdr.verdict;
                    if deny_gens.contains(&gen) {
                        if verdict != rk_verdict::RK_VERDICT_DENY as u8 {
                            anyhow::bail!(
                                "event for deny gen {gen} had non-deny verdict {verdict}"
                            );
                        }
                        deny_events += 1;
                    } else {
                        anyhow::bail!("unexpected deny event under Policy B with gen {gen}");
                    }
                }
            }
        }

        let drops_end = get_counter(&ebpf, rk_counter::RK_CNT_RINGBUF_DROP)?;
        let drops = drops_end.saturating_sub(drops_start);
        if drops > 0 {
            anyhow::bail!("expected zero drops during file reload atomic, got {drops}");
        }

        if counts.eperm != deny_events {
            anyhow::bail!(
                "counts.eperm ({}) != deny_events ({deny_events})",
                counts.eperm
            );
        }

        // Restore POLICY_TEXT
        engine.apply_text(&mut ebpf, POLICY_TEXT)?;

        Ok(format!(
            "2000 opens across 6 policy flips: child observed {} eperm, {} ok; exactly {deny_events} deny events recorded",
            counts.eperm, counts.ok
        ))
    });

    run_test(checks, "file_unbound_sibling_untouched", || {
        drain_ringbuf(&mut ring)?;
        spawn_child(
            "/sys/fs/cgroup/rk.slice/ungoverned-sibling",
            "file_open",
            &["/run/rk-test/file_read_deny", "r", "ok"],
        )?;
        thread::sleep(Duration::from_millis(50));
        if ring.next().is_some() {
            anyhow::bail!("unexpected event emitted for unbound sibling file access");
        }
        Ok("unbound sibling opened protected file successfully without events".into())
    });

    // Drop ring and rk.bpf.o instance before loading rk_emitfail.bpf.o
    drop(ring);
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

        // Kept alive for the whole run: a stale heartbeat denies every
        // governed ENFORCE action (docs/design/phase-6.md §4).
        let _heartbeat =
            rk_sensor::resilience::Heartbeat::start(&mut ebpf_fail, HARNESS_HEARTBEAT)?;
        rk_sensor::policy::attach_all(&mut ebpf_fail, cgroup_slice)?;
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
        let mut rb = rk_sensor::consumer::take_ring(&mut ebpf_fail)?;
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
fn drain_ringbuf(rb: &mut RingBuf<MapData>) -> Result<()> {
    let start = Instant::now();
    let mut records = 0u64;
    while rb.next().is_some() {
        records += 1;
        if start.elapsed() > DRAIN_DEADLINE {
            anyhow::bail!(
                "ring buffer never emptied: {records} records in {}s, so something governed is emitting continuously",
                DRAIN_DEADLINE.as_secs()
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct CapturedExecEvent {
    verdict: u8,
    rule_id: u32,
    cgroup_id: u64,
    #[allow(dead_code)]
    policy_gen: u64,
    flags: u32,
    filename: String,
    argv: Vec<String>,
}

#[cfg(target_os = "linux")]
fn poll_exec_event<F>(
    rb: &mut RingBuf<MapData>,
    timeout: Duration,
    predicate: F,
) -> Result<CapturedExecEvent>
where
    F: Fn(&CapturedExecEvent) -> bool,
{
    let start = Instant::now();
    let mut records = 0u64;
    while start.elapsed() < timeout {
        while let Some(item) = rb.next() {
            records += 1;
            if start.elapsed() > DRAIN_DEADLINE {
                anyhow::bail!("timed out after {records} records while waiting for exec event");
            }
            if let Ok(ev) = rk_sensor::decoder::decode(item.as_ref()) {
                if ev.hdr.type_ == rk_ebpf_common::rk_event_type::RK_EV_EXEC as u16 {
                    if let Payload::Exec { body, mut strings } = ev.payload {
                        let filename = strings
                            .next()
                            .and_then(|b| std::str::from_utf8(b).ok())
                            .unwrap_or_default()
                            .to_string();
                        let argv = strings
                            .next()
                            .map(|blob| {
                                blob.split(|&b| b == 0)
                                    .filter(|s| !s.is_empty())
                                    .filter_map(|s| std::str::from_utf8(s).ok().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let cap = CapturedExecEvent {
                            verdict: ev.hdr.verdict,
                            rule_id: ev.hdr.rule_id,
                            cgroup_id: ev.hdr.cgroup_id,
                            policy_gen: ev.hdr.policy_gen,
                            flags: body.flags,
                            filename,
                            argv,
                        };
                        if predicate(&cap) {
                            return Ok(cap);
                        }
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    anyhow::bail!(
        "timeout waiting for matching exec event after {:.2}s ({records} records seen)",
        timeout.as_secs_f32()
    );
}

const RK_FILE_READ: u32 = 1;
const RK_FILE_WRITE: u32 = 2;
const RK_FILE_CREATE: u32 = 8;
const RK_FILE_DELETE: u32 = 16;
const RK_FILE_RENAME: u32 = 32;
const RK_FILE_TRUNCATE: u32 = 64;
const RK_FILE_LINK: u32 = 128;
const RK_FILE_SETATTR: u32 = 256;

const RK_FILE_HOOK_OPEN: u16 = 1;
const RK_FILE_HOOK_UNLINK: u16 = 2;
const RK_FILE_HOOK_RENAME: u16 = 3;
const RK_FILE_HOOK_LINK: u16 = 4;
const RK_FILE_HOOK_CREATE: u16 = 5;
const RK_FILE_HOOK_SETATTR: u16 = 6;

const RK_FILE_EV_SUBTREE: u8 = 1;
const RK_FILE_EV_DEPTH_EXCEEDED: u8 = 2;

#[derive(Debug, Clone)]
struct CapturedFileEvent {
    verdict: u8,
    rule_id: u32,
    cgroup_id: u64,
    #[allow(dead_code)]
    policy_gen: u64,
    file_dev: u64,
    file_ino: u64,
    access: u32,
    hook: u16,
    flags: u8,
    #[allow(dead_code)]
    path: String,
}

#[cfg(target_os = "linux")]
fn poll_file_event<F>(
    rb: &mut RingBuf<MapData>,
    timeout: Duration,
    predicate: F,
) -> Result<CapturedFileEvent>
where
    F: Fn(&CapturedFileEvent) -> bool,
{
    let start = Instant::now();
    let mut records = 0u64;
    while start.elapsed() < timeout {
        while let Some(item) = rb.next() {
            records += 1;
            if start.elapsed() > DRAIN_DEADLINE {
                anyhow::bail!("timed out after {records} records while waiting for file event");
            }
            if let Ok(ev) = rk_sensor::decoder::decode(item.as_ref()) {
                if ev.hdr.type_ == rk_ebpf_common::rk_event_type::RK_EV_FILE_DENY as u16 {
                    if let Payload::FileDeny { body, mut strings } = ev.payload {
                        let path = strings
                            .next()
                            .and_then(|b| std::str::from_utf8(b).ok())
                            .unwrap_or_default()
                            .to_string();
                        let cap = CapturedFileEvent {
                            verdict: ev.hdr.verdict,
                            rule_id: ev.hdr.rule_id,
                            cgroup_id: ev.hdr.cgroup_id,
                            policy_gen: ev.hdr.policy_gen,
                            file_dev: body.file_dev,
                            file_ino: body.file_ino,
                            access: body.access,
                            hook: body.hook,
                            flags: body.flags,
                            path,
                        };
                        if predicate(&cap) {
                            return Ok(cap);
                        }
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    anyhow::bail!(
        "timeout waiting for matching file event after {:.2}s ({records} records seen)",
        timeout.as_secs_f32()
    );
}

#[cfg(target_os = "linux")]
fn file_rule_id(
    engine: &rk_sensor::policy::PolicyEngine,
    profile: &str,
    path: &str,
) -> Result<u32> {
    engine
        .policy()
        .and_then(|p| {
            p.origins
                .iter()
                .find(|o| o.profile == profile && o.origin.contains(path))
                .map(|o| o.id)
        })
        .with_context(|| format!("file rule for {path} in profile {profile} not found"))
}

#[cfg(target_os = "linux")]
fn file_identity(path: &str) -> Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(path).with_context(|| format!("stat {path}"))?;
    Ok((meta.dev(), meta.ino()))
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
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "exec_cmd",
        &["eperm", "/run/rk-test/unlisted_bin"],
    )?;
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "exec_cmd",
        &["ok", "/bin/true"],
    )?;
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "memfd_exec",
        &["eperm", "/bin/true"],
    )?;
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "file_open",
        &["/run/rk-test/file_read_deny", "r", "eperm"],
    )?;
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "file_open",
        &["/run/rk-test/file_write_deny", "w", "eperm"],
    )?;
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "file_truncate",
        &["/run/rk-test/file_truncate_deny", "eperm"],
    )?;
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "file_chmod",
        &["/run/rk-test/file_chmod_deny", "eperm"],
    )?;
    spawn_child(
        "/sys/fs/cgroup/rk.slice/enforce",
        "file_open",
        &[
            "/run/rk-test/subtree_dir/nested/deep/file.txt",
            "r",
            "eperm",
        ],
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_test<F>(checks: &mut Vec<TestCheck>, name: &'static str, f: F)
where
    F: FnOnce() -> Result<String>,
{
    progress!("START {name}");
    let start = Instant::now();
    let check = match f() {
        Ok(detail) => TestCheck::pass(name, detail),
        Err(e) => TestCheck::fail(name, format!("{e:#}")),
    };
    progress!(
        "{} {name} ({:.1}s)",
        if check.passed { "PASS" } else { "FAIL" },
        start.elapsed().as_secs_f64()
    );
    checks.push(check);
}

/// Waits for `child`, killing it if it outlives `deadline`. Child output is
/// small, so collecting it after exit cannot block on a full pipe.
#[cfg(target_os = "linux")]
fn wait_with_deadline(mut child: Child, what: &str, deadline: Duration) -> Result<Output> {
    let start = Instant::now();
    loop {
        if child.try_wait().context("poll child")?.is_some() {
            return child.wait_with_output().context("collect child output");
        }
        if start.elapsed() > deadline {
            let _ = child.kill();
            let stderr = child
                .wait_with_output()
                .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_string())
                .unwrap_or_default();
            anyhow::bail!(
                "{what} did not exit within {}s and was killed; stderr: {stderr}",
                deadline.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(20));
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

    let child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn child process")?;
    let output = wait_with_deadline(
        child,
        &format!("child workload '{workload}'"),
        CHILD_DEADLINE,
    )?;
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
    let _ = fs::create_dir_all("/sys/fs/cgroup/rk.slice/unlinked");
    let _ = fs::create_dir_all("/sys/fs/cgroup/rk.slice/ungoverned-sibling");
    let _ = fs::create_dir_all("/sys/fs/cgroup/ungoverned");

    // Prepare test directory and binaries for exec policy tests
    let test_dir = Path::new("/run/rk-test");
    let _ = fs::create_dir_all(test_dir);
    let _ = Command::new("mount")
        .args(["-t", "tmpfs", "-o", "exec", "tmpfs", "/run/rk-test"])
        .status();

    let _ = fs::copy("/bin/true", "/run/rk-test/unlisted_bin");
    let _ = fs::copy("/bin/true", "/run/rk-test/symlink_target_bin");
    let _ = fs::copy("/bin/true", "/run/rk-test/replaced_bin");
    let _ = fs::copy("/bin/true", "/run/rk-test/reload_bin");
    let _ = fs::copy("/bin/sh", "/run/rk-test/unlisted_interp");

    let _ = fs::remove_file("/run/rk-test/symlink_bin");
    let _ = std::os::unix::fs::symlink(
        "/run/rk-test/symlink_target_bin",
        "/run/rk-test/symlink_bin",
    );

    let _ = fs::write("/run/rk-test/allowed_script.sh", "#!/bin/sh\nexit 0\n");
    let _ = fs::write("/run/rk-test/unlisted_script.sh", "#!/bin/sh\nexit 0\n");
    let _ = fs::write(
        "/run/rk-test/denied_interp_script.sh",
        "#!/run/rk-test/unlisted_interp\nexit 0\n",
    );

    // Prepare files and directories for file policy tests (Phase 4)
    let plain_files = [
        "file_read_deny",
        "file_write_deny",
        "file_openat2_deny",
        "file_io_uring_deny",
        "file_o_trunc_deny",
        "file_truncate_deny",
        "file_ftruncate_deny",
        "file_unlink_deny",
        "file_rename_src_deny",
        "file_rename_replace_deny",
        "file_rename_exchange_a",
        "file_rename_exchange_b",
        "file_rename_src_allowed",
        "file_link_deny",
        "file_chmod_deny",
        "file_hardlink_base",
        "file_bind_base",
        "file_bind_alias",
        "file_symlink_base",
        "file_proc_fd_base",
        "file_relative_base",
        "file_reload_test",
        "audit_file_deny",
    ];
    for f in &plain_files {
        let p = format!("/run/rk-test/{f}");
        let _ = fs::write(&p, "test file data\n");
    }

    let _ = fs::create_dir_all("/run/rk-test/file_unlinkat_dir_deny");
    let _ = fs::create_dir_all("/run/rk-test/dir_create_deny");

    let _ = fs::remove_file("/run/rk-test/file_hardlink_alias");
    let _ = fs::hard_link(
        "/run/rk-test/file_hardlink_base",
        "/run/rk-test/file_hardlink_alias",
    );

    let _ = fs::remove_file("/run/rk-test/file_symlink_alias");
    let _ = std::os::unix::fs::symlink(
        "/run/rk-test/file_symlink_base",
        "/run/rk-test/file_symlink_alias",
    );

    let _ = Command::new("mount")
        .args([
            "--bind",
            "/run/rk-test/file_bind_base",
            "/run/rk-test/file_bind_alias",
        ])
        .status();

    let _ = fs::create_dir_all("/run/rk-test/subtree_dir/nested/deep");
    let _ = fs::write(
        "/run/rk-test/subtree_dir/nested/deep/file.txt",
        "subtree content\n",
    );

    let mut deep_path = std::path::PathBuf::from("/run/rk-test/deep");
    for i in 1..=35 {
        deep_path.push(format!("d{i}"));
    }
    let _ = fs::create_dir_all(&deep_path);
    let deep_file = deep_path.join("file.txt");
    let _ = fs::write(&deep_file, "deep nested content\n");

    if let Ok(entries) = fs::read_dir(test_dir) {
        for entry in entries.flatten() {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o755);
                    let _ = fs::set_permissions(entry.path(), perms);
                }
            }
        }
    }

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
