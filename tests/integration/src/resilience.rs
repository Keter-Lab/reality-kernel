//! Phase 6 resilience suite (docs/design/phase-6.md §8).
//!
//! Validates daemon resilience, adoption of pinned links/maps across restarts,
//! fail-closed heartbeat enforcement, and kernel self-protection guard hooks.

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use aya::maps::{Array, Map, MapData};
use rk_ebpf_common::rk_meta;
use serde_json::Value;

use crate::{run_test, wait_with_deadline, TestCheck, CHILD_DEADLINE};

pub const SUITE_FLAG: &str = "--resilience-suite";

const DIR: &str = "/run/rk-resilience-test";
const POLICY_FILE: &str = "/run/rk-resilience-test/policy.toml";
const DAEMON_LOG: &str = "/run/rk-resilience-test/daemon.log";
const SOCKET: &str = "/run/rk/agentd.sock";
const PIN_ROOT: &str = "/sys/fs/bpf/rk";
const META_PIN: &str = "/sys/fs/bpf/rk/maps/rk_meta";

const ENFORCE_CGROUP: &str = "/sys/fs/cgroup/rk.slice/enforce/cgroup.procs";
const AUDIT_CGROUP: &str = "/sys/fs/cgroup/rk.slice/audit/cgroup.procs";
const UNGOVERNED_CGROUP: &str = "/sys/fs/cgroup/rk.slice/ungoverned-sibling/cgroup.procs";

const DENY_ADDR: &str = "10.99.0.1:80";
const ALLOW_ADDR: &str = "10.99.0.2:80";

fn policy_text() -> String {
    r#"
[profiles.enforce]
mode = "enforce"
network.default = "deny"

[[profiles.enforce.network.allow]]
cidr = "10.99.0.2/32"
proto = ["tcp", "udp"]

[[profiles.enforce.network.allow]]
cidr = "127.0.0.1/32"
proto = ["tcp", "udp"]

[[profiles.enforce.network.deny]]
cidr = "10.99.0.1/32"
proto = ["tcp", "udp"]

[profiles.audit]
mode = "audit"
network.default = "allow"

[[profiles.audit.network.deny]]
cidr = "10.99.0.1/32"
proto = ["tcp", "udp"]

[[bindings]]
cgroup = "rk.slice/enforce"
profile = "enforce"

[[bindings]]
cgroup = "rk.slice/audit"
profile = "audit"
"#
    .to_string()
}

#[derive(Clone, Copy)]
#[repr(transparent)]
struct MetaPod(rk_meta);
// SAFETY: rk_meta is a bindgen Pod (no padding, any bit pattern valid).
unsafe impl aya::Pod for MetaPod {}

fn prepare() -> Result<()> {
    fs::create_dir_all(DIR)?;
    fs::create_dir_all("/sys/fs/cgroup/rk.slice/enforce")?;
    fs::create_dir_all("/sys/fs/cgroup/rk.slice/audit")?;
    fs::create_dir_all("/sys/fs/cgroup/rk.slice/ungoverned-sibling")?;

    for addr in ["10.99.0.1/24", "10.99.0.2/24"] {
        let _ = Command::new("ip")
            .args(["addr", "add", addr, "dev", "lo"])
            .stderr(Stdio::null())
            .status();
    }

    fs::write(POLICY_FILE, policy_text()).context("write policy file")?;
    let _ = fs::remove_file(DAEMON_LOG);
    Ok(())
}

fn log_tail() -> String {
    let log = fs::read_to_string(DAEMON_LOG).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    lines[lines.len().saturating_sub(20)..].join("\n")
}

struct ResilienceDaemon {
    child: Child,
    sensor: PathBuf,
}

impl ResilienceDaemon {
    fn start(sensor: &Path, heartbeat_secs: u64) -> Result<Self> {
        let _ = fs::remove_file(SOCKET);
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(DAEMON_LOG)
            .context("open daemon log")?;
        let child = Command::new(sensor)
            .args([
                "--policy",
                POLICY_FILE,
                "--heartbeat-timeout",
                &heartbeat_secs.to_string(),
            ])
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()
            .context("spawn rk-sensor")?;
        let mut daemon = Self {
            child,
            sensor: sensor.to_path_buf(),
        };
        let start = Instant::now();
        loop {
            if let Some(st) = daemon.child.try_wait()? {
                bail!("rk-sensor exited early ({st}): {}", log_tail());
            }
            if Path::new(SOCKET).exists() && Path::new(META_PIN).exists() {
                if std::os::unix::net::UnixStream::connect(SOCKET).is_ok() {
                    return Ok(daemon);
                }
            }
            if start.elapsed() > Duration::from_secs(30) {
                bail!("rk-sensor not ready after 30s: {}", log_tail());
            }
            thread::sleep(Duration::from_millis(200));
        }
    }

    fn pid(&self) -> i32 {
        self.child.id() as i32
    }

    fn kill_sigkill(&mut self) -> Result<()> {
        unsafe {
            libc::kill(self.pid(), libc::SIGKILL);
        }
        let _ = self.child.wait();
        Ok(())
    }

    fn stop_cleanly(&mut self) -> Result<()> {
        unsafe {
            libc::kill(self.pid(), libc::SIGTERM);
        }
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        Ok(())
    }
}

impl Drop for ResilienceDaemon {
    fn drop(&mut self) {
        let _ = self.stop_cleanly();
    }
}

fn run_workload(cgroup_procs: &str, workload: &str, args: &[&str]) -> Result<Output> {
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.arg(crate::workloads::CHILD_FLAG)
        .arg(cgroup_procs)
        .arg(workload);
    for a in args {
        cmd.arg(a);
    }
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn child workload")?;
    wait_with_deadline(
        child,
        &format!("child workload '{workload}'"),
        CHILD_DEADLINE,
    )
}

fn run_workload_ok(cgroup_procs: &str, workload: &str, args: &[&str]) -> Result<String> {
    let out = run_workload(cgroup_procs, workload, args)?;
    if !out.status.success() {
        bail!(
            "workload {workload} failed (exit {:?}): stdout: {}, stderr: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn get_link_ids(bpftool: &Path) -> Result<Vec<u64>> {
    let out = Command::new(bpftool)
        .args(["-j", "link", "list"])
        .output()
        .context("run bpftool -j link list")?;
    if !out.status.success() {
        bail!(
            "bpftool link list failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let val: Value = serde_json::from_slice(&out.stdout).context("parse bpftool link list json")?;
    let mut ids = Vec::new();
    if let Some(arr) = val.as_array() {
        for item in arr {
            if let Some(id) = item["id"].as_u64() {
                ids.push(id);
            }
        }
    }
    ids.sort_unstable();
    Ok(ids)
}

fn read_generation() -> Result<u64> {
    let start = Instant::now();
    loop {
        if let Ok(text) = fs::read_to_string("/run/rk/engine-state.json") {
            if let Ok(val) = serde_json::from_str::<Value>(&text) {
                if let Some(gen) = val["generation"].as_u64() {
                    return Ok(gen);
                }
            }
        }
        if start.elapsed() > Duration::from_secs(5) {
            bail!("timeout waiting to read generation from /run/rk/engine-state.json");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn logged_events() -> Result<Vec<Value>> {
    let log = fs::read_to_string(DAEMON_LOG).context("read daemon log")?;
    Ok(log
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|v| v.get("fields").cloned())
        .filter(|f| f["message"] == "event")
        .collect())
}

fn wait_for_heartbeat_deny() -> Result<()> {
    let start = Instant::now();
    loop {
        if let Ok(events) = logged_events() {
            for e in &events {
                let rule_id = e["rule_id"].as_u64();
                if rule_id == Some(4294967295) || rule_id == Some(u32::MAX as u64) {
                    return Ok(());
                }
            }
        }
        if start.elapsed() > Duration::from_secs(10) {
            bail!("timed out waiting for RK_RULE_HEARTBEAT (4294967295) in daemon log");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn corrupt_meta_pin() -> Result<()> {
    let data = MapData::from_pin(META_PIN).context("from_pin rk_meta")?;
    let mut array: Array<MapData, MetaPod> =
        Array::try_from(Map::Array(data)).context("Array::try_from rk_meta")?;
    let mut meta = array.get(&0, 0).context("read rk_meta")?;
    meta.0.object_sha256[0] ^= 0xff;
    array.set(0, meta, 0).context("write corrupted rk_meta")?;
    Ok(())
}

pub fn run_suite(args: &[String], checks: &mut Vec<TestCheck>) {
    let [sensor_str, bpftool_str] = args else {
        checks.push(TestCheck::fail(
            "resilience_suite_args",
            format!("usage: {SUITE_FLAG} <rk-sensor> <bpftool>, got {args:?}"),
        ));
        return;
    };
    let sensor = Path::new(sensor_str);
    let bpftool = Path::new(bpftool_str);

    if let Err(e) = prepare() {
        checks.push(TestCheck::fail("resilience_setup", format!("{e:#}")));
        return;
    }

    // Ensure pins from any previous suite are cleanly cleared
    let _ = Command::new(sensor).arg("--uninstall").status();

    let mut daemon = match ResilienceDaemon::start(sensor, 3) {
        Ok(d) => d,
        Err(e) => {
            checks.push(TestCheck::fail("resilience_daemon_start", format!("{e:#}")));
            return;
        }
    };

    // 1. sensor_kill_keeps_enforcement
    run_test(checks, "sensor_kill_keeps_enforcement", || {
        // Confirm baseline enforcement while daemon runs
        run_workload_ok(ENFORCE_CGROUP, "udp_connect", &[DENY_ADDR, "eperm"])?;
        run_workload_ok(ENFORCE_CGROUP, "udp_connect", &[ALLOW_ADDR, "ok"])?;

        // SIGKILL the daemon
        daemon.kill_sigkill()?;

        // Inside the 3-second heartbeat timeout, enforcement persists
        run_workload_ok(ENFORCE_CGROUP, "udp_connect", &[DENY_ADDR, "eperm"])?;
        run_workload_ok(ENFORCE_CGROUP, "udp_connect", &[ALLOW_ADDR, "ok"])?;
        Ok("enforcement persisted after SIGKILL inside timeout".to_string())
    });

    // 2. sensor_restart_adopts_pins
    run_test(checks, "sensor_restart_adopts_pins", || {
        // Restart daemon to adopt the pins
        daemon = ResilienceDaemon::start(sensor, 3)?;
        let links_before = get_link_ids(bpftool)?;
        if links_before.is_empty() {
            bail!("no links found attached by sensor before restart");
        }
        let gen_before = read_generation()?;

        // Spawn paced workload in background connecting to denied address across restart
        let mut paced_cmd = Command::new(std::env::current_exe()?);
        paced_cmd.args([
            crate::workloads::CHILD_FLAG,
            ENFORCE_CGROUP,
            "paced_workload",
            "udp_connect",
            DENY_ADDR,
            "300",
            "5000",
        ]);
        paced_cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        let paced_child = paced_cmd.spawn().context("spawn paced workload")?;

        // Restart daemon while workload is actively sending
        daemon.stop_cleanly()?;
        daemon = ResilienceDaemon::start(sensor, 3)?;

        let paced_out = wait_with_deadline(paced_child, "paced workload", Duration::from_secs(15))?;
        if !paced_out.status.success() {
            bail!(
                "paced workload failed: {}",
                String::from_utf8_lossy(&paced_out.stderr).trim()
            );
        }
        let stats: Value =
            serde_json::from_slice(&paced_out.stdout).context("parse paced workload stats")?;
        let ok = stats["ok"].as_u64().unwrap_or(1);
        let eperm = stats["eperm"].as_u64().unwrap_or(0);
        if ok != 0 || eperm == 0 {
            bail!("paced workload saw {ok} allowed connects across restart, {eperm} eperm");
        }

        let links_after = get_link_ids(bpftool)?;
        if links_before != links_after {
            bail!(
                "link ids changed across restart: before {links_before:?}, after {links_after:?}"
            );
        }

        let gen_after = read_generation()?;
        if gen_after <= gen_before {
            bail!(
                "generation did not increase across restart: before {gen_before}, after {gen_after}"
            );
        }
        Ok(format!(
            "links preserved ({links_after:?}), gen increased ({gen_before} -> {gen_after}), \
             paced workload: eperm={eperm}, ok={ok}"
        ))
    });

    // 3. heartbeat_stale_denies_enforce
    run_test(checks, "heartbeat_stale_denies_enforce", || {
        // Stop daemon and wait past the 3s timeout
        daemon.kill_sigkill()?;
        thread::sleep(Duration::from_secs(4));

        // In ENFORCE mode, allowed connects must now fail closed with EPERM
        run_workload_ok(ENFORCE_CGROUP, "udp_connect", &[ALLOW_ADDR, "eperm"])?;

        // In AUDIT mode, workload is unaffected
        run_workload_ok(AUDIT_CGROUP, "udp_connect", &[ALLOW_ADDR, "ok"])?;

        // Restart daemon to drain ringbuffer and log events
        daemon = ResilienceDaemon::start(sensor, 3)?;
        wait_for_heartbeat_deny()?;
        Ok("stale heartbeat denied enforce with RK_RULE_HEARTBEAT; audit unaffected".to_string())
    });

    // 4. heartbeat_recovers_on_restart
    run_test(checks, "heartbeat_recovers_on_restart", || {
        // Once daemon is running with fresh heartbeat, allowed connect works again
        run_workload_ok(ENFORCE_CGROUP, "udp_connect", &[ALLOW_ADDR, "ok"])?;
        Ok("allowed connect succeeded after sensor restart".to_string())
    });

    // 5. guard_bpf_syscall_denied
    run_test(checks, "guard_bpf_syscall_denied", || {
        run_workload_ok(ENFORCE_CGROUP, "guard_bpf", &["eperm"])?;
        run_workload_ok(UNGOVERNED_CGROUP, "guard_bpf", &["ok"])?;
        Ok("bpf() returned EPERM for governed task, succeeded for ungoverned".to_string())
    });

    // 6. guard_signal_sensor_denied
    run_test(checks, "guard_signal_sensor_denied", || {
        let pid_str = daemon.pid().to_string();
        run_workload_ok(ENFORCE_CGROUP, "guard_signal", &[&pid_str, "eperm"])?;
        run_workload_ok(UNGOVERNED_CGROUP, "guard_signal", &[&pid_str, "ok"])?;
        Ok("SIGCONT to sensor returned EPERM for governed task, succeeded for control".to_string())
    });

    // 7. guard_ptrace_sensor_denied
    run_test(checks, "guard_ptrace_sensor_denied", || {
        let pid_str = daemon.pid().to_string();
        run_workload_ok(ENFORCE_CGROUP, "guard_ptrace", &[&pid_str, "eperm"])?;
        run_workload_ok(UNGOVERNED_CGROUP, "guard_ptrace", &[&pid_str, "ok"])?;
        Ok(
            "ptrace and /proc/<pid>/mem returned EPERM for governed task, succeeded for control"
                .to_string(),
        )
    });

    // 8. guard_pins_cannot_be_removed
    run_test(checks, "guard_pins_cannot_be_removed", || {
        run_workload_ok(ENFORCE_CGROUP, "guard_pins", &[])?;
        Ok("unlink, rename, and umount in bpffs returned EPERM for governed task".to_string())
    });

    // 9. pin_dir_restricted
    run_test(checks, "pin_dir_restricted", || {
        let meta = fs::metadata(PIN_ROOT).context("metadata /sys/fs/bpf/rk")?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            bail!("/sys/fs/bpf/rk mode is {:o}, expected 0700", mode);
        }
        if meta.uid() != 0 || meta.gid() != 0 {
            bail!(
                "/sys/fs/bpf/rk owner is {}:{}, expected 0:0",
                meta.uid(),
                meta.gid()
            );
        }
        Ok("pin root /sys/fs/bpf/rk is mode 0700 owned by root".to_string())
    });

    // 10. incompatible_pins_replaced
    run_test(checks, "incompatible_pins_replaced", || {
        daemon.stop_cleanly()?;
        corrupt_meta_pin()?;

        // Clear daemon log to cleanly capture the replacement log line
        let _ = fs::remove_file(DAEMON_LOG);

        daemon = ResilienceDaemon::start(sensor, 3)?;
        let log = fs::read_to_string(DAEMON_LOG).unwrap_or_default();
        if !log.contains("pins were created by a different object: replacing them") {
            bail!("daemon log missing expected pin replacement warning: {log}");
        }
        if !Path::new(META_PIN).exists() {
            bail!("rk_meta pin does not exist after replacement");
        }
        Ok("incompatible pins were replaced with logged warning".to_string())
    });

    // 11. uninstall_removes_protection
    run_test(checks, "uninstall_removes_protection", || {
        daemon.stop_cleanly()?;
        let st = Command::new(sensor)
            .arg("--uninstall")
            .status()
            .context("rk-sensor --uninstall")?;
        if !st.success() {
            bail!("rk-sensor --uninstall failed with {st}");
        }
        if Path::new(PIN_ROOT).exists() {
            bail!("{PIN_ROOT} still exists after --uninstall");
        }
        // Previously denied connect should now succeed
        run_workload_ok(ENFORCE_CGROUP, "udp_connect", &[DENY_ADDR, "ok"])?;
        Ok("uninstall removed pins and unblocked previously denied connects".to_string())
    });

    // Final cleanup
    let _ = Command::new(sensor).arg("--uninstall").status();
}
