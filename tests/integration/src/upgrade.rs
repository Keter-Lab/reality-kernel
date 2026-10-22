//! Phase 10 upgrade suite (docs/design/phase-10.md §7).
//!
//! Two sensors whose embedded objects differ (`rk-sensor` and
//! `rk-sensor-next`, built from `rk-bpf/build/<arch>-next`) replace each other
//! while a governed child keeps trying actions the policy denies. Any success
//! is a protection gap. A negative control proves the probe does see a gap
//! when there is one, and `rk doctor` must pass on every supported kernel.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use serde_json::Value;

use crate::resilience::is_socket_ready;
use crate::{run_test, TestCheck};

pub const SUITE_FLAG: &str = "--upgrade-suite";

const DIR: &str = "/run/rk-upgrade";
const FIXTURES: &str = "/run/rk-upgrade/fixtures";
const POLICY: &str = "/run/rk-upgrade/policy.toml";
const STATE: &str = "/run/rk-upgrade/engine-state.json";
const AUDIT_DIR: &str = "/run/rk-upgrade/audit";
const KEY: &str = "/run/rk-upgrade/audit.key";
const SOCKET: &str = "/run/rk/agentd.sock";
const PIN_ROOT: &str = "/sys/fs/bpf/rk";
const CGROUP: &str = "/sys/fs/cgroup/rk.slice/up-enforce";
const DENY_TARGET: &str = "10.99.0.1:80";

fn blocked() -> String {
    format!("{FIXTURES}/blocked")
}

fn log_path(tag: &str) -> PathBuf {
    PathBuf::from(format!("{DIR}/daemon-{tag}.log"))
}

fn policy_text(lsm: bool) -> String {
    let raw = if lsm { "" } else { "network.deny_raw_sockets = false\n" };
    let mut p = format!(
        r#"
[profiles.up-enforce]
mode = "enforce"
network.default = "allow"
{raw}
[[profiles.up-enforce.network.deny]]
cidr = "10.99.0.1/32"
proto = ["udp", "tcp"]

[[bindings]]
cgroup = "rk.slice/up-enforce"
profile = "up-enforce"
"#
    );
    if lsm {
        p.push_str("\n[profiles.up-enforce.exec]\ndefault = \"deny\"\nallow = []\n");
    }
    p
}

fn prepare(lsm: bool) -> Result<()> {
    let _ = fs::remove_dir_all(DIR);
    fs::create_dir_all(FIXTURES)?;
    let _ = Command::new("mount")
        .args(["-t", "tmpfs", "-o", "exec,mode=755", "tmpfs", FIXTURES])
        .stderr(Stdio::null())
        .status();
    fs::copy("/bin/true", blocked())?;
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(blocked(), fs::Permissions::from_mode(0o755))?;
    }
    fs::create_dir_all(CGROUP)?;
    for args in [
        &["link", "set", "lo", "up"][..],
        &["addr", "add", "10.99.0.1/24", "dev", "lo"][..],
    ] {
        let _ = Command::new("ip").args(args).stderr(Stdio::null()).status();
    }
    fs::write(POLICY, policy_text(lsm))?;
    Ok(())
}

struct Daemon {
    child: Child,
    log: PathBuf,
}

impl Daemon {
    fn start(sensor: &Path, tag: &str) -> Result<Self> {
        let _ = fs::remove_file(SOCKET);
        let log = log_path(tag);
        let out = File::create(&log)?;
        let child = Command::new(sensor)
            .args([
                "--policy",
                POLICY,
                "--state-file",
                STATE,
                "--audit-dir",
                AUDIT_DIR,
                "--audit-key",
                KEY,
                "--metrics-addr",
                "off",
            ])
            .stdin(Stdio::null())
            .stdout(out.try_clone()?)
            .stderr(out)
            .spawn()
            .with_context(|| format!("spawn {}", sensor.display()))?;
        let mut d = Self { child, log };
        let start = Instant::now();
        loop {
            if let Some(st) = d.child.try_wait()? {
                bail!("{} exited early ({st}): {}", sensor.display(), d.tail());
            }
            if is_socket_ready(SOCKET) {
                return Ok(d);
            }
            if start.elapsed() > Duration::from_secs(30) {
                bail!("{} not ready after 30s: {}", sensor.display(), d.tail());
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn tail(&self) -> String {
        let text = fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        lines[lines.len().saturating_sub(20)..].join("\n")
    }

    fn text(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// SIGTERM: pins are kept, so enforcement continues without the sensor.
    fn stop(&mut self) -> Result<()> {
        if self.child.try_wait()?.is_some() {
            return Ok(());
        }
        // SAFETY: plain kill(2) on our own child.
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            if self.child.try_wait()?.is_some() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        bail!("sensor did not stop on SIGTERM: {}", self.tail())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Starts the gap probe in the governed cgroup for `ms` milliseconds.
fn start_probe(ms: u64, lsm: bool) -> Result<Child> {
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.arg(crate::workloads::CHILD_FLAG)
        .arg(format!("{CGROUP}/cgroup.procs"))
        .arg("gap_probe")
        .arg(DENY_TARGET)
        .arg(ms.to_string());
    if lsm {
        cmd.arg(blocked());
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn gap probe")
}

fn probe_result(child: Child) -> Result<Value> {
    let out = crate::wait_with_deadline(child, "gap probe", Duration::from_secs(60))?;
    ensure!(
        out.status.success(),
        "gap probe failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
    serde_json::from_str(&line).with_context(|| format!("gap probe output: {line}"))
}

fn count(v: &Value, key: &str) -> u64 {
    v[key].as_u64().unwrap_or(0)
}

fn rk_cli(rk: &Path, args: &[&str]) -> Result<(i32, String)> {
    let out = Command::new(rk).args(args).output().context("run rk")?;
    Ok((
        out.status.code().unwrap_or(-1),
        format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)),
    ))
}

pub fn run_suite(args: &[String], checks: &mut Vec<TestCheck>) {
    let [sensor, next, rk] = args else {
        checks.push(TestCheck::fail(
            "upgrade_suite_args",
            format!("usage: {SUITE_FLAG} <rk-sensor> <rk-sensor-next> <rk>, got {args:?}"),
        ));
        return;
    };
    let (sensor, next, rk) = (PathBuf::from(sensor), PathBuf::from(next), PathBuf::from(rk));
    let lsm = rk_sensor::policy::bpf_lsm_active();
    let _ = Command::new(&sensor).arg("--uninstall").status();
    if let Err(e) = prepare(lsm) {
        checks.push(TestCheck::fail("upgrade_setup", format!("{e:#}")));
        return;
    }

    run_test(checks, "upgrade_replaces_object_without_gap", || {
        let mut a = Daemon::start(&sensor, "a")?;
        // Long enough to cover both switches (each: a 2 s stop, then load,
        // attach and migrate) with margin after the second.
        let probe = start_probe(20_000, lsm)?;
        thread::sleep(Duration::from_millis(1500));

        // Upgrade: A -> B (different object).
        a.stop()?;
        let mut b = Daemon::start(&next, "b")?;
        let b_log = b.text();
        ensure!(
            b_log.contains("replaced the running object without a gap"),
            "upgrade did not take the replace path: {}",
            b.tail()
        );
        ensure!(
            b_log.contains("the replaced pin set's state"),
            "policy was not carried over from the old pin set's state: {}",
            b.tail()
        );
        ensure!(Path::new(PIN_ROOT).exists() && !Path::new(&format!("{PIN_ROOT}.next")).exists());
        thread::sleep(Duration::from_millis(4000));

        // Downgrade: B -> A, the same path in the other direction.
        b.stop()?;
        let mut a2 = Daemon::start(&sensor, "a2")?;
        ensure!(
            a2.text().contains("replaced the running object without a gap"),
            "downgrade did not take the replace path: {}",
            a2.tail()
        );

        let result = probe_result(probe)?;
        a2.stop()?;
        let (net_tries, net_ok) = (count(&result, "net_tries"), count(&result, "net_ok"));
        let (exec_tries, exec_ok) = (count(&result, "exec_tries"), count(&result, "exec_ok"));
        ensure!(net_ok == 0, "{net_ok} of {net_tries} denied connects got through during the upgrade: {result}");
        ensure!(exec_ok == 0, "{exec_ok} of {exec_tries} denied execs got through during the upgrade: {result}");
        ensure!(net_tries >= 1000, "probe made only {net_tries} attempts: the window was not covered");
        if lsm {
            ensure!(exec_tries >= 10, "probe made only {exec_tries} exec attempts");
        }

        // The audit chain continues across both replacements.
        let pubkey = format!("{KEY}.pub");
        let (code, out) = rk_cli(&rk, &["audit", "verify", "--dir", AUDIT_DIR, "--pubkey", pubkey.as_str()])?;
        ensure!(code == 0, "audit log does not verify across the upgrade ({code}): {out}");
        Ok(format!(
            "upgrade and downgrade replaced the object; 0 of {net_tries} connects and 0 of {exec_tries} execs got through; audit chain verified"
        ))
    });

    run_test(checks, "upgrade_gap_detector_works", || {
        // No sensor; the pins still enforce. Removing them mid-probe opens a
        // real gap, which the probe must report.
        let probe = start_probe(3000, false)?;
        thread::sleep(Duration::from_millis(1000));
        let st = Command::new(&sensor).arg("--uninstall").status()?;
        ensure!(st.success(), "rk-sensor --uninstall failed");
        let result = probe_result(probe)?;
        let net_ok = count(&result, "net_ok");
        ensure!(net_ok > 0, "probe saw no successes after protection was removed: {result}");
        Ok(format!("probe reported {net_ok} connects after the pins were removed"))
    });

    run_test(checks, "doctor_passes_on_supported_kernels", || {
        let (code, out) = rk_cli(&rk, &["doctor", "--json"])?;
        let report: Value = serde_json::from_str(&out).with_context(|| format!("rk doctor --json: {out}"))?;
        let failed: Vec<String> = report["checks"]
            .as_array()
            .context("no checks in the doctor report")?
            .iter()
            .filter(|c| c["status"] == "fail")
            .map(|c| format!("{}: {}", c["name"], c["detail"]))
            .collect();
        ensure!(code == 0 && failed.is_empty(), "rk doctor failed ({code}): {failed:?}");
        let lsm_check = report["checks"]
            .as_array()
            .and_then(|a| a.iter().find(|c| c["name"] == "bpf_lsm"))
            .context("no bpf_lsm check")?;
        ensure!(
            (lsm_check["status"] == "ok") == lsm,
            "doctor's bpf_lsm check ({}) disagrees with the kernel ({lsm})",
            lsm_check["status"]
        );
        Ok(format!("rk doctor: no failed check; bpf_lsm {}", lsm_check["status"]))
    });

    let _ = Command::new(&sensor).arg("--uninstall").status();
}
