//! Phase 9 observability suite (docs/design/phase-9.md §5).
//!
//! Runs the real `rk-sensor` daemon with an audit log and a metrics endpoint,
//! drives known decisions in governed cgroups, and checks that every deny and
//! audit-would-deny reached the signed audit log with its rule id, that the
//! metrics move, and that `rk audit verify` passes the log and catches a
//! flipped byte. A last check loads `rk_emitfail.bpf.o` in-process to prove
//! that lost events are recorded in the log rather than silently missing.

use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use aya::Btf;
use rk_ebpf_common::rk_counter;
use serde_json::Value;

use crate::resilience::{is_socket_ready, run_workload};
use crate::{get_counter, run_test, TestCheck};

pub const SUITE_FLAG: &str = "--observability-suite";

const DIR: &str = "/run/rk-observe";
const FIXTURES: &str = "/run/rk-observe/fixtures";
const POLICY: &str = "/run/rk-observe/policy.toml";
const LOG: &str = "/run/rk-observe/daemon.log";
const AUDIT_DIR: &str = "/run/rk-observe/audit";
const KEY: &str = "/run/rk-observe/audit.key";
const LOSS_DIR: &str = "/run/rk-observe/loss-audit";
const METRICS_ADDR: &str = "127.0.0.1:19464";
const SOCKET: &str = "/run/rk/agentd.sock";

const ENFORCE: &str = "/sys/fs/cgroup/rk.slice/obs-enforce";
const AUDIT: &str = "/sys/fs/cgroup/rk.slice/obs-audit";
const DENY_TARGET: &str = "10.99.0.1:80";

const NET_DENIES: usize = 5;
const NET_AUDITS: usize = 3;
const FILE_DENIES: usize = 2;
const EXEC_DENIES: usize = 2;

fn secret() -> String {
    format!("{FIXTURES}/secret")
}

fn blocked() -> String {
    format!("{FIXTURES}/blocked")
}

fn policy_text(lsm: bool) -> String {
    // Without BPF LSM only network rules are accepted (docs/policy.md).
    let raw = if lsm {
        ""
    } else {
        "network.deny_raw_sockets = false\n"
    };
    let mut p = format!(
        r#"
[profiles.obs-enforce]
mode = "enforce"
network.default = "allow"
{raw}
[[profiles.obs-enforce.network.deny]]
cidr = "10.99.0.1/32"
proto = ["udp"]

[profiles.obs-audit]
mode = "audit"
network.default = "allow"
{raw}
[[profiles.obs-audit.network.deny]]
cidr = "10.99.0.1/32"
proto = ["udp"]

[[bindings]]
cgroup = "rk.slice/obs-enforce"
profile = "obs-enforce"

[[bindings]]
cgroup = "rk.slice/obs-audit"
profile = "obs-audit"
"#
    );
    if lsm {
        p.push_str(&format!(
            r#"
[[profiles.obs-enforce.files.deny]]
path = "{}"
access = ["read"]

[profiles.obs-enforce.exec]
default = "deny"
allow = []
"#,
            secret()
        ));
    }
    p
}

fn prepare(lsm: bool) -> Result<()> {
    let _ = fs::remove_dir_all(DIR);
    fs::create_dir_all(FIXTURES)?;
    // Fixtures on a tmpfs that allows exec (/run may be noexec).
    let _ = Command::new("mount")
        .args(["-t", "tmpfs", "-o", "exec,mode=755", "tmpfs", FIXTURES])
        .stderr(Stdio::null())
        .status();
    fs::write(secret(), b"rk")?;
    fs::copy("/bin/true", blocked())?;
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(blocked(), fs::Permissions::from_mode(0o755))?;
    }
    for cg in [ENFORCE, AUDIT] {
        fs::create_dir_all(cg)?;
    }
    for args in [
        &["link", "set", "lo", "up"][..],
        &["addr", "add", "10.99.0.1/24", "dev", "lo"][..],
    ] {
        let _ = Command::new("ip").args(args).stderr(Stdio::null()).status();
    }
    fs::write(POLICY, policy_text(lsm))?;
    Ok(())
}

fn log_tail() -> String {
    let log = fs::read_to_string(LOG).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    lines[lines.len().saturating_sub(20)..].join("\n")
}

struct Daemon {
    child: Child,
}

impl Daemon {
    fn start(sensor: &Path) -> Result<Self> {
        let _ = fs::remove_file(SOCKET);
        let log = File::create(LOG)?;
        let child = Command::new(sensor)
            .args([
                "--policy",
                POLICY,
                "--audit-dir",
                AUDIT_DIR,
                "--audit-key",
                KEY,
                "--metrics-addr",
                METRICS_ADDR,
            ])
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()
            .context("spawn rk-sensor")?;
        let mut d = Self { child };
        let start = Instant::now();
        loop {
            if let Some(st) = d.child.try_wait()? {
                bail!("rk-sensor exited early ({st}): {}", log_tail());
            }
            if is_socket_ready(SOCKET) && TcpStream::connect(METRICS_ADDR).is_ok() {
                return Ok(d);
            }
            if start.elapsed() > Duration::from_secs(30) {
                bail!("rk-sensor not ready after 30s: {}", log_tail());
            }
            thread::sleep(Duration::from_millis(200));
        }
    }

    /// SIGTERM, which drains the pipeline and seals the open audit batch.
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
            thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        bail!("rk-sensor did not stop on SIGTERM: {}", log_tail())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn scrape() -> Result<String> {
    let mut s = TcpStream::connect(METRICS_ADDR).context("connect to the metrics endpoint")?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut out = String::new();
    s.read_to_string(&mut out)?;
    let (head, body) = out.split_once("\r\n\r\n").context("no HTTP body")?;
    ensure!(
        head.starts_with("HTTP/1.1 200"),
        "metrics endpoint answered: {head}"
    );
    Ok(body.to_string())
}

/// Sum of the samples of `name` whose labels contain every `labels` entry.
fn sum(body: &str, name: &str, labels: &[&str]) -> u64 {
    body.lines()
        .filter(|l| l.starts_with(name) && l[name.len()..].starts_with(['{', ' ']))
        .filter(|l| labels.iter().all(|want| l.contains(want)))
        .filter_map(|l| l.rsplit(' ').next()?.parse::<f64>().ok())
        .map(|v| v as u64)
        .sum()
}

/// Deny and audit-would-deny decisions counted by the kernel, from /metrics.
fn kernel_decisions(body: &str) -> (u64, u64) {
    (
        sum(body, "rk_decisions_total", &["verdict=\"deny\""]),
        sum(
            body,
            "rk_decisions_total",
            &["verdict=\"audit_would_deny\""],
        ),
    )
}

fn workload(cgroup: &str, name: &str, args: &[&str]) -> Result<()> {
    let out = run_workload(&format!("{cgroup}/cgroup.procs"), name, args)?;
    ensure!(
        out.status.success(),
        "{name} {args:?} in {cgroup}: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(())
}

/// Every record (not control line) of an audit directory.
fn records(dir: &str) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for seg in rk_audit::chain::segments(Path::new(dir))? {
        for line in fs::read_to_string(&seg)?.lines() {
            let v: Value =
                serde_json::from_str(line).with_context(|| format!("{}: {line}", seg.display()))?;
            if rk_audit::tail::is_record(&v) {
                out.push(v);
            }
        }
    }
    Ok(out)
}

fn rk_field<'a>(record: &'a Value, key: &str) -> &'a Value {
    &record["unmapped"]["rk"][key]
}

/// Decision records of one cgroup, OCSF class and verdict.
fn select<'a>(decisions: &[&'a Value], cgroup: u64, class: u64, verdict: &str) -> Vec<&'a Value> {
    decisions
        .iter()
        .copied()
        .filter(|r| {
            rk_field(r, "cgroup_id").as_u64() == Some(cgroup)
                && r["class_uid"] == class
                && rk_field(r, "verdict").as_str() == Some(verdict)
        })
        .collect()
}

fn rk_cli(rk: &Path, args: &[&str]) -> Result<(i32, String)> {
    let out = Command::new(rk).args(args).output().context("run rk")?;
    Ok((
        out.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    ))
}

fn copy_dir(from: &str, to: &str) -> Result<()> {
    let _ = fs::remove_dir_all(to);
    fs::create_dir_all(to)?;
    for e in fs::read_dir(from)? {
        let e = e?;
        fs::copy(e.path(), Path::new(to).join(e.file_name()))?;
    }
    Ok(())
}

pub fn run_suite(args: &[String], checks: &mut Vec<TestCheck>) {
    let [sensor, rk] = args else {
        checks.push(TestCheck::fail(
            "observability_suite_args",
            format!("usage: {SUITE_FLAG} <rk-sensor> <rk>, got {args:?}"),
        ));
        return;
    };
    let (sensor, rk) = (PathBuf::from(sensor), PathBuf::from(rk));
    let lsm = rk_sensor::policy::bpf_lsm_active();
    let _ = Command::new(&sensor).arg("--uninstall").status();
    if let Err(e) = prepare(lsm) {
        checks.push(TestCheck::fail("observability_setup", format!("{e:#}")));
        return;
    }
    let mut daemon = match Daemon::start(&sensor) {
        Ok(d) => d,
        Err(e) => {
            checks.push(TestCheck::fail("observability_setup", format!("{e:#}")));
            return;
        }
    };

    // Kernel decision counts before the workload; the audit check compares
    // the log against the kernel's own count of what happened since.
    let before = scrape().map(|b| kernel_decisions(&b));

    run_test(checks, "metrics_endpoint_serves", || {
        let b0 = scrape()?;
        workload(ENFORCE, "udp_connect", &[DENY_TARGET, "eperm"])?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let b1 = scrape()?;
            let deny0 = sum(
                &b0,
                "rk_decisions_total",
                &["hook=\"connect4\"", "verdict=\"deny\""],
            );
            let deny1 = sum(
                &b1,
                "rk_decisions_total",
                &["hook=\"connect4\"", "verdict=\"deny\""],
            );
            let hits0 = sum(
                &b0,
                "rk_rule_hits_total",
                &["verdict=\"deny\"", "profile=\"obs-enforce\""],
            );
            let hits1 = sum(
                &b1,
                "rk_rule_hits_total",
                &["verdict=\"deny\"", "profile=\"obs-enforce\""],
            );
            if deny1 > deny0 && hits1 > hits0 {
                let network = sum(&b1, "rk_enforcement_available", &["capability=\"network\""]);
                let lsm_metric = sum(&b1, "rk_enforcement_available", &["capability=\"lsm\""]);
                ensure!(
                    network == 1,
                    "rk_enforcement_available{{network}} = {network}"
                );
                ensure!(
                    lsm_metric == u64::from(lsm),
                    "rk_enforcement_available{{lsm}} = {lsm_metric}, kernel says {lsm}"
                );
                ensure!(
                    b1.contains("rk_audit_info{key_id=\""),
                    "no rk_audit_info: audit log not open"
                );
                ensure!(b1.contains("rk_heartbeat_age_seconds "), "no heartbeat age");
                return Ok(format!(
                    "connect4 denies {deny0} -> {deny1}, obs-enforce rule hits {hits0} -> {hits1}, enforcement network=1 lsm={lsm_metric}"
                ));
            }
            if Instant::now() > deadline {
                bail!("metrics did not move: connect4 denies {deny0} -> {deny1}, rule hits {hits0} -> {hits1}");
            }
            thread::sleep(Duration::from_millis(100));
        }
    });

    run_test(checks, "audit_every_decision_logged", || {
        let (deny0, audit0) = *before.as_ref().map_err(|e| anyhow::anyhow!("{e:#}"))?;
        for _ in 0..NET_DENIES {
            workload(ENFORCE, "udp_connect", &[DENY_TARGET, "eperm"])?;
        }
        for _ in 0..NET_AUDITS {
            workload(AUDIT, "udp_connect", &[DENY_TARGET, "ok"])?;
        }
        if lsm {
            for _ in 0..FILE_DENIES {
                workload(ENFORCE, "file_open", &[secret().as_str(), "r", "eperm"])?;
            }
            for _ in 0..EXEC_DENIES {
                workload(ENFORCE, "exec_cmd", &["eperm", blocked().as_str()])?;
            }
        }
        let (deny1, audit1) = kernel_decisions(&scrape()?);
        daemon.stop()?;

        let enforce_id = fs::metadata(ENFORCE)?.ino();
        let audit_id = fs::metadata(AUDIT)?.ino();
        let all = records(AUDIT_DIR)?;
        let decisions: Vec<&Value> = all.iter().filter(|r| r["class_uid"] != 6008).collect();
        let lost: u64 = all
            .iter()
            .filter(|r| r["class_uid"] == 6008)
            .map(|r| {
                rk_field(r, "lost")["kernel"].as_u64().unwrap_or(0)
                    + rk_field(r, "lost")["channel"].as_u64().unwrap_or(0)
            })
            .sum();

        // The metrics check above added one enforce network deny.
        let net_denies = select(&decisions, enforce_id, 4001, "deny");
        ensure!(
            net_denies.len() == NET_DENIES + 1,
            "{} network denies logged, {} made",
            net_denies.len(),
            NET_DENIES + 1
        );
        let rule = net_denies[0]["policy"]["uid"].clone();
        ensure!(
            rule != "0" && !rule.is_null(),
            "network deny logged without its rule id: {rule}"
        );
        for r in &net_denies {
            ensure!(
                r["policy"]["uid"] == rule,
                "rule ids differ: {} vs {rule}",
                r["policy"]["uid"]
            );
            ensure!(
                r["policy"]["name"] == "obs-enforce",
                "profile {}",
                r["policy"]["name"]
            );
            ensure!(
                r["dst_endpoint"]["ip"] == "10.99.0.1",
                "target {}",
                r["dst_endpoint"]
            );
            ensure!(r["disposition_id"] == 2, "deny without disposition Blocked");
        }
        let audits = select(&decisions, audit_id, 4001, "audit_would_deny");
        ensure!(
            audits.len() == NET_AUDITS,
            "{} audit-would-deny logged, {NET_AUDITS} made",
            audits.len()
        );
        ensure!(audits
            .iter()
            .all(|r| r["policy"]["name"] == "obs-audit" && r["policy"]["uid"] != "0"));
        let (mut files, mut execs) = (0, 0);
        if lsm {
            files = select(&decisions, enforce_id, 1001, "deny").len();
            execs = select(&decisions, enforce_id, 1007, "deny").len();
            ensure!(
                files == FILE_DENIES,
                "{files} file denies logged, {FILE_DENIES} made"
            );
            ensure!(
                execs == EXEC_DENIES,
                "{execs} exec denies logged, {EXEC_DENIES} made"
            );
        }

        // Complete by count: the kernel's own decision counters agree with
        // the log (plus any recorded loss).
        let verdicts = |v: &str| {
            decisions
                .iter()
                .filter(|r| rk_field(r, "verdict").as_str() == Some(v))
                .count() as u64
        };
        let (logged_denies, logged_audits) = (verdicts("deny"), verdicts("audit_would_deny"));
        ensure!(
            logged_denies + logged_audits + lost == (deny1 - deny0) + (audit1 - audit0),
            "kernel counted {} denies and {} audits; log has {logged_denies} and {logged_audits}, {lost} lost",
            deny1 - deny0,
            audit1 - audit0
        );
        Ok(format!(
            "{} network denies (rule {rule}), {} audit-would-deny, {files} file and {execs} exec denies; kernel counters match the log ({lost} lost)",
            net_denies.len(),
            audits.len()
        ))
    });

    run_test(checks, "audit_tamper_detected", || {
        let pubkey = format!("{KEY}.pub");
        let (code, out) = rk_cli(
            &rk,
            &[
                "audit",
                "verify",
                "--dir",
                AUDIT_DIR,
                "--pubkey",
                pubkey.as_str(),
            ],
        )?;
        ensure!(
            code == 0 && out.contains("VERIFIED"),
            "untouched log did not verify ({code}): {out}"
        );

        let tampered = format!("{DIR}/tampered");
        copy_dir(AUDIT_DIR, &tampered)?;
        // Flip one digit in the first record of the first segment.
        let first = rk_audit::chain::segments(Path::new(&tampered))?
            .into_iter()
            .next()
            .context("no audit segment")?;
        let text = fs::read_to_string(&first)?;
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        let at = lines
            .iter()
            .position(|l| l.contains("\"class_uid\"") && l.contains("\"time\":"))
            .context("no record to tamper with")?;
        let pos = lines[at].find("\"time\":").unwrap() + 7;
        let mut bytes = lines[at].clone().into_bytes();
        bytes[pos] = if bytes[pos] == b'1' { b'2' } else { b'1' };
        lines[at] = String::from_utf8(bytes)?;
        fs::write(&first, lines.join("\n") + "\n")?;

        let (code, out) = rk_cli(&rk, &["audit", "verify", "--dir", tampered.as_str()])?;
        ensure!(
            code == 2,
            "tampered log: exit code {code}, expected 2: {out}"
        );
        ensure!(
            out.contains("FAILED") && out.contains("batch"),
            "tampered log not reported: {out}"
        );
        Ok(format!(
            "untouched log verified with the pinned key; flipped byte on line {} reported",
            at + 1
        ))
    });

    drop(daemon);
    let _ = Command::new(&sensor).arg("--uninstall").status();

    run_test(checks, "audit_records_loss", || audit_records_loss(lsm));
}

/// With every emission failing, decisions still happen and are counted by
/// the kernel; the audit log must say how many were lost.
fn audit_records_loss(lsm: bool) -> Result<String> {
    use rk_sensor::consumer::{take_ring, Config, Consumer, PipelineStats};
    use rk_sensor::observe::{KernelLosses, Observer};
    use std::sync::atomic::{AtomicU64, Ordering};

    let bytes = crate::bpf::rk_emitfail_bytes().context("rk_emitfail.bpf.o not embedded")?;
    let mut ebpf = rk_sensor::loader::open_bytes(bytes, "rk_emitfail.bpf.o")?;
    let btf = Btf::from_sys_fs().ok();
    for r in rk_sensor::loader::load_programs(
        rk_sensor::loader::Object::Production,
        &mut ebpf,
        btf.as_ref(),
    ) {
        ensure!(r.loaded, "{} failed to load: {:?}", r.name, r.error);
    }
    let _heartbeat = rk_sensor::resilience::Heartbeat::start(&mut ebpf, Duration::from_secs(30))?;
    rk_sensor::policy::attach_all(&mut ebpf, Path::new("/sys/fs/cgroup/rk.slice"))?;
    let mut engine = rk_sensor::policy::PolicyEngine::default();
    engine.set_lsm_active(lsm);
    engine.apply_text(&mut ebpf, &policy_text(lsm))?;

    let lost_now = |ebpf: &aya::Ebpf| -> Result<u64> {
        Ok(get_counter(ebpf, rk_counter::RK_CNT_RINGBUF_DROP)?
            + get_counter(ebpf, rk_counter::RK_CNT_SCRATCH_MISS)?)
    };
    let deny_index = rk_counter::RK_CNT_DECISION_BASE
        + rk_ebpf_common::rk_hook::RK_HOOK_CONNECT4 * rk_ebpf_common::RK_VERDICTS
        + 1;
    let lost0 = lost_now(&ebpf)?;
    let denies0 = get_counter(&ebpf, deny_index)?;

    let _ = fs::remove_dir_all(LOSS_DIR);
    let writer = rk_audit::chain::Writer::open(
        Path::new(LOSS_DIR),
        rk_audit::key::AuditKey::generate()?,
        rk_audit::chain::WriterOptions::default(),
    )?;
    let losses = Arc::new(KernelLosses(AtomicU64::new(lost0)));
    let stats = Arc::new(PipelineStats::default());
    let observer = Observer::new(
        None,
        Arc::new(RwLock::new(Arc::new(engine.audit_context()))),
        Some(writer),
        false,
        Arc::new(rk_sensor::metrics::Metrics::default()),
        losses.clone(),
        stats.clone(),
        None,
    );
    let consumer = Consumer::start_with(
        take_ring(&mut ebpf)?,
        Box::new(observer),
        stats,
        Config::default(),
    )?;

    for _ in 0..3 {
        workload(ENFORCE, "udp_connect", &[DENY_TARGET, "eperm"])?;
    }
    let lost1 = lost_now(&ebpf)?;
    let denies1 = get_counter(&ebpf, deny_index)?;
    losses.0.store(lost1, Ordering::Relaxed);
    thread::sleep(Duration::from_millis(500));
    consumer.stop();

    let all = records(LOSS_DIR)?;
    let decisions = all.iter().filter(|r| r["class_uid"] != 6008).count();
    let recorded: u64 = all
        .iter()
        .filter(|r| r["class_uid"] == 6008)
        .map(|r| rk_field(r, "lost")["kernel"].as_u64().unwrap_or(0))
        .sum();
    ensure!(
        denies1 - denies0 >= 3,
        "kernel counted {} connect4 denies, expected 3",
        denies1 - denies0
    );
    ensure!(
        decisions == 0,
        "{decisions} decision records reached the log with emission failing"
    );
    ensure!(
        recorded == lost1 - lost0 && recorded >= 3,
        "loss records say {recorded} lost; kernel counted {} lost events",
        lost1 - lost0
    );
    let report = rk_audit::chain::verify_dir(Path::new(LOSS_DIR), None)?;
    ensure!(
        report.ok(),
        "loss log does not verify: {:?}",
        report.problems
    );
    Ok(format!(
        "{} denies decided, 0 events emitted, loss records account for all {recorded} lost events",
        denies1 - denies0
    ))
}
