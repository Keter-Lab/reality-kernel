//! Phase 5 agent suite (docs/design/phase-5.md §7).
//!
//! Starts the real `rk-sensor` daemon with a test policy and drives it through
//! the `rk` CLI, the way an operator would. Agents launched with `rk run` are
//! this binary in `--agent-probe` mode: each probe checks its own confinement
//! from inside the agent and exits non-zero if any check fails.
//!
//! Runs after the verdict suite has exited, so the daemon's programs are the
//! only ones attached.

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::{run_test, wait_with_deadline, TestCheck, CHILD_DEADLINE};

pub const PROBE_FLAG: &str = "--agent-probe";
pub const SUITE_FLAG: &str = "--agent-suite";

const DIR: &str = "/run/rk-agent-test";
const PROBE: &str = "/run/rk-agent-test/rk-integration";
const RK: &str = "/run/rk-agent-test/rk";
const DENIED_BIN: &str = "/run/rk-agent-test/denied_bin";
const POLICY_FILE: &str = "/run/rk-agent-test/policy.toml";
const POLICY_A_FILE: &str = "/run/rk-agent-test/policy-a.toml";
const POLICY_B_FILE: &str = "/run/rk-agent-test/policy-b.toml";
const DAEMON_LOG: &str = "/run/rk-agent-test/daemon.log";
const SOCKET: &str = "/run/rk/agentd.sock";
const CGROUP_FS: &str = "/sys/fs/cgroup";
/// Kernel name of `rk_cgroup_profile` (map names are cut to 15 bytes).
const BINDINGS_MAP: &str = "rk_cgroup_profi";
/// The daemon maps root callers to this service user.
const NOBODY: u32 = 65534;

/// Denied by both policies; the first thing every governed probe tries.
const DENY_ADDR: &str = "10.99.0.1:80";
/// Denied by A, allowed by B: the address whose verdict flips on apply.
const FLIP_ADDR: &str = "10.99.0.2:80";

const EV_EXEC: u64 = 1;
const EV_NET_CONNECT: u64 = 3;
const VERDICT_ALLOW: u64 = 0;
const VERDICT_DENY: u64 = 1;

/// Policy A. Profile `restricted` is launchable only by a uid that does not
/// exist, so root's `rk run` must be refused.
fn policy_a() -> String {
    policy(&["10.99.0.1/32", "10.99.0.2/32"])
}

/// Policy B: identical to A except that 10.99.0.2 is no longer denied.
fn policy_b() -> String {
    policy(&["10.99.0.1/32"])
}

fn policy(denied: &[&str]) -> String {
    let mut text = format!(
        r#"
[profiles.agent]
mode = "enforce"
launchable_by = ["root"]
network.default = "allow"

[profiles.agent.exec]
default = "deny"
allow = ["{PROBE}"]

[profiles.restricted]
mode = "enforce"
launchable_by = ["uid:4242"]
network.default = "deny"
"#
    );
    for cidr in denied {
        text.push_str(&format!(
            "\n[[profiles.agent.network.deny]]\ncidr = \"{cidr}\"\nproto = [\"tcp\", \"udp\"]\n"
        ));
    }
    text
}

// ---------------------------------------------------------------------------
// Probe side: runs inside the agent, as the unprivileged service user.
// ---------------------------------------------------------------------------

pub fn run_probe(args: &[String]) -> i32 {
    let Some((mode, rest)) = args.split_first() else {
        eprintln!("[probe] missing mode");
        return 2;
    };
    // Every probe first proves it runs inside an agent cgroup: an agent left
    // elsewhere is ungoverned, and the checks below would pass vacuously.
    // In a Kubernetes pod (RK_PROBE_IN_POD=1) the container's cgroup
    // namespace shows its cgroup as `/`; the k8s suite instead matches the
    // printed cgroup id against the daemon's deny events.
    let in_pod = std::env::var("RK_PROBE_IN_POD").as_deref() == Ok("1");
    match own_cgroup() {
        Ok(cg) if in_pod || cg.starts_with("/rk.slice/agent-") => {}
        Ok(cg) => {
            eprintln!("[probe] running in cgroup {cg}, not an rk.slice/agent-* cgroup");
            return 3;
        }
        Err(e) => {
            eprintln!("[probe] {e:#}");
            return 3;
        }
    }
    let rest: Vec<&str> = rest.iter().map(String::as_str).collect();
    let res = match (mode.as_str(), rest.as_slice()) {
        ("noop", []) => Ok(()),
        ("first", [denied, addr]) => probe_first(denied, addr),
        ("nest", [depth, expected, denied, addr]) => {
            return probe_nest(depth, expected, denied, addr)
        }
        ("privs", [uid]) => probe_privs(uid),
        ("escape", []) => probe_escape(),
        ("connect", [addr, expect]) => probe_connect(addr, expect),
        ("paced", [addr, count, pace_us]) => probe_paced(addr, count, pace_us),
        ("hold", [ms]) => probe_hold(ms),
        _ => Err(anyhow::anyhow!("unknown probe {mode} {rest:?}")),
    };
    match res {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("[probe] {e:#}");
            1
        }
    }
}

/// `/rk.slice/agent-...` from `/proc/self/cgroup` (cgroup v2: `0::/path`).
fn own_cgroup() -> Result<String> {
    let text = fs::read_to_string("/proc/self/cgroup").context("read /proc/self/cgroup")?;
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::to_string)
        .context("no cgroup v2 entry in /proc/self/cgroup")
}

fn cgroup_id(rel: &str) -> Result<u64> {
    let path = format!("{CGROUP_FS}{rel}");
    Ok(fs::metadata(&path)
        .with_context(|| format!("stat {path}"))?
        .ino())
}

/// One line the suite parses: `ident cgroup=<path> cgroup_id=<id> pid=<pid>`.
fn print_ident() -> Result<()> {
    let rel = own_cgroup()?;
    println!(
        "ident cgroup={rel} cgroup_id={} pid={}",
        cgroup_id(&rel)?,
        std::process::id()
    );
    Ok(())
}

fn udp_connect(addr: &str) -> std::io::Result<()> {
    let addr: SocketAddr = addr
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    UdpSocket::bind("0.0.0.0:0")?.connect(addr)
}

fn expect_eperm(what: &str, res: std::io::Result<()>) -> Result<()> {
    match res {
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => Ok(()),
        Err(e) => bail!("{what}: expected EPERM, got {e}"),
        Ok(()) => bail!("{what}: expected EPERM, but it succeeded"),
    }
}

/// The agent's first actions: an exec and a connect, both denied by policy.
fn probe_first(denied: &str, addr: &str) -> Result<()> {
    let exec = Command::new(denied).status().map(|_| ());
    let connect = udp_connect(addr);
    print_ident()?;
    expect_eperm(&format!("exec {denied}"), exec)?;
    expect_eperm(&format!("connect {addr}"), connect)
}

/// Re-executes itself `depth` times (fork, then exec), then the innermost
/// descendant checks it is still in the agent's cgroup and still governed.
fn probe_nest(depth: &str, expected: &str, denied: &str, addr: &str) -> i32 {
    let run = || -> Result<i32> {
        let depth: u32 = depth.parse().context("depth")?;
        let cgroup = own_cgroup()?;
        if expected != "-" && cgroup != expected {
            bail!("descendant at depth {depth} is in {cgroup}, expected {expected}");
        }
        if depth == 0 {
            probe_first(denied, addr)?;
            println!("nest ok cgroup={cgroup}");
            return Ok(0);
        }
        let next = (depth - 1).to_string();
        let status = Command::new(std::env::current_exe()?)
            .args([
                PROBE_FLAG,
                "nest",
                next.as_str(),
                cgroup.as_str(),
                denied,
                addr,
            ])
            .status()
            .context("spawn descendant")?;
        Ok(status.code().unwrap_or(1))
    };
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("[probe] {e:#}");
            1
        }
    }
}

fn status_field(status: &str, key: &str) -> Result<String> {
    status
        .lines()
        .find_map(|l| l.strip_prefix(key))
        .map(|v| v.trim().to_string())
        .with_context(|| format!("{key} missing from /proc/self/status"))
}

/// Unprivileged: the service uid and gid, no capabilities in any set,
/// `no_new_privs`, and no write access to its own cgroup.
fn probe_privs(uid: &str) -> Result<()> {
    let status = fs::read_to_string("/proc/self/status")?;
    for key in ["Uid:", "Gid:"] {
        let ids = status_field(&status, key)?;
        if ids.split_whitespace().any(|id| id != uid) {
            bail!("{key} {ids}, expected all {uid}");
        }
    }
    for key in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
        let caps = status_field(&status, key)?;
        if u64::from_str_radix(&caps, 16).context(key)? != 0 {
            bail!("{key} {caps}, expected none");
        }
    }
    let nnp = status_field(&status, "NoNewPrivs:")?;
    if nnp != "1" {
        bail!("NoNewPrivs: {nnp}, expected 1");
    }
    let groups = status_field(&status, "Groups:")?;
    if !groups.is_empty() {
        bail!("supplementary groups {groups}, expected none");
    }
    let cg = format!("{CGROUP_FS}{}", own_cgroup()?);
    for file in ["cgroup.procs", "cgroup.subtree_control", "cgroup.kill"] {
        let path = format!("{cg}/{file}");
        if fs::OpenOptions::new().write(true).open(&path).is_ok() {
            bail!("{path} is writable by the agent");
        }
    }
    if fs::create_dir(format!("{cg}/escape")).is_ok() {
        bail!("agent could create a child cgroup under {cg}");
    }
    Ok(())
}

/// Moving itself to another cgroup must fail and leave it where it was.
fn probe_escape() -> Result<()> {
    let before = own_cgroup()?;
    let pid = std::process::id().to_string();
    for target in ["", "/rk.slice", "/rk.slice/ungoverned-sibling"] {
        let procs = format!("{CGROUP_FS}{target}/cgroup.procs");
        if fs::write(&procs, &pid).is_ok() {
            bail!("agent moved itself via {procs}");
        }
    }
    let after = own_cgroup()?;
    if after != before {
        bail!("agent cgroup changed from {before} to {after}");
    }
    Ok(())
}

fn probe_connect(addr: &str, expect: &str) -> Result<()> {
    let res = udp_connect(addr);
    // After the connect, so the connect stays the first governed action.
    print_ident()?;
    match expect {
        "eperm" => expect_eperm(&format!("connect {addr}"), res),
        "notdenied" => match res {
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                bail!("connect {addr}: denied with EPERM, expected allowed")
            }
            _ => Ok(()),
        },
        other => bail!("unknown expectation {other}"),
    }
}

/// `count` UDP connects, each on a fresh socket so each one is governed.
/// Prints `{"pid":..,"eperm":..,"ok":..}`.
fn probe_paced(addr: &str, count: &str, pace_us: &str) -> Result<()> {
    let count: u64 = count.parse().context("count")?;
    let pace = Duration::from_micros(pace_us.parse().context("pace_us")?);
    let (mut eperm, mut ok) = (0u64, 0u64);
    for _ in 0..count {
        match udp_connect(addr) {
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => eperm += 1,
            Err(e) => bail!("connect {addr}: unexpected error {e}"),
            Ok(()) => ok += 1,
        }
        thread::sleep(pace);
    }
    println!(
        "{}",
        serde_json::json!({ "pid": std::process::id(), "eperm": eperm, "ok": ok })
    );
    Ok(())
}

fn probe_hold(ms: &str) -> Result<()> {
    print_ident()?;
    thread::sleep(Duration::from_millis(ms.parse().context("ms")?));
    Ok(())
}

// ---------------------------------------------------------------------------
// Suite side: runs as root in the VM.
// ---------------------------------------------------------------------------

struct Ident {
    cgroup: String,
    cgroup_id: u64,
}

fn parse_ident(stdout: &str) -> Result<Ident> {
    let line = stdout
        .lines()
        .find(|l| l.starts_with("ident "))
        .with_context(|| format!("no ident line in agent output: {stdout:?}"))?;
    let field = |key: &str| {
        line.split_whitespace()
            .find_map(|kv| kv.strip_prefix(key))
            .with_context(|| format!("{key} missing in {line:?}"))
    };
    Ok(Ident {
        cgroup: field("cgroup=")?.to_string(),
        cgroup_id: field("cgroup_id=")?.parse().context("cgroup_id")?,
    })
}

fn rk_cmd(args: &[&str]) -> Command {
    let mut cmd = Command::new(RK);
    cmd.args(args)
        .current_dir(DIR)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn finish(child: Child, what: &str) -> Result<Output> {
    wait_with_deadline(child, what, CHILD_DEADLINE)
}

/// Runs `rk ARGS` as root and returns its output, whatever the exit status.
fn rk(args: &[&str]) -> Result<Output> {
    let child = rk_cmd(args).spawn().context("spawn rk")?;
    finish(child, &format!("rk {}", args.join(" ")))
}

fn text(out: &Output) -> String {
    format!(
        "exit {:?}; stdout: {}; stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).trim(),
        String::from_utf8_lossy(&out.stderr).trim()
    )
}

/// Runs `rk ARGS`, failing unless it exits 0. Returns stdout.
fn rk_ok(args: &[&str]) -> Result<String> {
    let out = rk(args)?;
    if !out.status.success() {
        bail!("rk {} failed: {}", args.join(" "), text(&out));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `rk run --profile agent -- PROBE MODE ARGS`, failing unless it exits 0.
fn run_probe_ok(session: Option<&str>, mode_args: &[&str]) -> Result<String> {
    let mut args = vec!["run", "--profile", "agent"];
    if let Some(s) = session {
        args.extend(["--session", s]);
    }
    args.extend(["--", PROBE, PROBE_FLAG]);
    args.extend(mode_args);
    rk_ok(&args)
}

fn status() -> Result<Value> {
    let out = rk_ok(&["status", "--json"])?;
    serde_json::from_str(&out).with_context(|| format!("parse rk status: {out}"))
}

fn generation() -> Result<u64> {
    status()?["generation"]
        .as_u64()
        .context("status has no generation")
}

fn agents() -> Result<Vec<Value>> {
    Ok(status()?["agents"].as_array().cloned().unwrap_or_default())
}

/// `generation N` from `rk policy apply` / `rollback` output.
fn parsed_generation(stdout: &str) -> Result<u64> {
    stdout
        .split("generation ")
        .nth(1)
        .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|n| n.parse().ok())
        .with_context(|| format!("no generation in {stdout:?}"))
}

/// Event records the daemon logged (tracing JSON, one object per line).
fn logged_events() -> Result<Vec<Value>> {
    let log = fs::read_to_string(DAEMON_LOG).context("read daemon log")?;
    Ok(log
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|v| v.get("fields").cloned())
        .filter(|f| f["message"] == "event")
        .collect())
}

/// Polls the daemon log until `pred` holds for the events, or 10 s pass.
fn wait_for_events<F>(what: &str, pred: F) -> Result<Vec<Value>>
where
    F: Fn(&[Value]) -> bool,
{
    let start = Instant::now();
    loop {
        let events = logged_events()?;
        if pred(&events) {
            return Ok(events);
        }
        if start.elapsed() > Duration::from_secs(10) {
            bail!("timed out waiting for {what} in the daemon log");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn has_event(events: &[Value], cgroup_id: u64, type_: u64, verdict: u64) -> bool {
    events.iter().any(|e| {
        e["cgroup_id"].as_u64() == Some(cgroup_id)
            && e["event_type"].as_u64() == Some(type_)
            && e["verdict"].as_u64() == Some(verdict)
    })
}

/// Cgroup ids bound in the kernel's `rk_cgroup_profile` map, via bpftool.
fn kernel_bindings(bpftool: &Path) -> Result<Vec<u64>> {
    let out = Command::new(bpftool)
        .args(["-j", "map", "dump", "name", BINDINGS_MAP])
        .output()
        .context("run bpftool")?;
    if !out.status.success() {
        bail!(
            "bpftool map dump failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let entries: Value = serde_json::from_slice(&out.stdout).context("parse bpftool json")?;
    let mut ids = Vec::new();
    for entry in entries.as_array().into_iter().flatten() {
        let key = &entry["key"];
        let id = match key {
            Value::Number(n) => n.as_u64(),
            Value::Array(bytes) => {
                let mut raw = [0u8; 8];
                for (slot, b) in raw.iter_mut().zip(bytes) {
                    let s = b.as_str().unwrap_or("0x0").trim_start_matches("0x");
                    *slot = u8::from_str_radix(s, 16).unwrap_or(0);
                }
                Some(u64::from_ne_bytes(raw))
            }
            _ => None,
        };
        ids.extend(id.or_else(|| entry["formatted"]["key"].as_u64()));
    }
    Ok(ids)
}

fn agent_cgroups() -> Vec<String> {
    fs::read_dir(format!("{CGROUP_FS}/rk.slice"))
        .map(|dir| {
            dir.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("agent-"))
                .collect()
        })
        .unwrap_or_default()
}

fn write_file(path: &str, contents: &str, mode: u32) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("write {path}"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {path}"))
}

fn copy_exe(from: &Path, to: &str) -> Result<()> {
    fs::copy(from, to).with_context(|| format!("copy {} to {to}", from.display()))?;
    fs::set_permissions(to, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod {to}"))
}

/// Everything the agent needs lives on a world-readable exec tmpfs: the
/// runner's workspace is not reachable by the service user.
fn prepare(rk_bin: &Path) -> Result<()> {
    fs::create_dir_all(DIR)?;
    let _ = Command::new("mount")
        .args(["-t", "tmpfs", "-o", "exec,mode=755", "tmpfs", DIR])
        .status();
    copy_exe(&std::env::current_exe()?, PROBE)?;
    copy_exe(rk_bin, RK)?;
    copy_exe(Path::new("/bin/true"), DENIED_BIN)?;
    write_file(POLICY_FILE, &policy_a(), 0o644)?;
    write_file(POLICY_A_FILE, &policy_a(), 0o644)?;
    write_file(POLICY_B_FILE, &policy_b(), 0o644)?;
    fs::create_dir_all(format!("{CGROUP_FS}/rk.slice/ungoverned-sibling"))?;
    for addr in ["10.99.0.1/24", "10.99.0.2/24"] {
        let _ = Command::new("ip")
            .args(["addr", "add", addr, "dev", "lo"])
            .stderr(Stdio::null())
            .status();
    }
    Ok(())
}

struct Daemon {
    child: Child,
    sensor: PathBuf,
}

impl Daemon {
    fn start(sensor: &Path) -> Result<Self> {
        let _ = fs::remove_file(SOCKET);
        let log = File::create(DAEMON_LOG).context("create daemon log")?;
        let child = Command::new(sensor)
            .args(["--policy", POLICY_FILE])
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
            if Path::new(SOCKET).exists() && generation().map(|g| g >= 1).unwrap_or(false) {
                return Ok(daemon);
            }
            if start.elapsed() > Duration::from_secs(30) {
                bail!("rk-sensor not ready after 30s: {}", log_tail());
            }
            thread::sleep(Duration::from_millis(200));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        unsafe {
            libc::kill(self.child.id() as i32, libc::SIGTERM);
        }
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                let _ = Command::new(&self.sensor).arg("--uninstall").status();
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = Command::new(&self.sensor).arg("--uninstall").status();
    }
}

fn log_tail() -> String {
    let log = fs::read_to_string(DAEMON_LOG).unwrap_or_default();
    let lines: Vec<&str> = log.lines().collect();
    lines[lines.len().saturating_sub(20)..].join("\n")
}

pub fn run_suite(args: &[String], checks: &mut Vec<TestCheck>) {
    let [sensor, rk_bin, bpftool] = args else {
        checks.push(TestCheck::fail(
            "agent_suite_args",
            format!("usage: {SUITE_FLAG} <rk-sensor> <rk> <bpftool>, got {args:?}"),
        ));
        return;
    };
    let bpftool = PathBuf::from(bpftool);
    if let Err(e) = prepare(Path::new(rk_bin)) {
        checks.push(TestCheck::fail("agent_setup", format!("{e:#}")));
        return;
    }
    let daemon = match Daemon::start(Path::new(sensor)) {
        Ok(d) => d,
        Err(e) => {
            checks.push(TestCheck::fail("agent_daemon_start", format!("{e:#}")));
            return;
        }
    };

    run_test(checks, "agent_governed_from_first_instruction", || {
        // The very first exec, performed by the launcher inside the agent's
        // cgroup, is the policy's to refuse.
        let out = rk(&["run", "--profile", "agent", "--", DENIED_BIN])?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        if out.status.success() || !stderr.contains("errno 0001") {
            bail!(
                "launching a non-allowlisted binary must fail with EPERM: {}",
                text(&out)
            );
        }
        let stdout = run_probe_ok(None, &["first", DENIED_BIN, DENY_ADDR])?;
        let id = parse_ident(&stdout)?;
        wait_for_events("deny events for the agent's cgroup", |ev| {
            has_event(ev, id.cgroup_id, EV_EXEC, VERDICT_DENY)
                && has_event(ev, id.cgroup_id, EV_NET_CONNECT, VERDICT_DENY)
        })?;
        Ok(format!(
            "first exec refused with EPERM; probe's exec and connect denied; deny events carry cgroup {} ({})",
            id.cgroup, id.cgroup_id
        ))
    });

    run_test(checks, "agent_children_governed", || {
        let stdout = run_probe_ok(None, &["nest", "2", "-", DENIED_BIN, DENY_ADDR])?;
        if !stdout.contains("nest ok") {
            bail!("grandchild did not report: {stdout:?}");
        }
        let id = parse_ident(&stdout)?;
        wait_for_events("grandchild deny events", |ev| {
            has_event(ev, id.cgroup_id, EV_NET_CONNECT, VERDICT_DENY)
        })?;
        Ok(format!(
            "grandchild (fork+exec twice) stayed in {} and was denied exec and connect",
            id.cgroup
        ))
    });

    run_test(checks, "policy_apply_atomic", || {
        let mut deny_gens = vec![generation()?];
        let mut allow_gens = Vec::new();
        let child = rk_cmd(&[
            "run",
            "--profile",
            "agent",
            "--",
            PROBE,
            PROBE_FLAG,
            "paced",
            FLIP_ADDR,
            "2000",
            "1000",
        ])
        .spawn()
        .context("spawn paced agent")?;
        for i in 0..6 {
            let (file, gens) = if i % 2 == 0 {
                (POLICY_B_FILE, &mut allow_gens)
            } else {
                (POLICY_A_FILE, &mut deny_gens)
            };
            gens.push(parsed_generation(&rk_ok(&["policy", "apply", file])?)?);
            thread::sleep(Duration::from_millis(150));
        }
        let out = finish(child, "paced agent")?;
        if !out.status.success() {
            bail!("paced agent failed: {}", text(&out));
        }
        let counts: Value = serde_json::from_slice(&out.stdout)
            .with_context(|| format!("parse agent output: {}", text(&out)))?;
        let pid = counts["pid"].as_u64().context("pid")?;
        let eperm = counts["eperm"].as_u64().context("eperm")?;
        let ok = counts["ok"].as_u64().context("ok")?;
        if eperm + ok != 2000 {
            bail!("agent made {} connects, expected 2000", eperm + ok);
        }
        let mine = |ev: &[Value]| -> Vec<Value> {
            ev.iter()
                .filter(|e| {
                    e["pid"].as_u64() == Some(pid)
                        && e["event_type"].as_u64() == Some(EV_NET_CONNECT)
                })
                .cloned()
                .collect()
        };
        let events = wait_for_events("2000 connect events from the paced agent", |ev| {
            mine(ev).len() >= 2000
        })
        .map(|ev| mine(ev.as_slice()))?;
        let (mut deny_events, mut allow_events) = (0u64, 0u64);
        for e in &events {
            let gen = e["policy_gen"].as_u64().context("policy_gen")?;
            let verdict = e["verdict"].as_u64().context("verdict")?;
            if deny_gens.contains(&gen) && verdict == VERDICT_DENY {
                deny_events += 1;
            } else if allow_gens.contains(&gen) && verdict == VERDICT_ALLOW {
                allow_events += 1;
            } else {
                bail!("event with generation {gen} has verdict {verdict}: a torn policy (deny gens {deny_gens:?}, allow gens {allow_gens:?})");
            }
        }
        if deny_events != eperm || allow_events != ok {
            bail!(
                "agent saw {eperm} EPERM / {ok} allowed, events say {deny_events} / {allow_events}"
            );
        }
        if eperm == 0 || ok == 0 {
            bail!("the applies did not overlap the agent ({eperm} denied, {ok} allowed)");
        }
        Ok(format!(
            "6 applies through `rk policy apply` during 2000 connects: {eperm} denied, {ok} allowed, every event consistent with its generation"
        ))
    });

    run_test(checks, "policy_rollback_one_command", || {
        let before = generation()?;
        run_probe_ok(None, &["connect", FLIP_ADDR, "eperm"])?;
        let applied = parsed_generation(&rk_ok(&["policy", "apply", POLICY_B_FILE])?)?;
        run_probe_ok(None, &["connect", FLIP_ADDR, "notdenied"])?;
        let rolled = parsed_generation(&rk_ok(&["policy", "rollback"])?)?;
        run_probe_ok(None, &["connect", FLIP_ADDR, "eperm"])?;
        if !(before < applied && applied < rolled) {
            bail!("generations not increasing: {before} -> {applied} -> {rolled}");
        }
        Ok(format!(
            "B allowed {FLIP_ADDR} at generation {applied}; `rk policy rollback` denied it again at {rolled}"
        ))
    });

    run_test(checks, "agent_runs_unprivileged", || {
        let uid = NOBODY.to_string();
        run_probe_ok(None, &["privs", uid.as_str()])?;
        Ok(format!(
            "agent of a root caller runs as uid/gid {NOBODY}, no groups, no capabilities, no_new_privs, cannot write its cgroup"
        ))
    });

    run_test(checks, "agent_cannot_leave_cgroup", || {
        run_probe_ok(None, &["escape"])?;
        Ok("writes to the root, rk.slice and a sibling cgroup.procs all failed".into())
    });

    run_test(checks, "policy_dry_run_changes_nothing", || {
        let before = generation()?;
        let stdout = rk_ok(&["policy", "apply", "--dry-run", POLICY_B_FILE])?;
        if !stdout.contains("Changes:") {
            bail!("dry run reported no changes against a different policy: {stdout:?}");
        }
        let after = generation()?;
        if after != before {
            bail!("dry run moved the generation from {before} to {after}");
        }
        run_probe_ok(None, &["connect", FLIP_ADDR, "eperm"])?;
        Ok(format!(
            "generation stayed {before}; {FLIP_ADDR} still denied"
        ))
    });

    run_test(checks, "policy_diff_reports_changes", || {
        let changed = rk_ok(&["policy", "diff", POLICY_B_FILE])?;
        if !changed.contains("10.99.0.2") {
            bail!("diff against B does not mention 10.99.0.2: {changed:?}");
        }
        let same = rk_ok(&["policy", "diff", POLICY_A_FILE])?;
        if !same.contains("No changes") {
            bail!("diff against the active policy is not empty: {same:?}");
        }
        Ok(format!("diff B: {}", changed.trim().replace('\n', "; ")))
    });

    run_test(checks, "socket_rejects_unauthorised_apply", || {
        let before = generation()?;
        for args in [
            &["policy", "apply", POLICY_B_FILE][..],
            &["policy", "rollback"][..],
        ] {
            let child = rk_cmd(args)
                .uid(NOBODY)
                .gid(NOBODY)
                .spawn()
                .context("spawn rk as nobody")?;
            let out = finish(child, "rk as nobody")?;
            let stderr = String::from_utf8_lossy(&out.stderr);
            if out.status.success() || !stderr.contains("not authorised") {
                bail!(
                    "`rk {}` as uid {NOBODY} was not refused: {}",
                    args.join(" "),
                    text(&out)
                );
            }
        }
        let after = generation()?;
        if after != before {
            bail!("generation moved from {before} to {after}");
        }
        Ok(format!(
            "apply and rollback from uid {NOBODY} refused; generation stayed {before}"
        ))
    });

    let bpftool_ref = &bpftool;
    run_test(checks, "run_rejects_non_launchable_profile", || {
        let cgroups_before = agent_cgroups();
        let bindings_before = kernel_bindings(bpftool_ref)?.len();
        let out = rk(&[
            "run",
            "--profile",
            "restricted",
            "--",
            PROBE,
            PROBE_FLAG,
            "noop",
        ])?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        if out.status.success() || !stderr.contains("not authorised to launch") {
            bail!("root launched `restricted`: {}", text(&out));
        }
        if agent_cgroups() != cgroups_before {
            bail!("a refused launch created a cgroup: {:?}", agent_cgroups());
        }
        let bindings_after = kernel_bindings(bpftool_ref)?.len();
        if bindings_after != bindings_before {
            bail!(
                "a refused launch changed the binding count {bindings_before} -> {bindings_after}"
            );
        }
        Ok("refused before any cgroup or binding was created".into())
    });

    run_test(checks, "agent_exit_removes_binding_and_cgroup", || {
        let mut child = rk_cmd(&[
            "run",
            "--profile",
            "agent",
            "--",
            PROBE,
            PROBE_FLAG,
            "hold",
            "1500",
        ])
        .spawn()
        .context("spawn holding agent")?;
        let mut stdout = BufReader::new(child.stdout.take().context("agent stdout")?);
        let mut line = String::new();
        stdout.read_line(&mut line).context("read ident line")?;
        let id = parse_ident(&line)?;
        let path = format!("{CGROUP_FS}{}", id.cgroup);

        let live_agents = agents()?;
        let listed = live_agents
            .iter()
            .any(|a| a["cgroup_id"].as_u64() == Some(id.cgroup_id));
        let bound = kernel_bindings(bpftool_ref)?.contains(&id.cgroup_id);
        let existed = Path::new(&path).is_dir();

        let mut rest = String::new();
        let _ = stdout.read_to_string(&mut rest);
        let out = finish(child, "holding agent")?;
        if !out.status.success() {
            bail!("holding agent failed: {}", text(&out));
        }
        if !(listed && bound && existed) {
            bail!("while running: listed={listed} bound={bound} cgroup_exists={existed}");
        }
        if Path::new(&path).exists() {
            bail!("{path} still exists after the agent exited");
        }
        if kernel_bindings(bpftool_ref)?.contains(&id.cgroup_id) {
            bail!(
                "binding for cgroup {} still in the kernel map",
                id.cgroup_id
            );
        }
        if agents()?
            .iter()
            .any(|a| a["cgroup_id"].as_u64() == Some(id.cgroup_id))
        {
            bail!("agent still listed by `rk status`");
        }
        Ok(format!(
            "while running: listed, bound and cgroup present; after exit: {path} removed, binding {} gone, not listed",
            id.cgroup_id
        ))
    });

    run_test(checks, "agent_session_id_in_events", || {
        let session = "rk-session-5a";
        let stdout = run_probe_ok(Some(session), &["first", DENIED_BIN, DENY_ADDR])?;
        let id = parse_ident(&stdout)?;
        wait_for_events("events tagged with the session id", |ev| {
            ev.iter().any(|e| {
                e["session_id"] == session
                    && e["cgroup_id"].as_u64() == Some(id.cgroup_id)
                    && e["verdict"].as_u64() == Some(VERDICT_DENY)
            })
        })?;
        Ok(format!(
            "deny events for cgroup {} carry session_id {session}",
            id.cgroup_id
        ))
    });

    drop(daemon);
}
