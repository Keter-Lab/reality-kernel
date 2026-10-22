//! Policy conformance corpus, kernel side (docs/design/phase-8.md §3.2).
//!
//! Reads `tests/conformance/*.toml` (the same files `rk-policy`'s
//! `conformance_userspace` test checks), binds each case's `case` profile to
//! a cgroup, creates its fixtures, and performs every operation for real in a
//! child placed in that cgroup. One named check, `conformance_kernel`, lists
//! every disagreement.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use aya::Btf;
use serde::Deserialize;

use crate::{run_test, wait_with_deadline, workloads, TestCheck, CHILD_DEADLINE};

pub const CONFORMANCE_FLAG: &str = "--conformance";

const CGROUP: &str = "/sys/fs/cgroup/rk.slice/conformance";
const FIXTURES: &str = "/run/rk-conf";

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    description: String,
    #[serde(default)]
    setup: Vec<String>,
    policy: String,
    op: Vec<Op>,
}

#[derive(Debug, Deserialize)]
struct Op {
    kind: String,
    target: String,
    #[serde(default)]
    proto: Option<String>,
    #[serde(default)]
    access: Option<String>,
    expect: String,
}

fn corpus(dir: &Path) -> Result<Vec<Case>> {
    let mut paths: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    paths.sort();
    paths
        .iter()
        .map(|p| {
            let text = fs::read_to_string(p)?;
            toml::from_str(&text).with_context(|| format!("parse {}", p.display()))
        })
        .collect()
}

/// Recreates the fixture directory with the case's files.
fn fixtures(case: &Case) -> Result<()> {
    if let Ok(entries) = fs::read_dir(FIXTURES) {
        for e in entries.flatten() {
            let p = e.path();
            let _ = if p.is_dir() { fs::remove_dir_all(&p) } else { fs::remove_file(&p) };
        }
    }
    for fixture in &case.setup {
        let (kind, path) = fixture
            .split_once(':')
            .with_context(|| format!("setup entry {fixture:?}"))?;
        let path = Path::new(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        match kind {
            "exec" => {
                fs::copy("/bin/true", path).with_context(|| format!("copy to {}", path.display()))?;
                fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
            }
            "file" => fs::write(path, b"rk")?,
            other => bail!("unknown setup kind {other}"),
        }
    }
    Ok(())
}

/// Runs one operation in the governed cgroup; true when the outcome matches.
fn perform(op: &Op) -> Result<(bool, String)> {
    let outcome = if op.expect == "deny" { "eperm" } else { "ok" };
    let (workload, args): (&str, Vec<&str>) = match op.kind.as_str() {
        "connect" if op.proto.as_deref() == Some("tcp") => ("tcp_connect", vec![op.target.as_str(), outcome]),
        "connect" => ("udp_connect", vec![op.target.as_str(), outcome]),
        "exec" => ("exec_cmd", vec![outcome, op.target.as_str()]),
        "open" => (
            "file_open",
            vec![op.target.as_str(), op.access.as_deref().unwrap_or("r"), outcome],
        ),
        other => bail!("unknown op kind {other}"),
    };
    let child = Command::new(std::env::current_exe()?)
        .arg(workloads::CHILD_FLAG)
        .arg(format!("{CGROUP}/cgroup.procs"))
        .arg(workload)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn conformance child")?;
    let out = wait_with_deadline(child, workload, CHILD_DEADLINE)?;
    Ok((
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    ))
}

fn setup_environment() {
    let _ = fs::create_dir_all(CGROUP);
    let _ = fs::create_dir_all(FIXTURES);
    let _ = Command::new("mount")
        .args(["-t", "tmpfs", "-o", "exec,mode=755", "tmpfs", FIXTURES])
        .stderr(Stdio::null())
        .status();
    for args in [
        &["link", "set", "lo", "up"][..],
        &["addr", "add", "10.99.0.2/24", "dev", "lo"][..],
        &["addr", "add", "fd99::1/64", "dev", "lo"][..],
    ] {
        let _ = Command::new("ip").args(args).stderr(Stdio::null()).status();
    }
}

pub fn run(dir: &Path, checks: &mut Vec<TestCheck>) {
    setup_environment();
    let prepared = (|| -> Result<_> {
        let cases = corpus(dir)?;
        let bytes = crate::bpf::rk_bpf_bytes().context("built without embedded BPF objects")?;
        let mut ebpf = rk_sensor::loader::open_bytes(bytes, "rk.bpf.o")?;
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
        let heartbeat = rk_sensor::resilience::Heartbeat::start(&mut ebpf, Duration::from_secs(30))?;
        rk_sensor::policy::attach_all(&mut ebpf, Path::new("/sys/fs/cgroup/rk.slice"))?;
        Ok((cases, ebpf, heartbeat))
    })();
    let (cases, mut ebpf, _heartbeat) = match prepared {
        Ok(p) => p,
        Err(e) => {
            checks.push(TestCheck::fail("conformance_setup", format!("{e:#}")));
            return;
        }
    };

    run_test(checks, "conformance_kernel", || {
        let mut engine = rk_sensor::policy::PolicyEngine::default();
        let (mut ops, mut failures) = (0, Vec::new());
        for case in &cases {
            fixtures(case).with_context(|| format!("{}: fixtures", case.name))?;
            let text = format!(
                "{}\n[[bindings]]\ncgroup = \"rk.slice/conformance\"\nprofile = \"case\"\n",
                case.policy
            );
            if let Err(e) = engine.apply_text(&mut ebpf, &text) {
                failures.push(format!("{}: policy rejected: {e:#}", case.name));
                continue;
            }
            for op in &case.op {
                ops += 1;
                match perform(op) {
                    Ok((true, _)) => {}
                    Ok((false, stderr)) => failures.push(format!(
                        "{}: {} {} expected {} ({}): {stderr}",
                        case.name, op.kind, op.target, op.expect, case.description
                    )),
                    Err(e) => failures.push(format!("{}: {} {}: {e:#}", case.name, op.kind, op.target)),
                }
            }
        }
        if !failures.is_empty() {
            bail!("{} of {ops} operations disagree: {}", failures.len(), failures.join("; "));
        }
        Ok(format!("{} cases, {ops} operations: the kernel agrees with every expectation", cases.len()))
    });
}
