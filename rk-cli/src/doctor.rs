//! `rk doctor`: host preflight (docs/design/phase-10.md §6).
//!
//! Each check reports `ok`, `warn`, `fail` or `info`, what it found, and how
//! to fix it. Exit status 2 when any check failed. Every path is read below
//! an injectable root, so tests run the checks against fake trees.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// Oldest kernel in the supported matrix (docs/kernel-matrix.md).
const SUPPORTED: (u64, u64) = (5, 15);
/// Oldest kernel with the BPF features the sensor uses at all (ring buffer).
const MINIMUM: (u64, u64) = (5, 8);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Info,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub kernel: String,
    pub ok: bool,
    pub checks: Vec<Check>,
}

fn check(
    name: &'static str,
    status: Status,
    detail: impl Into<String>,
    fix: Option<&str>,
) -> Check {
    Check {
        name,
        status,
        detail: detail.into(),
        fix: fix.map(str::to_string),
    }
}

/// The host as seen from `root` (`/` in production).
pub struct Host {
    root: PathBuf,
}

impl Host {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn path(&self, p: &str) -> PathBuf {
        self.root.join(p.trim_start_matches('/'))
    }

    fn read(&self, p: &str) -> Option<String> {
        fs::read_to_string(self.path(p))
            .ok()
            .map(|s| s.trim().to_string())
    }

    fn exists(&self, p: &str) -> bool {
        self.path(p).exists()
    }
}

/// `(major, minor)` of a kernel release string such as `6.8.0-1017-azure`.
pub fn parse_release(release: &str) -> Option<(u64, u64)> {
    let mut parts = release.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor: String = parts
        .next()?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    Some((major, minor.parse().ok()?))
}

fn kernel_version(release: &str) -> Check {
    match parse_release(release) {
        Some(v) if v >= SUPPORTED => check(
            "kernel_version",
            Status::Ok,
            format!("{release} (supported: 5.15 and later)"),
            None,
        ),
        Some(v) if v >= MINIMUM => check(
            "kernel_version",
            Status::Warn,
            format!("{release} is below the supported matrix (5.15 and later)"),
            Some("use a 5.15 or newer kernel; older ones are untested"),
        ),
        Some(_) => check(
            "kernel_version",
            Status::Fail,
            format!("{release}: the sensor needs at least 5.8 (BPF ring buffer)"),
            Some("upgrade the kernel to 5.15 or newer"),
        ),
        None => check(
            "kernel_version",
            Status::Warn,
            format!("cannot parse kernel release `{release}`"),
            None,
        ),
    }
}

fn btf(h: &Host) -> Check {
    if h.exists("/sys/kernel/btf/vmlinux") {
        check("btf", Status::Ok, "/sys/kernel/btf/vmlinux present", None)
    } else {
        check(
            "btf",
            Status::Fail,
            "no kernel BTF: the CO-RE programs cannot be relocated",
            Some("use a kernel built with CONFIG_DEBUG_INFO_BTF=y (default on current distribution kernels)"),
        )
    }
}

/// Kernel config from `/boot/config-<release>` or `/lib/modules/<release>/config`.
fn kernel_config(h: &Host, release: &str) -> Check {
    let text = [
        format!("/boot/config-{release}"),
        format!("/lib/modules/{release}/config"),
    ]
    .iter()
    .find_map(|p| h.read(p));
    let Some(text) = text else {
        return check(
            "kernel_config",
            Status::Info,
            "kernel config not found in /boot or /lib/modules; the checks below test the features directly",
            None,
        );
    };
    let enabled = |opt: &str| {
        text.lines()
            .any(|l| l.strip_prefix(opt).is_some_and(|v| v == "=y" || v == "=m"))
    };
    let required = [
        "CONFIG_BPF_SYSCALL",
        "CONFIG_CGROUP_BPF",
        "CONFIG_DEBUG_INFO_BTF",
    ];
    let recommended = ["CONFIG_BPF_LSM", "CONFIG_BPF_JIT"];
    let missing: Vec<&str> = required.iter().copied().filter(|o| !enabled(*o)).collect();
    let weak: Vec<&str> = recommended
        .iter()
        .copied()
        .filter(|o| !enabled(*o))
        .collect();
    if !missing.is_empty() {
        check(
            "kernel_config",
            Status::Fail,
            format!("missing {}", missing.join(", ")),
            Some("use a kernel built with these options"),
        )
    } else if !weak.is_empty() {
        check(
            "kernel_config",
            Status::Warn,
            format!("missing {}", weak.join(", ")),
            Some("without CONFIG_BPF_LSM only network rules can be enforced"),
        )
    } else {
        check(
            "kernel_config",
            Status::Ok,
            "BPF, cgroup BPF, BTF, BPF LSM and JIT enabled",
            None,
        )
    }
}

fn bpf_lsm(h: &Host) -> Check {
    match h.read("/sys/kernel/security/lsm") {
        Some(list) if list.split(',').any(|l| l.trim() == "bpf") => {
            check("bpf_lsm", Status::Ok, format!("active ({list})"), None)
        }
        Some(list) => {
            let fix = format!(
                "add `lsm={list},bpf` to the kernel command line (GRUB_CMDLINE_LINUX in /etc/default/grub, then update-grub or grub2-mkconfig) and reboot"
            );
            check(
                "bpf_lsm",
                Status::Warn,
                format!("not active ({list}): only network rules can be enforced; exec, file and raw-socket rules are refused"),
                Some(fix.as_str()),
            )
        }
        None => check(
            "bpf_lsm",
            Status::Warn,
            "cannot read /sys/kernel/security/lsm (securityfs not mounted?)",
            Some("mount -t securityfs securityfs /sys/kernel/security"),
        ),
    }
}

fn cgroup_v2(h: &Host) -> Check {
    if h.exists("/sys/fs/cgroup/cgroup.controllers") {
        check(
            "cgroup_v2",
            Status::Ok,
            "unified cgroup v2 hierarchy at /sys/fs/cgroup",
            None,
        )
    } else {
        check(
            "cgroup_v2",
            Status::Fail,
            "no cgroup v2 hierarchy at /sys/fs/cgroup: every binding is a cgroup v2 cgroup",
            Some("boot with systemd.unified_cgroup_hierarchy=1 (the default on current distributions)"),
        )
    }
}

fn bpffs(h: &Host) -> Check {
    let mounted = h.read("/proc/self/mounts").is_some_and(|m| {
        m.lines().any(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            f.len() > 2 && f[1] == "/sys/fs/bpf" && f[2] == "bpf"
        })
    });
    if mounted {
        check("bpffs", Status::Ok, "bpffs mounted at /sys/fs/bpf", None)
    } else {
        check(
            "bpffs",
            Status::Fail,
            "bpffs is not mounted at /sys/fs/bpf: pins, which keep enforcement running across restarts, live there",
            Some("mount -t bpf bpf /sys/fs/bpf (systemd does this at boot)"),
        )
    }
}

/// The bracketed entry of `none [integrity] confidentiality`.
pub fn lockdown_mode(text: &str) -> Option<&str> {
    let start = text.find('[')? + 1;
    let end = start + text[start..].find(']')?;
    Some(&text[start..end])
}

fn lockdown(h: &Host) -> Check {
    match h
        .read("/sys/kernel/security/lockdown")
        .as_deref()
        .and_then(lockdown_mode)
    {
        Some("confidentiality") => check(
            "lockdown",
            Status::Fail,
            "lockdown=confidentiality forbids the kernel memory reads the programs make",
            Some("boot with lockdown=integrity instead"),
        ),
        Some("integrity") => check("lockdown", Status::Ok, "lockdown=integrity", None),
        Some(mode) => check(
            "lockdown",
            Status::Info,
            format!("lockdown={mode}"),
            Some("lockdown=integrity is recommended (docs/hardening.md)"),
        ),
        None => check(
            "lockdown",
            Status::Info,
            "kernel lockdown not available",
            None,
        ),
    }
}

fn unprivileged_bpf(h: &Host) -> Check {
    match h
        .read("/proc/sys/kernel/unprivileged_bpf_disabled")
        .as_deref()
    {
        Some("1") | Some("2") => check(
            "unprivileged_bpf",
            Status::Ok,
            "unprivileged bpf() disabled",
            None,
        ),
        Some(v) => check(
            "unprivileged_bpf",
            Status::Warn,
            format!("kernel.unprivileged_bpf_disabled = {v}"),
            Some("sysctl -w kernel.unprivileged_bpf_disabled=2 (docs/hardening.md)"),
        ),
        None => check(
            "unprivileged_bpf",
            Status::Info,
            "sysctl not readable",
            None,
        ),
    }
}

fn bpf_jit(h: &Host) -> Check {
    match h.read("/proc/sys/net/core/bpf_jit_enable").as_deref() {
        Some("0") => check(
            "bpf_jit",
            Status::Warn,
            "BPF JIT disabled: programs run in the interpreter, slower",
            Some("sysctl -w net.core.bpf_jit_enable=1"),
        ),
        Some(v) => check(
            "bpf_jit",
            Status::Ok,
            format!("net.core.bpf_jit_enable = {v}"),
            None,
        ),
        None => check("bpf_jit", Status::Info, "sysctl not readable", None),
    }
}

fn sensor(h: &Host) -> Check {
    let pins = h.exists("/sys/fs/bpf/rk");
    let socket = h.exists("/run/rk/agentd.sock");
    match (pins, socket) {
        (true, true) => check("sensor", Status::Ok, "running: pins at /sys/fs/bpf/rk, agentd socket present", None),
        (true, false) => check(
            "sensor",
            Status::Warn,
            "pins present but the sensor is not running: governed ENFORCE workloads are denied once the heartbeat is stale",
            Some("systemctl start rk-sensor, or rk-sensor --uninstall to end protection"),
        ),
        (false, _) => check("sensor", Status::Info, "not running (no pins at /sys/fs/bpf/rk)", None),
    }
}

/// Runs every check against `host` for kernel `release`.
pub fn run_checks(h: &Host, release: &str) -> Report {
    let checks = vec![
        kernel_version(release),
        btf(h),
        kernel_config(h, release),
        bpf_lsm(h),
        cgroup_v2(h),
        bpffs(h),
        lockdown(h),
        unprivileged_bpf(h),
        bpf_jit(h),
        sensor(h),
    ];
    Report {
        kernel: release.to_string(),
        ok: checks.iter().all(|c| c.status != Status::Fail),
        checks,
    }
}

fn status_word(s: Status) -> &'static str {
    match s {
        Status::Ok => "ok",
        Status::Info => "info",
        Status::Warn => "WARN",
        Status::Fail => "FAIL",
    }
}

/// `rk doctor`: prints the report; true when nothing failed.
pub fn run(as_json: bool) -> anyhow::Result<bool> {
    let host = Host::new("/");
    let release = host.read("/proc/sys/kernel/osrelease").unwrap_or_default();
    let report = run_checks(&host, &release);
    if as_json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Reality Kernel preflight (kernel {})", report.kernel);
        for c in &report.checks {
            println!("  {:4}  {:17} {}", status_word(c.status), c.name, c.detail);
            if let (Some(fix), Status::Warn | Status::Fail) = (&c.fix, c.status) {
                println!("        {:17} fix: {fix}", "");
            }
        }
        println!(
            "{}",
            if report.ok {
                "No blocking problem found."
            } else {
                "Blocking problems found: fix the FAIL lines above."
            }
        );
    }
    Ok(report.ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake host tree with the files a healthy, LSM-enabled host has.
    fn healthy(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("rk-doctor-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let put = |p: &str, text: &str| {
            let path = root.join(p.trim_start_matches('/'));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        };
        put("/sys/kernel/btf/vmlinux", "btf");
        put(
            "/sys/kernel/security/lsm",
            "lockdown,capability,landlock,yama,bpf\n",
        );
        put(
            "/sys/kernel/security/lockdown",
            "none [integrity] confidentiality\n",
        );
        put("/sys/fs/cgroup/cgroup.controllers", "cpu memory\n");
        put(
            "/proc/self/mounts",
            "cgroup2 /sys/fs/cgroup cgroup2 rw 0 0\nbpf /sys/fs/bpf bpf rw 0 0\n",
        );
        put("/proc/sys/kernel/unprivileged_bpf_disabled", "2\n");
        put("/proc/sys/net/core/bpf_jit_enable", "1\n");
        put(
            "/boot/config-6.12.0",
            "CONFIG_BPF_SYSCALL=y\nCONFIG_CGROUP_BPF=y\nCONFIG_DEBUG_INFO_BTF=y\nCONFIG_BPF_LSM=y\nCONFIG_BPF_JIT=y\n",
        );
        root
    }

    fn status(r: &Report, name: &str) -> Status {
        r.checks.iter().find(|c| c.name == name).unwrap().status
    }

    #[test]
    fn healthy_host_passes() {
        let root = healthy("ok");
        let r = run_checks(&Host::new(&root), "6.12.0");
        assert!(r.ok, "{:?}", r.checks);
        for name in [
            "kernel_version",
            "btf",
            "kernel_config",
            "bpf_lsm",
            "cgroup_v2",
            "bpffs",
            "lockdown",
        ] {
            assert_eq!(status(&r, name), Status::Ok, "{name}");
        }
        assert_eq!(status(&r, "sensor"), Status::Info);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_bpf_lsm_is_explained_as_a_warning() {
        let root = healthy("nolsm");
        fs::write(
            root.join("sys/kernel/security/lsm"),
            "lockdown,capability,yama,apparmor\n",
        )
        .unwrap();
        let r = run_checks(&Host::new(&root), "6.12.0");
        assert!(r.ok);
        let c = r.checks.iter().find(|c| c.name == "bpf_lsm").unwrap();
        assert_eq!(c.status, Status::Warn);
        assert!(c
            .fix
            .as_deref()
            .unwrap()
            .contains("lsm=lockdown,capability,yama,apparmor,bpf"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn blocking_problems_fail() {
        let root = healthy("fail");
        fs::remove_file(root.join("sys/kernel/btf/vmlinux")).unwrap();
        fs::remove_file(root.join("sys/fs/cgroup/cgroup.controllers")).unwrap();
        fs::write(
            root.join("proc/self/mounts"),
            "cgroup2 /sys/fs/cgroup cgroup2 rw 0 0\n",
        )
        .unwrap();
        fs::write(
            root.join("sys/kernel/security/lockdown"),
            "none integrity [confidentiality]\n",
        )
        .unwrap();
        fs::write(root.join("boot/config-6.12.0"), "CONFIG_BPF_SYSCALL=y\n").unwrap();
        let r = run_checks(&Host::new(&root), "6.12.0");
        assert!(!r.ok);
        for name in ["btf", "cgroup_v2", "bpffs", "lockdown", "kernel_config"] {
            assert_eq!(status(&r, name), Status::Fail, "{name}");
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn kernel_versions_are_graded() {
        assert_eq!(kernel_version("6.8.0-1017-azure").status, Status::Ok);
        assert_eq!(kernel_version("5.15.222").status, Status::Ok);
        assert_eq!(kernel_version("5.10.0").status, Status::Warn);
        assert_eq!(kernel_version("4.19.0").status, Status::Fail);
        assert_eq!(parse_release("6.12.3-rc1"), Some((6, 12)));
        assert_eq!(lockdown_mode("[none] integrity"), Some("none"));
    }

    #[test]
    fn stale_pins_without_a_sensor_are_flagged() {
        let root = healthy("pins");
        fs::create_dir_all(root.join("sys/fs/bpf/rk")).unwrap();
        let r = run_checks(&Host::new(&root), "6.12.0");
        assert_eq!(status(&r, "sensor"), Status::Warn);
        let _ = fs::remove_dir_all(&root);
    }
}
