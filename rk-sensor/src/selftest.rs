//! `rk-sensor --selftest`: loads every embedded program through the kernel
//! verifier, runs functional checks, and prints a machine-readable report.
//!
//! Exit codes:
//! - 0: every program loaded and every check passed;
//! - 1: a program failed to load or attach, or a functional check failed;
//! - 2: a required kernel feature is missing (the sensor could only run
//!   audit-only). Reported loudly, never as success.
//!
//! The functional checks drive the real kernel paths: the LSM hook must run,
//! cgroup/connect4 must deny TEST-NET-1 with EPERM inside a temporary cgroup,
//! and the records both programs emit through the production helpers must
//! decode with the production decoder and carry the expected values.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::loader::ProgramReport;

/// Internal flag used to re-execute the binary as the selftest child.
pub const CHILD_FLAG: &str = "--selftest-child";

pub const EXIT_OK: i32 = 0;
pub const EXIT_FAILED: i32 = 1;
pub const EXIT_MISSING_FEATURE: i32 = 2;

/// Port used for the TEST-NET-1 connect attempt (discard).
const TEST_PORT: u16 = 9;
const IPPROTO_TCP: u8 = 6;
const AF_INET: u16 = 2;
const TEST_RULE_ID: u32 = 1;
const TEST_POLICY_GEN: u64 = 1;
/// 192.0.2.1 as an IPv4-mapped IPv6 address.
const TEST_NET_1_MAPPED: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1];

#[derive(Debug, Serialize)]
pub struct Capabilities {
    pub kernel_release: String,
    pub arch: &'static str,
    /// `None` when securityfs is not readable.
    pub bpf_lsm_active: Option<bool>,
    pub btf_present: bool,
    pub cgroup_v2: bool,
    pub effective_capabilities: Vec<&'static str>,
}

impl Capabilities {
    pub fn detect() -> Self {
        Capabilities {
            kernel_release: fs::read_to_string("/proc/sys/kernel/osrelease")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            arch: std::env::consts::ARCH,
            bpf_lsm_active: fs::read_to_string("/sys/kernel/security/lsm")
                .ok()
                .map(|s| lsm_list_has_bpf(&s)),
            btf_present: Path::new("/sys/kernel/btf/vmlinux").exists(),
            cgroup_v2: Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
            effective_capabilities: fs::read_to_string("/proc/self/status")
                .map(|s| effective_caps(&s))
                .unwrap_or_default(),
        }
    }

    pub fn missing_features(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.btf_present {
            missing.push("btf");
        }
        if self.bpf_lsm_active != Some(true) {
            missing.push("bpf_lsm");
        }
        if !self.cgroup_v2 {
            missing.push("cgroup_v2");
        }
        missing
    }
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

impl Check {
    fn new(name: &'static str, passed: bool, detail: impl Into<String>) -> Self {
        Check {
            name,
            passed,
            detail: detail.into(),
        }
    }

    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        Check::new(name, false, detail)
    }
}

#[derive(Debug, Serialize)]
pub struct SelftestReport {
    pub sensor_version: &'static str,
    pub abi_version: u32,
    pub capabilities: Capabilities,
    pub missing_features: Vec<&'static str>,
    pub programs: Vec<ProgramReport>,
    /// Results of the `rk_probe_*` programs, keyed by feature name.
    pub kernel_features: BTreeMap<String, bool>,
    pub checks: Vec<Check>,
    pub enforcement_available: bool,
    pub exit_code: i32,
}

impl SelftestReport {
    fn finish(&mut self) {
        self.missing_features = self.capabilities.missing_features();
        let program_failed = self.programs.iter().any(|p| !p.probe && !p.loaded);
        let check_failed = self.checks.iter().any(|c| !c.passed);

        self.enforcement_available =
            !program_failed && !check_failed && self.missing_features.is_empty();
        self.exit_code = if program_failed {
            EXIT_FAILED
        } else if !self.missing_features.is_empty() {
            EXIT_MISSING_FEATURE
        } else if check_failed {
            EXIT_FAILED
        } else {
            EXIT_OK
        };
    }
}

pub fn run() -> SelftestReport {
    let mut report = SelftestReport {
        sensor_version: env!("CARGO_PKG_VERSION"),
        abi_version: rk_ebpf_common::RK_ABI_VERSION,
        capabilities: Capabilities::detect(),
        missing_features: Vec::new(),
        programs: Vec::new(),
        kernel_features: BTreeMap::new(),
        checks: Vec::new(),
        enforcement_available: false,
        exit_code: EXIT_FAILED,
    };

    #[cfg(target_os = "linux")]
    linux::run_checks(&mut report);
    #[cfg(not(target_os = "linux"))]
    report
        .checks
        .push(Check::fail("platform", "the selftest requires Linux"));

    report.finish();
    report
}

/// Body of the re-executed child: joins the temporary cgroup, opens the probe
/// file (LSM file_open record) and connects to TEST-NET-1 (connect4 record).
/// Returns 0 only if the connect fails with EPERM.
pub fn run_child(args: &[String]) -> i32 {
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    let (Some(procs), Some(probe_file)) = (args.first(), args.get(1)) else {
        return 20;
    };
    if fs::write(procs, std::process::id().to_string()).is_err() {
        return 21;
    }
    if fs::File::open(probe_file).is_err() {
        return 22;
    }
    let addr = SocketAddr::from(([192, 0, 2, 1], TEST_PORT));
    match TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
        Ok(_) => 23,
        Err(e) if e.raw_os_error() == Some(1) => 0,
        Err(_) => 24,
    }
}

fn describe_child(code: Option<i32>) -> String {
    match code {
        Some(0) => "connect to 192.0.2.1 failed with EPERM".to_string(),
        Some(20) => "child: missing arguments".to_string(),
        Some(21) => "child: could not join the temporary cgroup".to_string(),
        Some(22) => "child: could not open the probe file".to_string(),
        Some(23) => "connect to 192.0.2.1 succeeded: deny not enforced".to_string(),
        Some(24) => "connect to 192.0.2.1 failed with an error other than EPERM".to_string(),
        Some(other) => format!("child exited with unexpected code {other}"),
        None => "child terminated by a signal".to_string(),
    }
}

fn lsm_list_has_bpf(list: &str) -> bool {
    list.trim().split(',').any(|lsm| lsm == "bpf")
}

fn effective_caps(status: &str) -> Vec<&'static str> {
    const CAPS: [(u32, &str); 5] = [
        (12, "CAP_NET_ADMIN"),
        (21, "CAP_SYS_ADMIN"),
        (24, "CAP_SYS_RESOURCE"),
        (38, "CAP_PERFMON"),
        (39, "CAP_BPF"),
    ];
    let mask = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
        .unwrap_or(0);
    CAPS.iter()
        .filter(|(bit, _)| mask & (1u64 << bit) != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// Converts a userspace `st_dev` (glibc/musl encoding) to the kernel's
/// internal `dev_t` encoding (`MAJOR << 20 | MINOR`) used in ABI records.
pub fn kernel_dev(st_dev: u64) -> u64 {
    let major = ((st_dev >> 32) & 0xffff_f000) | ((st_dev >> 8) & 0x0000_0fff);
    let minor = ((st_dev >> 12) & 0xffff_ff00) | (st_dev & 0x0000_00ff);
    (major << 20) | minor
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::process::Command;
    use std::{fs, io};

    use aya::maps::{Array, HashMap as BpfHashMap, PerCpuArray, RingBuf};
    use aya::programs::{CgroupAttachMode, CgroupSockAddr, Lsm};
    use aya::{Btf, Ebpf};
    use rk_ebpf_common::{rk_counter, rk_hdr, rk_payload_file, rk_payload_net, rk_verdict};

    use super::*;
    use crate::decoder::{self, Payload};
    use crate::loader::{self, Object};

    pub(super) fn run_checks(report: &mut SelftestReport) {
        let btf = Btf::from_sys_fs().ok();

        match loader::open(Object::Production) {
            Ok(mut ebpf) => {
                report.programs.extend(loader::load_programs(
                    Object::Production,
                    &mut ebpf,
                    btf.as_ref(),
                ));
                let ok = ebpf.map("events_ringbuf").is_some();
                report.checks.push(Check::new(
                    "production_object_maps",
                    ok,
                    if ok {
                        "events_ringbuf present"
                    } else {
                        "events_ringbuf missing"
                    },
                ));
            }
            Err(e) => report
                .checks
                .push(Check::fail("production_object_open", format!("{e:#}"))),
        }

        match loader::open(Object::Probes) {
            Ok(mut probes) => {
                for p in loader::load_programs(Object::Probes, &mut probes, btf.as_ref()) {
                    let feature = p.name.trim_start_matches(loader::PROBE_PREFIX).to_string();
                    report.kernel_features.insert(feature, p.loaded);
                    report.programs.push(p);
                }
            }
            Err(e) => report
                .checks
                .push(Check::fail("probes_object_open", format!("{e:#}"))),
        }

        let mut ebpf = match loader::open(Object::Selftest) {
            Ok(ebpf) => ebpf,
            Err(e) => {
                report
                    .checks
                    .push(Check::fail("selftest_object_open", format!("{e:#}")));
                return;
            }
        };

        let programs = loader::load_programs(Object::Selftest, &mut ebpf, btf.as_ref());
        let is_loaded = |name: &str| programs.iter().any(|p| p.name == name && p.loaded);
        let lsm_loaded = is_loaded("rk_test_lsm_open");
        let connect_loaded = is_loaded("rk_test_connect4");
        report.programs.extend(programs);

        if lsm_loaded {
            report.checks.push(check_lsm_runs(&mut ebpf));
        }
        if lsm_loaded && connect_loaded {
            report.checks.extend(check_cgroup_roundtrip(&mut ebpf));
        }
        report.checks.push(check_no_drops(&ebpf));
    }

    fn err(e: impl std::fmt::Display) -> String {
        e.to_string()
    }

    fn lsm_counter(ebpf: &Ebpf) -> Result<u64, String> {
        let map = ebpf
            .map("lsm_exec_counter")
            .ok_or_else(|| "lsm_exec_counter map missing".to_string())?;
        let counter = Array::<_, u64>::try_from(map).map_err(err)?;
        counter.get(&0, 0).map_err(err)
    }

    fn check_lsm_runs(ebpf: &mut Ebpf) -> Check {
        const NAME: &str = "lsm_file_open_runs";
        let attached = ebpf
            .program_mut("rk_test_lsm_open")
            .ok_or_else(|| "program missing".to_string())
            .and_then(|p| <&mut Lsm>::try_from(p).map_err(err))
            .and_then(|lsm| lsm.attach().map_err(err));
        if let Err(e) = attached {
            return Check::fail(NAME, format!("attach failed: {e}"));
        }

        let before = match lsm_counter(ebpf) {
            Ok(v) => v,
            Err(e) => return Check::fail(NAME, e),
        };
        let _ = fs::read("/proc/self/stat");
        match lsm_counter(ebpf) {
            Ok(after) => Check::new(NAME, after > before, format!("counter {before} -> {after}")),
            Err(e) => Check::fail(NAME, e),
        }
    }

    fn check_cgroup_roundtrip(ebpf: &mut Ebpf) -> Vec<Check> {
        let pid = std::process::id();
        let cgroup_dir = format!("/sys/fs/cgroup/rk_selftest_{pid}");
        let probe_file = std::env::temp_dir().join(format!("rk_selftest_{pid}.probe"));
        let result = cgroup_roundtrip(ebpf, Path::new(&cgroup_dir), &probe_file);
        let _ = fs::remove_file(&probe_file);
        let _ = fs::remove_dir(&cgroup_dir);
        result.unwrap_or_else(|e| vec![Check::fail("cgroup_roundtrip_setup", e)])
    }

    fn cgroup_roundtrip(
        ebpf: &mut Ebpf,
        cgroup_dir: &Path,
        probe_file: &Path,
    ) -> Result<Vec<Check>, String> {
        let ctx = |what: &str, e: io::Error| format!("{what}: {e}");

        fs::create_dir(cgroup_dir).map_err(|e| ctx("create temporary cgroup", e))?;
        let cgroup_id = fs::metadata(cgroup_dir)
            .map_err(|e| ctx("stat temporary cgroup", e))?
            .ino();
        fs::write(probe_file, b"rk").map_err(|e| ctx("create probe file", e))?;
        let probe_meta = fs::metadata(probe_file).map_err(|e| ctx("stat probe file", e))?;
        let expected = ExpectedFile {
            cgroup_id,
            ino: probe_meta.ino(),
            dev: kernel_dev(probe_meta.dev()),
            name: probe_file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        };

        {
            let map = ebpf
                .map_mut("monitored_cgroups")
                .ok_or_else(|| "monitored_cgroups map missing".to_string())?;
            let mut governed = BpfHashMap::<_, u64, u64>::try_from(map).map_err(err)?;
            governed
                .insert(cgroup_id, TEST_POLICY_GEN, 0)
                .map_err(err)?;
        }
        {
            let cgroup = fs::File::open(cgroup_dir).map_err(|e| ctx("open temporary cgroup", e))?;
            let program = ebpf
                .program_mut("rk_test_connect4")
                .ok_or_else(|| "rk_test_connect4 missing".to_string())?;
            let connect4 = <&mut CgroupSockAddr>::try_from(program).map_err(err)?;
            // On kernels with BPF links (>= 5.7) aya attaches via bpf_link_create,
            // which rejects any attach flags for cgroups (EINVAL) and is always
            // multi-attach. AllowMultiple only matters for legacy prog_attach.
            connect4
                .attach(&cgroup, CgroupAttachMode::Single)
                .map_err(|e| format!("attach connect4: {e:?}"))?;
        }

        let exe = std::env::current_exe().map_err(|e| ctx("locate own executable", e))?;
        let status = Command::new(exe)
            .arg(CHILD_FLAG)
            .arg(cgroup_dir.join("cgroup.procs"))
            .arg(probe_file)
            .status()
            .map_err(|e| ctx("spawn selftest child", e))?;
        let child_code = status.code();

        let mut checks = vec![Check::new(
            "connect4_denies_test_net",
            child_code == Some(0),
            describe_child(child_code),
        )];
        checks.extend(drain_and_verify(ebpf, &expected)?);
        Ok(checks)
    }

    struct ExpectedFile {
        cgroup_id: u64,
        ino: u64,
        dev: u64,
        name: String,
    }

    fn drain_and_verify(ebpf: &mut Ebpf, expected: &ExpectedFile) -> Result<Vec<Check>, String> {
        let map = ebpf
            .map_mut("events_ringbuf")
            .ok_or_else(|| "events_ringbuf map missing".to_string())?;
        let mut ring = RingBuf::try_from(map).map_err(err)?;

        let mut records = 0usize;
        let mut decode_errors = Vec::new();
        let mut file_result: Option<Vec<String>> = None;
        let mut net_result: Option<Vec<String>> = None;

        while let Some(item) = ring.next() {
            records += 1;
            match decoder::decode(&item) {
                Ok(event) => match event.payload {
                    Payload::File { body, mut strings } => {
                        let is_probe = event.hdr.cgroup_id == expected.cgroup_id
                            && strings.next() == Some(expected.name.as_bytes());
                        if is_probe && file_result.is_none() {
                            file_result = Some(verify_file(&event.hdr, &body, expected));
                        }
                    }
                    Payload::Net { body }
                        if body.daddr_v6 == TEST_NET_1_MAPPED && net_result.is_none() =>
                    {
                        net_result = Some(verify_net(&event.hdr, &body));
                    }
                    _ => {}
                },
                Err(e) => decode_errors.push(e.to_string()),
            }
        }

        Ok(vec![
            Check::new(
                "ringbuf_records_decode",
                records > 0 && decode_errors.is_empty(),
                format!(
                    "{records} records, {} rejected {decode_errors:?}",
                    decode_errors.len()
                ),
            ),
            verdict_check("abi_roundtrip_file_open", file_result),
            verdict_check("abi_roundtrip_net_connect", net_result),
        ])
    }

    fn verdict_check(name: &'static str, result: Option<Vec<String>>) -> Check {
        match result {
            None => Check::fail(name, "no matching record received"),
            Some(problems) if problems.is_empty() => Check::new(name, true, "all fields match"),
            Some(problems) => Check::fail(name, problems.join("; ")),
        }
    }

    fn expect<T: PartialEq + std::fmt::Debug>(
        problems: &mut Vec<String>,
        field: &str,
        got: T,
        want: T,
    ) {
        if got != want {
            problems.push(format!("{field}: got {got:?}, want {want:?}"));
        }
    }

    fn verify_file(hdr: &rk_hdr, body: &rk_payload_file, expected: &ExpectedFile) -> Vec<String> {
        let mut p = Vec::new();
        expect(
            &mut p,
            "verdict",
            u32::from(hdr.verdict),
            rk_verdict::RK_VERDICT_ALLOW,
        );
        expect(&mut p, "policy_gen", hdr.policy_gen, TEST_POLICY_GEN);
        expect(&mut p, "pid_set", hdr.pid != 0, true);
        expect(&mut p, "file_ino", body.file_ino, expected.ino);
        expect(&mut p, "file_dev", body.file_dev, expected.dev);
        expect(&mut p, "str_count", body.str_count, 1);
        p
    }

    fn verify_net(hdr: &rk_hdr, body: &rk_payload_net) -> Vec<String> {
        let mut p = Vec::new();
        expect(
            &mut p,
            "verdict",
            u32::from(hdr.verdict),
            rk_verdict::RK_VERDICT_DENY,
        );
        expect(&mut p, "rule_id", hdr.rule_id, TEST_RULE_ID);
        expect(&mut p, "dport", body.dport, TEST_PORT);
        expect(&mut p, "family", body.family, AF_INET);
        expect(&mut p, "protocol", body.protocol, IPPROTO_TCP);
        p
    }

    fn check_no_drops(ebpf: &Ebpf) -> Check {
        const NAME: &str = "ringbuf_no_drops";
        let drops = ebpf
            .map("rk_counters")
            .ok_or_else(|| "rk_counters map missing".to_string())
            .and_then(|map| PerCpuArray::<_, u64>::try_from(map).map_err(err))
            .and_then(|counters| {
                counters
                    .get(&rk_counter::RK_CNT_RINGBUF_DROP, 0)
                    .map_err(err)
            })
            .map(|per_cpu| per_cpu.iter().sum::<u64>());
        match drops {
            Ok(0) => Check::new(NAME, true, "0 dropped events"),
            Ok(n) => Check::fail(NAME, format!("{n} dropped events")),
            Err(e) => Check::fail(NAME, e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_dev_encoding() {
        /// glibc `makedev`.
        fn makedev(major: u64, minor: u64) -> u64 {
            ((major & 0xfff) << 8)
                | ((major & !0xfff) << 32)
                | (minor & 0xff)
                | ((minor & !0xff) << 12)
        }
        // 8:1 (sda1) in glibc encoding is 0x801.
        assert_eq!(kernel_dev(0x801), (8 << 20) | 1);
        // Kernel dev_t has 12 major / 20 minor bits; cover both split ranges.
        for (major, minor) in [(8, 1), (259, 65536), (4095, 255), (4095, 1_048_575)] {
            assert_eq!(kernel_dev(makedev(major, minor)), (major << 20) | minor);
        }
    }

    #[test]
    fn parses_lsm_list() {
        assert!(lsm_list_has_bpf("lockdown,capability,landlock,yama,bpf\n"));
        assert!(!lsm_list_has_bpf("lockdown,capability,apparmor"));
        assert!(!lsm_list_has_bpf("bpfx"));
    }

    #[test]
    fn parses_effective_caps() {
        let status = "Name:\tx\nCapEff:\t000001c000001000\n";
        assert_eq!(
            effective_caps(status),
            vec!["CAP_NET_ADMIN", "CAP_PERFMON", "CAP_BPF"]
        );
        assert!(effective_caps("CapEff:\t0000000000000000").is_empty());
    }

    fn report(
        programs: Vec<ProgramReport>,
        checks: Vec<Check>,
        all_features: bool,
    ) -> SelftestReport {
        SelftestReport {
            sensor_version: "test",
            abi_version: 1,
            capabilities: Capabilities {
                kernel_release: "test".into(),
                arch: "x86_64",
                bpf_lsm_active: Some(all_features),
                btf_present: true,
                cgroup_v2: true,
                effective_capabilities: Vec::new(),
            },
            missing_features: Vec::new(),
            programs,
            kernel_features: BTreeMap::new(),
            checks,
            enforcement_available: false,
            exit_code: -1,
        }
    }

    fn program(name: &str, loaded: bool) -> ProgramReport {
        ProgramReport {
            object: "rk_selftest.bpf.o",
            name: name.to_string(),
            kind: "lsm",
            probe: name.starts_with(crate::loader::PROBE_PREFIX),
            loaded,
            error: None,
        }
    }

    #[test]
    fn verifier_rejection_fails_even_with_missing_features() {
        let mut r = report(vec![program("rk_test_lsm_open", false)], vec![], false);
        r.finish();
        assert_eq!(r.exit_code, EXIT_FAILED);
        assert!(!r.enforcement_available);
    }

    #[test]
    fn probe_rejection_is_not_a_failure() {
        let mut r = report(vec![program("rk_probe_x", false)], vec![], true);
        r.finish();
        assert_eq!(r.exit_code, EXIT_OK);
        assert!(r.enforcement_available);
    }

    #[test]
    fn missing_feature_is_reported_as_degraded() {
        let mut r = report(vec![program("rk_test_lsm_open", true)], vec![], false);
        r.finish();
        assert_eq!(r.exit_code, EXIT_MISSING_FEATURE);
        assert_eq!(r.missing_features, vec!["bpf_lsm"]);
        assert!(!r.enforcement_available);
    }

    #[test]
    fn failed_check_fails() {
        let mut r = report(vec![], vec![Check::fail("x", "boom")], true);
        r.finish();
        assert_eq!(r.exit_code, EXIT_FAILED);
    }

    #[test]
    fn describes_child_codes() {
        assert!(describe_child(Some(0)).contains("EPERM"));
        assert!(describe_child(Some(23)).contains("not enforced"));
        assert!(describe_child(None).contains("signal"));
    }
}
