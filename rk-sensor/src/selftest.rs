// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * selftest.rs — Sensor self-test module
 * Proves BPF-LSM functional execution via atomic counter,
 * verifies TEST-NET 192.0.2.1 denial with EPERM, checks ring buffer roundtrip,
 * and reports effective capabilities.
 */

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use serde::Serialize;
use tracing::{info, warn, error};

#[derive(Debug, Serialize)]
pub struct SelftestReport {
    pub kernel_version: String,
    pub bpf_lsm_status: String,       // "active" | "inactive" | "unknown"
    pub bpf_lsm_functional: bool,     // proven via atomic counter increment
    pub btf_available: bool,
    pub ring_buffer_supported: bool,
    pub cgroup_v2_unified: bool,
    pub effective_capabilities: Vec<String>,
    pub test_net_eperm_enforced: bool,
    pub ringbuf_roundtrip_ok: bool,
    pub enforcement_supported: bool,
}

pub fn run_selftest() -> (SelftestReport, i32) {
    let kernel_ver = read_kernel_version().unwrap_or_else(|| "unknown".to_string());
    let btf_available = Path::new("/sys/kernel/btf/vmlinux").exists();
    let cgroup_v2 = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();

    let bpf_lsm_status = match fs::read_to_string("/sys/kernel/security/lsm") {
        Ok(s) => {
            if s.split(',').any(|part| part.trim() == "bpf") {
                "active".to_string()
            } else {
                "inactive".to_string()
            }
        }
        Err(_) => "unknown".to_string(), // Unreadable securityfs = unknown
    };

    let effective_caps = read_effective_caps();

    // Functional BPF checks require Linux runtime and root capabilities
    #[cfg(target_os = "linux")]
    let (lsm_functional, net_denied, ringbuf_ok) = execute_linux_bpf_probes();

    #[cfg(not(target_os = "linux"))]
    let (lsm_functional, net_denied, ringbuf_ok) = (false, false, false);

    let ring_buffer_supported = btf_available && ringbuf_ok;
    let enforcement_supported = lsm_functional && btf_available && cgroup_v2 && net_denied;

    let report = SelftestReport {
        kernel_version: kernel_ver,
        bpf_lsm_status,
        bpf_lsm_functional: lsm_functional,
        btf_available,
        ring_buffer_supported,
        cgroup_v2_unified: cgroup_v2,
        effective_capabilities: effective_caps,
        test_net_eperm_enforced: net_denied,
        ringbuf_roundtrip_ok: ringbuf_ok,
        enforcement_supported,
    };

    // Exit code logic:
    // Exit 0: All enforcement checks pass
    // Exit 1: Degraded audit-only mode (missing LSM functional or net deny)
    // Exit 2: Fatal missing features (missing BTF or missing cgroup v2)
    let exit_code = if enforcement_supported {
        0
    } else if !btf_available || !cgroup_v2 {
        2
    } else {
        1
    };

    (report, exit_code)
}

fn read_kernel_version() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .ok()
}

fn read_effective_caps() -> Vec<String> {
    let mut caps = Vec::new();
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("CapEff:") {
                let hex_str = line.trim_start_matches("CapEff:").trim();
                if let Ok(mask) = u64::from_str_radix(hex_str, 16) {
                    if (mask & (1 << 21)) != 0 { caps.push("CAP_SYS_ADMIN".to_string()); }
                    if (mask & (1 << 38)) != 0 { caps.push("CAP_PERFMON".to_string()); }
                    if (mask & (1 << 39)) != 0 { caps.push("CAP_BPF".to_string()); }
                    if (mask & (1 << 12)) != 0 { caps.push("CAP_NET_ADMIN".to_string()); }
                }
            }
        }
    }
    caps
}

#[cfg(target_os = "linux")]
fn execute_linux_bpf_probes() -> (bool, bool, bool) {
    use aya::programs::{CgroupAttachMode, CgroupSockAddr, Lsm};
    use aya::maps::{Array, RingBuf};
    use aya::{Btf, Ebpf};
    use std::process::Command;

    let btf = match Btf::from_sys_fs() {
        Ok(b) => b,
        Err(_) => return (false, false, false),
    };

    let mut ebpf = match Ebpf::load(crate::loader::BPF_OBJECT_BYTES) {
        Ok(e) => e,
        Err(_) => return (false, false, false),
    };

    // 1. Test LSM file_open execution via atomic counter increment
    let mut lsm_functional = false;
    if let Some(prog) = ebpf.program_mut("rk_test_lsm_open") {
        if let Ok(lsm) = prog.try_into() as Result<&mut Lsm, _> {
            if lsm.load("file_open", &btf).is_ok() && lsm.attach().is_ok() {
                if let Some(map) = ebpf.map_mut("lsm_exec_counter") {
                    if let Ok(counter_map) = Array::<_, u64>::try_from(map) {
                        let before = counter_map.get(&0, 0).unwrap_or(0);
                        // Trigger file open
                        let _ = std::fs::File::open("/proc/self/cmdline");
                        let after = counter_map.get(&0, 0).unwrap_or(0);
                        if after > before {
                            lsm_functional = true;
                        }
                    }
                }
            }
        }
    }

    // 2. Test cgroup/connect4 TEST-NET denial with EPERM and ringbuffer roundtrip
    let mut net_denied = false;
    let mut ringbuf_ok = false;

    let temp_cgroup_dir = format!("/sys/fs/cgroup/rk_selftest_{}", std::process::id());
    if std::fs::create_dir(&temp_cgroup_dir).is_ok() {
        let procs_path = format!("{}/cgroup.procs", temp_cgroup_dir);
        if let Ok(cgroup_file) = std::fs::File::open(&temp_cgroup_dir) {
            if let Some(prog) = ebpf.program_mut("rk_test_connect4") {
                if let Ok(connect4) = prog.try_into() as Result<&mut CgroupSockAddr, _> {
                    if connect4.load().is_ok()
                        && connect4.attach(&cgroup_file, CgroupAttachMode::AllowMultiple).is_ok()
                    {
                        if let Ok(current_exe) = std::env::current_exe() {
                            let status = Command::new(current_exe)
                                .args(["--test-connect", &procs_path])
                                .status();
                            if let Ok(st) = status {
                                if st.code() == Some(0) {
                                    net_denied = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Test ring buffer roundtrip marker if connect4 was blocked
        if let Some(map) = ebpf.take_map("selftest_ringbuf") {
            if let Ok(mut rb) = RingBuf::try_from(map) {
                while let Some(item) = rb.next() {
                    let bytes = item.as_ref();
                    if bytes.len() >= 8 {
                        if let Ok(slice) = bytes[..8].try_into() {
                            let marker = u64::from_ne_bytes(slice);
                            if marker == 0xDEADC0000201ULL {
                                ringbuf_ok = true;
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Clean up temporary cgroup
        let _ = std::fs::remove_dir(&temp_cgroup_dir);
    }

    (lsm_functional, net_denied, ringbuf_ok)
}

pub fn run_test_connect(cgroup_procs: &str) -> i32 {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    // 1. Move current process into the temporary cgroup
    if let Ok(mut f) = OpenOptions::new().write(true).open(cgroup_procs) {
        let pid = std::process::id();
        let _ = writeln!(f, "{}", pid);
    } else {
        return 101; // Failed to write to cgroup.procs
    }

    // 2. Attempt to connect to 192.0.2.1:80 (TEST-NET-1)
    let addr: SocketAddr = match "192.0.2.1:80".parse() {
        Ok(a) => a,
        Err(_) => return 102,
    };

    match TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
        Ok(_) => {
            // Connected unexpectedly; deny failed
            103
        }
        Err(e) => {
            // On Linux, EPERM is raw os error 1
            if e.raw_os_error() == Some(1) {
                0 // Success: connection blocked with -EPERM
            } else {
                104 // Other network error (e.g., ETIMEDOUT, ENETUNREACH)
            }
        }
    }
}
