//! Loads the BPF objects embedded at build time.
//!
//! There is deliberately no way to load an object from a filesystem path: the
//! only source of BPF bytecode is [`object_bytes`], and release builds without
//! the `embedded-bpf` feature fail to compile (see `main.rs`).

use std::fmt;

use anyhow::{Context, Result};
use aya::programs::Program;
use aya::{Btf, Ebpf};
use serde::Serialize;

/// Name prefix of the programs in [`Object::Probes`]; stripped to name the
/// feature in the selftest report.
pub const PROBE_PREFIX: &str = "rk_probe_";

/// Longest verifier log kept in a report (the tail is the useful part).
const MAX_ERROR_LEN: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Object {
    /// `rk.bpf.o`: loaded by the daemon.
    Production,
    /// `rk_selftest.bpf.o`: functional test programs, loaded only by `--selftest`.
    Selftest,
    /// `rk_probes.bpf.o`: kernel feature probes, loaded only by `--selftest`.
    Probes,
}

impl Object {
    pub const ALL: [Object; 3] = [Object::Production, Object::Selftest, Object::Probes];

    pub fn file_name(self) -> &'static str {
        match self {
            Object::Production => "rk.bpf.o",
            Object::Selftest => "rk_selftest.bpf.o",
            Object::Probes => "rk_probes.bpf.o",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotEmbedded;

impl fmt::Display for NotEmbedded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "rk-sensor was built without embedded BPF objects; run `make -C rk-bpf` \
             and rebuild with `--features embedded-bpf`",
        )
    }
}

impl std::error::Error for NotEmbedded {}

#[cfg(feature = "embedded-bpf")]
mod embedded {
    pub static PRODUCTION: &[u8] =
        aya::include_bytes_aligned!(concat!(env!("RK_BPF_DIR"), "/rk.bpf.o"));
    pub static SELFTEST: &[u8] =
        aya::include_bytes_aligned!(concat!(env!("RK_BPF_DIR"), "/rk_selftest.bpf.o"));
    pub static PROBES: &[u8] =
        aya::include_bytes_aligned!(concat!(env!("RK_BPF_DIR"), "/rk_probes.bpf.o"));
}

/// The embedded bytecode for `object`.
pub fn object_bytes(object: Object) -> Result<&'static [u8], NotEmbedded> {
    #[cfg(feature = "embedded-bpf")]
    {
        Ok(match object {
            Object::Production => embedded::PRODUCTION,
            Object::Selftest => embedded::SELFTEST,
            Object::Probes => embedded::PROBES,
        })
    }
    #[cfg(not(feature = "embedded-bpf"))]
    {
        let _ = object;
        Err(NotEmbedded)
    }
}

/// Opens BPF bytecode supplied by the caller. Only for test harnesses that
/// embed their own objects (tests/integration); `rk-sensor` itself never
/// calls this and exposes no way to reach it at runtime.
#[doc(hidden)]
pub fn open_bytes(bytes: &[u8], name: &str) -> Result<Ebpf> {
    Ebpf::load(bytes).with_context(|| format!("failed to open {name}"))
}

/// Parses the embedded object, creates its maps and applies CO-RE relocations.
/// Programs are not loaded into the kernel yet; see [`load_programs`].
pub fn open(object: Object) -> Result<Ebpf> {
    let bytes = object_bytes(object)?;
    Ebpf::load(bytes).with_context(|| format!("failed to open embedded {}", object.file_name()))
}

#[derive(Debug, Clone, Serialize)]
pub struct ProgramReport {
    pub object: &'static str,
    pub name: String,
    pub kind: &'static str,
    /// Program from [`Object::Probes`]: a failure here is informational.
    pub probe: bool,
    pub loaded: bool,
    pub error: Option<String>,
}

/// Loads every program in `ebpf` through the verifier and reports each result.
/// A program type the loader does not know is reported as a failure, so a new
/// program can never be silently skipped.
pub fn load_programs(object: Object, ebpf: &mut Ebpf, btf: Option<&Btf>) -> Vec<ProgramReport> {
    let report = |name: &str, kind, result: Result<(), String>| ProgramReport {
        object: object.file_name(),
        name: name.to_string(),
        kind,
        probe: object == Object::Probes,
        loaded: result.is_ok(),
        error: result.err().map(|e| tail(&e, MAX_ERROR_LEN)),
    };

    let mut reports = Vec::new();
    for (name, program) in ebpf.programs_mut() {
        if SETATTR_VARIANTS.contains(&name) {
            continue; // loaded below, in a fixed order
        }
        let (kind, result) = load_program(name, program, btf);
        reports.push(report(name, kind, result));
    }

    // inode_setattr gained an `idmap` argument in Linux 6.9. v2 reads three
    // arguments, so the verifier only accepts it where the hook has them; trying
    // v2 first and v1 only if v2 is rejected therefore selects the matching
    // variant on every kernel. (programs_mut() iteration order is unspecified:
    // trying v1 first could load it with shifted arguments on 6.9-6.11.)
    let mut setattr = Vec::new();
    for name in SETATTR_VARIANTS {
        let Some(program) = ebpf.program_mut(name) else {
            continue;
        };
        let (kind, result) = load_program(name, program, btf);
        let loaded = result.is_ok();
        setattr.push(report(name, kind, result));
        if loaded {
            break;
        }
    }
    // Report the variant that loaded; if none did, report every failure.
    match setattr.iter().position(|r| r.loaded) {
        Some(i) => reports.push(setattr.swap_remove(i)),
        None => reports.extend(setattr),
    }

    reports.sort_by(|a, b| a.name.cmp(&b.name));
    reports
}

/// `inode_setattr` variants in load order: v2 (6.9+, with `idmap`) first.
pub const SETATTR_VARIANTS: [&str; 2] = ["rk_file_setattr_v2", "rk_file_setattr_v1"];

/// LSM hook for each LSM program. Every LSM program must be listed here.
fn lsm_hook(program: &str) -> Option<&'static str> {
    match program {
        "rk_test_lsm_open" => Some("file_open"),
        "rk_net_socket_create" => Some("socket_create"),
        "rk_exec_check" => Some("bprm_check_security"),
        "rk_file_open" => Some("file_open"),
        "rk_file_unlink" => Some("inode_unlink"),
        "rk_file_rmdir" => Some("inode_rmdir"),
        "rk_file_rename" => Some("inode_rename"),
        "rk_file_link" => Some("inode_link"),
        "rk_file_create" => Some("inode_create"),
        "rk_file_mkdir" => Some("inode_mkdir"),
        "rk_file_setattr_v1" => Some("inode_setattr"),
        "rk_file_setattr_v2" => Some("inode_setattr"),
        _ => None,
    }
}

/// Tracepoint for each BTF tracepoint program. Every one must be listed here.
fn btf_tracepoint(program: &str) -> Option<&'static str> {
    match program {
        "rk_exec_record" => Some("sched_process_exec"),
        _ => None,
    }
}

fn load_program(
    name: &str,
    program: &mut Program,
    btf: Option<&Btf>,
) -> (&'static str, Result<(), String>) {
    match program {
        Program::Lsm(lsm) => {
            let result = match (lsm_hook(name), btf) {
                (Some(hook), Some(btf)) => lsm.load(hook, btf).map_err(|e| e.to_string()),
                (None, _) => Err(format!("no LSM hook registered for program `{name}`")),
                (Some(_), None) => Err("kernel BTF is unavailable".to_string()),
            };
            ("lsm", result)
        }
        Program::CgroupSockAddr(prog) => {
            ("cgroup_sock_addr", prog.load().map_err(|e| e.to_string()))
        }
        Program::BtfTracePoint(prog) => {
            let result = match (btf_tracepoint(name), btf) {
                (Some(tp), Some(btf)) => prog.load(tp, btf).map_err(|e| e.to_string()),
                (None, _) => Err(format!("no tracepoint registered for program `{name}`")),
                (Some(_), None) => Err("kernel BTF is unavailable".to_string()),
            };
            ("btf_tracepoint", result)
        }
        _ => (
            "unsupported",
            Err(format!(
                "program `{name}` has a type the loader does not handle"
            )),
        ),
    }
}

/// Keeps the last `max` bytes of `s`, on a char boundary.
fn tail(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut start = s.len() - max;
    while !s.is_char_boundary(start) {
        start += 1;
    }
    format!("…{}", &s[start..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_names_are_stable() {
        assert_eq!(Object::Production.file_name(), "rk.bpf.o");
        assert_eq!(Object::Selftest.file_name(), "rk_selftest.bpf.o");
        assert_eq!(Object::Probes.file_name(), "rk_probes.bpf.o");
    }

    #[cfg(not(feature = "embedded-bpf"))]
    #[test]
    fn missing_objects_are_an_error_not_a_stub() {
        assert_eq!(object_bytes(Object::Production), Err(NotEmbedded));
        assert!(open(Object::Selftest).is_err());
    }

    #[cfg(feature = "embedded-bpf")]
    #[test]
    fn embedded_objects_are_elf() {
        for object in Object::ALL {
            let bytes = object_bytes(object).unwrap();
            assert_eq!(
                &bytes[..4],
                b"\x7fELF",
                "{} is not an ELF object",
                object.file_name()
            );
        }
    }

    #[test]
    fn every_lsm_test_program_has_a_hook() {
        assert_eq!(lsm_hook("rk_test_lsm_open"), Some("file_open"));
        assert_eq!(lsm_hook("rk_unknown"), None);
        assert_eq!(lsm_hook("rk_exec_check"), Some("bprm_check_security"));
        assert_eq!(lsm_hook("rk_file_open"), Some("file_open"));
        assert_eq!(lsm_hook("rk_file_unlink"), Some("inode_unlink"));
        assert_eq!(lsm_hook("rk_file_rmdir"), Some("inode_rmdir"));
        assert_eq!(lsm_hook("rk_file_rename"), Some("inode_rename"));
        assert_eq!(lsm_hook("rk_file_link"), Some("inode_link"));
        assert_eq!(lsm_hook("rk_file_create"), Some("inode_create"));
        assert_eq!(lsm_hook("rk_file_mkdir"), Some("inode_mkdir"));
        assert_eq!(lsm_hook("rk_file_setattr_v1"), Some("inode_setattr"));
        assert_eq!(lsm_hook("rk_file_setattr_v2"), Some("inode_setattr"));
        assert_eq!(btf_tracepoint("rk_exec_record"), Some("sched_process_exec"));
        assert_eq!(btf_tracepoint("rk_unknown"), None);
    }

    #[test]
    fn tail_keeps_the_end() {
        assert_eq!(tail("abc", 10), "abc");
        assert_eq!(tail("abcdef", 3), "…def");
        assert_eq!(tail("ééé", 3), "…é");
    }
}
