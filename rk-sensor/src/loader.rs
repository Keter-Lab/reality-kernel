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
    let mut reports: Vec<ProgramReport> = ebpf
        .programs_mut()
        .map(|(name, program)| {
            let (kind, result) = load_program(name, program, btf);
            ProgramReport {
                object: object.file_name(),
                name: name.to_string(),
                kind,
                probe: object == Object::Probes,
                loaded: result.is_ok(),
                error: result.err().map(|e| tail(&e, MAX_ERROR_LEN)),
            }
        })
        .collect();
    reports.sort_by(|a, b| a.name.cmp(&b.name));
    reports
}

/// LSM hook for each LSM program. Every LSM program must be listed here.
fn lsm_hook(program: &str) -> Option<&'static str> {
    match program {
        "rk_test_lsm_open" => Some("file_open"),
        "rk_net_socket_create" => Some("socket_create"),
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
    }

    #[test]
    fn tail_keeps_the_end() {
        assert_eq!(tail("abc", 10), "abc");
        assert_eq!(tail("abcdef", 3), "…def");
        assert_eq!(tail("ééé", 3), "…é");
    }
}
