// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * loader.rs — Embedded multi-arch BPF loader
 * Embeds per-arch BPF objects at compile-time and attaches
 * programs in multi-attach mode with no unwrap calls.
 */

use anyhow::{Context, Result};
use aya::programs::{CgroupAttachMode, CgroupSockAddr, Lsm};
use aya::{Btf, Ebpf};

// Embedded BPF object:
// On x86_64, uses rk_bpf_x86.o.
// On aarch64, uses rk_bpf_arm64.o.
// For fresh clones / host builds before BPF compilation, dev-stub bytes are provided.
#[cfg(all(target_arch = "x86_64", feature = "embedded-bpf"))]
pub static BPF_OBJECT_BYTES: &[u8] = aya::include_bytes_aligned!("../../rk-bpf/build/rk_bpf_x86.o");

#[cfg(all(target_arch = "aarch64", feature = "embedded-bpf"))]
pub static BPF_OBJECT_BYTES: &[u8] = aya::include_bytes_aligned!("../../rk-bpf/build/rk_bpf_arm64.o");

#[cfg(not(feature = "embedded-bpf"))]
pub static BPF_OBJECT_BYTES: &[u8] = include_bytes!("dev_stub.bpf.o");

pub struct LoadedProbes {
    pub ebpf: Ebpf,
    pub attached_hooks: Vec<String>,
}

pub fn load_and_attach() -> Result<LoadedProbes> {
    let mut ebpf = Ebpf::load(BPF_OBJECT_BYTES)
        .context("failed to load embedded eBPF object")?;

    let mut attached = Vec::new();
    let btf = Btf::from_sys_fs().ok();

    // 1. Attach LSM file_open probe if supported
    if let Some(ref btf_ref) = btf {
        if let Some(prog) = ebpf.program_mut("rk_test_lsm_open") {
            if let Ok(lsm) = prog.try_into() as Result<&mut Lsm, _> {
                if lsm.load("file_open", btf_ref).is_ok() {
                    if lsm.attach().is_ok() {
                        attached.push("lsm/file_open".to_string());
                    }
                }
            }
        }
    }

    // 2. Attach cgroup/connect4 probe in multi-attach mode
    if let Ok(cgroup) = std::fs::File::open("/sys/fs/cgroup") {
        if let Some(prog) = ebpf.program_mut("rk_test_connect4") {
            if let Ok(cgroup_prog) = prog.try_into() as Result<&mut CgroupSockAddr, _> {
                if cgroup_prog.load().is_ok() {
                    // Multi-program mode (BPF_F_ALLOW_MULTI) allows coexistence
                    if cgroup_prog.attach(&cgroup, CgroupAttachMode::AllowMultiple).is_ok() {
                        attached.push("cgroup/connect4".to_string());
                    }
                }
            }
        }
    }

    Ok(LoadedProbes {
        ebpf,
        attached_hooks: attached,
    })
}
