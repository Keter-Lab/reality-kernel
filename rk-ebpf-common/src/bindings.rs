// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * rk_abi_bindings.rs — Committed Rust bindings for rk_abi.h
 * Single source of truth: rk-bpf/include/rk_abi.h
 */

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub const RK_ABI_VERSION: u8 = 1;
pub const RK_SCRATCH_PAYLOAD_MAX: usize = 2048;

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum rk_event_type {
    RK_EV_NONE        = 0,
    RK_EV_EXEC        = 1,
    RK_EV_FILE_OPEN   = 2,
    RK_EV_NET_CONNECT = 3,
    RK_EV_UNLINK      = 4,
    RK_EV_RENAME      = 5,
    RK_EV_FORK        = 6,
    RK_EV_EXIT        = 7,
    RK_EV_TAMPER      = 8,
    RK_EV_SENDMSG     = 9,
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum rk_verdict {
    RK_VERDICT_ALLOW            = 0,
    RK_VERDICT_DENY             = 1,
    RK_VERDICT_AUDIT_WOULD_DENY = 2,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct rk_hdr {
    pub ts_ns: u64,
    pub cgroup_id: u64,
    pub policy_gen: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub type_: u16,
    pub verdict: u8,
    pub abi: u8,
    pub rule_id: u32,
}

#[repr(C)]
pub struct rk_scratch_msg {
    pub hdr: rk_hdr,
    pub payload_len: u32,
    pub _reserved: u32,
    pub payload: [u8; RK_SCRATCH_PAYLOAD_MAX],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct rk_payload_exec {
    pub file_dev: u64,
    pub file_ino: u64,
    pub flags: u32,
    pub str_count: u16,
    pub _pad: u16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct rk_payload_file {
    pub file_dev: u64,
    pub file_ino: u64,
    pub open_flags: u32,
    pub mode: u32,
    pub str_count: u16,
    pub _pad: u16,
    pub _pad2: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct rk_payload_net {
    pub saddr_v6: [u8; 16],
    pub daddr_v6: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    pub protocol: u8,
    pub _pad: u8,
}
