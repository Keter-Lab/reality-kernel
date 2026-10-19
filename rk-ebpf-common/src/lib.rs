#![no_std]

pub mod bindings;
pub use bindings::*;

/*
 * Compile-time Layout and Offset Assertions
 * Strictly verified using core::mem::offset_of! and core::mem::size_of
 */
const _: () = {
    // rk_hdr layout
    assert!(core::mem::size_of::<rk_hdr>() == 48);
    assert!(core::mem::offset_of!(rk_hdr, ts_ns) == 0);
    assert!(core::mem::offset_of!(rk_hdr, cgroup_id) == 8);
    assert!(core::mem::offset_of!(rk_hdr, policy_gen) == 16);
    assert!(core::mem::offset_of!(rk_hdr, pid) == 24);
    assert!(core::mem::offset_of!(rk_hdr, tgid) == 28);
    assert!(core::mem::offset_of!(rk_hdr, uid) == 32);
    assert!(core::mem::offset_of!(rk_hdr, gid) == 36);
    assert!(core::mem::offset_of!(rk_hdr, type_) == 40);
    assert!(core::mem::offset_of!(rk_hdr, verdict) == 42);
    assert!(core::mem::offset_of!(rk_hdr, abi) == 43);
    assert!(core::mem::offset_of!(rk_hdr, rule_id) == 44);

    // rk_scratch_msg layout
    assert!(core::mem::offset_of!(rk_scratch_msg, hdr) == 0);
    assert!(core::mem::offset_of!(rk_scratch_msg, payload_len) == 48);
    assert!(core::mem::offset_of!(rk_scratch_msg, _reserved) == 52);
    assert!(core::mem::offset_of!(rk_scratch_msg, payload) == 56);
    assert!(core::mem::size_of::<rk_scratch_msg>() == 56 + RK_SCRATCH_PAYLOAD_MAX);

    // rk_payload_exec layout
    assert!(core::mem::size_of::<rk_payload_exec>() == 24);
    assert!(core::mem::offset_of!(rk_payload_exec, file_dev) == 0);
    assert!(core::mem::offset_of!(rk_payload_exec, file_ino) == 8);
    assert!(core::mem::offset_of!(rk_payload_exec, flags) == 16);
    assert!(core::mem::offset_of!(rk_payload_exec, str_count) == 20);

    // rk_payload_file layout
    assert!(core::mem::size_of::<rk_payload_file>() == 32);
    assert!(core::mem::offset_of!(rk_payload_file, file_dev) == 0);
    assert!(core::mem::offset_of!(rk_payload_file, file_ino) == 8);
    assert!(core::mem::offset_of!(rk_payload_file, open_flags) == 16);
    assert!(core::mem::offset_of!(rk_payload_file, mode) == 20);
    assert!(core::mem::offset_of!(rk_payload_file, str_count) == 24);
    assert!(core::mem::offset_of!(rk_payload_file, _pad2) == 28);

    // rk_payload_net layout
    assert!(core::mem::size_of::<rk_payload_net>() == 40);
    assert!(core::mem::offset_of!(rk_payload_net, saddr_v6) == 0);
    assert!(core::mem::offset_of!(rk_payload_net, daddr_v6) == 16);
    assert!(core::mem::offset_of!(rk_payload_net, sport) == 32);
    assert!(core::mem::offset_of!(rk_payload_net, dport) == 34);
    assert!(core::mem::offset_of!(rk_payload_net, family) == 36);
    assert!(core::mem::offset_of!(rk_payload_net, protocol) == 38);
};
