use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
    bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
};

use crate::maps::EVENT_DROPS;

pub const O_WRONLY: u32 = 0x1;
pub const O_RDWR: u32 = 0x2;

#[inline(always)]
pub fn fill_comm(comm: &mut [u8; 16]) {
    unsafe {
        let _ = bpf_get_current_comm(comm.as_mut_ptr() as *mut _);
    }
}

#[inline(always)]
pub fn identity() -> (u64, u32, u32, u32, u32, u64) {
    let ts_ns = unsafe { bpf_ktime_get_ns() };
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let uid_gid = unsafe { bpf_get_current_uid_gid() };
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    let pid = (pid_tgid & 0xffff_ffff) as u32;
    let tgid = ((pid_tgid >> 32) & 0xffff_ffff) as u32;
    let uid = (uid_gid & 0xffff_ffff) as u32;
    let gid = ((uid_gid >> 32) & 0xffff_ffff) as u32;

    (ts_ns, pid, tgid, uid, gid, cgroup_id)
}

#[inline(always)]
pub fn ns_stub() -> (u64, u64, u32) {
    // TODO(Phase 4+): populate mnt_ns/pid_ns/ppid using CO-RE task_struct traversal.
    (0, 0, 0)
}

#[inline(always)]
pub fn read_user_cstr<const N: usize>(user_ptr: *const u8, out: &mut [u8; N]) {
    if user_ptr.is_null() {
        return;
    }
    unsafe {
        let _ = bpf_probe_read_user_str_bytes(user_ptr as *const _, out);
    }
}

#[inline(always)]
pub fn read_user_ptr<T: Copy>(user_ptr: *const T) -> Option<T> {
    if user_ptr.is_null() {
        return None;
    }
    let mut value = core::mem::MaybeUninit::<T>::uninit();
    let ret = unsafe {
        bpf_probe_read_user(
            value.as_mut_ptr() as *mut _,
            core::mem::size_of::<T>() as u32,
            user_ptr as *const _,
        )
    };
    if ret < 0 {
        None
    } else {
        Some(unsafe { value.assume_init() })
    }
}

#[inline(always)]
pub fn path_has_sensitive_prefix(path: &[u8]) -> bool {
    starts_with(path, b"/etc/")
        || starts_with(path, b"/root/")
        || starts_with(path, b"/home/")
        || starts_with(path, b"/proc/")
        || starts_with(path, b"/var/")
}

#[inline(always)]
fn starts_with(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    let mut i = 0;
    while i < needle.len() {
        if haystack[i] != needle[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[inline(always)]
pub fn bump_drop_counter() {
    unsafe {
        if let Some(slot) = EVENT_DROPS.get_ptr_mut(0) {
            *slot = slot.read().wrapping_add(1);
        }
    }
}

#[inline(always)]
pub fn is_loopback_v4(addr_be: u32) -> bool {
    // 127.0.0.0/8
    (addr_be.to_be() & 0xff00_0000) == 0x7f00_0000
}

#[inline(always)]
pub fn is_loopback_v6(addr: &[u8; 16]) -> bool {
    let mut i = 0;
    while i < 15 {
        if addr[i] != 0 {
            return false;
        }
        i += 1;
    }
    addr[15] == 1
}
