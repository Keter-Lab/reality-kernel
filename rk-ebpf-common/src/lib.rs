#![no_std]

pub const EVENT_TAG_EXEC: u8 = 1;
pub const EVENT_TAG_FILE_OPEN: u8 = 2;
pub const EVENT_TAG_NET_CONNECT: u8 = 3;
pub const EVENT_TAG_UNLINK: u8 = 4;

pub const COMM_LEN: usize = 16;
pub const TASK_LEN: usize = 16;
pub const PATH_LEN: usize = 256;
pub const ARGS_LEN: usize = 256;
pub const IP_ADDR_LEN: usize = 16;

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(not(target_arch = "bpf"), derive(Debug))]
pub struct ExecEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub mnt_ns: u64,
    pub pid_ns: u64,
    pub cgroup_id: u64,
    pub retval: i32,
    pub comm: [u8; COMM_LEN],
    pub filename: [u8; PATH_LEN],
    pub argv_summary: [u8; ARGS_LEN],
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(not(target_arch = "bpf"), derive(Debug))]
pub struct FileOpenEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub mnt_ns: u64,
    pub cgroup_id: u64,
    pub flags: u32,
    pub mode: u32,
    pub retval: i32,
    pub comm: [u8; COMM_LEN],
    pub path: [u8; PATH_LEN],
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(not(target_arch = "bpf"), derive(Debug))]
pub struct NetConnectEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub net_ns: u64,
    pub cgroup_id: u64,
    pub family: u16,
    pub protocol: u16,
    pub port_be: u16,
    pub verdict: u8,
    pub _pad0: u8,
    pub _pad1: u16,
    pub comm: [u8; COMM_LEN],
    pub addr: [u8; IP_ADDR_LEN],
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(not(target_arch = "bpf"), derive(Debug))]
pub struct UnlinkEvent {
    pub ts_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub mnt_ns: u64,
    pub cgroup_id: u64,
    pub retval: i32,
    pub comm: [u8; COMM_LEN],
    pub path: [u8; PATH_LEN],
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(not(target_arch = "bpf"), derive(Debug))]
pub struct TaggedExecEvent {
    pub tag: u8,
    pub _pad: [u8; 7],
    pub event: ExecEvent,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(not(target_arch = "bpf"), derive(Debug))]
pub struct TaggedFileOpenEvent {
    pub tag: u8,
    pub _pad: [u8; 7],
    pub event: FileOpenEvent,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(not(target_arch = "bpf"), derive(Debug))]
pub struct TaggedNetConnectEvent {
    pub tag: u8,
    pub _pad: [u8; 7],
    pub event: NetConnectEvent,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(not(target_arch = "bpf"), derive(Debug))]
pub struct TaggedUnlinkEvent {
    pub tag: u8,
    pub _pad: [u8; 7],
    pub event: UnlinkEvent,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FileOpenEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for NetConnectEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for UnlinkEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TaggedExecEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TaggedFileOpenEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TaggedNetConnectEvent {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TaggedUnlinkEvent {}
