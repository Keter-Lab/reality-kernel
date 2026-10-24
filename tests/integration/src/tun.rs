//! TUN/TAP helpers for the Phase 16 tests (docs/design/phase-16.md), used by
//! the harness (to prepare devices) and by child workloads (the attempts).
//!
//! The ioctl numbers and the `struct ifreq` layout are kernel ABI
//! (`include/uapi/linux/if_tun.h`, `include/uapi/linux/if.h`), spelled out
//! because `libc` does not export all of them on every target (musl).

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Device node the suite creates in its own tmpfs (char 10:200, mode 0666).
/// Without udev, `/dev/net/tun` would be root-only (0600), and an
/// unprivileged attach would fail with `EACCES` before reaching any TUN hook.
pub const NODE: &str = "/run/rk-test/net-tun";

/// uid and gid the unprivileged attempts run as.
pub const NOBODY: u32 = 65534;

// _IOW('T', nr, int)
const TUNSETIFF: u32 = 0x4004_54ca;
const TUNSETPERSIST: u32 = 0x4004_54cb;
const TUNSETOWNER: u32 = 0x4004_54cc;
const TUNSETQUEUE: u32 = 0x4004_54d9;

pub const IFF_TUN: i16 = 0x0001;
pub const IFF_NO_PI: i16 = 0x1000;
pub const IFF_MULTI_QUEUE: i16 = 0x0100;
const IFF_ATTACH_QUEUE: i16 = 0x0200;
const IFF_DETACH_QUEUE: i16 = 0x0400;

/// Flags of a single-queue TUN interface.
pub const TUN: i16 = IFF_TUN | IFF_NO_PI;
/// Flags of a multi-queue TUN interface.
pub const TUN_MQ: i16 = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;

/// `struct ifreq` on 64-bit Linux: a 16-byte name, then a 24-byte union whose
/// first member is `short ifr_flags`. Only the kernel reads the fields.
#[repr(C)]
#[allow(dead_code)]
struct IfReq {
    name: [u8; 16],
    flags: i16,
    _pad: [u8; 22],
}

const _: () = assert!(core::mem::size_of::<IfReq>() == 40);

fn ifreq(name: &str, flags: i16) -> IfReq {
    let mut req = IfReq {
        name: [0; 16],
        flags,
        _pad: [0; 22],
    };
    let bytes = name.as_bytes();
    let n = bytes.len().min(15);
    req.name[..n].copy_from_slice(&bytes[..n]);
    req
}

fn check(rc: libc::c_int) -> io::Result<()> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn ioctl_ifreq(fd: RawFd, request: u32, req: &mut IfReq) -> io::Result<()> {
    // SAFETY: `req` is a live, correctly sized `struct ifreq`.
    check(unsafe { libc::ioctl(fd, request as _, req as *mut IfReq) })
}

fn ioctl_value(fd: RawFd, request: u32, value: libc::c_ulong) -> io::Result<()> {
    // SAFETY: these ioctls take their argument by value.
    check(unsafe { libc::ioctl(fd, request as _, value) })
}

/// Creates [`NODE`] (replacing any previous one).
pub fn make_node() -> io::Result<()> {
    let _ = std::fs::remove_file(NODE);
    let path = CString::new(NODE).expect("no NUL in NODE");
    // SAFETY: plain syscalls on a valid C string.
    unsafe {
        check(libc::mknod(
            path.as_ptr(),
            libc::S_IFCHR | 0o666,
            libc::makedev(10, 200),
        ))?;
        // mknod applies the umask.
        check(libc::chmod(path.as_ptr(), 0o666))
    }
}

fn open_node(flags: libc::c_int) -> io::Result<OwnedFd> {
    let path = CString::new(NODE).expect("no NUL in NODE");
    // SAFETY: plain syscall on a valid C string; the fd is owned below.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just opened and is owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Opens [`NODE`], close-on-exec.
pub fn open() -> io::Result<OwnedFd> {
    open_node(libc::O_CLOEXEC)
}

/// Opens [`NODE`] without close-on-exec, so a spawned child inherits it.
pub fn open_inheritable() -> io::Result<OwnedFd> {
    open_node(0)
}

/// `TUNSETIFF`: creates interface `name`, or attaches to it if it exists.
pub fn set_iff(fd: &OwnedFd, name: &str, flags: i16) -> io::Result<()> {
    ioctl_ifreq(fd.as_raw_fd(), TUNSETIFF, &mut ifreq(name, flags))
}

pub fn set_persist(fd: &OwnedFd, persist: bool) -> io::Result<()> {
    ioctl_value(fd.as_raw_fd(), TUNSETPERSIST, libc::c_ulong::from(persist))
}

pub fn set_owner(fd: &OwnedFd, uid: u32) -> io::Result<()> {
    ioctl_value(fd.as_raw_fd(), TUNSETOWNER, libc::c_ulong::from(uid))
}

/// `TUNSETQUEUE` with `IFF_ATTACH_QUEUE` on a raw (inherited) descriptor.
pub fn attach_queue(fd: RawFd) -> io::Result<()> {
    ioctl_ifreq(fd, TUNSETQUEUE, &mut ifreq("", IFF_ATTACH_QUEUE))
}

pub fn detach_queue(fd: &OwnedFd) -> io::Result<()> {
    ioctl_ifreq(fd.as_raw_fd(), TUNSETQUEUE, &mut ifreq("", IFF_DETACH_QUEUE))
}

/// Creates a persistent single-queue interface owned by `owner`. Nothing stays
/// attached to it.
pub fn create_persistent(name: &str, owner: u32) -> io::Result<()> {
    let fd = open()?;
    set_iff(&fd, name, TUN)?;
    set_owner(&fd, owner)?;
    set_persist(&fd, true)
}

/// Removes a persistent interface made by [`create_persistent`].
pub fn remove_persistent(name: &str) -> io::Result<()> {
    let fd = open()?;
    set_iff(&fd, name, TUN)?;
    set_persist(&fd, false)
}

/// A multi-queue interface held by `keep`, plus a second queue descriptor
/// that has been detached and can be inherited by a child.
pub fn detached_queue(name: &str) -> io::Result<(OwnedFd, OwnedFd)> {
    let keep = open()?;
    set_iff(&keep, name, TUN_MQ)?;
    let queue = open_inheritable()?;
    set_iff(&queue, name, TUN_MQ)?;
    detach_queue(&queue)?;
    Ok((keep, queue))
}

/// Drops to [`NOBODY`] with no supplementary groups. Leaving uid 0 clears
/// every capability (no `SECBIT_KEEP_CAPS`).
pub fn become_nobody() -> io::Result<()> {
    // SAFETY: plain syscalls with integer arguments.
    unsafe {
        check(libc::setgroups(0, std::ptr::null()))?;
        check(libc::setgid(NOBODY))?;
        check(libc::setuid(NOBODY))
    }
}
