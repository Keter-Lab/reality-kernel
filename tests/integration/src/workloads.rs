//! Workload routines executed inside child processes placed in target cgroups.

use std::fs;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

pub const CHILD_FLAG: &str = "--child";

pub fn run_child(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("[child] missing cgroup_procs or workload arg");
        return 201;
    }

    let cgroup_procs = &args[0];
    let workload = &args[1];
    let rest = &args[2..];

    // Join target cgroup
    if let Err(e) = fs::write(cgroup_procs, std::process::id().to_string()) {
        eprintln!("[child] failed to join cgroup {cgroup_procs}: {e}");
        return 202;
    }

    match workload.as_str() {
        "tcp_connect" => handle_tcp_connect(rest),
        "udp_connect" => handle_udp_connect(rest),
        "udp_sendmsg" => handle_udp_sendmsg(rest),
        "raw_socket" => handle_raw_socket(),
        "packet_socket" => handle_packet_socket(),
        "unobserved_sockets" => handle_unobserved_sockets(rest),
        "tcp_fastopen" => handle_tcp_fastopen(rest),
        "io_uring_connect" => handle_io_uring_connect(rest),
        "blast_connect" => handle_blast_connect(rest),
        "flood_ringbuf" => handle_flood_ringbuf(rest),
        "paced_workload" => handle_paced_workload(rest),
        "bench" => handle_bench(rest),
        "exec_cmd" => handle_exec_cmd(rest),
        "exec_large_argv" => handle_exec_large_argv(rest),
        "exec_reload_workload" => handle_exec_reload_workload(rest),
        "memfd_exec" => handle_memfd_exec(rest),
        "file_open" => handle_file_open(rest),
        "file_openat2" => handle_file_openat2(rest),
        "file_io_uring_openat" => handle_file_io_uring_openat(rest),
        "file_truncate" => handle_file_truncate(rest),
        "file_ftruncate" => handle_file_ftruncate(rest),
        "file_unlink" => handle_file_unlink(rest),
        "file_rmdir" => handle_file_rmdir(rest),
        "file_rename" => handle_file_rename(rest),
        "file_rename_exchange" => handle_file_rename_exchange(rest),
        "file_link" => handle_file_link(rest),
        "file_create" => handle_file_create(rest),
        "file_symlink" => handle_file_symlink(rest),
        "file_mkfifo" => handle_file_mkfifo(rest),
        "file_chmod" => handle_file_chmod(rest),
        "file_proc_fd_reopen" => handle_file_proc_fd_reopen(rest),
        "file_relative_open" => handle_file_relative_open(rest),
        "file_reload_workload" => handle_file_reload_workload(rest),
        "guard_bpf" => handle_guard_bpf(rest),
        "guard_signal" => handle_guard_signal(rest),
        "guard_ptrace" => handle_guard_ptrace(rest),
        "guard_pins" => handle_guard_pins(),
        "gap_probe" => handle_gap_probe(rest),
        "tun" => handle_tun(rest),
        other => {
            eprintln!("[child] unknown workload: {other}");
            203
        }
    }
}

fn handle_tcp_connect(args: &[String]) -> i32 {
    if args.len() < 2 {
        return 210;
    }
    let addr_str = &args[0];
    let expected = &args[1];

    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[child] invalid addr {addr_str}: {e}");
            return 211;
        }
    };

    let res = TcpStream::connect_timeout(&addr, Duration::from_millis(500));
    match expected.as_str() {
        "eperm" => match res {
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => 0,
            Ok(_) => {
                eprintln!("[child] connect to {addr} succeeded but expected EPERM");
                1
            }
            Err(e) => {
                eprintln!("[child] connect to {addr} failed with unexpected error: {e:?}");
                2
            }
        },
        "ok" => match res {
            Ok(_) => 0,
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                eprintln!("[child] connect to {addr} blocked with EPERM but expected OK");
                3
            }
            Err(e) => {
                eprintln!("[child] connect to {addr} error: {e:?}");
                // In some test setups without remote response, ECONNREFUSED or timeout is okay as long as not EPERM
                0
            }
        },
        _ => 212,
    }
}

fn handle_udp_connect(args: &[String]) -> i32 {
    if args.len() < 2 {
        return 220;
    }
    let addr_str = &args[0];
    let expected = &args[1];

    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return 221,
    };

    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[child] udp bind failed: {e}");
            return 222;
        }
    };

    let res = sock.connect(addr);
    match expected.as_str() {
        "eperm" => match res {
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => 0,
            Ok(_) => {
                eprintln!("[child] udp connect to {addr} succeeded but expected EPERM");
                1
            }
            Err(e) => {
                eprintln!("[child] udp connect to {addr} returned unexpected error: {e:?}");
                2
            }
        },
        "ok" => match res {
            Ok(_) => 0,
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                eprintln!("[child] udp connect to {addr} blocked with EPERM");
                3
            }
            Err(_) => 0,
        },
        _ => 223,
    }
}

fn handle_udp_sendmsg(args: &[String]) -> i32 {
    if args.len() < 2 {
        return 230;
    }
    let addr_str = &args[0];
    let expected = &args[1];

    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return 231,
    };

    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[child] udp bind failed: {e}");
            return 232;
        }
    };

    let res = sock.send_to(b"ping", addr);
    match expected.as_str() {
        "eperm" => match res {
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => 0,
            Ok(_) => {
                eprintln!("[child] udp send_to to {addr} succeeded but expected EPERM");
                1
            }
            Err(e) => {
                eprintln!("[child] udp send_to to {addr} returned unexpected: {e:?}");
                2
            }
        },
        "ok" => match res {
            Ok(_) => 0,
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                eprintln!("[child] udp send_to to {addr} blocked with EPERM");
                3
            }
            Err(_) => 0,
        },
        _ => 233,
    }
}

fn handle_raw_socket() -> i32 {
    unsafe {
        let fd4 = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
        if fd4 >= 0 {
            libc::close(fd4);
            eprintln!("[child] socket(AF_INET, SOCK_RAW) succeeded; expected EPERM");
            return 1;
        }
        let err4 = std::io::Error::last_os_error().raw_os_error();
        if err4 != Some(libc::EPERM) {
            eprintln!("[child] socket(AF_INET, SOCK_RAW) returned error {err4:?}; expected EPERM");
            return 2;
        }

        let fd6 = libc::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_RAW);
        if fd6 >= 0 {
            libc::close(fd6);
            eprintln!("[child] socket(AF_INET6, SOCK_RAW) succeeded; expected EPERM");
            return 3;
        }
        let err6 = std::io::Error::last_os_error().raw_os_error();
        if err6 != Some(libc::EPERM) {
            eprintln!("[child] socket(AF_INET6, SOCK_RAW) returned error {err6:?}; expected EPERM");
            return 4;
        }
    }
    0
}

fn handle_packet_socket() -> i32 {
    unsafe {
        let proto = (libc::ETH_P_ALL as u16).to_be() as i32;
        let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto);
        if fd >= 0 {
            libc::close(fd);
            eprintln!("[child] socket(AF_PACKET, SOCK_RAW) succeeded; expected EPERM");
            return 1;
        }
        let err = std::io::Error::last_os_error().raw_os_error();
        if err != Some(libc::EPERM) {
            eprintln!("[child] socket(AF_PACKET, SOCK_RAW) returned error {err:?}; expected EPERM");
            return 2;
        }
    }
    0
}

/// Inet socket shapes whose traffic no cgroup sock_addr hook observes
/// (rk_sock_observed in net.bpf.c). Literal values, so the test does not
/// depend on which constants the libc crate exports.
const UNOBSERVED_SOCKETS: [(&str, i32, i32, i32); 12] = [
    (
        "ping (AF_INET, SOCK_DGRAM, IPPROTO_ICMP)",
        libc::AF_INET,
        2,
        1,
    ),
    (
        "ping (AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6)",
        libc::AF_INET6,
        2,
        58,
    ),
    (
        "UDP-Lite (AF_INET, SOCK_DGRAM, IPPROTO_UDPLITE)",
        libc::AF_INET,
        2,
        136,
    ),
    (
        "UDP-Lite (AF_INET6, SOCK_DGRAM, IPPROTO_UDPLITE)",
        libc::AF_INET6,
        2,
        136,
    ),
    (
        "SCTP (AF_INET, SOCK_STREAM, IPPROTO_SCTP)",
        libc::AF_INET,
        1,
        132,
    ),
    (
        "SCTP (AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)",
        libc::AF_INET,
        5,
        132,
    ),
    (
        "SCTP (AF_INET6, SOCK_STREAM, IPPROTO_SCTP)",
        libc::AF_INET6,
        1,
        132,
    ),
    (
        "DCCP (AF_INET, SOCK_DCCP, IPPROTO_DCCP)",
        libc::AF_INET,
        6,
        33,
    ),
    ("DCCP (AF_INET6, SOCK_DCCP, 0)", libc::AF_INET6, 6, 0),
    (
        "MPTCP (AF_INET, SOCK_STREAM, IPPROTO_MPTCP)",
        libc::AF_INET,
        1,
        262,
    ),
    ("SOCK_SEQPACKET (AF_INET, protocol 0)", libc::AF_INET, 5, 0),
    (
        "UDP protocol on a stream (AF_INET, SOCK_STREAM, IPPROTO_UDP)",
        libc::AF_INET,
        1,
        17,
    ),
];

/// Inet socket shapes the sock_addr hooks observe: always allowed, including
/// protocol 0 (resolved by the kernel after the LSM hook) and the type flags.
const OBSERVED_SOCKETS: [(&str, i32, i32, i32); 7] = [
    (
        "TCP (AF_INET, SOCK_STREAM, 0)",
        libc::AF_INET,
        libc::SOCK_STREAM,
        0,
    ),
    (
        "TCP (AF_INET, SOCK_STREAM, IPPROTO_TCP)",
        libc::AF_INET,
        libc::SOCK_STREAM,
        6,
    ),
    (
        "TCP (AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)",
        libc::AF_INET6,
        libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
        0,
    ),
    (
        "UDP (AF_INET, SOCK_DGRAM, 0)",
        libc::AF_INET,
        libc::SOCK_DGRAM,
        0,
    ),
    (
        "UDP (AF_INET, SOCK_DGRAM, IPPROTO_UDP)",
        libc::AF_INET,
        libc::SOCK_DGRAM,
        17,
    ),
    (
        "UDP (AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP)",
        libc::AF_INET6,
        libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
        17,
    ),
    (
        "AF_UNIX (SOCK_STREAM, 0)",
        libc::AF_UNIX,
        libc::SOCK_STREAM,
        0,
    ),
];

/// Creates one socket; Ok(()) on success (the descriptor is closed).
fn try_socket(family: i32, ty: i32, protocol: i32) -> Result<(), std::io::Error> {
    // SAFETY: plain syscall with integer arguments; the fd is closed at once.
    let fd = unsafe { libc::socket(family, ty, protocol) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd was just returned by socket(2) and is owned here.
    unsafe { libc::close(fd) };
    Ok(())
}

/// `unobserved_sockets <eperm|ok>`. `eperm`: every unobserved shape fails
/// with EPERM, every observed shape is created. `ok` (deny_raw_sockets =
/// false): no shape fails with EPERM (a missing protocol module or the ping
/// group range may still refuse one with another error), and UDP-Lite over
/// IPv4, which is built into every IPv4 kernel, is created.
fn handle_unobserved_sockets(args: &[String]) -> i32 {
    let Some(expected) = args.first() else {
        eprintln!("[child] unobserved_sockets: expected <eperm|ok>");
        return 360;
    };
    match expected.as_str() {
        "eperm" => {
            for (what, family, ty, protocol) in UNOBSERVED_SOCKETS {
                match try_socket(family, ty, protocol) {
                    Err(e) if e.raw_os_error() == Some(libc::EPERM) => {}
                    Ok(()) => {
                        eprintln!("[child] {what} was created; expected EPERM");
                        return 361;
                    }
                    Err(e) => {
                        eprintln!("[child] {what} failed with {e}; expected EPERM");
                        return 362;
                    }
                }
            }
            for (what, family, ty, protocol) in OBSERVED_SOCKETS {
                if let Err(e) = try_socket(family, ty, protocol) {
                    eprintln!("[child] {what} failed with {e}; expected success");
                    return 363;
                }
            }
            0
        }
        "ok" => {
            for (what, family, ty, protocol) in UNOBSERVED_SOCKETS {
                if let Err(e) = try_socket(family, ty, protocol) {
                    if e.raw_os_error() == Some(libc::EPERM) {
                        eprintln!("[child] {what} failed with EPERM without deny_raw_sockets");
                        return 364;
                    }
                }
            }
            if let Err(e) = try_socket(libc::AF_INET, libc::SOCK_DGRAM, 136) {
                eprintln!("[child] UDP-Lite (AF_INET) failed with {e}; expected success");
                return 365;
            }
            0
        }
        other => {
            eprintln!("[child] unobserved_sockets: unknown expectation `{other}`");
            366
        }
    }
}

/// One TUN/TAP attempt (docs/design/phase-16.md):
/// `tun <create|attach> <ifname> <ok|eperm> [nobody]` or
/// `tun attach_queue <inherited fd> <ok|eperm> [nobody]`.
/// `nobody` drops to uid/gid 65534 and every capability first.
fn handle_tun(args: &[String]) -> i32 {
    if args.len() < 3 {
        eprintln!("[child] tun: expected <op> <target> <ok|eperm> [nobody]");
        return 1;
    }
    let (op, target, expected) = (args[0].as_str(), args[1].as_str(), args[2].as_str());
    if args.get(3).map(String::as_str) == Some("nobody") {
        if let Err(e) = crate::tun::become_nobody() {
            eprintln!("[child] tun: dropping to nobody failed: {e}");
            return 2;
        }
    }
    let result = match op {
        "create" | "attach" => {
            crate::tun::open().and_then(|fd| crate::tun::set_iff(&fd, target, crate::tun::TUN))
        }
        "attach_queue" => match target.parse() {
            Ok(fd) => crate::tun::attach_queue(fd),
            Err(e) => {
                eprintln!("[child] tun: bad fd {target}: {e}");
                return 3;
            }
        },
        other => {
            eprintln!("[child] tun: unknown op {other}");
            return 4;
        }
    };
    match (expected, &result) {
        ("ok", Ok(())) => 0,
        ("eperm", Err(e)) if e.raw_os_error() == Some(libc::EPERM) => 0,
        _ => {
            eprintln!("[child] tun {op} {target}: got {result:?}, expected {expected}");
            5
        }
    }
}

fn handle_tcp_fastopen(args: &[String]) -> i32 {
    if args.is_empty() {
        return 240;
    }
    let addr_str = &args[0];
    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return 241,
    };

    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return 242;
        }

        let mut sin: libc::sockaddr_in = std::mem::zeroed();
        sin.sin_family = libc::AF_INET as u16;
        sin.sin_port = addr.port().to_be();
        let ip_bytes = match addr.ip() {
            std::net::IpAddr::V4(v4) => v4.octets(),
            _ => {
                libc::close(fd);
                return 243;
            }
        };
        sin.sin_addr.s_addr = u32::from_ne_bytes(ip_bytes);

        let data = b"fastopen payload";
        let ret = libc::sendto(
            fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            libc::MSG_FASTOPEN,
            &sin as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&sin) as libc::socklen_t,
        );
        let err = std::io::Error::last_os_error().raw_os_error();
        libc::close(fd);

        if ret < 0 && err == Some(libc::EPERM) {
            0
        } else {
            eprintln!("[child] TCP fastopen sendto returned {ret}, errno {err:?}; expected EPERM");
            1
        }
    }
}

fn handle_io_uring_connect(args: &[String]) -> i32 {
    if args.is_empty() {
        return 250;
    }
    let addr_str = &args[0];
    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return 251,
    };

    let mut ring = match io_uring::IoUring::new(8) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[child] io_uring_setup failed: {e}");
            return 252;
        }
    };

    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return 253;
        }

        let mut sin: libc::sockaddr_in = std::mem::zeroed();
        sin.sin_family = libc::AF_INET as u16;
        sin.sin_port = addr.port().to_be();
        if let std::net::IpAddr::V4(v4) = addr.ip() {
            sin.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
        }

        let connect_e = io_uring::opcode::Connect::new(
            io_uring::types::Fd(fd),
            &sin as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&sin) as libc::socklen_t,
        );

        if ring.submission().push(&connect_e.build()).is_err() {
            libc::close(fd);
            return 254;
        }

        if let Err(e) = ring.submit_and_wait(1) {
            libc::close(fd);
            eprintln!("[child] io_uring submit_and_wait error: {e}");
            return 255;
        }

        let cqe = match ring.completion().next() {
            Some(c) => c,
            None => {
                libc::close(fd);
                return 256;
            }
        };

        let res = cqe.result();
        libc::close(fd);

        if res == -libc::EPERM {
            0
        } else {
            eprintln!("[child] io_uring connect result: {res}, expected -EPERM (-1)");
            1
        }
    }
}

fn handle_blast_connect(args: &[String]) -> i32 {
    if args.is_empty() {
        return 260;
    }
    let addr_str = &args[0];
    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return 261,
    };

    for _ in 0..300 {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(50)) {
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {}
            Ok(_) => {
                eprintln!("[child] blast_connect: connection allowed unexpectedly");
                return 1;
            }
            Err(e) => {
                eprintln!("[child] blast_connect: non-EPERM error: {e:?}");
                return 2;
            }
        }
    }
    0
}

fn handle_flood_ringbuf(args: &[String]) -> i32 {
    let addr_str = if !args.is_empty() {
        &args[0]
    } else {
        "10.99.0.1:80"
    };
    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(_) => return 261,
    };
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[child] udp bind failed: {e}");
            return 262;
        }
    };
    let _ = sock.set_nonblocking(true);
    // 15,000 UDP sends to fill 1MB ring buffer (~10k events capacity) and trigger drops
    for _ in 0..15_000 {
        let _ = sock.send_to(b"flood", addr);
    }
    0
}

fn handle_paced_workload(args: &[String]) -> i32 {
    if args.len() < 4 {
        eprintln!("[child] paced_workload expects <proto> <addr> <count> <pace_us>");
        return 270;
    }
    let proto = &args[0];
    let addr_str = &args[1];
    let count: usize = match args[2].parse() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[child] invalid count {}: {e}", args[2]);
            return 271;
        }
    };
    let pace_us: u64 = match args[3].parse() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[child] invalid pace_us {}: {e}", args[3]);
            return 272;
        }
    };

    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[child] invalid addr {addr_str}: {e}");
            return 273;
        }
    };

    let mut eperm_count = 0u64;
    let mut ok_count = 0u64;

    if proto == "udp_connect" {
        for _ in 0..count {
            let sock = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[child] udp bind failed: {e}");
                    return 274;
                }
            };
            match sock.connect(addr) {
                Ok(_) => ok_count += 1,
                Err(e) if e.raw_os_error() == Some(libc::EPERM) => eperm_count += 1,
                Err(e) => {
                    eprintln!("[child] unexpected udp connect error: {e}");
                    return 275;
                }
            }
            if pace_us > 0 {
                std::thread::sleep(Duration::from_micros(pace_us));
            }
        }
    } else if proto == "udp" {
        let sock = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[child] udp bind failed: {e}");
                return 274;
            }
        };
        let _ = sock.set_nonblocking(true);

        for _ in 0..count {
            match sock.send_to(b"ping", addr) {
                Ok(_) => ok_count += 1,
                Err(e) if e.raw_os_error() == Some(libc::EPERM) => eperm_count += 1,
                Err(e) => {
                    eprintln!("[child] unexpected send_to error: {e}");
                    return 275;
                }
            }
            if pace_us > 0 {
                std::thread::sleep(Duration::from_micros(pace_us));
            }
        }
    } else {
        for _ in 0..count {
            match TcpStream::connect_timeout(&addr, Duration::from_millis(50)) {
                Ok(_) => ok_count += 1,
                Err(e) if e.raw_os_error() == Some(libc::EPERM) => eperm_count += 1,
                Err(e) => {
                    eprintln!("[child] unexpected tcp connect error: {e}");
                    return 276;
                }
            }
            if pace_us > 0 {
                std::thread::sleep(Duration::from_micros(pace_us));
            }
        }
    }

    println!("{{\"eperm\":{eperm_count},\"ok\":{ok_count}}}");
    0
}

fn handle_guard_bpf(args: &[String]) -> i32 {
    let expected = args.first().map(|s| s.as_str()).unwrap_or("eperm");
    #[repr(C)]
    struct BpfAttrGetNextId {
        start_id: u32,
        next_id: u32,
        open_flags: u32,
    }
    let mut attr = BpfAttrGetNextId {
        start_id: 0,
        next_id: 0,
        open_flags: 0,
    };
    let res = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            11, /* BPF_PROG_GET_NEXT_ID */
            &mut attr as *mut _ as *mut libc::c_void,
            std::mem::size_of::<BpfAttrGetNextId>() as u32,
        )
    };
    let err = if res < 0 {
        std::io::Error::last_os_error().raw_os_error()
    } else {
        None
    };
    match expected {
        "eperm" => {
            if err == Some(libc::EPERM) {
                0
            } else {
                eprintln!("[guard_bpf] expected EPERM, got res={res}, err={err:?}");
                1
            }
        }
        "ok" => {
            if res >= 0 || err == Some(libc::ENOENT) {
                0
            } else {
                eprintln!("[guard_bpf] expected OK, got res={res}, err={err:?}");
                1
            }
        }
        _ => 2,
    }
}

fn handle_guard_signal(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("[guard_signal] expects <target_pid> <expected: eperm|ok>");
        return 2;
    }
    let target_pid: i32 = match args[0].parse() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[guard_signal] invalid target_pid {}: {e}", args[0]);
            return 2;
        }
    };
    let expected = &args[1];
    let res = unsafe { libc::kill(target_pid, libc::SIGCONT) };
    let err = if res != 0 {
        std::io::Error::last_os_error().raw_os_error()
    } else {
        None
    };
    match expected.as_str() {
        "eperm" => {
            if err == Some(libc::EPERM) {
                0
            } else {
                eprintln!("[guard_signal] expected EPERM, got res={res}, err={err:?}");
                1
            }
        }
        "ok" => {
            if res == 0 {
                0
            } else {
                eprintln!("[guard_signal] expected OK, got res={res}, err={err:?}");
                1
            }
        }
        _ => 2,
    }
}

fn handle_guard_ptrace(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("[guard_ptrace] expects <target_pid> <expected: eperm|ok>");
        return 2;
    }
    let target_pid: i32 = match args[0].parse() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[guard_ptrace] invalid target_pid {}: {e}", args[0]);
            return 2;
        }
    };
    let expected = &args[1];
    let ptrace_res = unsafe { libc::ptrace(libc::PTRACE_SEIZE, target_pid as libc::pid_t, 0, 0) };
    let ptrace_err = if ptrace_res != 0 {
        std::io::Error::last_os_error().raw_os_error()
    } else {
        unsafe {
            libc::ptrace(libc::PTRACE_DETACH, target_pid as libc::pid_t, 0, 0);
        }
        None
    };
    let mem_path = format!("/proc/{target_pid}/mem");
    let mem_res = fs::File::open(&mem_path);
    let mem_err = match &mem_res {
        Err(e) => e.raw_os_error(),
        Ok(_) => None,
    };
    match expected.as_str() {
        "eperm" => {
            // procfs reports any failed ptrace access check on /proc/<pid>/mem
            // as EACCES, whichever LSM refused it (mm_access in fs/proc/base.c).
            if ptrace_err == Some(libc::EPERM) && mem_err == Some(libc::EACCES) {
                0
            } else {
                eprintln!(
                    "[guard_ptrace] expected ptrace EPERM and mem EACCES, got ptrace={ptrace_err:?}, mem={mem_err:?}"
                );
                1
            }
        }
        "ok" => {
            if ptrace_err.is_none() && mem_err.is_none() {
                0
            } else {
                eprintln!("[guard_ptrace] expected OK, got ptrace={ptrace_err:?}, mem={mem_err:?}");
                1
            }
        }
        _ => 2,
    }
}

fn handle_guard_pins() -> i32 {
    let unlink_res = unsafe { libc::unlink(c"/sys/fs/bpf/rk/maps/rk_meta".as_ptr()) };
    let unlink_err = if unlink_res != 0 {
        std::io::Error::last_os_error().raw_os_error()
    } else {
        None
    };
    let rename_res = unsafe {
        libc::rename(
            c"/sys/fs/bpf/rk/maps/rk_meta".as_ptr(),
            c"/sys/fs/bpf/rk/maps/rk_meta_renamed".as_ptr(),
        )
    };
    let rename_err = if rename_res != 0 {
        std::io::Error::last_os_error().raw_os_error()
    } else {
        None
    };
    let umount_res = unsafe { libc::umount(c"/sys/fs/bpf".as_ptr()) };
    let umount_err = if umount_res != 0 {
        std::io::Error::last_os_error().raw_os_error()
    } else {
        None
    };
    if unlink_err == Some(libc::EPERM)
        && rename_err == Some(libc::EPERM)
        && umount_err == Some(libc::EPERM)
    {
        0
    } else {
        eprintln!(
            "[guard_pins] expected EPERM, unlink={unlink_err:?}, \
             rename={rename_err:?}, umount={umount_err:?}"
        );
        1
    }
}

fn handle_exec_cmd(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("[child] exec_cmd expects <expected: ok|eperm> <path> [args...]");
        return 280;
    }
    let expected = &args[0];
    let path = &args[1];
    let cmd_args = &args[1..];

    let c_path = match std::ffi::CString::new(path.as_str()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[child] invalid path: {e}");
            return 281;
        }
    };

    let mut c_args: Vec<std::ffi::CString> = Vec::new();
    for a in cmd_args {
        match std::ffi::CString::new(a.as_str()) {
            Ok(ca) => c_args.push(ca),
            Err(e) => {
                eprintln!("[child] invalid arg: {e}");
                return 282;
            }
        }
    }

    let mut argv: Vec<*const libc::c_char> = c_args.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());

    let envp: [*const libc::c_char; 1] = [std::ptr::null()];

    unsafe {
        libc::execve(c_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
    }

    let err = std::io::Error::last_os_error();
    match expected.as_str() {
        "eperm" => {
            let code = err.raw_os_error();
            if code == Some(libc::EPERM) || code == Some(libc::EACCES) {
                0
            } else {
                eprintln!("[child] execve({path}) returned error {err:?}; expected EPERM/EACCES");
                1
            }
        }
        "ok" => {
            eprintln!("[child] execve({path}) failed: {err:?}; expected OK");
            2
        }
        _ => 283,
    }
}

fn handle_exec_large_argv(args: &[String]) -> i32 {
    let path = if !args.is_empty() {
        &args[0]
    } else {
        "/bin/true"
    };
    let c_path = match std::ffi::CString::new(path) {
        Ok(p) => p,
        Err(_) => return 290,
    };

    let mut c_args: Vec<std::ffi::CString> = Vec::new();
    c_args.push(c_path.clone());
    let dummy_arg = "A".repeat(60);
    for _ in 0..50 {
        if let Ok(ca) = std::ffi::CString::new(dummy_arg.as_str()) {
            c_args.push(ca);
        }
    }

    let mut argv: Vec<*const libc::c_char> = c_args.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());

    let envp: [*const libc::c_char; 1] = [std::ptr::null()];

    unsafe {
        libc::execve(c_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
    }

    let err = std::io::Error::last_os_error();
    eprintln!("[child] large execve({path}) failed: {err:?}");
    291
}

fn handle_exec_reload_workload(args: &[String]) -> i32 {
    if args.len() < 3 {
        eprintln!("[child] exec_reload expects <bin_path> <count> <pace_us>");
        return 292;
    }
    let bin_path = &args[0];
    let count: usize = match args[1].parse() {
        Ok(c) => c,
        Err(_) => return 293,
    };
    let pace_us: u64 = match args[2].parse() {
        Ok(p) => p,
        Err(_) => return 294,
    };

    let c_path = match std::ffi::CString::new(bin_path.as_str()) {
        Ok(p) => p,
        Err(_) => return 295,
    };
    let argv = [c_path.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null()];

    let mut eperm_count = 0u64;
    let mut ok_count = 0u64;

    for _ in 0..count {
        unsafe {
            let pid = libc::fork();
            if pid < 0 {
                eprintln!("[child] fork failed: {}", std::io::Error::last_os_error());
                return 296;
            } else if pid == 0 {
                libc::execve(c_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EPERM)
                    || err.raw_os_error() == Some(libc::EACCES)
                {
                    libc::_exit(1);
                } else {
                    libc::_exit(2);
                }
            } else {
                let mut status: libc::c_int = 0;
                let waited = libc::waitpid(pid, &mut status, 0);
                if waited < 0 {
                    eprintln!(
                        "[child] waitpid failed: {}",
                        std::io::Error::last_os_error()
                    );
                    return 297;
                }
                if libc::WIFEXITED(status) {
                    let code = libc::WEXITSTATUS(status);
                    if code == 0 {
                        ok_count += 1;
                    } else if code == 1 {
                        eperm_count += 1;
                    } else {
                        eprintln!("[child] child exited with unexpected code {code}");
                        return 298;
                    }
                } else {
                    eprintln!("[child] child did not exit normally");
                    return 299;
                }
            }
        }
        if pace_us > 0 {
            std::thread::sleep(Duration::from_micros(pace_us));
        }
    }

    println!("{{\"eperm\":{eperm_count},\"ok\":{ok_count}}}");
    0
}

fn handle_memfd_exec(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("[child] memfd_exec expects <expected: ok|eperm> [template]");
        return 300;
    }
    let expected = &args[0];
    let template = args.get(1).map(|s| s.as_str()).unwrap_or("/bin/true");

    let bytes = match fs::read(template) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[child] failed to read template {template}: {e}");
            return 301;
        }
    };

    let name = match std::ffi::CString::new("rk_memfd_test") {
        Ok(n) => n,
        Err(_) => return 302,
    };

    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC as libc::c_ulong,
        ) as libc::c_int
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        eprintln!("[child] memfd_create failed: {err}");
        return 303;
    }

    let mut written = 0;
    while written < bytes.len() {
        let n = unsafe {
            libc::write(
                fd,
                bytes[written..].as_ptr() as *const libc::c_void,
                bytes.len() - written,
            )
        };
        if n <= 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("[child] write to memfd failed: {err}");
            unsafe {
                libc::close(fd);
            }
            return 304;
        }
        written += n as usize;
    }

    let arg0 = match std::ffi::CString::new("memfd_prog") {
        Ok(a) => a,
        Err(_) => {
            unsafe {
                libc::close(fd);
            }
            return 305;
        }
    };
    let argv = [arg0.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null()];

    let rc = unsafe { libc::fexecve(fd, argv.as_ptr(), envp.as_ptr()) };
    let err = std::io::Error::last_os_error();
    unsafe {
        libc::close(fd);
    }

    match expected.as_str() {
        "eperm" => {
            let code = err.raw_os_error();
            if rc < 0 && (code == Some(libc::EPERM) || code == Some(libc::EACCES)) {
                0
            } else {
                eprintln!("[child] memfd fexecve returned {rc}, errno {err:?}; expected EPERM");
                1
            }
        }
        "ok" => {
            eprintln!("[child] memfd fexecve failed with {err:?}; expected OK");
            2
        }
        _ => 306,
    }
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[cfg(target_arch = "x86_64")]
const SYS_OPENAT2: libc::c_long = 437;
#[cfg(target_arch = "aarch64")]
const SYS_OPENAT2: libc::c_long = 437;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const SYS_OPENAT2: libc::c_long = libc::SYS_openat2;

#[cfg(target_arch = "x86_64")]
const SYS_RENAMEAT2: libc::c_long = 316;
#[cfg(target_arch = "aarch64")]
const SYS_RENAMEAT2: libc::c_long = 276;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const SYS_RENAMEAT2: libc::c_long = libc::SYS_renameat2;

fn handle_file_open(args: &[String]) -> i32 {
    if args.len() < 3 {
        eprintln!("[child] file_open expects <path> <mode: r|w|rw|o_trunc> <expected: ok|eperm>");
        return 310;
    }
    let path = &args[0];
    let mode = &args[1];
    let expected = &args[2];

    let c_path = match std::ffi::CString::new(path.as_str()) {
        Ok(p) => p,
        Err(_) => return 311,
    };

    let flags = match mode.as_str() {
        "r" => libc::O_RDONLY,
        "w" => libc::O_WRONLY,
        "rw" => libc::O_RDWR,
        "o_trunc" => libc::O_WRONLY | libc::O_TRUNC,
        _ => return 312,
    };

    let fd = unsafe { libc::open(c_path.as_ptr(), flags, 0o644) };
    if fd >= 0 {
        unsafe { libc::close(fd) };
        if expected == "ok" {
            0
        } else {
            eprintln!("[child] open({path}) succeeded but expected {expected}");
            1
        }
    } else {
        let err = std::io::Error::last_os_error();
        if expected == "eperm" && err.raw_os_error() == Some(libc::EPERM) {
            0
        } else {
            eprintln!("[child] open({path}) failed with error: {err:?}, expected {expected}");
            2
        }
    }
}

fn handle_file_openat2(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprintln!("[child] file_openat2 expects <path> <expected: ok|eperm>");
        return 313;
    }
    let path = &args[0];
    let expected = &args[1];

    let c_path = match std::ffi::CString::new(path.as_str()) {
        Ok(p) => p,
        Err(_) => return 314,
    };

    let how = OpenHow {
        flags: libc::O_RDONLY as u64,
        mode: 0,
        resolve: 0,
    };

    let fd = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            libc::AT_FDCWD,
            c_path.as_ptr(),
            &how as *const _ as *const libc::c_void,
            std::mem::size_of::<OpenHow>(),
        )
    };

    if fd >= 0 {
        unsafe { libc::close(fd as libc::c_int) };
        if expected == "ok" {
            0
        } else {
            eprintln!("[child] openat2({path}) succeeded but expected {expected}");
            1
        }
    } else {
        let err = std::io::Error::last_os_error();
        if expected == "eperm" && err.raw_os_error() == Some(libc::EPERM) {
            0
        } else {
            eprintln!("[child] openat2({path}) failed with error: {err:?}");
            2
        }
    }
}

fn handle_file_io_uring_openat(args: &[String]) -> i32 {
    if args.is_empty() {
        return 315;
    }
    let path = &args[0];
    let c_path = match std::ffi::CString::new(path.as_str()) {
        Ok(p) => p,
        Err(_) => return 316,
    };

    let mut ring = match io_uring::IoUring::new(8) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[child] io_uring_setup failed: {e}");
            return 317;
        }
    };

    let open_e =
        io_uring::opcode::OpenAt::new(io_uring::types::Fd(libc::AT_FDCWD), c_path.as_ptr())
            .flags(libc::O_RDONLY);

    unsafe {
        if ring.submission().push(&open_e.build()).is_err() {
            return 318;
        }
        if let Err(e) = ring.submit_and_wait(1) {
            eprintln!("[child] io_uring submit_and_wait error: {e}");
            return 319;
        }
        let cqe = match ring.completion().next() {
            Some(c) => c,
            None => return 320,
        };
        let res = cqe.result();
        if res >= 0 {
            libc::close(res);
            eprintln!("[child] io_uring openat succeeded, expected -EPERM");
            1
        } else if res == -libc::EPERM {
            0
        } else {
            eprintln!("[child] io_uring openat result {res}, expected -EPERM");
            2
        }
    }
}

fn handle_file_truncate(args: &[String]) -> i32 {
    if args.len() < 2 {
        return 321;
    }
    let path = &args[0];
    let expected = &args[1];
    let c_path = match std::ffi::CString::new(path.as_str()) {
        Ok(p) => p,
        Err(_) => return 322,
    };

    let rc = unsafe { libc::truncate(c_path.as_ptr(), 0) };
    if rc == 0 {
        if expected == "ok" {
            0
        } else {
            1
        }
    } else {
        let err = std::io::Error::last_os_error();
        if expected == "eperm" && err.raw_os_error() == Some(libc::EPERM) {
            0
        } else {
            2
        }
    }
}

fn handle_file_ftruncate(args: &[String]) -> i32 {
    if args.len() < 2 {
        return 323;
    }
    let path = &args[0];
    let expected = &args[1];
    let c_path = match std::ffi::CString::new(path.as_str()) {
        Ok(p) => p,
        Err(_) => return 324,
    };

    unsafe {
        let fd = libc::open(c_path.as_ptr(), libc::O_WRONLY);
        if fd < 0 {
            eprintln!(
                "[child] open for ftruncate failed: {}",
                std::io::Error::last_os_error()
            );
            return 325;
        }
        let rc = libc::ftruncate(fd, 0);
        let err = std::io::Error::last_os_error();
        libc::close(fd);
        if rc == 0 {
            if expected == "ok" {
                0
            } else {
                1
            }
        } else if expected == "eperm" && err.raw_os_error() == Some(libc::EPERM) {
            0
        } else {
            2
        }
    }
}

fn handle_file_unlink(args: &[String]) -> i32 {
    if args.len() < 2 {
        return 326;
    }
    let path = &args[0];
    let expected = &args[1];
    let c_path = match std::ffi::CString::new(path.as_str()) {
        Ok(p) => p,
        Err(_) => return 327,
    };

    let rc = unsafe { libc::unlink(c_path.as_ptr()) };
    if rc == 0 {
        if expected == "ok" {
            0
        } else {
            1
        }
    } else {
        let err = std::io::Error::last_os_error();
        if expected == "eperm" && err.raw_os_error() == Some(libc::EPERM) {
            0
        } else {
            2
        }
    }
}

fn handle_file_rmdir(args: &[String]) -> i32 {
    if args.len() < 2 {
        return 328;
    }
    let path = &args[0];
    let expected = &args[1];
    let c_path = match std::ffi::CString::new(path.as_str()) {
        Ok(p) => p,
        Err(_) => return 329,
    };

    let rc = unsafe { libc::rmdir(c_path.as_ptr()) };
    if rc == 0 {
        if expected == "ok" {
            0
        } else {
            1
        }
    } else {
        let err = std::io::Error::last_os_error();
        if expected == "eperm" && err.raw_os_error() == Some(libc::EPERM) {
            0
        } else {
            2
        }
    }
}

fn handle_file_rename(args: &[String]) -> i32 {
    if args.len() < 3 {
        return 330;
    }
    let old_path = &args[0];
    let new_path = &args[1];
    let expected = &args[2];
    let c_old = match std::ffi::CString::new(old_path.as_str()) {
        Ok(p) => p,
        Err(_) => return 331,
    };
    let c_new = match std::ffi::CString::new(new_path.as_str()) {
        Ok(p) => p,
        Err(_) => return 332,
    };

    let rc = unsafe { libc::rename(c_old.as_ptr(), c_new.as_ptr()) };
    if rc == 0 {
        if expected == "ok" {
            0
        } else {
            1
        }
    } else {
        let err = std::io::Error::last_os_error();
        if expected == "eperm" && err.raw_os_error() == Some(libc::EPERM) {
            0
        } else {
            2
        }
    }
}

fn handle_file_rename_exchange(args: &[String]) -> i32 {
    if args.len() < 3 {
        return 333;
    }
    let path_a = &args[0];
    let path_b = &args[1];
    let expected = &args[2];
    let c_a = match std::ffi::CString::new(path_a.as_str()) {
        Ok(p) => p,
        Err(_) => return 334,
    };
    let c_b = match std::ffi::CString::new(path_b.as_str()) {
        Ok(p) => p,
        Err(_) => return 335,
    };

    const RENAME_EXCHANGE: libc::c_uint = 2;
    let rc = unsafe {
        libc::syscall(
            SYS_RENAMEAT2,
            libc::AT_FDCWD,
            c_a.as_ptr(),
            libc::AT_FDCWD,
            c_b.as_ptr(),
            RENAME_EXCHANGE,
        )
    };
    if rc == 0 {
        if expected == "ok" {
            0
        } else {
            1
        }
    } else {
        let err = std::io::Error::last_os_error();
        if expected == "eperm" && err.raw_os_error() == Some(libc::EPERM) {
            0
        } else {
            2
        }
    }
}

fn handle_file_link(args: &[String]) -> i32 {
    if args.len() < 3 {
        return 336;
    }
    let old_path = &args[0];
    let new_path = &args[1];
    let expected = &args[2];
    let c_old = match std::ffi::CString::new(old_path.as_str()) {
        Ok(p) => p,
        Err(_) => return 337,
    };
    let c_new = match std::ffi::CString::new(new_path.as_str()) {
        Ok(p) => p,
        Err(_) => return 338,
    };

    let rc = unsafe { libc::link(c_old.as_ptr(), c_new.as_ptr()) };
    if rc == 0 {
        if expected == "ok" {
            0
        } else {
            1
        }
    } else {
        let err = std::io::Error::last_os_error();
        if expected == "eperm" && err.raw_os_error() == Some(libc::EPERM) {
            0
        } else {
            2
        }
    }
}

fn handle_file_create(args: &[String]) -> i32 {
    if args.len() < 2 {
        return 339;
    }
    let path = &args[0];
    let expected = &args[1];
    let c_path = match std::ffi::CString::new(path.as_str()) {
        Ok(p) => p,
        Err(_) => return 340,
    };

    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_EXCL,
            0o644,
        )
    };
    if fd >= 0 {
        unsafe { libc::close(fd) };
        if expected == "ok" {
            0
        } else {
            1
        }
    } else {
        let err = std::io::Error::last_os_error();
        if expected == "eperm" && err.raw_os_error() == Some(libc::EPERM) {
            0
        } else {
            2
        }
    }
}

/// `file_symlink <target> <linkpath> <ok|eperm>`: symlink(2).
fn handle_file_symlink(args: &[String]) -> i32 {
    if args.len() < 3 {
        return 370;
    }
    let (Ok(c_target), Ok(c_link)) = (
        std::ffi::CString::new(args[0].as_str()),
        std::ffi::CString::new(args[1].as_str()),
    ) else {
        return 371;
    };
    // SAFETY: both pointers are valid NUL-terminated strings.
    let rc = unsafe { libc::symlink(c_target.as_ptr(), c_link.as_ptr()) };
    expect_rc(rc, &args[2])
}

/// `file_mkfifo <path> <ok|eperm>`: mknod(2) of a FIFO, which needs no
/// privilege and reaches the inode_mknod hook (a regular-file mknod would
/// go through inode_create instead).
fn handle_file_mkfifo(args: &[String]) -> i32 {
    if args.len() < 2 {
        return 372;
    }
    let Ok(c_path) = std::ffi::CString::new(args[0].as_str()) else {
        return 373;
    };
    // SAFETY: valid NUL-terminated path; mode is a plain integer.
    let rc = unsafe { libc::mknod(c_path.as_ptr(), libc::S_IFIFO | 0o600, 0) };
    expect_rc(rc, &args[1])
}

/// Maps a syscall return code to the child's exit code: 0 when it matches
/// `expected` (`ok` = success, `eperm` = failure with EPERM).
fn expect_rc(rc: i32, expected: &str) -> i32 {
    if rc == 0 {
        return if expected == "ok" { 0 } else { 1 };
    }
    let err = std::io::Error::last_os_error();
    if expected == "eperm" && err.raw_os_error() == Some(libc::EPERM) {
        0
    } else {
        eprintln!("[child] failed with {err}; expected {expected}");
        2
    }
}

fn handle_file_chmod(args: &[String]) -> i32 {
    if args.len() < 2 {
        return 341;
    }
    let path = &args[0];
    let expected = &args[1];
    let c_path = match std::ffi::CString::new(path.as_str()) {
        Ok(p) => p,
        Err(_) => return 342,
    };

    let rc = unsafe { libc::chmod(c_path.as_ptr(), 0o600) };
    if rc == 0 {
        if expected == "ok" {
            0
        } else {
            1
        }
    } else {
        let err = std::io::Error::last_os_error();
        if expected == "eperm" && err.raw_os_error() == Some(libc::EPERM) {
            0
        } else {
            2
        }
    }
}

fn handle_file_proc_fd_reopen(args: &[String]) -> i32 {
    if args.len() < 2 {
        return 343;
    }
    let path = &args[0];
    let expected = &args[1];
    let c_path = match std::ffi::CString::new(path.as_str()) {
        Ok(p) => p,
        Err(_) => return 344,
    };

    unsafe {
        let fd = libc::open(c_path.as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            eprintln!(
                "[child] open RDONLY failed: {}",
                std::io::Error::last_os_error()
            );
            return 345;
        }
        let proc_path = format!("/proc/self/fd/{fd}");
        let c_proc = std::ffi::CString::new(proc_path).unwrap();
        let fd2 = libc::open(c_proc.as_ptr(), libc::O_WRONLY);
        let err = std::io::Error::last_os_error();
        libc::close(fd);
        if fd2 >= 0 {
            libc::close(fd2);
            if expected == "ok" {
                0
            } else {
                1
            }
        } else if expected == "eperm" && err.raw_os_error() == Some(libc::EPERM) {
            0
        } else {
            2
        }
    }
}

fn handle_file_relative_open(args: &[String]) -> i32 {
    if args.len() < 3 {
        return 346;
    }
    let dir = &args[0];
    let rel_path = &args[1];
    let expected = &args[2];
    let c_dir = match std::ffi::CString::new(dir.as_str()) {
        Ok(p) => p,
        Err(_) => return 347,
    };
    let c_rel = match std::ffi::CString::new(rel_path.as_str()) {
        Ok(p) => p,
        Err(_) => return 348,
    };

    unsafe {
        if libc::chdir(c_dir.as_ptr()) < 0 {
            eprintln!(
                "[child] chdir({dir}) failed: {}",
                std::io::Error::last_os_error()
            );
            return 349;
        }
        let fd = libc::open(c_rel.as_ptr(), libc::O_RDONLY);
        if fd >= 0 {
            libc::close(fd);
            if expected == "ok" {
                0
            } else {
                1
            }
        } else {
            let err = std::io::Error::last_os_error();
            if expected == "eperm" && err.raw_os_error() == Some(libc::EPERM) {
                0
            } else {
                2
            }
        }
    }
}

fn handle_file_reload_workload(args: &[String]) -> i32 {
    if args.len() < 3 {
        return 350;
    }
    let path = &args[0];
    let count: usize = match args[1].parse() {
        Ok(c) => c,
        Err(_) => return 351,
    };
    let pace_us: u64 = match args[2].parse() {
        Ok(p) => p,
        Err(_) => return 352,
    };

    let c_path = match std::ffi::CString::new(path.as_str()) {
        Ok(p) => p,
        Err(_) => return 353,
    };

    let mut eperm_count = 0u64;
    let mut ok_count = 0u64;

    for _ in 0..count {
        unsafe {
            let fd = libc::open(c_path.as_ptr(), libc::O_RDONLY);
            if fd >= 0 {
                ok_count += 1;
                libc::close(fd);
            } else {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EPERM) {
                    eperm_count += 1;
                }
            }
        }
        if pace_us > 0 {
            std::thread::sleep(Duration::from_micros(pace_us));
        }
    }

    println!("{{\"eperm\":{eperm_count},\"ok\":{ok_count}}}");
    0
}

/// Pins the calling thread to CPU 0, so a benchmark isn't migrated mid-run.
fn pin_to_cpu0() {
    // SAFETY: zeroed cpu_set_t is a valid empty set; sched_setaffinity reads it.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(0, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

/// Phase 7 microbenchmark (docs/design/phase-7.md §6): `bench <op> <iters>`
/// times one syscall loop per iteration after a warm-up, and prints
/// `{"p50":ns,"p99":ns,"mean":ns,"n":iters}`.
fn handle_bench(args: &[String]) -> i32 {
    let (Some(op), Some(iters)) = (
        args.first(),
        args.get(1).and_then(|s| s.parse::<usize>().ok()),
    ) else {
        eprintln!("[child] bench expects <op> <iterations>");
        return 290;
    };
    if iters == 0 {
        eprintln!("[child] bench needs at least one iteration");
        return 290;
    }
    pin_to_cpu0();
    let path = c"/run/rk-bench/file";
    let udp = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[child] bind: {e}");
            return 291;
        }
    };
    // Added to lo by the bench setup; allowed by the bench profile.
    let target: SocketAddr = "10.99.0.2:9".parse().expect("static address");
    let one = || -> Result<(), String> {
        match op.as_str() {
            "open" => {
                // SAFETY: valid NUL-terminated path; the fd is closed at once.
                let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
                if fd < 0 {
                    return Err(format!("open: {}", std::io::Error::last_os_error()));
                }
                unsafe { libc::close(fd) };
            }
            "connect" => udp.connect(target).map_err(|e| format!("connect: {e}"))?,
            "socket" => {
                // SAFETY: plain syscalls; the fd is closed at once.
                let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
                if fd < 0 {
                    return Err(format!("socket: {}", std::io::Error::last_os_error()));
                }
                unsafe { libc::close(fd) };
            }
            "exec" => {
                let st = std::process::Command::new("/bin/true")
                    .status()
                    .map_err(|e| format!("exec: {e}"))?;
                if !st.success() {
                    return Err(format!("exec: /bin/true exited {st}"));
                }
            }
            other => return Err(format!("unknown bench op {other}")),
        }
        Ok(())
    };
    for _ in 0..(iters / 10).max(10) {
        if let Err(e) = one() {
            eprintln!("[child] {e}");
            return 292;
        }
    }
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = std::time::Instant::now();
        if let Err(e) = one() {
            eprintln!("[child] {e}");
            return 292;
        }
        samples.push(start.elapsed().as_nanos() as u64);
    }
    samples.sort_unstable();
    let n = samples.len().max(1);
    let mean = samples.iter().sum::<u64>() / n as u64;
    println!(
        "{{\"p50\":{},\"p99\":{},\"mean\":{mean},\"n\":{n}}}",
        samples[n / 2],
        samples[(n * 99 / 100).min(n - 1)]
    );
    0
}

/// Phase 10 §7: keeps trying actions the policy denies for `duration_ms` and
/// reports how many got through. Any success while a sensor is replaced means
/// protection had a gap. Args: `<udp addr> <duration_ms> [exec path]`; the
/// exec probe (one fork per try) runs every 20th iteration. Prints one JSON
/// line and exits 0: the caller judges the counts.
fn handle_gap_probe(args: &[String]) -> i32 {
    let (Some(addr), Some(ms)) = (
        args.first().and_then(|a| a.parse::<SocketAddr>().ok()),
        args.get(1).and_then(|m| m.parse::<u64>().ok()),
    ) else {
        eprintln!("[child] gap_probe expects <udp addr> <duration_ms> [exec path]");
        return 290;
    };
    let exec = args.get(2);
    let deadline = std::time::Instant::now() + Duration::from_millis(ms);
    let (mut net_tries, mut net_ok, mut net_other) = (0u64, 0u64, 0u64);
    let (mut exec_tries, mut exec_ok) = (0u64, 0u64);
    while std::time::Instant::now() < deadline {
        net_tries += 1;
        match UdpSocket::bind("0.0.0.0:0").and_then(|s| s.connect(addr)) {
            Ok(()) => net_ok += 1,
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {}
            Err(_) => net_other += 1,
        }
        if let Some(path) = exec {
            if net_tries.is_multiple_of(20) {
                exec_tries += 1;
                if std::process::Command::new(path)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .is_ok()
                {
                    exec_ok += 1;
                }
            }
        }
    }
    println!(
        "{{\"net_tries\":{net_tries},\"net_ok\":{net_ok},\"net_other\":{net_other},\"exec_tries\":{exec_tries},\"exec_ok\":{exec_ok}}}"
    );
    0
}
