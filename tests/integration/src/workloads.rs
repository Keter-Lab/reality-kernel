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
        "tcp_fastopen" => handle_tcp_fastopen(rest),
        "io_uring_connect" => handle_io_uring_connect(rest),
        "blast_connect" => handle_blast_connect(rest),
        "flood_ringbuf" => handle_flood_ringbuf(rest),
        "paced_workload" => handle_paced_workload(rest),
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
    // 35,000 UDP sends to fill 1MB ring buffer (~10k events capacity) and trigger drops
    for _ in 0..35_000 {
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

    if proto == "udp" {
        let sock = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[child] udp bind failed: {e}");
                return 274;
            }
        };

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
