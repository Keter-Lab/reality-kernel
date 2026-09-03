use aya_ebpf::macros::cgroup_sock_addr;
use aya_ebpf::programs::SockAddrContext;

use rk_ebpf_common::{TaggedNetConnectEvent, EVENT_TAG_NET_CONNECT};

use crate::maps::EVENTS;
use crate::util::{bump_drop_counter, fill_comm, identity, is_loopback_v4, is_loopback_v6};

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const TCP_PROTO: u16 = 6;
const UDP_PROTO: u16 = 17;

#[cgroup_sock_addr(name = "rk_connect4")]
pub fn rk_connect4(ctx: SockAddrContext) -> i32 {
    unsafe {
        match emit_connect(&ctx, AF_INET) {
            Ok(_) => 1,
            Err(_) => 1,
        }
    }
}

#[cgroup_sock_addr(name = "rk_connect6")]
pub fn rk_connect6(ctx: SockAddrContext) -> i32 {
    unsafe {
        match emit_connect(&ctx, AF_INET6) {
            Ok(_) => 1,
            Err(_) => 1,
        }
    }
}

unsafe fn emit_connect(ctx: &SockAddrContext, family: u16) -> Result<(), i64> {
    let Some(mut slot) = EVENTS.reserve::<TaggedNetConnectEvent>(0) else {
        bump_drop_counter();
        return Ok(());
    };

    let tagged = slot.as_mut_ptr();
    (*tagged).tag = EVENT_TAG_NET_CONNECT;
    (*tagged)._pad = [0; 7];

    let event = &mut (*tagged).event;
    let (ts_ns, pid, tgid, uid, gid, cgroup_id) = identity();

    event.ts_ns = ts_ns;
    event.pid = pid;
    event.tgid = tgid;
    event.uid = uid;
    event.gid = gid;
    event.net_ns = 0;
    event.cgroup_id = cgroup_id;
    event.family = family;
    event.protocol = match ctx.protocol() {
        6 => TCP_PROTO,
        17 => UDP_PROTO,
        other => other as u16,
    };
    // user_port() is network-endian; store host-order value for userland policy checks.
    event.port_be = u16::from_be(ctx.user_port());
    event.verdict = 0;
    event._pad0 = 0;
    event._pad1 = 0;
    event.comm = [0; 16];
    event.addr = [0; 16];
    fill_comm(&mut event.comm);

    if family == AF_INET {
        let ip = ctx.user_ip4();
        if is_loopback_v4(ip) {
            slot.discard(0);
            return Ok(());
        }
        event.addr[0..4].copy_from_slice(&ip.to_be_bytes());
    } else {
        let ip6 = ctx.user_ip6();
        let bytes = ip6.octets();
        if is_loopback_v6(&bytes) {
            slot.discard(0);
            return Ok(());
        }
        event.addr = bytes;
    }

    slot.submit(0);
    Ok(())
}
