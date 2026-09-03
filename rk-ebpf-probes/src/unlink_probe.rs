use aya_ebpf::macros::tracepoint;
use aya_ebpf::programs::TracePointContext;

use rk_ebpf_common::{TaggedUnlinkEvent, EVENT_TAG_UNLINK};

use crate::maps::EVENTS;
use crate::util::{bump_drop_counter, fill_comm, identity, ns_stub, read_user_cstr};

const ARG1_OFFSET: usize = 24;

#[tracepoint(name = "unlinkat_enter")]
pub fn unlinkat_enter(ctx: TracePointContext) -> u32 {
    match unsafe { do_unlinkat(&ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

unsafe fn do_unlinkat(ctx: &TracePointContext) -> Result<(), i64> {
    let pathname_ptr = ctx.read_at::<*const u8>(ARG1_OFFSET)?;

    let Some(mut slot) = EVENTS.reserve::<TaggedUnlinkEvent>(0) else {
        bump_drop_counter();
        return Ok(());
    };

    let tagged = slot.as_mut_ptr();
    (*tagged).tag = EVENT_TAG_UNLINK;
    (*tagged)._pad = [0; 7];

    let event = &mut (*tagged).event;
    let (ts_ns, pid, tgid, uid, gid, cgroup_id) = identity();
    let (mnt_ns, _, _) = ns_stub();

    event.ts_ns = ts_ns;
    event.pid = pid;
    event.tgid = tgid;
    event.uid = uid;
    event.gid = gid;
    event.mnt_ns = mnt_ns;
    event.cgroup_id = cgroup_id;
    event.retval = 0;
    event.comm = [0; 16];
    event.path = [0; 256];

    fill_comm(&mut event.comm);
    read_user_cstr(pathname_ptr, &mut event.path);

    slot.submit(0);
    Ok(())
}
