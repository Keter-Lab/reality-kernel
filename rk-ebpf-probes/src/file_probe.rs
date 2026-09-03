use aya_ebpf::macros::{lsm, tracepoint};
use aya_ebpf::programs::{LsmContext, TracePointContext};

use rk_ebpf_common::{TaggedFileOpenEvent, EVENT_TAG_FILE_OPEN};

use crate::maps::EVENTS;
use crate::util::{
    bump_drop_counter, fill_comm, identity, ns_stub, path_has_sensitive_prefix, read_user_cstr, O_RDWR,
    O_WRONLY,
};

const OPENAT_FILENAME_OFFSET: usize = 24;
const OPENAT_FLAGS_OFFSET: usize = 32;
const OPENAT_MODE_OFFSET: usize = 40;

#[lsm(name = "rk_lsm_file_open")]
pub fn rk_lsm_file_open(_ctx: LsmContext) -> i32 {
    // NOTE: full path extraction from struct file requires CO-RE traversal.
    // We keep the LSM attachment active; fallback tracepoint captures path-rich events.
    0
}

#[tracepoint(name = "openat_enter")]
pub fn openat_enter(ctx: TracePointContext) -> u32 {
    match unsafe { do_openat(&ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

unsafe fn do_openat(ctx: &TracePointContext) -> Result<(), i64> {
    let filename_ptr = ctx.read_at::<*const u8>(OPENAT_FILENAME_OFFSET)?;
    let flags = ctx.read_at::<u32>(OPENAT_FLAGS_OFFSET)?;
    let mode = ctx.read_at::<u32>(OPENAT_MODE_OFFSET)?;

    let Some(mut slot) = EVENTS.reserve::<TaggedFileOpenEvent>(0) else {
        bump_drop_counter();
        return Ok(());
    };

    let tagged = slot.as_mut_ptr();
    (*tagged).tag = EVENT_TAG_FILE_OPEN;
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
    event.flags = flags;
    event.mode = mode;
    event.retval = 0;
    event.comm = [0; 16];
    event.path = [0; 256];

    fill_comm(&mut event.comm);
    read_user_cstr(filename_ptr, &mut event.path);

    let is_sensitive = path_has_sensitive_prefix(&event.path);
    let is_write = (flags & (O_WRONLY | O_RDWR)) != 0;

    // Sensitive reads are always emitted; writes on sensitive paths are also emitted.
    if !(is_sensitive || (is_write && is_sensitive)) {
        slot.discard(0);
        return Ok(());
    }

    slot.submit(0);
    Ok(())
}
