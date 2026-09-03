use aya_ebpf::macros::tracepoint;
use aya_ebpf::programs::TracePointContext;

use rk_ebpf_common::{
    TaggedExecEvent, EVENT_TAG_EXEC,
};

use crate::maps::EVENTS;
use crate::util::{bump_drop_counter, fill_comm, identity, ns_stub, read_user_cstr, read_user_ptr};

const ARG0_OFFSET: usize = 16;
const ARG1_OFFSET: usize = 24;
const ARG2_OFFSET: usize = 32;

#[tracepoint(name = "exec_enter_execve")]
pub fn exec_enter_execve(ctx: TracePointContext) -> u32 {
    match unsafe { do_execve(&ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[tracepoint(name = "exec_enter_execveat")]
pub fn exec_enter_execveat(ctx: TracePointContext) -> u32 {
    match unsafe { do_execveat(&ctx) } {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

unsafe fn do_execve(ctx: &TracePointContext) -> Result<(), i64> {
    let filename_ptr = ctx.read_at::<*const u8>(ARG0_OFFSET)?;
    let argv_ptr = ctx.read_at::<*const *const u8>(ARG1_OFFSET)?;
    emit_exec(filename_ptr, argv_ptr)
}

unsafe fn do_execveat(ctx: &TracePointContext) -> Result<(), i64> {
    let filename_ptr = ctx.read_at::<*const u8>(ARG1_OFFSET)?;
    let argv_ptr = ctx.read_at::<*const *const u8>(ARG2_OFFSET)?;
    emit_exec(filename_ptr, argv_ptr)
}

unsafe fn emit_exec(filename_ptr: *const u8, argv_ptr: *const *const u8) -> Result<(), i64> {
    let Some(mut slot) = EVENTS.reserve::<TaggedExecEvent>(0) else {
        bump_drop_counter();
        return Ok(());
    };

    let tagged = slot.as_mut_ptr();
    (*tagged).tag = EVENT_TAG_EXEC;
    (*tagged)._pad = [0; 7];

    let event = &mut (*tagged).event;
    let (ts_ns, pid, tgid, uid, gid, cgroup_id) = identity();
    let (mnt_ns, pid_ns, ppid) = ns_stub();

    event.ts_ns = ts_ns;
    event.pid = pid;
    event.tgid = tgid;
    event.ppid = ppid;
    event.uid = uid;
    event.gid = gid;
    event.mnt_ns = mnt_ns;
    event.pid_ns = pid_ns;
    event.cgroup_id = cgroup_id;
    event.retval = 0;
    event.comm = [0; 16];
    event.filename = [0; 256];
    event.argv_summary = [0; 256];

    fill_comm(&mut event.comm);
    read_user_cstr(filename_ptr, &mut event.filename);

    let argv1_ptr = read_user_ptr(argv_ptr.add(1)).unwrap_or(core::ptr::null());
    read_user_cstr(argv1_ptr, &mut event.argv_summary);

    slot.submit(0);
    Ok(())
}
