// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * guard.bpf.c — self-protection hooks (docs/design/phase-6.md §5).
 *
 * Governed tasks may not use bpf(), signal or ptrace the sensor, or remove
 * pins (unlink, rename, rmdir in bpffs, umount of bpffs). ENFORCE returns
 * -EPERM; AUDIT reports and allows. Every decision is an RK_EV_TAMPER event.
 * Included by rk.bpf.c; the maps live in common.bpf.h.
 */

#define RK_GUARD_EPERM 1
#define RK_BPF_FS_MAGIC 0xcafe4a11

/*
 * The sensor is identified by tgid and process start time, so a recycled PID
 * after the sensor exits is never mistaken for it. start_ticks is
 * /proc/<tgid>/stat starttime, which the kernel derives from the group
 * leader's start_boottime the same way.
 */
static __always_inline int rk_is_sensor(struct task_struct *task)
{
    __u32 zero = 0;
    struct rk_guard_target *sensor = bpf_map_lookup_elem(&rk_guard, &zero);
    __u64 start;

    if (!sensor || !sensor->tgid)
        return 0;
    if ((__u32)BPF_CORE_READ(task, tgid) != sensor->tgid)
        return 0;
    start = BPF_CORE_READ(task, group_leader, start_boottime);
    return start / RK_NSEC_PER_CLOCK_TICK == sensor->start_ticks;
}

/* Reports one tampering attempt; returns the LSM verdict. */
static __always_inline int rk_guard_decide(const struct rk_gov *g, __u16 hook, __u32 target_tgid,
                                           __u64 detail)
{
    struct rk_scratch_msg *msg = rk_scratch();
    struct rk_payload_tamper *body;

    if (msg) {
        rk_fill_hdr(&msg->hdr, g->cgroup_id, g->policy_gen, RK_EV_TAMPER,
                    rk_reported_verdict(g, RK_ACTION_DENY), 0);
        rk_fill_task(&msg->hdr);
        body = (struct rk_payload_tamper *)msg->payload;
        __builtin_memset(body, 0, sizeof(*body));
        body->hook = hook;
        body->target_tgid = target_tgid;
        body->detail = detail;
        msg->payload_len = sizeof(*body);
        rk_emit(msg);
    }

    /* LSM return must be provably in [-4095, 0]; see net.bpf.c. */
    int deny = rk_enforced_deny(g, RK_ACTION_DENY);

    barrier_var(deny);
    if (deny)
        return -RK_GUARD_EPERM;
    return 0;
}

static __always_inline int rk_is_bpffs(struct super_block *sb)
{
    return BPF_CORE_READ(sb, s_magic) == RK_BPF_FS_MAGIC;
}

/*
 * Reads only `cmd`: newer kernels append a `bool kernel` argument, which would
 * move the trailing `ret` this program would otherwise read.
 */
SEC("lsm/bpf")
int BPF_PROG(rk_guard_bpf, int cmd)
{
    struct rk_gov g = {};

    if (!rk_governance(&g))
        return 0;
    return rk_guard_decide(&g, RK_TAMPER_BPF, 0, (__u64)cmd);
}

SEC("lsm/task_kill")
int BPF_PROG(rk_guard_task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig,
             const struct cred *cred, int ret)
{
    struct rk_gov g = {};

    if (ret)
        return ret;
    if (!rk_is_sensor(p) || !rk_governance(&g))
        return 0;
    return rk_guard_decide(&g, RK_TAMPER_SIGNAL, (__u32)BPF_CORE_READ(p, tgid), (__u64)sig);
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(rk_guard_ptrace, struct task_struct *child, unsigned int mode, int ret)
{
    struct rk_gov g = {};

    if (ret)
        return ret;
    if (!rk_is_sensor(child) || !rk_governance(&g))
        return 0;
    return rk_guard_decide(&g, RK_TAMPER_PTRACE, (__u32)BPF_CORE_READ(child, tgid), (__u64)mode);
}

SEC("lsm/inode_unlink")
int BPF_PROG(rk_guard_pin_unlink, struct inode *dir, struct dentry *dentry, int ret)
{
    struct rk_gov g = {};

    if (ret)
        return ret;
    if (!rk_is_bpffs(BPF_CORE_READ(dir, i_sb)) || !rk_governance(&g))
        return 0;
    return rk_guard_decide(&g, RK_TAMPER_PIN_UNLINK, 0, 0);
}

SEC("lsm/inode_rename")
int BPF_PROG(rk_guard_pin_rename, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry, int ret)
{
    struct rk_gov g = {};

    if (ret)
        return ret;
    if ((!rk_is_bpffs(BPF_CORE_READ(old_dir, i_sb)) && !rk_is_bpffs(BPF_CORE_READ(new_dir, i_sb))) ||
        !rk_governance(&g))
        return 0;
    return rk_guard_decide(&g, RK_TAMPER_PIN_RENAME, 0, 0);
}

SEC("lsm/inode_rmdir")
int BPF_PROG(rk_guard_pin_rmdir, struct inode *dir, struct dentry *dentry, int ret)
{
    struct rk_gov g = {};

    if (ret)
        return ret;
    if (!rk_is_bpffs(BPF_CORE_READ(dir, i_sb)) || !rk_governance(&g))
        return 0;
    return rk_guard_decide(&g, RK_TAMPER_PIN_RMDIR, 0, 0);
}

SEC("lsm/sb_umount")
int BPF_PROG(rk_guard_umount, struct vfsmount *mnt, int flags, int ret)
{
    struct rk_gov g = {};

    if (ret)
        return ret;
    if (!rk_is_bpffs(BPF_CORE_READ(mnt, mnt_sb)) || !rk_governance(&g))
        return 0;
    return rk_guard_decide(&g, RK_TAMPER_UMOUNT, 0, (__u64)flags);
}
