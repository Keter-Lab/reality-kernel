// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * exec.bpf.c — kernel-enforced execution policy (Phase 3).
 * Included by rk.bpf.c; see docs/design/phase-3.md.
 *
 * rk_exec_check decides: the identity of the file being executed (device,
 * inode) is looked up in the profile's allowlist. It runs for every stage of
 * an exec, so a script and its interpreter must both be allowed.
 * rk_exec_record observes: after the exec commits it records the filename and
 * the argument area exactly as the new process sees them.
 */

#define RK_EXEC_EPERM 1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rk_exec_key);
    __type(value, struct rk_exec_rule);
    __uint(max_entries, 65536);
} rk_exec_allow SEC(".maps");

static __always_inline void rk_exec_key_of(struct rk_exec_key *key, const struct rk_gov *g, struct inode *inode)
{
    key->scope = g->scope;
    key->_pad = 0;
    key->dev = BPF_CORE_READ(inode, i_sb, s_dev);
    key->ino = BPF_CORE_READ(inode, i_ino);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(rk_exec_check, struct linux_binprm *bprm, int ret)
{
    struct rk_payload_exec *body;
    struct rk_scratch_msg *msg;
    struct rk_exec_key key = {};
    struct rk_exec_rule *rule;
    struct rk_gov g = {};
    struct inode *inode;
    __u32 rule_id = 0, flags = RK_EXEC_DECISION;
    __u8 action;

    if (ret)
        return ret;
    if (!rk_governance(&g))
        return 0;

    inode = BPF_CORE_READ(bprm, file, f_inode);
    rk_exec_key_of(&key, &g, inode);

    if (BPF_CORE_READ(inode, i_nlink) == 0)
        flags |= RK_EXEC_UNLINKED;

    if ((flags & RK_EXEC_UNLINKED) && !(g.flags & RK_PROFILE_EXEC_ALLOW_UNLINKED)) {
        /* No stable on-disk identity (memfd, deleted file). */
        action = RK_ACTION_DENY;
    } else {
        rule = bpf_map_lookup_elem(&rk_exec_allow, &key);
        if (rule) {
            action = RK_ACTION_ALLOW;
            rule_id = rule->rule_id;
        } else {
            action = (g.flags & RK_PROFILE_EXEC_DENY_DEFAULT) ? RK_ACTION_DENY : RK_ACTION_ALLOW;
        }
    }

    /* Denied (or audit-would-deny) execs never reach sched_process_exec, so the
     * decision is recorded here. Allowed execs are recorded by rk_exec_record. */
    if (action == RK_ACTION_DENY) {
        msg = rk_scratch();
        if (msg) {
            rk_fill_hdr(&msg->hdr, g.cgroup_id, g.policy_gen, RK_EV_EXEC, rk_reported_verdict(&g, action),
                        rule_id);
            rk_fill_task(&msg->hdr);
            body = (struct rk_payload_exec *)msg->payload;
            body->file_dev = key.dev;
            body->file_ino = key.ino;
            body->flags = flags;
            body->str_count = 1;
            body->_pad = 0;
            msg->payload_len = sizeof(*body);
            rk_append_kstr(msg, BPF_CORE_READ(bprm, filename), 256);
            rk_emit(msg);
        }
    }

    /* LSM return must be provably in [-4095, 0]; see net.bpf.c. */
    int deny = rk_enforced_deny(&g, action);

    barrier_var(deny);
    if (deny)
        return -RK_EXEC_EPERM;
    return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(rk_exec_record, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
    struct rk_payload_exec *body;
    struct rk_scratch_msg *msg;
    struct rk_exec_key key = {};
    struct rk_exec_rule *rule;
    struct rk_gov g = {};
    struct inode *inode;
    struct mm_struct *mm;
    unsigned long arg_start, arg_end;
    __u32 flags = 0;
    int copied;

    if (!rk_governance(&g))
        return 0;

    msg = rk_scratch();
    if (!msg)
        return 0;

    inode = BPF_CORE_READ(bprm, file, f_inode);
    rk_exec_key_of(&key, &g, inode);
    rule = bpf_map_lookup_elem(&rk_exec_allow, &key);
    if (BPF_CORE_READ(inode, i_nlink) == 0)
        flags |= RK_EXEC_UNLINKED;

    rk_fill_hdr(&msg->hdr, g.cgroup_id, g.policy_gen, RK_EV_EXEC, RK_VERDICT_ALLOW, rule ? rule->rule_id : 0);
    rk_fill_task(&msg->hdr);

    body = (struct rk_payload_exec *)msg->payload;
    body->file_dev = key.dev;
    body->file_ino = key.ino;
    body->str_count = 2;
    body->_pad = 0;
    msg->payload_len = sizeof(*body);

    rk_append_kstr(msg, BPF_CORE_READ(bprm, filename), 256);

    /* The new image's argument area, read from the new mm (current == p). */
    mm = BPF_CORE_READ(p, mm);
    arg_start = BPF_CORE_READ(mm, arg_start);
    arg_end = BPF_CORE_READ(mm, arg_end);
    copied = rk_append_ublob(msg, (const void *)arg_start, arg_end > arg_start ? arg_end - arg_start : 0);
    if (copied > 0)
        flags |= RK_EXEC_ARGV_TRUNCATED;
    else if (copied < 0)
        flags |= RK_EXEC_ARGV_UNAVAILABLE;

    body->flags = flags;
    rk_emit(msg);
    return 0;
}
