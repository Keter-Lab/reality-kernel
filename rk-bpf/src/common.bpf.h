/* SPDX-License-Identifier: (GPL-2.0-only OR MIT) */
/*
 * common.bpf.h — shared maps and event-emission helpers.
 *
 * Emission is strictly best effort: helpers return nothing that a hook could
 * branch on, so telemetry can never change a verdict. Failures only bump a
 * per-CPU counter (enum rk_counter).
 */
#ifndef COMMON_BPF_H
#define COMMON_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "rk_abi.h"

#define RK_PAYLOAD_MASK (RK_SCRATCH_PAYLOAD_MAX - 1)

#ifndef barrier_var /* provided by libbpf >= 1.0 */
#define barrier_var(var) asm volatile("" : "+r"(var))
#endif

_Static_assert((RK_SCRATCH_PAYLOAD_MAX & RK_PAYLOAD_MASK) == 0,
               "RK_SCRATCH_PAYLOAD_MAX must be a power of two");

/*
 * Map value for the per-CPU scratch buffer. The slack tail lets the verifier
 * prove that payload[off & MASK] with a copy length of (len & MASK) always
 * stays inside the map value. Only msg is ever emitted.
 */
struct rk_scratch_buf {
    struct rk_scratch_msg msg;
    __u8 slack[RK_SCRATCH_PAYLOAD_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct rk_scratch_buf);
    __uint(max_entries, 1);
} scratch_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, RK_CNT_MAX);
} rk_counters SEC(".maps");

/* Governed cgroups: key = cgroup id, value = policy generation. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 1024);
} monitored_cgroups SEC(".maps");

/* Policy maps (docs/design/phase-2.md §4). Written only by rk-sensor. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, struct rk_binding);
    __uint(max_entries, 4096);
} rk_cgroup_profile SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct rk_profile);
    __uint(max_entries, RK_POLICY_SLOTS * RK_MAX_PROFILES);
} rk_profiles SEC(".maps");

/* Commit point of a policy apply: which generation slot is live. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} rk_active_slot SEC(".maps");

static __always_inline void rk_count(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&rk_counters, &idx);

    if (val)
        *val += 1; /* per-CPU slot: no atomics needed */
}

/* Returns the policy generation for the current cgroup, or 0 if ungoverned. */
static __always_inline __u64 rk_governed_gen(__u64 cgroup_id)
{
    __u64 *gen = bpf_map_lookup_elem(&monitored_cgroups, &cgroup_id);

    return gen ? *gen : 0;
}

/* The governance context of one decision (steps 1-3 of the decision path). */
struct rk_gov {
    __u64 cgroup_id;
    __u64 policy_gen;
    __u32 scope;          /* slot << 31 | profile: LPM key prefix */
    __u8  mode;
    __u8  net_default;
    __u16 flags;
};

/*
 * Returns 0 for an ungoverned task (fast path: one hash lookup). A cgroup bound
 * to a profile whose slot entry was never written is a configuration error and
 * fails closed: ENFORCE, default deny, raw sockets denied, no rule matches.
 */
static __always_inline int rk_governance(struct rk_gov *g)
{
    __u64 cg = bpf_get_current_cgroup_id();
    struct rk_binding *binding;
    struct rk_profile *prof;
    __u32 zero = 0, slot = 0, idx, profile;
    __u32 *active;

    binding = bpf_map_lookup_elem(&rk_cgroup_profile, &cg);
    if (!binding)
        return 0;

    active = bpf_map_lookup_elem(&rk_active_slot, &zero);
    if (active)
        slot = *active & 1;
    profile = binding->profile;

    g->cgroup_id = cg;
    if (profile >= RK_MAX_PROFILES)
        goto fail_closed;
    idx = slot * RK_MAX_PROFILES + profile;
    prof = bpf_map_lookup_elem(&rk_profiles, &idx);
    if (!prof || prof->policy_gen == 0)
        goto fail_closed;

    g->policy_gen = prof->policy_gen;
    g->scope = (slot << 31) | profile;
    g->mode = prof->mode;
    g->net_default = prof->net_default;
    g->flags = prof->flags;
    return 1;

fail_closed:
    g->policy_gen = 0;
    g->scope = 0xffffffff; /* no trie entry uses this scope */
    g->mode = RK_MODE_ENFORCE;
    g->net_default = RK_ACTION_DENY;
    g->flags = RK_PROFILE_DENY_RAW_SOCKETS;
    return 1;
}

/* Verdict reported in events: AUDIT turns a deny into audit-would-deny. */
static __always_inline __u8 rk_reported_verdict(const struct rk_gov *g, __u8 action)
{
    if (action != RK_ACTION_DENY)
        return RK_VERDICT_ALLOW;
    return g->mode == RK_MODE_ENFORCE ? RK_VERDICT_DENY : RK_VERDICT_AUDIT_WOULD_DENY;
}

static __always_inline int rk_enforced_deny(const struct rk_gov *g, __u8 action)
{
    return action == RK_ACTION_DENY && g->mode == RK_MODE_ENFORCE;
}

static __always_inline struct rk_scratch_msg *rk_scratch(void)
{
    __u32 zero = 0;
    struct rk_scratch_buf *buf;

#ifdef RK_TEST_FORCE_EMIT_FAIL
    /* Test-only build (rk_emitfail.bpf.o): every emission fails. */
    rk_count(RK_CNT_SCRATCH_MISS);
    return 0;
#endif
    buf = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!buf) {
        rk_count(RK_CNT_SCRATCH_MISS);
        return 0;
    }
    buf->msg.payload_len = 0;
    buf->msg._reserved = 0;
    return &buf->msg;
}

/*
 * Fill the header fields that every hook type can provide. pid/tgid are left
 * at 0 here because bpf_get_current_pid_tgid is not available to every
 * program type on every supported kernel; callers that can, set them.
 */
static __always_inline void rk_fill_hdr(struct rk_hdr *hdr, __u64 cgroup_id, __u64 policy_gen,
                                        __u16 type, __u8 verdict, __u32 rule_id)
{
    __u64 uid_gid = bpf_get_current_uid_gid();

    hdr->ts_ns = bpf_ktime_get_boot_ns();
    hdr->cgroup_id = cgroup_id;
    hdr->policy_gen = policy_gen;
    hdr->pid = 0;
    hdr->tgid = 0;
    hdr->uid = (__u32)uid_gid;
    hdr->gid = (__u32)(uid_gid >> 32);
    hdr->type = type;
    hdr->verdict = verdict;
    hdr->abi = RK_ABI_VERSION;
    hdr->rule_id = rule_id;
}

static __always_inline void rk_fill_task(struct rk_hdr *hdr)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    hdr->pid = (__u32)pid_tgid;
    hdr->tgid = (__u32)(pid_tgid >> 32);
}

/*
 * Append [__u16 len][bytes] read from kernel memory. Truncates to fit.
 *
 * Every offset and length passed to the verifier is masked and then pinned
 * with barrier_var(): after a range check clang otherwise drops the mask as
 * redundant, and the verifier (which tracks registers, not C semantics) sees
 * an unbounded pointer. Caught by the VM matrix on every kernel.
 */
static __always_inline void rk_append_kstr(struct rk_scratch_msg *msg, const void *src, __u32 max_len)
{
    __u32 off = msg->payload_len;
    __u32 len_off, str_off, room;
    __u16 *len_ptr;
    long n;

    if (off > RK_SCRATCH_PAYLOAD_MAX - 3) /* need 2 length bytes + 1 data byte */
        return;

    len_off = off & RK_PAYLOAD_MASK;
    barrier_var(len_off);
    len_ptr = (__u16 *)&msg->payload[len_off];

    str_off = (off + 2) & RK_PAYLOAD_MASK;
    barrier_var(str_off);

    room = RK_SCRATCH_PAYLOAD_MAX - (off + 2);
    if (max_len > room)
        max_len = room;
    max_len &= RK_PAYLOAD_MASK;
    barrier_var(max_len);

    n = bpf_probe_read_kernel_str(&msg->payload[str_off], max_len, src);
    if (n <= 0) {
        *len_ptr = 0;
        msg->payload_len = off + 2;
        return;
    }
    /* n includes the NUL terminator, which is not transmitted. */
    *len_ptr = (__u16)(n - 1);
    msg->payload_len = off + 2 + (__u32)(n - 1);
}

/* Emit hdr + payload_len + _reserved + payload at its real size. */
static __always_inline void rk_emit(struct rk_scratch_msg *msg)
{
    __u32 len = msg->payload_len;

    if (len > RK_SCRATCH_PAYLOAD_MAX)
        len = RK_SCRATCH_PAYLOAD_MAX;
    /* Mask pinned for the verifier as above; 4095 + 56 still fits the map value. */
    len &= (2 * RK_SCRATCH_PAYLOAD_MAX - 1);
    barrier_var(len);
    if (bpf_ringbuf_output(&events_ringbuf, msg, sizeof(struct rk_hdr) + 8 + len, 0) < 0)
        rk_count(RK_CNT_RINGBUF_DROP);
}

#endif /* COMMON_BPF_H */
