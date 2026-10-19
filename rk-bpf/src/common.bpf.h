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

static __always_inline struct rk_scratch_msg *rk_scratch(void)
{
    __u32 zero = 0;
    struct rk_scratch_buf *buf = bpf_map_lookup_elem(&scratch_map, &zero);

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

/* Append [__u16 len][bytes] read from kernel memory. Truncates to fit. */
static __always_inline void rk_append_kstr(struct rk_scratch_msg *msg, const void *src, __u32 max_len)
{
    __u32 off = msg->payload_len;
    __u16 *len_ptr;
    __u32 room;
    long n;

    if (off + 2 >= RK_SCRATCH_PAYLOAD_MAX)
        return;
    len_ptr = (__u16 *)&msg->payload[off & RK_PAYLOAD_MASK];
    off += 2;

    room = RK_SCRATCH_PAYLOAD_MAX - off;
    if (max_len > room)
        max_len = room;

    n = bpf_probe_read_kernel_str(&msg->payload[off & RK_PAYLOAD_MASK], max_len & RK_PAYLOAD_MASK, src);
    if (n <= 0) {
        *len_ptr = 0;
        msg->payload_len = off;
        return;
    }
    /* n includes the NUL terminator, which is not transmitted. */
    *len_ptr = (__u16)(n - 1);
    msg->payload_len = off + (__u32)(n - 1);
}

/* Emit hdr + payload_len + _reserved + payload at its real size. */
static __always_inline void rk_emit(struct rk_scratch_msg *msg)
{
    __u32 len = msg->payload_len;

    if (len > RK_SCRATCH_PAYLOAD_MAX)
        len = RK_SCRATCH_PAYLOAD_MAX;
    if (bpf_ringbuf_output(&events_ringbuf, msg, sizeof(struct rk_hdr) + 8 + len, 0) < 0)
        rk_count(RK_CNT_RINGBUF_DROP);
}

#endif /* COMMON_BPF_H */
