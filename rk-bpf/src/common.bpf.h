#ifndef COMMON_BPF_H
#define COMMON_BPF_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "rk_abi.h"

/* BPF Ring Buffer for events */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1MB ring buffer */
} events_ringbuf SEC(".maps");

/* Per-CPU Scratch Map to avoid BPF 512-byte stack limit */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct rk_scratch_msg);
    __uint(max_entries, 1);
} scratch_map SEC(".maps");

/* Monitored cgroups map: key = cgroup_id, value = policy_generation */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 1024);
} monitored_cgroups SEC(".maps");

/* Helper to safely retrieve per-CPU scratch buffer initialized to zero */
static __always_inline struct rk_scratch_msg *get_scratch_msg(void) {
    __u32 zero = 0;
    struct rk_scratch_msg *msg = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!msg)
        return 0;
    msg->payload_len = 0;
    msg->_reserved = 0;
    return msg;
}

/* Helper to append a string with a __u16 length prefix into scratch payload.
 * Room check + mask/clamp on every offset with power-of-two mask for the verifier.
 */
static __always_inline int append_scratch_str(struct rk_scratch_msg *msg, const char *src, __u16 max_str_len) {
    if (!msg || !src)
        return -1;

    __u32 cur_len = msg->payload_len;
    /* Strict room check: need 2 bytes for __u16 len + at least 1 byte of string */
    if (cur_len + 2 >= RK_SCRATCH_PAYLOAD_MAX)
        return -1;

    /* Write __u16 placeholder */
    __u16 *len_ptr = (__u16 *)&msg->payload[cur_len & (RK_SCRATCH_PAYLOAD_MAX - 1)];
    cur_len += 2;

    /* Clamp maximum copy length to remaining scratch room */
    __u32 rem = RK_SCRATCH_PAYLOAD_MAX - cur_len;
    __u32 to_read = max_str_len;
    if (to_read > rem)
        to_read = rem;

    /* Bounded copy from kernel memory */
    long bytes_read = bpf_probe_read_kernel_str(
        &msg->payload[cur_len & (RK_SCRATCH_PAYLOAD_MAX - 1)],
        to_read & (RK_SCRATCH_PAYLOAD_MAX - 1),
        src
    );

    if (bytes_read <= 0) {
        *len_ptr = 0;
        msg->payload_len = cur_len;
        return 0;
    }

    /* Exclude null terminator from byte count if present */
    __u16 final_str_len = (__u16)(bytes_read > 0 ? (bytes_read - 1) : 0);
    *len_ptr = final_str_len;
    msg->payload_len = cur_len + final_str_len;
    return 0;
}

/* Safe ringbuffer submission */
static __always_inline void emit_scratch_event(struct rk_scratch_msg *msg) {
    if (!msg)
        return;
    __u32 len = msg->payload_len;
    if (len > RK_SCRATCH_PAYLOAD_MAX)
        len = RK_SCRATCH_PAYLOAD_MAX;

    __u32 total = sizeof(struct rk_hdr) + 8 + len;
    bpf_ringbuf_output(&events_ringbuf, msg, total, 0);
}

#endif /* COMMON_BPF_H */
