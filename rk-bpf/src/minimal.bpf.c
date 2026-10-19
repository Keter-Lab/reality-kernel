// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * minimal.bpf.c — Phase 0 verification probe
 * Proves BPF-LSM execution via atomic counter side-effect and
 * enforces cgroup network deny of TEST-NET-1 (192.0.2.1) with EPERM.
 */

#include "common.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Atomic execution counter incremented on file_open */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} lsm_exec_counter SEC(".maps");

/* Ring buffer test map for roundtrip probe */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} selftest_ringbuf SEC(".maps");

/*
 * Phase 0 LSM Probe: Increments atomic counter on file_open
 * to prove functional LSM kernel attachment.
 */
SEC("lsm/file_open")
int BPF_PROG(rk_test_lsm_open, void *file) {
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&lsm_exec_counter, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
    return 0; /* Allow in Phase 0 */
}

/*
 * Phase 0 cgroup/connect4 probe:
 * Blocks connections to TEST-NET-1 (192.0.2.1 / 0xC0000201 in network byte order)
 * with -EPERM (-1), and logs test packet to ringbuf.
 */
SEC("cgroup/connect4")
int rk_test_connect4(struct bpf_sock_addr *ctx) {
    if (!ctx)
        return 1;

    /* 
     * 192.0.2.1 in network byte order (big endian):
     * Byte 0: 192 (0xC0), Byte 1: 0 (0x00), Byte 2: 2 (0x02), Byte 3: 1 (0x01)
     * Value in memory (host integer on LE): 0x010200C0
     */
    __u32 ip = ctx->user_ip4;
    __u8 *b = (__u8 *)&ip;

    /* Check TEST-NET-1: 192.0.2.1 */
    if (b[0] == 192 && b[1] == 0 && b[2] == 2 && b[3] == 1) {
        /* Round-trip probe: emit test event */
        __u64 test_marker = 0xDEADC0000201ULL;
        bpf_ringbuf_output(&selftest_ringbuf, &test_marker, sizeof(test_marker), 0);
        return 0; /* Deny with -EPERM */
    }

    return 1; /* Allow all other connections */
}
