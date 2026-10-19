// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * rk_selftest.bpf.c — programs loaded only by `rk-sensor --selftest`.
 *
 * Functional checks: a load or attach failure of any program here fails the
 * selftest (and the bpftool positive control in CI). Optional kernel feature
 * probes live in rk_probes.bpf.c.
 *
 * Both rk_test_* programs emit real ABI records through the production
 * helpers in common.bpf.h, which the selftest decodes with the production
 * decoder (end-to-end ABI check on every kernel in the CI matrix).
 */

#include "common.bpf.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define RK_AF_INET 2
#define RK_TEST_NET_1 0xC0000201 /* 192.0.2.1, host order */
#define RK_TEST_RULE_ID 1

/* Incremented on every file_open on the host: proves the LSM hook runs. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} lsm_exec_counter SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(rk_test_lsm_open, struct file *file, int ret)
{
    struct rk_payload_file *body;
    struct rk_scratch_msg *msg;
    __u32 key = 0;
    __u64 *count;
    __u64 cg, gen;

    if (ret)
        return ret;

    count = bpf_map_lookup_elem(&lsm_exec_counter, &key);
    if (count)
        __sync_fetch_and_add(count, 1);

    cg = bpf_get_current_cgroup_id();
    gen = rk_governed_gen(cg);
    if (!gen)
        return 0; /* fast path: not governed, no event */

    msg = rk_scratch();
    if (!msg)
        return 0;

    rk_fill_hdr(&msg->hdr, cg, gen, RK_EV_FILE_OPEN, RK_VERDICT_ALLOW, 0);
    rk_fill_task(&msg->hdr);

    body = (struct rk_payload_file *)msg->payload;
    body->file_dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    body->file_ino = BPF_CORE_READ(file, f_inode, i_ino);
    body->open_flags = BPF_CORE_READ(file, f_flags);
    body->mode = BPF_CORE_READ(file, f_mode);
    body->str_count = 1;
    body->_pad = 0;
    body->_pad2 = 0;
    msg->payload_len = sizeof(*body);

    rk_append_kstr(msg, BPF_CORE_READ(file, f_path.dentry, d_name.name), 256);
    rk_emit(msg);
    return 0;
}

/*
 * Attached only to the selftest's temporary cgroup. Denies TEST-NET-1 with
 * EPERM. The verdict is computed before the event is built and is returned
 * unchanged whatever happens to the event.
 */
SEC("cgroup/connect4")
int rk_test_connect4(struct bpf_sock_addr *ctx)
{
    struct rk_payload_net *body;
    struct rk_scratch_msg *msg;
    /* volatile forces full 4-byte context loads; narrow loads of these
     * fields are not accepted by every supported verifier. */
    volatile __u32 daddr = ctx->user_ip4;
    volatile __u32 port = ctx->user_port;
    volatile __u32 proto = ctx->protocol;
    __u32 addr = daddr;
    int deny = addr == bpf_htonl(RK_TEST_NET_1);

    msg = rk_scratch();
    if (msg) {
        /*
         * cgroup_id stays 0: bpf_get_current_cgroup_id is not available to
         * cgroup/connect4 on every supported kernel (see rk_probes.bpf.c).
         */
        rk_fill_hdr(&msg->hdr, 0, 0, RK_EV_NET_CONNECT,
                    deny ? RK_VERDICT_DENY : RK_VERDICT_ALLOW, deny ? RK_TEST_RULE_ID : 0);

        body = (struct rk_payload_net *)msg->payload;
        __builtin_memset(body, 0, sizeof(*body));
        body->daddr_v6[10] = 0xff;
        body->daddr_v6[11] = 0xff;
        __builtin_memcpy(&body->daddr_v6[12], &addr, 4);
        body->dport = bpf_ntohs((__u16)port);
        body->family = RK_AF_INET;
        body->protocol = (__u8)proto;
        msg->payload_len = sizeof(*body);
        rk_emit(msg);
    }

    return deny ? 0 : 1;
}
