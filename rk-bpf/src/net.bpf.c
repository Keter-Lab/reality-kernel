// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * net.bpf.c — kernel-enforced network egress policy (Phase 2).
 * Included by rk.bpf.c; see docs/design/phase-2.md.
 *
 * Every program follows the shared decision path: governance lookup (fast
 * path for ungoverned tasks), verdict from kernel-owned maps, best-effort
 * event, then a return value that depends only on the verdict and the mode.
 */

#define RK_AF_INET   2
#define RK_AF_INET6  10
#define RK_AF_PACKET 17
#define RK_SOCK_RAW  3
#define RK_IPPROTO_TCP 6
#define RK_IPPROTO_UDP 17
#define RK_EPERM 1

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct rk_net_key);
    __type(value, struct rk_net_rule);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} rk_net_deny SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct rk_net_key);
    __type(value, struct rk_net_rule);
    __uint(max_entries, 65536);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} rk_net_allow SEC(".maps");

static __always_inline __u8 rk_proto_bit(__u32 protocol)
{
    if (protocol == RK_IPPROTO_TCP)
        return RK_PROTO_TCP;
    if (protocol == RK_IPPROTO_UDP)
        return RK_PROTO_UDP;
    return RK_PROTO_OTHER;
}

/*
 * Longest-prefix lookup, then the first range (most specific first, as
 * flattened by rk-policy) that matches port and protocol.
 */
static __always_inline int rk_net_match(void *trie, const struct rk_net_key *key, __u16 port, __u8 proto,
                                        __u32 *rule_id)
{
    struct rk_net_rule *rule = bpf_map_lookup_elem(trie, key);
    __u32 n;

    if (!rule)
        return 0;
    n = rule->nranges;

    for (int i = 0; i < RK_NET_MAX_RANGES; i++) {
        if ((__u32)i >= n)
            break;
        if ((rule->ranges[i].proto_mask & proto) && port >= rule->ranges[i].port_lo &&
            port <= rule->ranges[i].port_hi) {
            *rule_id = rule->ranges[i].rule_id;
            return 1;
        }
    }
    return 0;
}

static __always_inline __u8 rk_net_verdict(const struct rk_gov *g, const __u8 addr[16], __u16 port, __u8 proto,
                                           __u32 *rule_id)
{
    struct rk_net_key key = {};

    key.prefixlen = 32 + 128;
    key.scope = g->scope;
    __builtin_memcpy(key.addr, addr, 16);

    if (rk_net_match(&rk_net_deny, &key, port, proto, rule_id))
        return RK_ACTION_DENY;
    if (rk_net_match(&rk_net_allow, &key, port, proto, rule_id))
        return RK_ACTION_ALLOW;
    *rule_id = 0;
    return g->net_default == RK_ACTION_DENY ? RK_ACTION_DENY : RK_ACTION_ALLOW;
}

static __always_inline void rk_net_emit(const struct rk_gov *g, __u16 type, __u8 action, __u32 rule_id,
                                        const __u8 addr[16], __u16 port, __u16 family, __u32 protocol)
{
    struct rk_scratch_msg *msg = rk_scratch();
    struct rk_payload_net *body;

    if (!msg)
        return;
    rk_fill_hdr(&msg->hdr, g->cgroup_id, g->policy_gen, type, rk_reported_verdict(g, action), rule_id);
    rk_fill_task(&msg->hdr);

    body = (struct rk_payload_net *)msg->payload;
    __builtin_memset(body, 0, sizeof(*body));
    __builtin_memcpy(body->daddr_v6, addr, 16);
    body->dport = port;
    body->family = family;
    body->protocol = (__u8)protocol;
    msg->payload_len = sizeof(*body);
    rk_emit(msg);
}

/*
 * Shared body of the four sock_addr hooks. Context fields are read with
 * volatile full-width loads: narrow loads are not accepted everywhere.
 */
static __always_inline int rk_net_sock_addr(struct bpf_sock_addr *ctx, int v6, __u16 type)
{
    __u8 addr[16] = {};
    struct rk_gov g = {};
    __u32 rule_id = 0;
    __u8 action;

    if (!rk_governance(&g))
        return 1;

    volatile __u32 port_raw = ctx->user_port;
    volatile __u32 protocol = ctx->protocol;
    __u16 port = bpf_ntohs((__u16)port_raw);

    if (v6) {
        volatile __u32 a0 = ctx->user_ip6[0];
        volatile __u32 a1 = ctx->user_ip6[1];
        volatile __u32 a2 = ctx->user_ip6[2];
        volatile __u32 a3 = ctx->user_ip6[3];
        __u32 words[4] = { a0, a1, a2, a3 };

        __builtin_memcpy(addr, words, 16);
    } else {
        volatile __u32 a = ctx->user_ip4;
        __u32 ip4 = a;

        addr[10] = 0xff;
        addr[11] = 0xff;
        __builtin_memcpy(&addr[12], &ip4, 4);
    }

    action = rk_net_verdict(&g, addr, port, rk_proto_bit(protocol), &rule_id);
    rk_net_emit(&g, type, action, rule_id, addr, port, v6 ? RK_AF_INET6 : RK_AF_INET, protocol);
    return rk_enforced_deny(&g, action) ? 0 : 1;
}

SEC("cgroup/connect4")
int rk_net_connect4(struct bpf_sock_addr *ctx)
{
    return rk_net_sock_addr(ctx, 0, RK_EV_NET_CONNECT);
}

SEC("cgroup/connect6")
int rk_net_connect6(struct bpf_sock_addr *ctx)
{
    return rk_net_sock_addr(ctx, 1, RK_EV_NET_CONNECT);
}

SEC("cgroup/sendmsg4")
int rk_net_sendmsg4(struct bpf_sock_addr *ctx)
{
    return rk_net_sock_addr(ctx, 0, RK_EV_SENDMSG);
}

SEC("cgroup/sendmsg6")
int rk_net_sendmsg6(struct bpf_sock_addr *ctx)
{
    return rk_net_sock_addr(ctx, 1, RK_EV_SENDMSG);
}

/*
 * Raw (inet) and packet sockets bypass every sock_addr hook, so governed
 * profiles with RK_PROFILE_DENY_RAW_SOCKETS may not create them. LSM hook:
 * runs for every socket() on the host; ungoverned tasks cost one lookup.
 */
SEC("lsm/socket_create")
int BPF_PROG(rk_net_socket_create, int family, int type, int protocol, int kern, int ret)
{
    struct rk_payload_sock *body;
    struct rk_scratch_msg *msg;
    struct rk_gov g = {};
    __u8 action;

    if (ret)
        return ret;
    if (kern)
        return 0; /* kernel-internal sockets */
    if (family != RK_AF_PACKET && !(type == RK_SOCK_RAW && (family == RK_AF_INET || family == RK_AF_INET6)))
        return 0;
    if (!rk_governance(&g))
        return 0;

    action = (g.flags & RK_PROFILE_DENY_RAW_SOCKETS) ? RK_ACTION_DENY : RK_ACTION_ALLOW;

    msg = rk_scratch();
    if (msg) {
        rk_fill_hdr(&msg->hdr, g.cgroup_id, g.policy_gen, RK_EV_SOCK_CREATE, rk_reported_verdict(&g, action), 0);
        rk_fill_task(&msg->hdr);
        body = (struct rk_payload_sock *)msg->payload;
        __builtin_memset(body, 0, sizeof(*body));
        body->family = (__u16)family;
        body->type = (__u32)type;
        body->protocol = (__u32)protocol;
        msg->payload_len = sizeof(*body);
        rk_emit(msg);
    }

    return rk_enforced_deny(&g, action) ? -RK_EPERM : 0;
}
