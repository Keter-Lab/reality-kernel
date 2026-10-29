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

/*
 * Phase 6 (docs/design/phase-6.md). Written only by rk-sensor:
 * BPF_F_RDONLY_PROG makes the verifier reject any program write.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64); /* CLOCK_BOOTTIME ns of the last sensor heartbeat */
    __uint(max_entries, 1);
    __uint(map_flags, BPF_F_RDONLY_PROG);
} rk_heartbeat SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct rk_config);
    __uint(max_entries, 1);
    __uint(map_flags, BPF_F_RDONLY_PROG);
} rk_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct rk_guard_target);
    __uint(max_entries, 1);
    __uint(map_flags, BPF_F_RDONLY_PROG);
} rk_guard SEC(".maps");

/* Never read by programs; pinned with the set so a restart can check it. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct rk_meta);
    __uint(max_entries, 1);
    __uint(map_flags, BPF_F_RDONLY_PROG);
} rk_meta SEC(".maps");

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
    __u8  stale;          /* sensor heartbeat older than the timeout */
};

/*
 * True when the sensor's heartbeat is older than the configured timeout.
 * Missing maps, a timeout never configured (0) and a heartbeat never written
 * (0) all count as stale: fail closed (docs/design/phase-6.md §4).
 */
static __always_inline __u8 rk_heartbeat_stale(void)
{
    __u32 zero = 0;
    __u64 *beat = bpf_map_lookup_elem(&rk_heartbeat, &zero);
    struct rk_config *cfg = bpf_map_lookup_elem(&rk_config, &zero);
    __u64 last, timeout, now;

    if (!beat || !cfg)
        return 1;
    last = *beat;
    timeout = cfg->heartbeat_timeout_ns;
    if (!last || !timeout)
        return 1;
    now = bpf_ktime_get_boot_ns();
    if (last >= now)
        return 0;
    return now - last > timeout;
}

/*
 * The cgroup whose binding governs the current task: its own if bound, else
 * the nearest bound ancestor (docs/design/cgroup-ancestry.md). On an exact
 * miss, walks only the hierarchy levels that hold a binding (rk_config's
 * governed_levels bitmask), deepest first, so a task that moved into a
 * descendant of its bound cgroup stays governed under that cgroup's profile.
 * Returns 0 (ungoverned) when neither the task nor a bound ancestor matches;
 * governed_levels == 0 means no walk, so a host with no bindings keeps the
 * one-lookup fast path. On a match it returns the binding and sets `*governed`
 * to the governing cgroup id (self when directly bound, else the ancestor),
 * which the caller reports so the decision keeps its profile attribution.
 */
static __always_inline struct rk_binding *rk_governed_binding(__u64 self, __u64 *governed)
{
    struct rk_binding *b = bpf_map_lookup_elem(&rk_cgroup_profile, &self);
    __u32 zero = 0;
    struct rk_config *cfg;
    __u64 levels;

    if (b) {
        *governed = self;
        return b;
    }
    cfg = bpf_map_lookup_elem(&rk_config, &zero);
    levels = cfg ? cfg->governed_levels : 0;
    if (!levels)
        return 0;
#pragma unroll
    for (int level = RK_CGROUP_MAX_DEPTH; level >= 1; level--) {
        __u64 anc;

        if (!(levels & (1ULL << level)))
            continue;
        anc = bpf_get_current_ancestor_cgroup_id(level);
        if (!anc || anc == self)
            continue;
        b = bpf_map_lookup_elem(&rk_cgroup_profile, &anc);
        if (b) {
            *governed = anc;
            return b;
        }
    }
    return 0;
}

/*
 * Returns 0 for an ungoverned task (fast path: one hash lookup when the task's
 * own cgroup is bound, or when no cgroup is bound at all). A cgroup bound to a
 * profile whose slot entry was never written is a configuration error and
 * fails closed: ENFORCE, default deny, raw sockets denied, no rule matches.
 */
static __always_inline int rk_governance(struct rk_gov *g)
{
    __u64 cg = bpf_get_current_cgroup_id();
    __u64 governed = cg;
    struct rk_binding *binding = rk_governed_binding(cg, &governed);
    struct rk_profile *prof;
    __u32 zero = 0, slot = 0, idx, profile;
    __u32 *active;

    if (!binding)
        return 0;

    active = bpf_map_lookup_elem(&rk_active_slot, &zero);
    if (active)
        slot = *active & 1;
    profile = binding->profile;

    /* Report the governing cgroup (self when directly bound, else the bound
     * ancestor) so userspace attributes the decision to its profile, metrics
     * and OTLP session (docs/design/cgroup-ancestry.md). */
    g->cgroup_id = governed;
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
    /* Only ENFORCE acts on it; AUDIT skips the two lookups. */
    g->stale = g->mode == RK_MODE_ENFORCE ? rk_heartbeat_stale() : 0;
    return 1;

fail_closed:
    g->policy_gen = 0;
    g->scope = 0xffffffff; /* no trie entry uses this scope */
    g->mode = RK_MODE_ENFORCE;
    g->net_default = RK_ACTION_DENY;
    g->flags = RK_PROFILE_DENY_RAW_SOCKETS | RK_PROFILE_EXEC_DENY_DEFAULT;
    g->stale = rk_heartbeat_stale();
    return 1;
}

/* Verdict reported in events: AUDIT turns a deny into audit-would-deny. */
/* A stale heartbeat turns every governed ENFORCE action into a deny. */
static __always_inline int rk_effective_deny(const struct rk_gov *g, __u8 action)
{
    return action == RK_ACTION_DENY || (g->stale && g->mode == RK_MODE_ENFORCE);
}

static __always_inline __u8 rk_reported_verdict(const struct rk_gov *g, __u8 action)
{
    if (!rk_effective_deny(g, action))
        return RK_VERDICT_ALLOW;
    return g->mode == RK_MODE_ENFORCE ? RK_VERDICT_DENY : RK_VERDICT_AUDIT_WOULD_DENY;
}

static __always_inline int rk_enforced_deny(const struct rk_gov *g, __u8 action)
{
    return rk_effective_deny(g, action) && g->mode == RK_MODE_ENFORCE;
}

/*
 * Counts one governed decision by hook class and reported verdict
 * (docs/design/phase-9.md §3.4). Independent of emission, so userspace can
 * tell a lost event from a decision that never happened.
 */
static __always_inline void rk_count_decision(__u32 hook, const struct rk_gov *g, __u8 action)
{
    __u32 verdict = rk_reported_verdict(g, action);

    if (hook >= RK_HOOK_MAX || verdict >= RK_VERDICTS)
        return;
    rk_count(RK_CNT_DECISION_BASE + hook * RK_VERDICTS + verdict);
}

/* rule_id for events: RK_RULE_HEARTBEAT when only the stale heartbeat denied. */
static __always_inline __u32 rk_rule(const struct rk_gov *g, __u8 action, __u32 rule_id)
{
    if (action != RK_ACTION_DENY && g->stale && g->mode == RK_MODE_ENFORCE)
        return RK_RULE_HEARTBEAT;
    return rule_id;
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

/*
 * Append [__u16 len][bytes] copied from user memory (`want` bytes at `src`).
 * Returns 0 on success, 1 if the data was truncated to fit, -1 if the memory
 * could not be read (an empty string is appended). Same verifier discipline
 * as rk_append_kstr: masked, barrier-pinned offsets and lengths.
 */
static __always_inline int rk_append_ublob(struct rk_scratch_msg *msg, const void *src, __u64 want)
{
    __u32 off = msg->payload_len;
    __u32 len_off, str_off, room, n;
    __u16 *len_ptr;
    int truncated = 0;

    if (off > RK_SCRATCH_PAYLOAD_MAX - 3)
        return 1;

    len_off = off & RK_PAYLOAD_MASK;
    barrier_var(len_off);
    len_ptr = (__u16 *)&msg->payload[len_off];

    str_off = (off + 2) & RK_PAYLOAD_MASK;
    barrier_var(str_off);

    room = RK_SCRATCH_PAYLOAD_MAX - (off + 2);
    if (want > room) {
        n = room;
        truncated = 1;
    } else {
        n = (__u32)want;
    }
    n &= RK_PAYLOAD_MASK;
    barrier_var(n);

    if (bpf_probe_read_user(&msg->payload[str_off], n, src) < 0) {
        *len_ptr = 0;
        msg->payload_len = off + 2;
        return -1;
    }
    *len_ptr = (__u16)n;
    msg->payload_len = off + 2 + n;
    return truncated;
}

/* Emit hdr + payload_len + _reserved + payload at its real size. */
/*
 * Adaptive wakeups (docs/design/phase-7.md §4): bytes of unread data at which
 * a record wakes the consumer. Set by the loader to an eighth of the ring;
 * below it records are written without a wakeup and the consumer's epoll
 * timeout picks them up. 0 (not set) keeps the kernel's default behaviour.
 */
const volatile __u64 rk_wakeup_threshold = 0;

static __always_inline void rk_emit(struct rk_scratch_msg *msg)
{
    __u32 len = msg->payload_len;
    __u64 flags = 0;

    if (len > RK_SCRATCH_PAYLOAD_MAX)
        len = RK_SCRATCH_PAYLOAD_MAX;
    /* Mask pinned for the verifier as above; 4095 + 56 still fits the map value. */
    len &= (2 * RK_SCRATCH_PAYLOAD_MAX - 1);
    barrier_var(len);
    if (rk_wakeup_threshold)
        flags = bpf_ringbuf_query(&events_ringbuf, BPF_RB_AVAIL_DATA) >= rk_wakeup_threshold
                    ? BPF_RB_FORCE_WAKEUP
                    : BPF_RB_NO_WAKEUP;
    if (bpf_ringbuf_output(&events_ringbuf, msg, sizeof(struct rk_hdr) + 8 + len, flags) < 0)
        rk_count(RK_CNT_RINGBUF_DROP);
}

#endif /* COMMON_BPF_H */
