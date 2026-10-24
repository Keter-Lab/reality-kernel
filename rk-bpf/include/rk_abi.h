/* SPDX-License-Identifier: (GPL-2.0-only OR MIT) */
/*
 * rk_abi.h — single source of truth for the kernel <-> userspace contract.
 *
 * Consumed by the BPF programs in rk-bpf/src (after vmlinux.h) and by bindgen
 * (rk-ebpf-common/build.rs, which defines RK_ABI_TYPES_PROVIDED). See docs/abi.md.
 *
 * Wire record emitted on events_ringbuf:
 *   struct rk_hdr | __u32 payload_len | __u32 _reserved (0) | payload[payload_len]
 * Integers are in host byte order, except IP addresses which are raw
 * network-order bytes. Strings are [__u16 len][len bytes], no NUL, not
 * guaranteed to be UTF-8.
 */
#ifndef RK_ABI_H
#define RK_ABI_H

#if !defined(__VMLINUX_H__) && !defined(RK_ABI_TYPES_PROVIDED)
#include <linux/types.h>
#endif

#define RK_ABI_VERSION 1
#define RK_SCRATCH_PAYLOAD_MAX 2048

/* Hook classes for the decision counters (docs/design/phase-9.md §3.4). */
enum rk_hook {
    RK_HOOK_CONNECT4    = 0,
    RK_HOOK_CONNECT6    = 1,
    RK_HOOK_SENDMSG4    = 2,
    RK_HOOK_SENDMSG6    = 3,
    RK_HOOK_SOCK_CREATE = 4,
    RK_HOOK_EXEC        = 5,
    RK_HOOK_FILE        = 6,
    RK_HOOK_GUARD       = 7,
    RK_HOOK_TUN         = 8, /* docs/design/phase-16.md */
    RK_HOOK_MAX         = 9,
};

/*
 * Indexes into the per-CPU rk_counters map. Summed in userspace.
 * Every governed decision is counted at
 * RK_CNT_DECISION_BASE + hook * RK_VERDICTS + verdict (enum rk_verdict),
 * whether or not its event reaches the ring buffer.
 */
#define RK_VERDICTS 3
enum rk_counter {
    RK_CNT_RINGBUF_DROP  = 0, /* bpf_ringbuf_output failed; event lost, verdict unaffected */
    RK_CNT_SCRATCH_MISS  = 1, /* per-CPU scratch lookup failed */
    RK_CNT_DECISION_BASE = 2,
    RK_CNT_MAX           = 29, /* RK_CNT_DECISION_BASE + RK_HOOK_MAX * RK_VERDICTS */
};

enum rk_event_type {
    RK_EV_NONE        = 0, /* Rejected by userspace decoder */
    RK_EV_EXEC        = 1,
    RK_EV_FILE_OPEN   = 2,
    RK_EV_NET_CONNECT = 3,
    RK_EV_UNLINK      = 4,
    RK_EV_RENAME      = 5,
    RK_EV_FORK        = 6,
    RK_EV_EXIT        = 7,
    RK_EV_TAMPER      = 8,
    RK_EV_SENDMSG     = 9,
    RK_EV_SOCK_CREATE = 10,
    RK_EV_FILE_DENY   = 11,
    RK_EV_TUN         = 12,
};

enum rk_verdict {
    RK_VERDICT_ALLOW            = 0,
    RK_VERDICT_DENY             = 1,
    RK_VERDICT_AUDIT_WOULD_DENY = 2,
};

/* Fixed 48-byte header — Exactly naturally aligned, 0 implicit padding bytes */
struct rk_hdr {
    __u64 ts_ns;          /* offset  0: bpf_ktime_get_boot_ns() */
    __u64 cgroup_id;      /* offset  8: bpf_get_current_cgroup_id() */
    __u64 policy_gen;     /* offset 16: Active policy generation counter */
    __u32 pid;            /* offset 24: Host PID */
    __u32 tgid;           /* offset 28: Host TGID */
    __u32 uid;            /* offset 32: Host UID */
    __u32 gid;            /* offset 36: Host GID */
    __u16 type;           /* offset 40: enum rk_event_type */
    __u8  verdict;        /* offset 42: enum rk_verdict */
    __u8  abi;            /* offset 43: RK_ABI_VERSION */
    __u32 rule_id;        /* offset 44: Matched rule ID (0 = default) */
};

/* Fixed-size per-CPU scratch layout */
struct rk_scratch_msg {
    struct rk_hdr hdr;    /* offset  0 */
    __u32 payload_len;    /* offset 48: Clamped dynamically <= RK_SCRATCH_PAYLOAD_MAX */
    __u32 _reserved;      /* offset 52: Must be 0 */
    __u8  payload[RK_SCRATCH_PAYLOAD_MAX]; /* offset 56 */
};

/* 
 * Payload Body Definitions:
 * Payload = Fixed Body Struct + [__u16 length + UTF-8 string bytes]...
 */

/*
 * RK_EV_EXEC Payload (24 bytes). Strings: [0] kernel-resolved filename;
 * [1] (exec records only) the new process's argument area as the process
 * sees it: arguments separated by NUL bytes. flags: enum rk_exec_flag.
 */
struct rk_payload_exec {
    __u64 file_dev;       /* offset  0 */
    __u64 file_ino;       /* offset  8 */
    __u32 flags;          /* offset 16 */
    __u16 str_count;      /* offset 20: Number of following strings (see below) */
    __u16 _pad;           /* offset 22 */
    /* Trailing: str_count occurrences of: [__u16 str_len][__u8 str_bytes[str_len]] */
};

/* RK_EV_FILE_OPEN Payload (32 bytes). file_dev uses the kernel dev_t encoding (MAJOR << 20 | MINOR). */
struct rk_payload_file {
    __u64 file_dev;       /* offset  0 */
    __u64 file_ino;       /* offset  8 */
    __u32 open_flags;     /* offset 16 */
    __u32 mode;           /* offset 20 */
    __u16 str_count;      /* offset 24: Number of following strings (path or name, logs only) */
    __u16 _pad;           /* offset 26 */
    __u32 _pad2;          /* offset 28: Explicit padding to 32 bytes */
    /* Trailing: str_count occurrences of: [__u16 str_len][__u8 str_bytes[str_len]] */
};

/* RK_EV_NET_CONNECT / SENDMSG Payload (40 bytes - v4-mapped v6 only) */
struct rk_payload_net {
    __u8  saddr_v6[16];   /* offset  0: IPv6 or IPv4-mapped IPv6 */
    __u8  daddr_v6[16];   /* offset 16: IPv6 or IPv4-mapped IPv6 */
    __u16 sport;          /* offset 32: host byte order */
    __u16 dport;          /* offset 34: host byte order */
    __u16 family;         /* offset 36: AF_INET or AF_INET6 */
    __u8  protocol;       /* offset 38: IPPROTO_TCP or IPPROTO_UDP */
    __u8  _pad;           /* offset 39 */
};

/* RK_EV_SOCK_CREATE Payload (16 bytes): a governed socket() call. */
struct rk_payload_sock {
    __u16 family;         /* offset  0: AF_* */
    __u16 _pad;           /* offset  2 */
    __u32 type;           /* offset  4: SOCK_* (flags already masked) */
    __u32 protocol;       /* offset  8 */
    __u32 _pad2;          /* offset 12 */
};

/* Operations on a TUN/TAP device, one per TUN LSM hook (docs/design/phase-16.md). */
enum rk_tun_op {
    RK_TUN_CREATE       = 1, /* tun_dev_create: TUNSETIFF, new interface */
    RK_TUN_ATTACH       = 2, /* tun_dev_open: TUNSETIFF, existing interface */
    RK_TUN_ATTACH_QUEUE = 3, /* tun_dev_attach_queue: TUNSETQUEUE, IFF_ATTACH_QUEUE */
};

/* RK_EV_TUN Payload (8 bytes). The hooks receive no interface name. */
struct rk_payload_tun {
    __u32 op;             /* offset  0: enum rk_tun_op */
    __u32 _pad;           /* offset  4 */
};

/*
 * ------------------------------------------------------------------------
 * Policy maps (written by rk-sensor from rk-policy output; read by hooks).
 * See docs/design/phase-2.md §4.
 * ------------------------------------------------------------------------
 */
#define RK_MAX_PROFILES   1024
#define RK_POLICY_SLOTS   2
#define RK_NET_MAX_RANGES 8

enum rk_mode {
    RK_MODE_AUDIT   = 0,
    RK_MODE_ENFORCE = 1,
};

enum rk_action {
    RK_ACTION_ALLOW = 0,
    RK_ACTION_DENY  = 1,
};

/* rk_net_range.proto_mask bits */
enum rk_proto_bit {
    RK_PROTO_TCP   = 1,
    RK_PROTO_UDP   = 2,
    RK_PROTO_OTHER = 4,
    RK_PROTO_ANY   = 7,
};

/* rk_profile.flags bits */
enum rk_profile_flag {
    RK_PROFILE_DENY_RAW_SOCKETS     = 1,
    RK_PROFILE_EXEC_DENY_DEFAULT    = 2, /* exec allowlist mode */
    RK_PROFILE_EXEC_ALLOW_UNLINKED  = 4, /* admin override: allow nlink == 0 files */
};

/* rk_payload_exec.flags bits */
enum rk_exec_flag {
    RK_EXEC_ARGV_TRUNCATED   = 1, /* argument area larger than the record */
    RK_EXEC_ARGV_UNAVAILABLE = 2, /* argument area could not be read */
    RK_EXEC_UNLINKED         = 4, /* file had no links (memfd, deleted) */
    RK_EXEC_DECISION         = 8, /* emitted by the exec check (verdict), not the exec record */
};

/* rk_cgroup_profile value: cgroup id -> profile id (stable across reloads). */
struct rk_binding {
    __u32 profile;        /* offset 0 */
    __u32 _pad;           /* offset 4 */
};

/* rk_profiles value, indexed by slot * RK_MAX_PROFILES + profile. */
struct rk_profile {
    __u8  mode;           /* offset 0: enum rk_mode */
    __u8  net_default;    /* offset 1: enum rk_action */
    __u16 flags;          /* offset 2: enum rk_profile_flag */
    __u32 _pad;           /* offset 4 */
    __u64 policy_gen;     /* offset 8: 0 = slot entry never written */
};

/*
 * LPM trie key for rk_net_deny / rk_net_allow. scope = slot << 31 | profile,
 * prefixlen = 32 + CIDR length over the 16-byte (IPv4-mapped) address.
 */
struct rk_net_key {
    __u32 prefixlen;      /* offset 0 */
    __u32 scope;          /* offset 4 */
    __u8  addr[16];       /* offset 8: network byte order */
};

/* One port/protocol range of a compiled rule. Ports in host byte order. */
struct rk_net_range {
    __u32 rule_id;        /* offset 0 */
    __u16 port_lo;        /* offset 4 */
    __u16 port_hi;        /* offset 6 */
    __u8  proto_mask;     /* offset 8: enum rk_proto_bit */
    __u8  _pad[3];        /* offset 9 */
};

/*
 * LPM trie value: the ranges of the matched prefix followed by those of every
 * covering shorter prefix (flattened by rk-policy), most specific first.
 */
struct rk_net_rule {
    __u32 nranges;        /* offset 0: <= RK_NET_MAX_RANGES */
    struct rk_net_range ranges[RK_NET_MAX_RANGES]; /* offset 4 */
};

/* rk_exec_allow key: scope = slot << 31 | profile, then the file identity. */
struct rk_exec_key {
    __u32 scope;          /* offset  0 */
    __u32 _pad;           /* offset  4 */
    __u64 dev;            /* offset  8: kernel dev_t encoding */
    __u64 ino;            /* offset 16 */
};

struct rk_exec_rule {
    __u32 rule_id;        /* offset 0 */
    __u32 flags;          /* offset 4: reserved, 0 */
};

/* ---- File policy (Phase 4, docs/design/phase-4.md) ---- */

/* Ancestor directories checked for subtree rules before failing closed. */
#define RK_FILE_MAX_DEPTH 32

/* Access types: rk_file_rule.deny_mask and rk_payload_file_deny.access. */
enum rk_file_access {
    RK_FILE_READ     = 1,
    RK_FILE_WRITE    = 2,
    RK_FILE_EXEC     = 4,
    RK_FILE_CREATE   = 8,
    RK_FILE_DELETE   = 16,
    RK_FILE_RENAME   = 32,
    RK_FILE_TRUNCATE = 64,
    RK_FILE_LINK     = 128,
    RK_FILE_SETATTR  = 256,
    RK_FILE_ALL      = 511,
};

/* rk_file_rule.flags */
enum rk_file_rule_flag {
    RK_FILE_SUBTREE = 1, /* directory rule covering everything beneath it */
};

/* rk_payload_file_deny.hook */
enum rk_file_hook {
    RK_FILE_HOOK_OPEN    = 1,
    RK_FILE_HOOK_UNLINK  = 2,
    RK_FILE_HOOK_RENAME  = 3,
    RK_FILE_HOOK_LINK    = 4,
    RK_FILE_HOOK_CREATE  = 5,
    RK_FILE_HOOK_SETATTR = 6,
};

/* rk_payload_file_deny.flags */
enum rk_file_event_flag {
    RK_FILE_EV_SUBTREE        = 1, /* matched rule was a subtree rule */
    RK_FILE_EV_DEPTH_EXCEEDED = 2, /* ancestor walk hit RK_FILE_MAX_DEPTH: failed closed */
};

/* rk_file_protect key: same layout as rk_exec_key. */
struct rk_file_key {
    __u32 scope;          /* offset  0: slot << 31 | profile */
    __u32 _pad;           /* offset  4 */
    __u64 dev;            /* offset  8: kernel dev_t encoding */
    __u64 ino;            /* offset 16 */
};

struct rk_file_rule {
    __u32 rule_id;        /* offset  0 */
    __u32 deny_mask;      /* offset  4: enum rk_file_access bits */
    __u32 flags;          /* offset  8: enum rk_file_rule_flag */
    __u32 _pad;           /* offset 12 */
};

/* RK_EV_FILE_DENY payload (32 bytes) + str_count strings: [0] log path. */
struct rk_payload_file_deny {
    __u64 file_dev;       /* offset  0 */
    __u64 file_ino;       /* offset  8 */
    __u32 access;         /* offset 16: requested access bits */
    __u16 hook;           /* offset 20: enum rk_file_hook */
    __u8  flags;          /* offset 22: enum rk_file_event_flag */
    __u8  _pad;           /* offset 23 */
    __u16 str_count;      /* offset 24 */
    __u16 _pad2;          /* offset 26 */
    __u32 _pad3;          /* offset 28 */
};

/*
 * ------------------------------------------------------------------------
 * Phase 6: heartbeat, self-protection and pin metadata
 * (docs/design/phase-6.md §3-§6). These maps are BPF_F_RDONLY_PROG:
 * programs read them, only rk-sensor writes them.
 * ------------------------------------------------------------------------
 */

/* rule_id of a governed action denied only because the heartbeat is stale. */
#define RK_RULE_HEARTBEAT 0xFFFFFFFFu

/* /proc/<pid>/stat starttime unit (USER_HZ) in nanoseconds. */
#define RK_NSEC_PER_CLOCK_TICK 10000000ull

/* rk_config[0]. A timeout of 0 means never configured: fail closed. */
struct rk_config {
    __u64 heartbeat_timeout_ns; /* offset 0 */
};

/* rk_guard[0]: the sensor process the guard hooks protect. */
struct rk_guard_target {
    __u32 tgid;           /* offset 0 */
    __u32 _pad;           /* offset 4 */
    __u64 start_ticks;    /* offset 8: /proc/<tgid>/stat starttime */
};

/* rk_meta[0]: identifies the object a pin set was created by. */
struct rk_meta {
    __u32 abi;            /* offset  0: RK_ABI_VERSION */
    __u32 _pad;           /* offset  4 */
    __u8  object_sha256[32]; /* offset 8 */
    __u8  epoch[16];      /* offset 40: random per pin set */
};

enum rk_tamper_hook {
    RK_TAMPER_BPF        = 1, /* bpf() syscall; detail = cmd */
    RK_TAMPER_SIGNAL     = 2, /* signal to the sensor; detail = signal */
    RK_TAMPER_PTRACE     = 3, /* ptrace access to the sensor; detail = mode */
    RK_TAMPER_PIN_UNLINK = 4, /* unlink in bpffs */
    RK_TAMPER_PIN_RENAME = 5, /* rename in bpffs */
    RK_TAMPER_PIN_RMDIR  = 6, /* rmdir in bpffs */
    RK_TAMPER_UMOUNT     = 7, /* umount of a bpffs mount */
};

/* RK_EV_TAMPER payload (16 bytes). */
struct rk_payload_tamper {
    __u16 hook;           /* offset  0: enum rk_tamper_hook */
    __u16 _pad;           /* offset  2 */
    __u32 target_tgid;    /* offset  4: sensor tgid for SIGNAL/PTRACE, else 0 */
    __u64 detail;         /* offset  8 */
};

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct rk_config) == 8, "config size");
_Static_assert(sizeof(struct rk_guard_target) == 16, "guard_target size");
_Static_assert(__builtin_offsetof(struct rk_guard_target, start_ticks) == 8, "guard start_ticks");
_Static_assert(sizeof(struct rk_meta) == 56, "meta size");
_Static_assert(__builtin_offsetof(struct rk_meta, epoch) == 40, "meta epoch");
_Static_assert(sizeof(struct rk_payload_tamper) == 16, "payload_tamper size");
_Static_assert(__builtin_offsetof(struct rk_payload_tamper, detail) == 8, "tamper detail");
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct rk_exec_key) == 24, "exec_key size");
_Static_assert(__builtin_offsetof(struct rk_exec_key, dev) == 8, "exec_key dev");
_Static_assert(sizeof(struct rk_exec_rule) == 8, "exec_rule size");
_Static_assert(sizeof(struct rk_file_key) == 24, "file_key size");
_Static_assert(sizeof(struct rk_file_rule) == 16, "file_rule size");
_Static_assert(sizeof(struct rk_payload_file_deny) == 32, "payload_file_deny size");
_Static_assert(__builtin_offsetof(struct rk_payload_file_deny, str_count) == 24, "file_deny str_count");
_Static_assert(sizeof(struct rk_payload_sock) == 16, "payload_sock size");
_Static_assert(sizeof(struct rk_payload_tun) == 8, "payload_tun size");
_Static_assert(sizeof(struct rk_binding) == 8, "binding size");
_Static_assert(sizeof(struct rk_profile) == 16, "profile size");
_Static_assert(__builtin_offsetof(struct rk_profile, policy_gen) == 8, "profile policy_gen");
_Static_assert(sizeof(struct rk_net_key) == 24, "net_key size");
_Static_assert(__builtin_offsetof(struct rk_net_key, addr) == 8, "net_key addr");
_Static_assert(sizeof(struct rk_net_range) == 12, "net_range size");
_Static_assert(sizeof(struct rk_net_rule) == 4 + 12 * RK_NET_MAX_RANGES, "net_rule size");
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct rk_hdr) == 48, "rk_hdr size");
_Static_assert(__builtin_offsetof(struct rk_hdr, ts_ns) == 0, "ts_ns offset");
_Static_assert(__builtin_offsetof(struct rk_hdr, cgroup_id) == 8, "cgroup_id offset");
_Static_assert(__builtin_offsetof(struct rk_hdr, policy_gen) == 16, "policy_gen offset");
_Static_assert(__builtin_offsetof(struct rk_hdr, pid) == 24, "pid offset");
_Static_assert(__builtin_offsetof(struct rk_hdr, tgid) == 28, "tgid offset");
_Static_assert(__builtin_offsetof(struct rk_hdr, uid) == 32, "uid offset");
_Static_assert(__builtin_offsetof(struct rk_hdr, gid) == 36, "gid offset");
_Static_assert(__builtin_offsetof(struct rk_hdr, type) == 40, "type offset");
_Static_assert(__builtin_offsetof(struct rk_hdr, verdict) == 42, "verdict offset");
_Static_assert(__builtin_offsetof(struct rk_hdr, abi) == 43, "abi offset");
_Static_assert(__builtin_offsetof(struct rk_hdr, rule_id) == 44, "rule_id offset");

_Static_assert(__builtin_offsetof(struct rk_scratch_msg, hdr) == 0, "scratch hdr offset");
_Static_assert(__builtin_offsetof(struct rk_scratch_msg, payload_len) == 48, "scratch payload_len offset");
_Static_assert(__builtin_offsetof(struct rk_scratch_msg, _reserved) == 52, "scratch _reserved offset");
_Static_assert(__builtin_offsetof(struct rk_scratch_msg, payload) == 56, "scratch payload offset");
_Static_assert(sizeof(struct rk_scratch_msg) == 56 + RK_SCRATCH_PAYLOAD_MAX, "scratch msg size");

_Static_assert(sizeof(struct rk_payload_exec) == 24, "payload_exec size");
_Static_assert(__builtin_offsetof(struct rk_payload_exec, file_dev) == 0, "payload_exec file_dev");
_Static_assert(__builtin_offsetof(struct rk_payload_exec, file_ino) == 8, "payload_exec file_ino");
_Static_assert(__builtin_offsetof(struct rk_payload_exec, flags) == 16, "payload_exec flags");
_Static_assert(__builtin_offsetof(struct rk_payload_exec, str_count) == 20, "payload_exec str_count");

_Static_assert(sizeof(struct rk_payload_file) == 32, "payload_file size must be exactly 32 bytes");
_Static_assert(__builtin_offsetof(struct rk_payload_file, file_dev) == 0, "payload_file file_dev");
_Static_assert(__builtin_offsetof(struct rk_payload_file, file_ino) == 8, "payload_file file_ino");
_Static_assert(__builtin_offsetof(struct rk_payload_file, open_flags) == 16, "payload_file open_flags");
_Static_assert(__builtin_offsetof(struct rk_payload_file, mode) == 20, "payload_file mode");
_Static_assert(__builtin_offsetof(struct rk_payload_file, str_count) == 24, "payload_file str_count");
_Static_assert(__builtin_offsetof(struct rk_payload_file, _pad2) == 28, "payload_file _pad2");

_Static_assert(sizeof(struct rk_payload_net) == 40, "payload_net size must be exactly 40 bytes");
_Static_assert(__builtin_offsetof(struct rk_payload_net, saddr_v6) == 0, "payload_net saddr_v6");
_Static_assert(__builtin_offsetof(struct rk_payload_net, daddr_v6) == 16, "payload_net daddr_v6");
_Static_assert(__builtin_offsetof(struct rk_payload_net, sport) == 32, "payload_net sport");
_Static_assert(__builtin_offsetof(struct rk_payload_net, dport) == 34, "payload_net dport");
_Static_assert(__builtin_offsetof(struct rk_payload_net, family) == 36, "payload_net family");
_Static_assert(__builtin_offsetof(struct rk_payload_net, protocol) == 38, "payload_net protocol");
#endif

#endif /* RK_ABI_H */
