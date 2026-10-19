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

/* Indexes into the per-CPU rk_counters map. Summed in userspace. */
enum rk_counter {
    RK_CNT_RINGBUF_DROP = 0, /* bpf_ringbuf_output failed; event lost, verdict unaffected */
    RK_CNT_SCRATCH_MISS = 1, /* per-CPU scratch lookup failed */
    RK_CNT_MAX          = 2,
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

/* RK_EV_EXEC Payload (24 bytes) */
struct rk_payload_exec {
    __u64 file_dev;       /* offset  0 */
    __u64 file_ino;       /* offset  8 */
    __u32 flags;          /* offset 16 */
    __u16 str_count;      /* offset 20: Number of following strings (comm, filename, argv) */
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
