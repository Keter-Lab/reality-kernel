// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * file.bpf.c — kernel-enforced file access policy (Phase 4).
 * Included by rk.bpf.c; see docs/design/phase-4.md.
 *
 * rk_file_protect holds the protected objects of every profile, keyed by
 * (slot << 31 | profile, device, inode) and double-buffered by generation
 * slot like the network and exec rules.
 */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rk_file_key);
    __type(value, struct rk_file_rule);
    __uint(max_entries, 65536);
} rk_file_protect SEC(".maps");
