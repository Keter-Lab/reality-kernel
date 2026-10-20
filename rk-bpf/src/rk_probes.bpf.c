// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * rk_probes.bpf.c — kernel feature probes, loaded only by `rk-sensor --selftest`.
 *
 * Each program is loaded on its own; a verifier rejection means the feature is
 * unavailable on this kernel and is reported under "kernel_features" in the
 * selftest report. A rejection here never fails the selftest.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* bpf_get_current_cgroup_id from cgroup/connect4 (needed by Phase 2). */
SEC("cgroup/connect4")
int rk_probe_sockaddr_cgroup_id(struct bpf_sock_addr *ctx)
{
    return bpf_get_current_cgroup_id() ? 1 : 1;
}

/* bpf_get_current_pid_tgid from cgroup/connect4 (pid in network events). */
SEC("cgroup/connect4")
int rk_probe_sockaddr_pid_tgid(struct bpf_sock_addr *ctx)
{
    return bpf_get_current_pid_tgid() ? 1 : 1;
}
