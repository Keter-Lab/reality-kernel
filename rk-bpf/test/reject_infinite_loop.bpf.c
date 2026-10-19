// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * reject_infinite_loop.bpf.c — Negative control test program
 * Contains an intentionally unprovable infinite loop to verify that
 * the Linux kernel verifier rejects it in CI.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("lsm/file_open")
int BPF_PROG(rk_negative_control_loop, void *file) {
    volatile int counter = 0;
    while (counter >= 0) {
        counter++;
    }
    return 0;
}
