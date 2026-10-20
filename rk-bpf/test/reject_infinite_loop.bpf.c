// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * reject_infinite_loop.bpf.c — negative control.
 * Contains a loop the verifier cannot bound; CI asserts the kernel rejects it.
 * Never embedded in rk-sensor.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

SEC("lsm/file_open")
int BPF_PROG(rk_negative_control_loop, struct file *file)
{
    volatile int counter = 0;

    while (counter >= 0)
        counter++;
    return 0;
}
