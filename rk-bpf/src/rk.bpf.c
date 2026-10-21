// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * rk.bpf.c — production object loaded by the rk-sensor daemon.
 *
 * Shared maps live in common.bpf.h; each policy domain is one source file
 * included here so all programs share a single set of maps.
 */

#include "common.bpf.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#include "net.bpf.c"
#include "exec.bpf.c"
