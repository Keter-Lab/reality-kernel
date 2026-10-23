// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * rk.bpf.c — production object loaded by the rk-sensor daemon.
 *
 * Shared maps live in common.bpf.h; each policy domain is one source file
 * included here so all programs share a single set of maps.
 */

#include "common.bpf.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

#ifdef RK_OBJECT_VARIANT
/*
 * Upgrade tests only (docs/design/phase-10.md §7): the `next` build differs
 * from the production object by this constant, so a sensor embedding it
 * takes the replace path, as a new release would.
 */
const volatile __u32 rk_object_variant = RK_OBJECT_VARIANT;
#endif

#include "net.bpf.c"
#include "exec.bpf.c"
#include "file.bpf.c"
#include "guard.bpf.c"
