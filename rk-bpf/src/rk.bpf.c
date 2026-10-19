// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * rk.bpf.c — production object loaded by the rk-sensor daemon.
 *
 * Phase 0/1 ships only the shared maps (events_ringbuf, rk_counters,
 * monitored_cgroups, scratch_map). Enforcing hooks are added by Phases 2-4.
 */

#include "common.bpf.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";
