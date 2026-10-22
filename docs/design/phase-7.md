# Design note: Phase 7 — sensor performance

Status: **PROPOSED** (2026-10-22), awaiting review of the decisions in §8.
Branch: `phase-7-performance` (from `main` at 75389d8)
Plan reference: RealityKernel_Engineering_Plan.pdf, Phase 7 ("Low and
predictable overhead with measured, published numbers").

## 1. Goal and acceptance criteria

Plan acceptance criteria (must pass in CI):

1. p50 and p99 per-hook overhead are reported by CI on at least two kernels.
2. An overhead budget, set from the first measured baseline, is enforced as a
   CI regression gate.
3. Zero event loss at a defined sustained rate on the reference runner; loss
   beyond it is counted and reported.

Two kinds of cost are in play, and they are measured separately:
- **Enforcement overhead**: time the BPF hooks add to a syscall. This sits on
  the workload's hot path and is what budgets protect.
- **Telemetry throughput**: how many events per second reach userspace
  without loss. This is the sensor's pipeline, off the workload's hot path:
  events are best-effort by design (Phase 2), and a full ring never changes a
  verdict.

## 2. Where things stand

- The consumer is an async task that drains the ring, then **sleeps 10 ms**.
  It decodes and logs inline, so logging I/O sits on the drain path and
  latency is quantised to 10 ms.
- Every `bpf_ringbuf_output` passes flags `0`, so the kernel may wake the
  consumer on every record.
- The ring is a fixed 1 MiB, whatever the CPU count.
- Per-CPU counters (`rk_counters`: ring-buffer drops, scratch misses) exist in
  BPF, but only the test harness reads them; the daemon never reports them.
- The sensor does **no per-event `/proc` reads** (only at startup), so the
  plan's "process table replaces per-event /proc reads" has nothing to
  replace yet (see decision 4).

## 3. New consumer pipeline

```
ring buffer ──epoll──> drain thread ──bounded channel──> worker(s) ──> sinks
 (kernel)            (OS thread: copy   (capacity N;     (decode, session    (JSON log
                      raw records out,   full = drop      enrichment,         today; OTLP
                      never blocks)      + count)         counters)           etc. later)
```

- **Drain thread** (a dedicated OS thread, not a tokio task): waits on the
  ring buffer fd with `epoll` (aya's `RingBuf` exposes it). Each wakeup drains
  every available record, copies its bytes out (records are small, under
  2 KiB), and hands batches to the channel. It never decodes, logs or awaits
  anything, so a slow sink can't stall it.
- **Bounded channel**: if it is full, the batch is dropped and counted
  (`userspace_drops`), never blocked on. Blocking would back the ring up and
  move the loss into the kernel, where it is harder to attribute.
- **Workers**: decode (existing decoder, unchanged), attach session ids from
  the agent registry, update counters, write to sinks. One worker today; the
  stage is where Phase 9 enrichment and sinks plug in.
- **Shutdown**: the drain thread stops on a flag plus an eventfd in the same
  epoll set, then drains whatever is left before exiting.

## 4. Adaptive wakeups and ring sizing

- **Wakeups**: `rk_emit` asks the kernel how full the ring is
  (`bpf_ringbuf_query(BPF_RB_AVAIL_DATA)`, Linux 5.8+). Below a threshold it
  writes with `BPF_RB_NO_WAKEUP`; at or above, with `BPF_RB_FORCE_WAKEUP`. The
  threshold is a `.rodata` constant set at load (an eighth of the ring), so no
  ABI change is needed. Under load this turns one wakeup per record into one
  per batch.
- **Latency bound**: data below the threshold is picked up by the drain
  thread's epoll timeout (default 100 ms). That bounds event latency at low
  rates and costs no wakeups at high ones.
- **Sizing**: ring = next power of two of `CPUs × 256 KiB`, clamped to
  [1 MiB, 64 MiB], with `--ring-size-mb` to override. It is applied at first
  load via `EbpfLoader::set_max_entries`. An adopted pin set keeps the size it
  was created with (Phase 6); a different size counts as a different object
  only when it is set explicitly.

## 5. Counters

All counters are reported by `rk status` and in the periodic stats log line:
- **kernel, per-CPU, summed in userspace**: `ringbuf_drops`, `scratch_misses`;
- **userspace**: `records_drained`, `userspace_drops`, `decoded`,
  `decode_rejected`.

Loss is exact: `drained + kernel drops` equals events produced.

## 6. Benchmarks (`tests/bench`, run in the VM matrix)

A new `rk-integration --bench` mode, run on all five kernels, prints a JSON
report between markers. CI publishes it as an artifact and as a table in the
job summary.

- **Per-hook overhead.** Microbenchmarks pinned to one CPU, after warm-up,
  20 000 iterations each, recording every iteration's latency:

  | Hook | Syscall loop |
  |---|---|
  | `file_open` | `open` + `close` of an unprotected file |
  | `connect4` | UDP `connect` to an allowed address |
  | `bprm_check_security` | `fork` + `exec` of `/bin/true` |
  | `socket_create` | `socket` + `close` (UDP) |

  Each runs in three configurations: **baseline** (programs not attached),
  **ungoverned** (attached, task not in a bound cgroup: the cost every
  process on the host pays) and **governed** (attached and bound). Overhead
  is the p50 and p99 difference from baseline, in nanoseconds.
- **Per-program cross-check.** `kernel.bpf_stats_enabled=1` during the
  governed run, then each program's `run_time_ns / run_cnt` from `bpftool -j
  prog show`.
- **Sustained rate.** A governed workload produces events at a fixed rate for
  10 s. The report states the highest rate with zero loss, and a run above it
  shows loss counted exactly (produced = received + counted drops).

## 7. Regression gate

`tests/bench/budget.json` holds the per-hook budgets: p50 and p99 overhead in
ns, ungoverned and governed, plus the zero-loss rate. A small script
(`tests/bench/gate.py`) fails the job when a measurement exceeds its budget.

Nested-VM CI runners are noisy, so the gate is built not to flake:
- Budgets are set from the first measured baseline (the plan's rule): the
  worst value across the five kernels × 2 for p50, × 3 for p99, with a
  1 µs floor.
- The gate compares the median of 3 repetitions.
- It keys on ungoverned p50 first: that is the cost the whole host pays.

The first implementation commit measures; a second commits `budget.json`
from those numbers. After that every PR is gated.

## 8. Decisions requested from the reviewer

1. **Drain thread + bounded channel that drops (and counts) when full**, not
   one that blocks. Recommended: a slow sink must never stall the ring, and
   counted userspace loss is easier to diagnose than silent kernel loss.
2. **Adaptive wakeups with a 100 ms latency bound.** Recommended: removes
   per-record wakeups under load; 100 ms is far below anything a human or an
   alert pipeline notices.
3. **Gate on overhead relative to an in-run baseline, with budgets from the
   first measurement (×2 p50, ×3 p99, 1 µs floor).** Recommended: absolute
   timings on shared runners vary run to run, deltas within one run are far
   more stable.
4. **Defer the process table to Phase 9 (audit schema).** Recommended: there
   are no per-event `/proc` reads to replace today; the table's purpose is
   enrichment (executable, parent), whose fields the Phase 9 schema defines.
   The worker stage in §3 is where it plugs in. The alternative is building
   it now with guessed fields.
