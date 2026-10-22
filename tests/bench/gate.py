#!/usr/bin/env python3
"""Phase 7 benchmark report and regression gate (docs/design/phase-7.md §6-§7).

    gate.py <budget.json> <bench-<kernel>.json>...

Prints a Markdown report (per-hook p50/p99 overhead per kernel, per-program
kernel-measured run time, event throughput) and exits 1 when a gated
measurement exceeds its budget.

What is gated, and why (measured on the first run, see §7):
- each BPF program's average run time from kernel.bpf_stats_enabled
  (measured by the kernel itself, the least noisy signal; covers every hook,
  exec included), for programs with at least MIN_RUNS runs;
- the p50 syscall overhead of open, connect and socket;
- zero loss at the sustained rate.
The exec syscall timings and every p99 are reported but not gated: in nested
CI VMs they are dominated by noise (process launch alone varies by hundreds
of microseconds), and a gate that fails at random gets ignored.

Without a budget file it reports only and prints a proposed budget from this
run: the worst value across kernels x2, with a 1 us floor (the plan's
"budget set from the first baseline"). Standard library only.
"""

import json
import os
import sys

FLOOR_NS = 1000
FACTOR = 2
MIN_RUNS = 1000
GATED_OPS = ("open", "connect", "socket")
CONFIGS = ("ungoverned", "governed")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def kernel_name(report, path):
    return report.get("kernel") or os.path.basename(path)


def programs(report):
    """{name: avg_ns} for programs with enough runs to be meaningful."""
    per = report.get("per_program") or {}
    return {
        name: p["avg_ns"]
        for name, p in per.items()
        if isinstance(p, dict) and p.get("runs", 0) >= MIN_RUNS
    }


def check(budget, reports):
    """Return a list of human-readable budget violations."""
    failures = []
    for name, report in reports:
        for op, limits in budget.get("hooks", {}).items():
            hook = report.get("hooks", {}).get(op)
            if hook is None:
                failures.append(f"{name}: no measurement for {op}")
                continue
            for config in CONFIGS:
                for pct in ("p50", "p99"):
                    key = f"{config}_{pct}_ns"
                    if key not in limits:
                        continue
                    got = hook["overhead"][config][pct]
                    if got > limits[key]:
                        failures.append(
                            f"{name}: {op} {config} {pct} overhead {got} ns > budget {limits[key]} ns"
                        )
        measured = programs(report)
        if budget.get("programs") and "error" in (report.get("per_program") or {}):
            failures.append(f"{name}: no per-program stats ({report['per_program']['error']})")
        for prog, limits in budget.get("programs", {}).items():
            got = measured.get(prog)
            if got is not None and got > limits["avg_ns"]:
                failures.append(f"{name}: {prog} avg {got} ns > budget {limits['avg_ns']} ns")
        sustained = report.get("sustained", {}).get("result", {})
        lost = sustained.get("kernel_drops", 0) + sustained.get("userspace_drops", 0)
        if budget.get("zero_loss_at_sustained_rate", True) and lost:
            failures.append(f"{name}: {lost} events lost at the sustained rate")
    return failures


def propose(reports):
    """A budget from this run: worst across kernels x FACTOR, floored."""
    hooks, progs = {}, {}
    for _, report in reports:
        for op in GATED_OPS:
            hook = report.get("hooks", {}).get(op)
            if hook is None:
                continue
            limits = hooks.setdefault(op, {})
            for config in CONFIGS:
                key = f"{config}_p50_ns"
                value = max(FLOOR_NS, hook["overhead"][config]["p50"] * FACTOR)
                limits[key] = max(limits.get(key, 0), value)
        for prog, avg in programs(report).items():
            value = max(FLOOR_NS, avg * FACTOR)
            progs[prog] = {"avg_ns": max(progs.get(prog, {}).get("avg_ns", 0), value)}
    return {
        "version": 1,
        "zero_loss_at_sustained_rate": True,
        "hooks": hooks,
        "programs": progs,
    }


def markdown(reports):
    lines = ["## Reality Kernel benchmark report", ""]
    lines.append(
        "Overhead = configuration minus baseline (no programs attached), ns; "
        "median of repeated runs. Gated: per-program averages, open/connect/socket p50, "
        "zero loss; the rest is reported."
    )
    lines.append("")
    lines.append("| Kernel | Op (hook) | Ungoverned p50 | Ungoverned p99 | Governed p50 | Governed p99 |")
    lines.append("|---|---|---|---|---|---|")
    for name, report in reports:
        for op, hook in sorted(report.get("hooks", {}).items()):
            o = hook["overhead"]
            lines.append(
                f"| {name} | {op} ({hook['hook']}) | {o['ungoverned']['p50']} | {o['ungoverned']['p99']} "
                f"| {o['governed']['p50']} | {o['governed']['p99']} |"
            )
    lines.append("")
    names = sorted({p for _, r in reports for p in (r.get("per_program") or {}) if p != "error"})
    if names:
        lines.append("Kernel-measured average run time per BPF program, ns (`bpf_stats`):")
        lines.append("")
        lines.append("| Kernel | " + " | ".join(names) + " |")
        lines.append("|---|" + "---|" * len(names))
        for name, report in reports:
            per = report.get("per_program") or {}
            cells = [str(per.get(p, {}).get("avg_ns", "")) for p in names]
            lines.append(f"| {name} | " + " | ".join(cells) + " |")
        lines.append("")
    lines.append("| Kernel | Sustained (target/achieved ev/s) | Lost | Flood (ev/s) | Flood sent | Flood drained | Flood lost |")
    lines.append("|---|---|---|---|---|---|---|")
    for name, report in reports:
        s = report.get("sustained", {})
        r = s.get("result", {})
        fl = report.get("flood", {})
        lines.append(
            f"| {name} | {s.get('target_rate')}/{r.get('achieved_rate')} "
            f"| {r.get('kernel_drops', 0) + r.get('userspace_drops', 0)} "
            f"| {fl.get('achieved_rate')} | {fl.get('sent')} | {fl.get('drained')} "
            f"| {fl.get('kernel_drops', 0) + fl.get('userspace_drops', 0)} |"
        )
    return "\n".join(lines) + "\n"


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    budget_path, paths = argv[1], argv[2:]
    reports = [(kernel_name(r, p), r) for p, r in ((p, load(p)) for p in paths)]
    if not reports:
        print("no benchmark reports found", file=sys.stderr)
        return 1
    print(markdown(reports))
    if not os.path.exists(budget_path):
        print("No budget yet: report only. Proposed budget.json from this run:\n")
        print("```json\n" + json.dumps(propose(reports), indent=2, sort_keys=True) + "\n```")
        return 0
    failures = check(load(budget_path), reports)
    if failures:
        print("### Budget exceeded\n")
        for f in failures:
            print(f"- {f}")
        return 1
    print("All gated measurements within budget.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
