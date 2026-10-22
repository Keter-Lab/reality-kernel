#!/usr/bin/env python3
"""Phase 7 benchmark report and regression gate (docs/design/phase-7.md §6-§7).

    gate.py <budget.json> <bench-<kernel>.json>...

Prints a Markdown report (per-hook p50/p99 overhead per kernel, per-program
averages, event throughput) and exits 1 when any measurement exceeds its
budget. Without a budget file it reports only and prints a proposed budget
derived from this run: the worst value across kernels, x2 for p50 and x3 for
p99, with a 1 us floor (the plan's "budget set from the first baseline").
Standard library only.
"""

import json
import os
import sys

FLOOR_NS = 1000
P50_FACTOR = 2
P99_FACTOR = 3
CONFIGS = ("ungoverned", "governed")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def kernel_name(report, path):
    return report.get("kernel") or os.path.basename(path)


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
        sustained = report.get("sustained", {}).get("result", {})
        lost = sustained.get("kernel_drops", 0) + sustained.get("userspace_drops", 0)
        if budget.get("zero_loss_at_sustained_rate", True) and lost:
            failures.append(f"{name}: {lost} events lost at the sustained rate")
    return failures


def propose(reports):
    """A budget from this run: worst across kernels x factor, floored."""
    hooks = {}
    for _, report in reports:
        for op, hook in report.get("hooks", {}).items():
            limits = hooks.setdefault(op, {})
            for config in CONFIGS:
                for pct, factor in (("p50", P50_FACTOR), ("p99", P99_FACTOR)):
                    key = f"{config}_{pct}_ns"
                    value = max(FLOOR_NS, hook["overhead"][config][pct] * factor)
                    limits[key] = max(limits.get(key, 0), value)
    return {"version": 1, "zero_loss_at_sustained_rate": True, "hooks": hooks}


def markdown(reports):
    lines = ["## Reality Kernel benchmark report", ""]
    lines.append("Overhead = configuration minus baseline (no programs attached), ns; median of repeated runs.")
    lines.append("")
    lines.append("| Kernel | Op (hook) | Ungoverned p50 | Ungoverned p99 | Governed p50 | Governed p99 |")
    lines.append("|---|---|---|---|---|---|")
    for name, report in reports:
        for op, hook in report.get("hooks", {}).items():
            o = hook["overhead"]
            lines.append(
                f"| {name} | {op} ({hook['hook']}) | {o['ungoverned']['p50']} | {o['ungoverned']['p99']} "
                f"| {o['governed']['p50']} | {o['governed']['p99']} |"
            )
    lines.append("")
    lines.append("| Kernel | Sustained rate (target/achieved ev/s) | Lost | Flood sent | Flood drained | Flood lost |")
    lines.append("|---|---|---|---|---|---|")
    for name, report in reports:
        s = report.get("sustained", {})
        r = s.get("result", {})
        fl = report.get("flood", {})
        lines.append(
            f"| {name} | {s.get('target_rate')}/{r.get('achieved_rate')} "
            f"| {r.get('kernel_drops', 0) + r.get('userspace_drops', 0)} "
            f"| {fl.get('sent')} | {fl.get('drained')} "
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
    print("All measurements within budget.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
