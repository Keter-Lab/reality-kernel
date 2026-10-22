#!/usr/bin/env python3
"""Per-crate line coverage table from `cargo llvm-cov report --json`
(docs/design/phase-8.md §3.5). Report-only: always exits 0 on valid input."""

import json
import pathlib
import sys


def per_crate(export, root):
    """{crate directory: (covered, total)} from an llvm-cov JSON export."""
    totals = {}
    for f in export["data"][0]["files"]:
        path = pathlib.PurePath(f["filename"])
        try:
            rel = path.relative_to(root)
        except ValueError:
            continue  # dependencies and the standard library
        # tests/<suite> are crates of their own.
        crate = "/".join(rel.parts[:2]) if rel.parts[0] == "tests" else rel.parts[0]
        lines = f["summary"]["lines"]
        covered, total = totals.get(crate, (0, 0))
        totals[crate] = (covered + lines["covered"], total + lines["count"])
    return totals


def table(totals):
    rows = ["| Crate | Lines covered | Coverage |", "|---|---:|---:|"]
    all_covered = all_total = 0
    for crate, (covered, total) in sorted(totals.items()):
        pct = 100.0 * covered / total if total else 0.0
        rows.append(f"| {crate} | {covered}/{total} | {pct:.1f}% |")
        all_covered += covered
        all_total += total
    pct = 100.0 * all_covered / all_total if all_total else 0.0
    rows.append(f"| **total** | {all_covered}/{all_total} | **{pct:.1f}%** |")
    return "\n".join(rows)


def main(argv):
    if len(argv) != 3:
        print("usage: coverage_summary.py EXPORT.json REPO_ROOT", file=sys.stderr)
        return 2
    export = json.loads(pathlib.Path(argv[1]).read_text())
    print("## Userspace line coverage (report-only)\n")
    print(table(per_crate(export, pathlib.PurePath(argv[2]))))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
