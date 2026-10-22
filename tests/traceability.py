#!/usr/bin/env python3
"""Acceptance criterion -> test traceability (docs/design/phase-8.md §3.1).

    traceability.py static  [--root DIR]
    traceability.py reports [--root DIR] --kernels 5.15,6.1,... ARTIFACT_DIR

static:  every criterion in tests/traceability.toml has at least one test,
         and every named test exists in the source.
reports: every vm: test passed on every listed kernel, and every k8s: test
         passed, according to the JSON reports CI collected in ARTIFACT_DIR
         (integration-/agent-/resilience-<kernel>.json and k8s.json).

Exits 1 on any gap and prints a Markdown summary. Standard library only.
"""

import argparse
import json
import pathlib
import re
import sys
import tomllib

KINDS = ("vm", "k8s", "unit", "go", "py", "ci")
VM_SOURCES = ("tests/integration/src/main.rs", "tests/integration/src/agent.rs",
              "tests/integration/src/conformance.rs",
              "tests/integration/src/resilience.rs")
VM_REPORTS = ("integration", "agent", "resilience", "conformance")


def load_criteria(root):
    with open(root / "tests" / "traceability.toml", "rb") as f:
        return tomllib.load(f).get("criterion", [])


def split(test):
    kind, sep, name = test.partition(":")
    if not sep or kind not in KINDS or not name:
        raise ValueError(f"malformed test reference {test!r}")
    return kind, name


def read(paths):
    return "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in paths if p.is_file())


def source_index(root):
    """Text to search for each test kind."""
    skip = ("target", ".git", "node_modules", ".venv")

    def files(pattern, base="."):
        return [p for p in (root / base).rglob(pattern) if not any(s in p.parts for s in skip)]

    return {
        "vm": read([root / s for s in VM_SOURCES]),
        "k8s": read([root / "tests" / "k8s" / "run.sh"]),
        "unit": read(files("*.rs")),
        "go": read(files("*_test.go", "rk-nri")),
        "py": read(files("*.py", "tests")),
        "ci": read(files("*.yml", ".github/workflows")),
    }


def exists(kind, name, index):
    n = re.escape(name)
    patterns = {
        "vm": rf'run_test\(\s*checks,\s*"{n}"',
        "k8s": rf"^\s*run_test {n}\s",
        "unit": rf"\bfn {n}\s*\(",
        "go": rf"^func {n}\(",
        "py": rf"^def {n}\(",
        "ci": rf"^  {n}:\s*$",
    }
    return re.search(patterns[kind], index[kind], re.MULTILINE) is not None


def check_static(root):
    criteria = load_criteria(root)
    index = source_index(root)
    failures = []
    if not criteria:
        failures.append("tests/traceability.toml lists no criteria")
    ids = set()
    for c in criteria:
        cid = c.get("id", "?")
        if cid in ids:
            failures.append(f"duplicate criterion id {cid}")
        ids.add(cid)
        tests = c.get("tests", [])
        if not tests:
            failures.append(f"[{cid}] has no test")
        for t in tests:
            try:
                kind, name = split(t)
            except ValueError as e:
                failures.append(f"[{cid}] {e}")
                continue
            if not exists(kind, name, index):
                failures.append(f"[{cid}] {t} not found in the source")
    return criteria, failures


def passed_names(path):
    """Names of tests reported as passed in a JSON report (list of checks)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, list):
        return None
    return {c.get("name") for c in data if isinstance(c, dict) and c.get("passed") is True}


def check_reports(root, artifacts, kernels):
    criteria = load_criteria(root)
    failures = []
    per_kernel = {}
    for k in kernels:
        names = set()
        for suite in VM_REPORTS:
            found = list(artifacts.rglob(f"{suite}-{k}.json"))
            got = passed_names(found[0]) if found else None
            if got is None:
                failures.append(f"Linux {k}: no {suite} report")
                continue
            names |= got
        per_kernel[k] = names
    k8s_files = list(artifacts.rglob("k8s.json"))
    k8s = passed_names(k8s_files[0]) if k8s_files else None
    if k8s is None:
        failures.append("no k8s report")
        k8s = set()
    for c in criteria:
        for t in c.get("tests", []):
            kind, name = split(t)
            if kind == "vm":
                for k, names in per_kernel.items():
                    if name not in names:
                        failures.append(f"[{c['id']}] {name} did not pass on Linux {k}")
            elif kind == "k8s" and name not in k8s:
                failures.append(f"[{c['id']}] {name} did not pass on Kubernetes")
    return criteria, failures


def summary(title, criteria, failures, ok_line):
    by_phase = {}
    for c in criteria:
        by_phase.setdefault(c.get("phase", "?"), []).append(c)
    lines = [f"## {title}", ""]
    lines.append(f"{len(criteria)} criteria, "
                 f"{sum(len(c.get('tests', [])) for c in criteria)} test references.")
    lines.append("")
    lines.append("| Phase | Criteria |")
    lines.append("|---|---|")
    for phase in sorted(by_phase, key=lambda p: (int(re.match(r"\d+", p).group()), p)):
        lines.append(f"| {phase} | {len(by_phase[phase])} |")
    lines.append("")
    if failures:
        lines.append(f"### {len(failures)} gap(s)")
        lines.append("")
        lines.extend(f"- {f}" for f in failures)
    else:
        lines.append(ok_line)
    return "\n".join(lines) + "\n"


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mode", choices=("static", "reports"))
    ap.add_argument("--root", default=pathlib.Path(__file__).resolve().parents[1], type=pathlib.Path)
    ap.add_argument("--kernels", default="")
    ap.add_argument("artifacts", nargs="?", type=pathlib.Path)
    args = ap.parse_intermixed_args(argv)
    if args.mode == "static":
        criteria, failures = check_static(args.root)
        print(summary("Traceability (source)", criteria, failures,
                      "Every criterion maps to tests, and every named test exists in the source."))
    else:
        kernels = [k for k in args.kernels.split(",") if k]
        if not kernels or args.artifacts is None:
            ap.error("reports needs --kernels and ARTIFACT_DIR")
        criteria, failures = check_reports(args.root, args.artifacts, kernels)
        print(summary("Traceability (this run's reports)", criteria, failures,
                      "Every vm: test passed on every kernel and every k8s: test passed."))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
