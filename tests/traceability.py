#!/usr/bin/env python3
"""Acceptance criterion -> test traceability (docs/design/phase-8.md §3.1).

    traceability.py static  [--root DIR]
    traceability.py evidence [--root DIR]   (prints docs/evidence.md)
    traceability.py reports [--root DIR] --kernels 5.15,6.1,... [--distros A,B] ARTIFACT_DIR

static:  every criterion in tests/traceability.toml has at least one test,
         and every named test exists in the source and would run: a unit:
         test is a #[test] fn that is not #[ignore]d, a py: test is a
         collected test_ function that is not marked skip or xfail, and a
         ci: job is enabled and still has a step that does something.
reports: every vm: test passed on every listed kernel, and every k8s: test
         passed, according to the JSON reports CI collected in ARTIFACT_DIR
         (integration-/agent-/resilience-<kernel>.json and k8s.json), and
         every pkg: test passed on every listed distribution
         (pkg-<distro>.json, docs/design/phase-10.md §7).

evidence: the evidence page, one section per criterion with its tests;
         `static` also fails when docs/evidence.md is not current
         (docs/design/phase-11.md §5).

Exits 1 on any gap and prints a Markdown summary. Standard library only.
"""

import argparse
import ast
import json
import pathlib
import re
import sys
import tomllib

KINDS = ("vm", "k8s", "pkg", "unit", "go", "py", "ci")
VM_SOURCES = ("tests/integration/src/main.rs", "tests/integration/src/agent.rs",
              "tests/integration/src/conformance.rs",
              "tests/integration/src/observability.rs",
              "tests/integration/src/resilience.rs",
              "tests/integration/src/upgrade.rs")
VM_REPORTS = ("integration", "agent", "resilience", "conformance", "observability", "upgrade")


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

    def texts(paths):
        return [(p, p.read_text(encoding="utf-8", errors="replace")) for p in paths if p.is_file()]

    py_files = texts(files("*.py", "tests"))
    ci_files = texts(files("*.yml", ".github/workflows"))
    return {
        "vm": read([root / s for s in VM_SOURCES]),
        "k8s": read([root / "tests" / "k8s" / "run.sh"]),
        "pkg": read([root / "tests" / "packaging" / "run.sh"]),
        "unit": read(files("*.rs")),
        "go": read(files("*_test.go", "rk-nri")),
        "py": "\n".join(text for _, text in py_files),
        "ci": "\n".join(text for _, text in ci_files),
        "py_files": py_files,
        "ci_files": ci_files,
    }


def exists(kind, name, index):
    n = re.escape(name)
    patterns = {
        "vm": rf'run_test\(\s*checks,\s*"{n}"',
        "k8s": rf"^\s*run_test {n}\s",
        "pkg": rf"^\s*run_test {n}\s",
        "unit": rf"\bfn {n}\s*\(",
        "go": rf"^func {n}\(",
        "py": rf"^def {n}\(",
        "ci": rf"^  {n}:\s*$",
    }
    return re.search(patterns[kind], index[kind], re.MULTILINE) is not None


# A test that exists but never runs proves nothing (Strix review: an
# #[ignore]d unit test and an emptied CI job both passed this check).
TEST_ATTR = re.compile(r"#\[(?:\w+::)*test\b")
IGNORE_ATTR = re.compile(r"#\[\s*(?:ignore\b|cfg_attr\s*\(.*\bignore\b)")


def attributes_before(text, pos):
    """The attribute lines (`#[...]`) directly above position `pos`, doc
    comments skipped, plus whatever precedes `pos` on its own line."""
    start = text.rfind("\n", 0, pos) + 1
    attrs = [text[start:pos].strip()]
    while start > 0:
        prev = text.rfind("\n", 0, start - 1) + 1
        line = text[prev:start - 1].strip()
        if line.startswith("#["):
            attrs.append(line)
        elif not line.startswith("//"):
            break
        start = prev
    return [a for a in attrs if a.startswith("#[")]


def unit_problem(name, text):
    """None when some `fn name` is a Rust test that runs, else why not."""
    ignored = False
    for m in re.finditer(rf"\bfn {re.escape(name)}\s*\(", text):
        attrs = attributes_before(text, m.start())
        if not any(TEST_ATTR.match(a) for a in attrs):
            continue
        if any(IGNORE_ATTR.match(a) for a in attrs):
            ignored = True
            continue
        return None
    if ignored:
        return "is #[ignore]d, so it never runs"
    return "is not a #[test] function, so it never runs"


PY_NEVER_RUNS = re.compile(r"(?:pytest\.mark|unittest)\.(?:skip|expectedFailure|xfail)\b")


def py_problem(name, files):
    """None when `def name` is a pytest test that runs, else why not."""
    if not name.startswith("test"):
        return "is not named test*, so pytest never collects it"
    found = []
    for path, text in files:
        if not (path.name.startswith("test_") or path.name.endswith("_test.py")):
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        nodes = list(tree.body)
        for cls in (n for n in tree.body if isinstance(n, ast.ClassDef) and n.name.startswith("Test")):
            nodes.extend(cls.body)
        for n in nodes:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
                found.append(n)
    if not found:
        return "is not a test function pytest collects (module level or in a Test class of a test_*.py file)"
    for n in found:
        marks = [ast.unparse(d) for d in n.decorator_list]
        if not any(PY_NEVER_RUNS.match(m) for m in marks):
            return None
    return "is marked skip or xfail, so it never proves anything"


def workflow_jobs(text):
    """{job id: its lines} for the top-level `jobs:` mapping of a workflow."""
    jobs = {}
    lines = text.split("\n")
    try:
        i = next(i for i, line in enumerate(lines) if re.match(r"^jobs:\s*(#.*)?$", line))
    except StopIteration:
        return jobs
    current = None
    for line in lines[i + 1:]:
        if line.strip() and not line.startswith(" ") and not line.startswith("#"):
            break
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*(#.*)?$", line)
        if m:
            current = m.group(1)
            jobs[current] = []
        elif current is not None:
            jobs[current].append(line)
    return jobs


DISABLED = re.compile(r"^\s*-?\s*if:\s*(?:\$\{\{\s*)?false\s*(?:\}\})?\s*(#.*)?$")
# Commands that change nothing (echo/printf only when not redirected).
NO_OP = re.compile(r"^(?:true|:|exit 0|(?:echo|printf)\b[^>|]*|sleep\b.*)?$")


def steps_of(job):
    """The job's steps, each a list of lines (indentation kept)."""
    steps, inside, item_indent = [], False, None
    for line in job:
        if re.match(r"^    steps:\s*(#.*)?$", line):
            inside = True
            continue
        if not inside or not line.strip():
            if inside and steps:
                steps[-1].append(line)
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= 4:
            inside = False
            continue
        if line.lstrip().startswith("- ") and item_indent in (None, indent):
            item_indent = indent
            steps.append([line])
        elif steps:
            steps[-1].append(line)
    return steps


def step_does_something(step):
    if any(DISABLED.match(line) for line in step):
        return False
    for k, line in enumerate(step):
        m = re.match(r"^(\s*)(?:- )?\s*(uses|run):\s*(.*)$", line)
        if not m:
            continue
        key, value = m.group(2), m.group(3).strip()
        if key == "uses":
            if not value.startswith("actions/checkout@"):
                return True
            continue
        if value in ("|", ">", "|-", ">-", "|+", ">+"):
            # A block scalar: the following lines indented deeper than the key.
            key_indent = len(line) - len(line.lstrip(" -"))
            body = []
            for cont in step[k + 1:]:
                if cont.strip() and len(cont) - len(cont.lstrip()) <= key_indent:
                    break
                body.append(cont)
        else:
            body = [value]
        commands = [c.strip() for c in body if c.strip() and not c.strip().startswith("#")]
        if any(not NO_OP.match(c) for c in commands):
            return True
    return False


def ci_problem(name, files):
    """None when some workflow has an enabled job `name` with a real step."""
    problem = "is not a job under `jobs:` in .github/workflows"
    for _, text in files:
        job = workflow_jobs(text).get(name)
        if job is None:
            continue
        if any(re.match(r"^    if:", line) and DISABLED.match(line) for line in job):
            problem = "is disabled (if: false), so it never runs"
            continue
        if any(re.match(r"^    uses:\s*\S", line) for line in job):
            return None  # a reusable workflow
        if any(step_does_something(s) for s in steps_of(job)):
            return None
        problem = "has no step that does anything (only checkout, no-ops or disabled steps)"
    return problem


def never_runs(kind, name, index):
    """Why an existing test would never run or prove anything, or None."""
    if kind == "unit":
        return unit_problem(name, index["unit"])
    if kind == "py":
        return py_problem(name, index["py_files"])
    if kind == "ci":
        return ci_problem(name, index["ci_files"])
    return None


KIND_WHERE = {
    "vm": "VM suite, every kernel",
    "k8s": "Kubernetes (kind)",
    "pkg": "package test, every distribution",
    "unit": "Rust test",
    "go": "Go test",
    "py": "Python test",
    "ci": "CI job",
}


def phase_key(phase):
    """Engineering-plan phases ("2", "5b") in order, then releases ("v0.2.0")."""
    m = re.match(r"\d+", phase)
    if m:
        return (0, int(m.group()), (), phase)
    m = re.match(r"v(\d+)\.(\d+)\.(\d+)", phase)
    if m:
        return (1, 0, tuple(int(x) for x in m.groups()), phase)
    return (2, 0, (), phase)


def phase_title(phase):
    return f"Release {phase}" if phase.startswith("v") else f"Phase {phase}"


def evidence_page(criteria):
    """docs/evidence.md: every criterion, with the tests that prove it."""
    lines = [
        "# Evidence",
        "",
        "Generated from `tests/traceability.toml` by `python3 tests/traceability.py",
        "evidence`; CI fails if this page is out of date. Every test listed here",
        "exists in the source, and the `traceability` job checks that every VM,",
        "Kubernetes and package test passed on every kernel and distribution in",
        "the same run (docs/testing.md).",
        "",
    ]
    for phase in sorted({c.get("phase", "?") for c in criteria}, key=phase_key):
        lines += [f"## {phase_title(phase)}", ""]
        for c in (c for c in criteria if c.get("phase") == phase):
            lines += [f"### {c['id']}", "", c["text"], ""]
            for t in c.get("tests", []):
                try:
                    kind, name = split(t)
                except ValueError:
                    lines.append(f"- `{t}` (malformed reference)")
                    continue
                lines.append(f"- `{name}` ({KIND_WHERE[kind]})")
            lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def check_static(root):
    criteria = load_criteria(root)
    index = source_index(root)
    failures = []
    evidence = root / "docs" / "evidence.md"
    if not evidence.is_file() or evidence.read_text(encoding="utf-8") != evidence_page(criteria):
        failures.append("docs/evidence.md is not current: run `python3 tests/traceability.py evidence > docs/evidence.md`")
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
                continue
            why = never_runs(kind, name, index)
            if why:
                failures.append(f"[{cid}] {t} {why}")
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


def check_reports(root, artifacts, kernels, distros=()):
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
    per_distro = {}
    for d in distros:
        found = list(artifacts.rglob(f"pkg-{d}.json"))
        got = passed_names(found[0]) if found else None
        if got is None:
            failures.append(f"{d}: no package test report")
            got = set()
        per_distro[d] = got
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
            elif kind == "pkg":
                if not distros:
                    failures.append(f"[{c['id']}] {name}: no --distros given to check it against")
                for d, names in per_distro.items():
                    if name not in names:
                        failures.append(f"[{c['id']}] {name} did not pass on {d}")
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
    for phase in sorted(by_phase, key=phase_key):
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
    ap.add_argument("mode", choices=("static", "reports", "evidence"))
    ap.add_argument("--root", default=pathlib.Path(__file__).resolve().parents[1], type=pathlib.Path)
    ap.add_argument("--kernels", default="")
    ap.add_argument("--distros", default="")
    ap.add_argument("artifacts", nargs="?", type=pathlib.Path)
    args = ap.parse_intermixed_args(argv)
    if args.mode == "evidence":
        sys.stdout.write(evidence_page(load_criteria(args.root)))
        return 0
    if args.mode == "static":
        criteria, failures = check_static(args.root)
        print(summary("Traceability (source)", criteria, failures,
                      "Every criterion maps to tests, and every named test exists in the source."))
    else:
        kernels = [k for k in args.kernels.split(",") if k]
        if not kernels or args.artifacts is None:
            ap.error("reports needs --kernels and ARTIFACT_DIR")
        distros = [d for d in args.distros.split(",") if d]
        criteria, failures = check_reports(args.root, args.artifacts, kernels, distros)
        print(summary("Traceability (this run's reports)", criteria, failures,
                      "Every vm: test passed on every kernel, every k8s: test passed, "
                      "and every pkg: test passed on every distribution."))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
