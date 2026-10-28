"""Unit tests for tests/traceability.py (docs/design/phase-8.md §3.1)."""

import importlib.util
import json
import pathlib

import pytest

_spec = importlib.util.spec_from_file_location(
    "traceability", pathlib.Path(__file__).parent / "traceability.py"
)
tr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tr)


def tree(tmp_path, toml):
    """A minimal repository: one VM test, one k8s test, one Rust unit test."""
    (tmp_path / "tests" / "integration" / "src").mkdir(parents=True)
    (tmp_path / "tests" / "k8s").mkdir()
    (tmp_path / "tests" / "integration" / "src" / "main.rs").write_text(
        'run_test(\n        checks,\n        "net_demo_denied",\n        || Ok(()));\n'
    )
    (tmp_path / "tests" / "k8s" / "run.sh").write_text("    run_test k8s_demo t_demo\n")
    (tmp_path / "lib.rs").write_text("#[test]\nfn demo_unit() {}\n")
    (tmp_path / "tests" / "traceability.toml").write_text(toml)
    write_evidence(tmp_path)
    return tmp_path


def write_evidence(root):
    """The generated evidence page, as CI expects it to be committed."""
    (root / "docs").mkdir(exist_ok=True)
    page = tr.evidence_page(tr.load_criteria(root))
    (root / "docs" / "evidence.md").write_text(page, encoding="utf-8", newline="\n")


GOOD = """
[[criterion]]
phase = "2"
id = "demo"
text = "demo"
tests = ["vm:net_demo_denied", "k8s:k8s_demo", "unit:demo_unit"]
"""


def test_static_finds_every_kind(tmp_path):
    criteria, failures = tr.check_static(tree(tmp_path, GOOD))
    assert len(criteria) == 1
    assert failures == []


def test_static_flags_missing_and_empty_and_malformed(tmp_path):
    toml = GOOD.replace("unit:demo_unit", "unit:gone") + """
[[criterion]]
phase = "3"
id = "empty"
text = "no tests"
tests = []

[[criterion]]
phase = "3"
id = "bad"
text = "bad ref"
tests = ["nonsense"]
"""
    _, failures = tr.check_static(tree(tmp_path, toml))
    assert any("unit:gone not found" in f for f in failures)
    assert any("[empty] has no test" in f for f in failures)
    assert any("malformed" in f for f in failures)


def write_reports(d, kernels, vm_passed=True, k8s_passed=True):
    for k in kernels:
        (d / f"integration-{k}.json").write_text(
            json.dumps([{"name": "net_demo_denied", "passed": vm_passed}])
        )
        (d / f"agent-{k}.json").write_text("[]")
        (d / f"resilience-{k}.json").write_text("[]")
        (d / f"conformance-{k}.json").write_text("[]")
        (d / f"observability-{k}.json").write_text("[]")
        (d / f"upgrade-{k}.json").write_text("[]")
    (d / "k8s.json").write_text(json.dumps([{"name": "k8s_demo", "passed": k8s_passed}]))


def test_reports_pass_when_every_test_passed(tmp_path):
    root = tree(tmp_path / "repo", GOOD)
    art = tmp_path / "art"
    art.mkdir()
    write_reports(art, ["5.15", "6.18"])
    _, failures = tr.check_reports(root, art, ["5.15", "6.18"])
    assert failures == []


@pytest.mark.parametrize("vm_passed,k8s_passed,expect", [
    (False, True, "net_demo_denied did not pass on Linux 5.15"),
    (True, False, "k8s_demo did not pass on Kubernetes"),
])
def test_reports_flag_failed_tests(tmp_path, vm_passed, k8s_passed, expect):
    root = tree(tmp_path / "repo", GOOD)
    art = tmp_path / "art"
    art.mkdir()
    write_reports(art, ["5.15"], vm_passed, k8s_passed)
    _, failures = tr.check_reports(root, art, ["5.15"])
    assert any(expect in f for f in failures)


def test_reports_flag_missing_kernel(tmp_path):
    root = tree(tmp_path / "repo", GOOD)
    art = tmp_path / "art"
    art.mkdir()
    write_reports(art, ["5.15"])
    _, failures = tr.check_reports(root, art, ["5.15", "6.1"])
    assert any("Linux 6.1: no integration report" in f for f in failures)


PKG = GOOD + """
[[criterion]]
phase = "10"
id = "pkg"
text = "pkg"
tests = ["pkg:pkg_demo"]
"""


def pkg_tree(tmp_path):
    root = tree(tmp_path / "repo", PKG)
    (root / "tests" / "packaging").mkdir()
    (root / "tests" / "packaging" / "run.sh").write_text("    run_test pkg_demo t_pkg\n")
    return root


def test_reports_check_package_tests_per_distribution(tmp_path):
    root = pkg_tree(tmp_path)
    assert tr.check_static(root)[1] == []
    art = tmp_path / "art"
    art.mkdir()
    write_reports(art, ["5.15"])
    (art / "pkg-ubuntu-24.04.json").write_text(json.dumps([{"name": "pkg_demo", "passed": True}]))
    assert tr.check_reports(root, art, ["5.15"], ["ubuntu-24.04"])[1] == []
    _, failures = tr.check_reports(root, art, ["5.15"], ["ubuntu-24.04", "rockylinux-9"])
    assert any("rockylinux-9: no package test report" in f for f in failures)
    _, failures = tr.check_reports(root, art, ["5.15"])
    assert any("no --distros" in f for f in failures)


def test_stale_evidence_page_fails(tmp_path):
    root = tree(tmp_path, GOOD)
    (root / "docs" / "evidence.md").write_text("# Evidence\n\nold\n")
    _, failures = tr.check_static(root)
    assert any("docs/evidence.md is not current" in f for f in failures)
    write_evidence(root)
    assert tr.check_static(root)[1] == []


def test_repository_index_is_complete():
    """The real tests/traceability.toml passes the static check."""
    _, failures = tr.check_static(pathlib.Path(__file__).resolve().parents[1])
    assert failures == []


def test_releases_sort_after_phases():
    phases = ["v0.10.0", "16", "v0.2.0", "5b", "2", "v0.3.0"]
    assert sorted(phases, key=tr.phase_key) == ["2", "5b", "16", "v0.2.0", "v0.3.0", "v0.10.0"]
    assert tr.phase_title("v0.2.0") == "Release v0.2.0"
    assert tr.phase_title("5b") == "Phase 5b"


# A test that exists but never runs proves nothing (Strix review: an
# #[ignore]d unit test and an emptied CI job both passed the static check).

RUNS = """
[[criterion]]
phase = "2"
id = "runs"
text = "runs"
tests = ["unit:demo_unit", "py:test_demo", "ci:demo"]
"""

WORKFLOW = """name: demo
on:
  push:
  pull_request:

jobs:
  demo:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000 # v1
      - name: test
        run: |
          # the real work
          cargo test --workspace
"""


def runs_tree(tmp_path, rust="#[test]\nfn demo_unit() {}\n", py="def test_demo():\n    pass\n",
              workflow=WORKFLOW):
    root = tree(tmp_path, RUNS)
    (root / "lib.rs").write_text(rust)
    (root / "tests" / "test_demo.py").write_text(py)
    (root / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    (root / ".github" / "workflows" / "demo.yml").write_text(workflow)
    return root


def test_static_accepts_tests_that_run(tmp_path):
    assert tr.check_static(runs_tree(tmp_path / "plain"))[1] == []
    rust = ("/// doc\n#[tokio::test(flavor = \"current_thread\")]\n#[should_panic]\n"
            "async fn demo_unit() {}\n")
    assert tr.check_static(runs_tree(tmp_path / "tokio", rust=rust))[1] == []
    py = ("import pytest\n\n@pytest.mark.skipif(False, reason='x')\n"
          "@pytest.mark.parametrize('a', [1])\ndef test_demo(a):\n    pass\n")
    assert tr.check_static(runs_tree(tmp_path / "skipif", py=py))[1] == []


@pytest.mark.parametrize("rust,expect", [
    ("#[test]\n#[ignore]\nfn demo_unit() {}\n", "unit:demo_unit is #[ignore]d"),
    ("#[test]\n#[ignore = \"slow\"]\nfn demo_unit() {}\n", "unit:demo_unit is #[ignore]d"),
    ("#[cfg_attr(not(feature = \"x\"), ignore)]\n#[test]\nfn demo_unit() {}\n",
     "unit:demo_unit is #[ignore]d"),
    ("fn demo_unit() {}\n", "unit:demo_unit is not a #[test] function"),
])
def test_static_flags_an_ignored_or_non_test_rust_fn(tmp_path, rust, expect):
    _, failures = tr.check_static(runs_tree(tmp_path, rust=rust))
    assert any(expect in f for f in failures), failures


@pytest.mark.parametrize("py,expect", [
    ("import pytest\n\n@pytest.mark.skip(reason='later')\ndef test_demo():\n    pass\n",
     "py:test_demo is marked skip or xfail"),
    ("import pytest\n\n@pytest.mark.xfail\ndef test_demo():\n    pass\n",
     "py:test_demo is marked skip or xfail"),
])
def test_static_flags_a_skipped_python_test(tmp_path, py, expect):
    _, failures = tr.check_static(runs_tree(tmp_path, py=py))
    assert any(expect in f for f in failures), failures


@pytest.mark.parametrize("steps,expect", [
    # Emptied: only checkout and no-ops left.
    ("      - uses: actions/checkout@0000000000000000000000000000000000000000\n"
     "      - run: true\n"
     "      - run: |\n          # gone\n          echo skipped\n",
     "ci:demo has no step that does anything"),
    # The real step disabled.
    ("      - name: test\n        if: false\n        run: cargo test --workspace\n",
     "ci:demo has no step that does anything"),
])
def test_static_flags_an_emptied_ci_job(tmp_path, steps, expect):
    workflow = WORKFLOW.split("    steps:\n")[0] + "    steps:\n" + steps
    _, failures = tr.check_static(runs_tree(tmp_path, workflow=workflow))
    assert any(expect in f for f in failures), failures


def test_static_flags_a_disabled_ci_job(tmp_path):
    workflow = WORKFLOW.replace("    runs-on:", "    if: ${{ false }}\n    runs-on:")
    _, failures = tr.check_static(runs_tree(tmp_path, workflow=workflow))
    assert any("ci:demo is disabled" in f for f in failures), failures


def test_static_ci_reference_must_be_a_job(tmp_path):
    # `push:` under `on:` has the shape of a job key but is not one.
    toml = RUNS.replace("ci:demo", "ci:push")
    root = runs_tree(tmp_path)
    (root / "tests" / "traceability.toml").write_text(toml)
    write_evidence(root)
    _, failures = tr.check_static(root)
    assert any("ci:push is not a job" in f for f in failures), failures
