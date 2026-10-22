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
    return tmp_path


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


def test_repository_index_is_complete():
    """The real tests/traceability.toml passes the static check."""
    _, failures = tr.check_static(pathlib.Path(__file__).resolve().parents[1])
    assert failures == []
