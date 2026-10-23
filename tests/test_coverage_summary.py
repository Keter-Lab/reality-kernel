"""Unit tests for tests/coverage_summary.py."""

import importlib.util
import pathlib

_spec = importlib.util.spec_from_file_location(
    "coverage_summary", pathlib.Path(__file__).parent / "coverage_summary.py"
)
cs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cs)


def entry(name, covered, count):
    return {"filename": name, "summary": {"lines": {"covered": covered, "count": count}}}


def test_groups_by_crate_and_skips_dependencies():
    export = {"data": [{"files": [
        entry("/repo/rk-policy/src/net.rs", 90, 100),
        entry("/repo/rk-policy/src/file.rs", 10, 20),
        entry("/repo/tests/integration/src/main.rs", 5, 10),
        entry("/home/runner/.cargo/registry/src/serde/lib.rs", 1, 1000),
    ]}]}
    totals = cs.per_crate(export, pathlib.PurePath("/repo"))
    assert totals == {"rk-policy": (100, 120), "tests/integration": (5, 10)}


def test_table_has_total_row():
    out = cs.table({"a": (1, 2), "b": (3, 6)})
    assert "| a | 1/2 | 50.0% |" in out
    assert out.splitlines()[-1] == "| **total** | 4/8 | **50.0%** |"
