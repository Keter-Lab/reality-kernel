"""Unit tests for the Phase 7 benchmark gate (tests/bench/gate.py)."""

import importlib.util
import json
import pathlib

_spec = importlib.util.spec_from_file_location(
    "gate", pathlib.Path(__file__).parent / "bench" / "gate.py"
)
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


def report(open_gov_p50=300, open_gov_p99=900, lost=0, exec_avg=1600, exec_runs=5000):
    def hook(name, gp50, gp99):
        return {
            "hook": name,
            "overhead": {
                "ungoverned": {"p50": 40, "p99": 120},
                "governed": {"p50": gp50, "p99": gp99},
            },
        }

    return {
        "kernel": "6.6.0",
        "hooks": {
            "open": hook("file_open", open_gov_p50, open_gov_p99),
            "connect": hook("connect4", 200, 600),
            "exec": hook("bprm_check_security", 90000, 400000),
        },
        "per_program": {
            "rk_exec_check": {"avg_ns": exec_avg, "runs": exec_runs},
            "rk_guard_bpf": {"avg_ns": 150, "runs": 12},
        },
        "sustained": {"target_rate": 20000, "result": {"kernel_drops": lost, "userspace_drops": 0}},
        "flood": {"sent": 1, "drained": 1, "kernel_drops": 0, "userspace_drops": 0},
    }


def test_propose_gates_p50_of_stable_ops_and_program_averages():
    b = gate.propose([("a", report()), ("b", report(open_gov_p50=700, exec_avg=2000))])
    # worst across kernels x2
    assert b["hooks"]["open"]["governed_p50_ns"] == 1400
    # 40 x 2 = 80 is below the 1 us floor
    assert b["hooks"]["open"]["ungoverned_p50_ns"] == gate.FLOOR_NS
    # p99 and the noisy exec syscall timing are reported, not gated
    assert "governed_p99_ns" not in b["hooks"]["open"]
    assert "exec" not in b["hooks"]
    # kernel-measured program averages are gated
    assert b["programs"]["rk_exec_check"]["avg_ns"] == 4000
    # programs with too few runs are not
    assert "rk_guard_bpf" not in b["programs"]


def test_check_passes_within_budget_and_flags_regressions():
    budget = gate.propose([("a", report())])
    assert gate.check(budget, [("a", report())]) == []
    failures = gate.check(budget, [("b", report(open_gov_p50=5000))])
    assert any("open governed p50" in f for f in failures)
    failures = gate.check(budget, [("b", report(exec_avg=10000))])
    assert any("rk_exec_check avg" in f for f in failures)


def test_p99_noise_does_not_fail_the_gate():
    budget = gate.propose([("a", report())])
    assert gate.check(budget, [("a", report(open_gov_p99=10**7))]) == []


def test_check_flags_loss_at_sustained_rate():
    budget = gate.propose([("a", report())])
    failures = gate.check(budget, [("a", report(lost=3))])
    assert any("3 events lost" in f for f in failures)


def test_check_flags_missing_hook_and_missing_stats():
    budget = gate.propose([("a", report())])
    r = report()
    del r["hooks"]["connect"]
    r["per_program"] = {"error": "bpf_stats or bpftool unavailable"}
    failures = gate.check(budget, [("a", r)])
    assert any("no measurement for connect" in f for f in failures)
    assert any("no per-program stats" in f for f in failures)


def test_main_without_budget_reports_only(tmp_path, capsys):
    path = tmp_path / "bench-6.6.json"
    path.write_text(json.dumps(report()))
    assert gate.main(["gate.py", str(tmp_path / "missing.json"), str(path)]) == 0
    out = capsys.readouterr().out
    assert "Proposed budget.json" in out
    assert "| 6.6.0 | open (file_open)" in out
    assert "rk_exec_check" in out


def test_main_fails_over_budget(tmp_path):
    budget = tmp_path / "budget.json"
    budget.write_text(json.dumps(gate.propose([("a", report())])))
    path = tmp_path / "bench.json"
    path.write_text(json.dumps(report(open_gov_p50=10**6)))
    assert gate.main(["gate.py", str(budget), str(path)]) == 1
