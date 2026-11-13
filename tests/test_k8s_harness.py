"""The Kubernetes suite's harness must record a failed assertion as a failure.

`tests/k8s/run.sh` runs without `set -e`. Its `fail` helper used to
`return 1`, so `[ ... ] || fail ...` followed by more commands let the test
pass anyway; most k8s assertions could never fail. These tests run the real
`fail` and `run_test` from run.sh against small test functions.
"""

import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUN_SH = ROOT / "tests" / "k8s" / "run.sh"


def harness_functions():
    text = RUN_SH.read_text(encoding="utf-8")
    fail = re.search(r"^fail\(\) \{.*\}$", text, re.M)
    run_test = re.search(r"^run_test\(\) \{.*?^\}$", text, re.M | re.S)
    assert fail and run_test, "fail() or run_test() not found in tests/k8s/run.sh"
    return fail.group(0) + "\n" + run_test.group(0) + "\n"


def run(body, tmp_path):
    script = (
        "set -uo pipefail\n"
        "log() { :; }\n"
        "results=()\n"
        'record() { results+=("$1=$2"); }\n'
        + harness_functions()
        + body
        + '\nprintf "%s\\n" "${results[@]}"\n'
    )
    path = tmp_path / "harness.sh"
    path.write_text(script, encoding="utf-8")
    out = subprocess.run(
        [shutil.which("bash"), str(path)], capture_output=True, text=True, check=True
    )
    return dict(line.split("=", 1) for line in out.stdout.split())


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_a_failed_assertion_fails_the_test_even_with_commands_after_it(tmp_path):
    got = run(
        't_mid() { [ 1 = 2 ] || fail "mismatch"; echo "reached the end"; }\n'
        't_ok() { [ 1 = 1 ] || fail "nope"; echo "fine"; }\n'
        "run_test mid t_mid\n"
        "run_test ok t_ok\n",
        tmp_path,
    )
    assert got == {"mid": "false", "ok": "true"}


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
def test_a_failing_test_still_runs_its_cleanup_trap(tmp_path):
    marker = tmp_path / "cleaned"
    got = run(
        f't_trap() {{ trap "echo done >> {marker}" EXIT; fail "boom"; }}\n'
        "run_test trap t_trap\n",
        tmp_path,
    )
    assert got == {"trap": "false"}
    assert marker.read_text().strip() == "done"
