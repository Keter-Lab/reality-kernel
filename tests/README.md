# tests/

What each suite proves, where it runs, and how to extend it. The strategy
behind the layout is in [docs/testing.md](../docs/testing.md).

| Path | What it proves | Runs in |
|---|---|---|
| `integration/` | Every kernel-facing acceptance criterion, by real operations against the loaded programs: verdict suite (`main.rs`), agent/NRI path (`agent.rs`), restart and tamper resilience (`resilience.rs`), the conformance corpus (`conformance.rs`), the audit log, metrics and loss accounting against the real daemon (`observability.rs`), the Phase 7 bench (`bench.rs`) | `kernel.yml` / vm-matrix, as root in a VM per kernel (5.15, 6.1, 6.6, 6.12, 6.18) |
| `vm/selftest.sh` | The VM entry point: loads, runs each suite, extracts the JSON reports | vm-matrix |
| `k8s/run.sh` | The DaemonSet, NRI plugin and annotation binding on a kind cluster | `kernel.yml` / k8s |
| `conformance/` | One TOML file per policy semantic, with expected verdicts. The **same files** are checked by the userspace evaluator (`rk-policy/tests/conformance.rs`) and by the kernel (`integration/src/conformance.rs`), so the two engines cannot drift | `ci.yml` / test, and vm-matrix |
| `parity/` | Golden cases for `rk-engine-core` | `ci.yml` / test |
| `bench/` | `gate.py` compares bench reports with `budget.json` (Phase 7) | `kernel.yml` / bench-report |
| `traceability.toml` | Every acceptance criterion of every phase, mapped to the named tests that prove it | see below |
| `traceability.py` | `static`: every criterion has tests, and every named test exists. `reports`: every named VM and k8s test passed on every kernel in this run | `ci.yml` / python, and `kernel.yml` / traceability |
| `coverage_summary.py` | The per-crate line coverage table | `ci.yml` / coverage |
| `test_dashboard.py` | The Grafana dashboard (`deploy/grafana/`) queries only metrics the sensor exports | `ci.yml` / python |
| `test_*.py` | Unit tests for the scripts above, and the security regressions | `ci.yml` / python |

Fuzz targets live in `../fuzz/` (`decoder_fuzz`, `policy_fuzz`; five minutes
each in `kernel.yml` / fuzz). Unit and property tests live next to the code
they test (`#[cfg(test)]`, `proptest`).

## Adding a conformance case

Create `conformance/<name>.toml` (format in `conformance/README.md`): a
policy whose profile is called `case`, optional `setup` fixtures, and
`[[op]]` entries with the verdict you expect. Both runners pick it up; no
code changes. A case one engine disagrees with fails `conformance_userspace`
or `conformance_kernel`, naming the case and the operation.

## Adding an acceptance test

1. Write the test with a stable name: `run_test(checks, "name", ...)` in the
   integration harness, `run_test name` in `k8s/run.sh`, or an ordinary
   `#[test] fn name`, `func Test...`, `def test_...`.
2. Add it to the criterion's `tests` list in `traceability.toml` as
   `vm:`, `k8s:`, `unit:`, `go:`, `py:` or `ci:` (a workflow job id).
3. `python3 tests/traceability.py static` checks the reference locally.

Renaming or deleting a referenced test fails the static check. A VM or k8s
test that did not pass on every kernel fails the `traceability` job.
