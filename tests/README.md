# tests/

What each suite proves, where it runs, and how to extend it. The strategy
behind the layout is in [docs/testing.md](../docs/testing.md).

| Path | What it proves | Runs in |
|---|---|---|
| `integration/` | Every kernel-facing acceptance criterion, by real operations against the loaded programs: verdict suite (`main.rs`), agent/NRI path (`agent.rs`), restart and tamper resilience (`resilience.rs`), the conformance corpus (`conformance.rs`), the audit log, metrics and loss accounting against the real daemon (`observability.rs`), zero-gap upgrades between two different objects and `rk doctor` (`upgrade.rs`), the Phase 7 bench (`bench.rs`) | `kernel.yml` / vm-matrix, as root in a VM per kernel (5.15, 6.1, 6.6, 6.12, 6.18) |
| `vm/selftest.sh` | The VM entry point: loads, runs each suite, extracts the JSON reports | vm-matrix |
| `k8s/run.sh` | The DaemonSet, NRI plugin and annotation binding on a kind cluster | `kernel.yml` / k8s |
| `packaging/run.sh` | The deb and rpm: fresh install enforces under the systemd unit, upgrade to a different object with a gap probe running, uninstall removes everything (Phase 10) | `kernel.yml` / package-test, on Ubuntu 24.04 (runner) and Rocky Linux 9 (systemd container) |
| `conformance/` | One TOML file per policy semantic, with expected verdicts. The **same files** are checked by the userspace evaluator (`rk-policy/tests/conformance.rs`) and by the kernel (`integration/src/conformance.rs`), so the two engines cannot drift | `ci.yml` / test, and vm-matrix |
| `bench/` | `gate.py` compares bench reports with `budget.json` (Phase 7) | `kernel.yml` / bench-report |
| `traceability.toml` | Every acceptance criterion of every phase, mapped to the named tests that prove it | see below |
| `traceability.py` | `static`: every criterion has tests, every named test exists, and `docs/evidence.md` is current. `reports`: every named VM and k8s test passed on every kernel in this run. `evidence`: prints the evidence page | `ci.yml` / python, and `kernel.yml` / traceability |
| `readme_claims.py` | Every README claim links to a criterion, every evidence link resolves, and no performance number or superlative appears outside the claims (Phase 11) | `ci.yml` / python, through `test_readme_claims.py` |
| `test_workflows.py` | Actions pinned by commit SHA, read-only default token permissions, and a release workflow that signs, attests and verifies every artifact | `ci.yml` / python |
| `coverage_summary.py` | The per-crate line coverage table | `ci.yml` / coverage |
| `test_dashboard.py` | The Grafana dashboard (`deploy/grafana/`) queries only metrics the sensor exports | `ci.yml` / python |
| `test_site.py` | The website: links resolve, nothing of the retired product, the README's claims rules, strict-CSP compatibility, partials and sitemap (Phase 12) | `ci.yml` / python |
| `test_repository.py` | Only the open-source project's crates and paths are present (Phase 12) | `ci.yml` / python |
| `test_*.py` | Unit tests for the scripts above and the workflow policy | `ci.yml` / python |

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
   `vm:`, `k8s:`, `pkg:`, `unit:`, `go:`, `py:` or `ci:` (a workflow job id).
3. `python3 tests/traceability.py static` checks the reference locally.
4. Regenerate the evidence page:
   `python3 tests/traceability.py evidence > docs/evidence.md`.

Renaming or deleting a referenced test fails the static check. A VM or k8s
test that did not pass on every kernel fails the `traceability` job.
