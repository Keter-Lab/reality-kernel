# Design note: Phase 8 — test strategy

Status: **ACCEPTED** (2026-10-22). All four decisions in §6 approved as recommended.
Branch: `phase-8-tests` (from `phase-7-performance` at 0e47019; rebased onto
`main` once Phase 7 merges)
Plan reference: RealityKernel_Engineering_Plan.pdf, Phase 8 ("Confidence
that every enforcement claim is continuously verified").

## 1. Goal and acceptance criteria

Plan acceptance criteria (must pass in CI):

1. Every acceptance criterion in Phases 2–6 maps to at least one named test.
2. The integration suite runs on the full kernel matrix for every PR touching
   `rk-bpf/` or `rk-sensor/`.

Today criterion 2 already holds, with margin: the kernel workflow runs on
every push to `main` and `phase-*` and on every pull request, with no path
filter. Criterion 1 holds in practice (every design note's test table names
its tests), but nothing *checks* it, so a renamed or deleted test would go
unnoticed. Phase 8 makes it machine-checked.

## 2. What already exists

| Plan item | Status |
|---|---|
| Unit tests: rk-policy, decoder, sensor | Exist; rk-policy includes a property test that the compiled longest-prefix lookup always agrees with the reference evaluator |
| Integration suite in VMs (AUDIT and ENFORCE) | Exists: 60 verdict, 12 agent and 11 resilience tests on five kernels, plus 14 on Kubernetes |
| Invariant: telemetry failure never changes verdicts | Exists: the full verdict suite re-runs against `rk_emitfail.bpf.o`, where every emission fails |
| Invariant: policy reload is atomic | Exists: `net_`, `exec_`, `file_reload_atomic` and `policy_apply_atomic` |
| Invariant: ungoverned processes are untouched | Exists: `*_ungoverned_untouched`, `*_unbound_sibling_untouched` |
| Decoder fuzzing | Exists: 10 min per CI run |
| Process table unit tests | Moved to Phase 9 with the table itself (Phase 7, decision 4) |

## 3. What Phase 8 adds

### 3.1 Traceability, machine-checked (criterion 1)

`tests/traceability.toml` lists every acceptance criterion from Phases 2–7
(the plan's, plus the ones each design note added), each with the named tests
that prove it. `tests/traceability.py` (standard library only) checks two
things:
- **Statically, in the lint job:** every named test exists in the source, as a
  Rust `#[test] fn`, a `run_test` name in the VM or kind suites, or a pytest
  function, and every criterion has at least one test.
- **Dynamically, in a new `traceability` job after the VM matrix and kind:**
  every VM- and kind-suite test named there **passed** in that run's reports,
  on every kernel where it runs.

A deleted, renamed or failing test therefore fails CI against the criterion
it proves. The file also becomes the human-readable "claim → test" index the
plan's later README rule (Phase 11) needs.

### 3.2 Policy conformance corpus

`tests/conformance/*.toml`: each case is a small policy, one operation and the
expected verdict. Two runners read the same files:
- **userspace:** `rk-policy`'s reference evaluator, for network cases (the
  one domain with a pure-userspace evaluator);
- **kernel:** a new `conformance` group in the VM verdict harness applies each
  case's policy and performs the real operation (connect, sendmsg, exec,
  open/unlink/rename…) in a governed child, then compares the verdict.

A disagreement between the corpus and either engine fails CI. The initial
corpus covers the edge cases the plan and the earlier phases call out:
longest-prefix and deny-over-allow, v4-mapped and NAT64 equivalence, port
ranges and protocol masks, AUDIT versus ENFORCE, exec allowlist identity
(symlink, rename, replaced file), and file access bits with subtree rules.
Adding a regression case means adding a file, no code. See decision 1 for
the format.

### 3.3 Fuzzing and property tests

- New fuzz target `policy_fuzz`: arbitrary text through `rk-policy`
  parse-and-compile must never panic. The CI fuzz budget stays at 10 minutes,
  split 5 + 5 between the decoder and the policy parser.
- New property tests:
  - kernel `dev_t` encoding round-trips (`MAJOR << 20 | MINOR`, the identity
    key for exec and file rules);
  - CIDR parsing normalises every v4 form to its v4-mapped v6 network;
  - the engine state file round-trips and is rejected under a different pin
    epoch (Phase 6).

### 3.4 BPF_PROG_TEST_RUN: where it applies

The plan asks for BPF program tests "where the program type supports it".
The Linux 6.12 source settles it: `lsm_prog_ops` and `cg_sock_addr_prog_ops`
define **no** `test_run`, so every enforcement hook (BPF-LSM and cgroup
`sock_addr`) has no BPF_PROG_TEST_RUN at all. `tracing_prog_ops` has one, but
for fentry/fexit/fmod_ret, not the `tp_btf` raw tracepoint `rk_exec_record`
uses. Enforcement logic is therefore tested the way that also proves the
attachment: real operations in real kernels (the VM suites and the
conformance runner). `docs/testing.md` records this per program type, so the
gap is explicit rather than silent.

### 3.5 Coverage report

A `coverage` job runs `cargo llvm-cov` over the userspace crates (rk-policy,
rk-sensor's userspace modules, rk-agentd, rk-ebpf-common, rk-cli). It
publishes an lcov file, an HTML artifact and a per-crate table in the job
summary. It reports only, no threshold yet (decision 3).

### 3.6 Documentation

- `tests/README.md`: the layout of `tests/`, what each suite proves, where
  it runs, and how to add a case or a test.
- `docs/testing.md`: the strategy behind it (the levels, the matrix, the
  invariants, what can't be tested and why).

## 4. Tests

| Criterion | Evidence |
|---|---|
| Every Phase 2–6 criterion maps to a named test | `traceability_static` (lint job) and `traceability_passed` (after VMs and kind): fail on a missing, renamed or failing test |
| Integration suite on the full matrix for PRs touching rk-bpf/rk-sensor | the existing `kernel.yml` triggers (all pushes and PRs); `traceability_passed` also fails if a kernel's report is missing |
| Conformance (added) | `conformance_userspace` (unit test over the corpus) and the `conformance_*` group in the VM harness, one named check per case |
| Fuzzing (added) | `policy_fuzz` in the fuzz job |
| Coverage (added) | `coverage` job artifact and summary |

## 5. Out of scope

Process table tests (Phase 9). Performance tests are Phase 7's gate, already
in place.

## 6. Decisions requested from the reviewer

1. **Conformance corpus in TOML, not YAML.** Recommended: the plan says YAML,
   but the Rust YAML options are poor. `serde_yaml` is deprecated (its last
   release is `0.9.34+deprecated`). Its fork `serde_yml` carries an
   unsoundness advisory (RUSTSEC-2025-0068) and was archived. `yaml-rust`,
   which others build on, is flagged unmaintained (RUSTSEC-2024-0320), which
   our cargo-deny gate rejects. TOML is already a dependency, and the policy
   itself is TOML, so a case's policy embeds without quoting games.
2. **Traceability checked statically and against the run's actual
   reports.** Recommended: "exists in the source" alone would pass a test
   that is skipped or failing; checking the reports proves it ran and passed
   on every kernel.
3. **Coverage report-only for now.** Recommended: a threshold set before the
   first measurement would be arbitrary. As with the Phase 7 budget, measure
   first, then gate on not regressing.
4. **No BPF_PROG_TEST_RUN tests.** Recommended: the kernel doesn't support it
   for our program types (§3.4), and the VM suites test the same logic
   end to end, attachment included.
