# Testing strategy

How Reality Kernel is tested, and why the layers are what they are. The file
layout and how to add tests are in [tests/README.md](../tests/README.md).
Design: [docs/design/phase-8.md](design/phase-8.md).

## Principle: every claim has a named test

Each phase's acceptance criteria are listed in `tests/traceability.toml`
together with the tests that prove them. CI checks the mapping twice:

- **statically** on every push (`ci.yml` / python): every criterion names at
  least one test, and every named test exists in the source;
- **against results** after the kernel matrix (`kernel.yml` / traceability):
  every named VM and Kubernetes test passed on every kernel of that run.
  A missing report counts as a failure.

So a criterion cannot silently lose its evidence through a renamed,
deleted, skipped or failing test.

## Layers

| Layer | What it catches | Where |
|---|---|---|
| Unit tests | Logic: policy parsing and compilation, map key layouts, ABI struct sizes (on x86_64 and arm64), consumer accounting | `cargo test`, both architectures |
| Property tests | Invariants over all inputs: dev_t encoding, CIDR normalisation, v4 vs v4-mapped verdicts, compile/diff stability, the engine state file | `proptest`, in the unit test runs |
| Conformance corpus | Drift between the userspace reference evaluator and the kernel: the same TOML cases run against both | `rk-policy/tests/conformance.rs`, VM harness |
| Fuzzing | Panics and inconsistencies on hostile input: ring buffer event decoding, policy text | `cargo fuzz`, 2 × 5 min per run |
| Kernel integration | That programs load, attach and enforce: real `connect`, `execve` and `open` calls in governed cgroups, restarts and tampering | VM per kernel, as root |
| Observability | Every deny and audit-would-deny reaches the signed audit log with its rule id, the kernel's decision counters agree with the log, a flipped byte fails `rk audit verify`, lost events are recorded, `/metrics` moves | VM per kernel, real daemon (`observability.rs`); OCSF records validated against a vendored 1.9.0 schema subset in unit tests |
| Kubernetes | Deployment, NRI binding, annotations, fail-closed behaviour | kind cluster |
| Performance | Hook cost and event loss against a budget | Phase 7 bench and `tests/bench/gate.py` |
| Coverage | Untested userspace code (report-only for now) | `cargo llvm-cov`, job summary |

## What runs when

| Event | ci.yml (lint, tests, coverage) | kernel.yml (VMs, kind, fuzz, traceability) |
|---|---|---|
| Push to `phase-*` | always; rustfmt reports but does not fail (autofix commits the formatting) | skipped when only docs, Markdown, assets, Python unit tests or other workflows changed |
| Pull request to `main` | always, rustfmt strict | always, full matrix |
| Push to `main` | always, rustfmt strict | same path filter as phase pushes |

Autofix commits (rustfmt, gofmt, lock files) do not trigger CI. The pull
request's own run covers the merged result.

## The kernel matrix

The VM suites run on Linux 5.15, 6.1, 6.6, 6.12 and 6.18: the oldest
supported LTS, every LTS since, and the newest stable. Kernel behaviour
that differs between them (BPF-LSM availability, kfuncs, verifier limits)
is exercised where it actually happens instead of being mocked. See
[kernel-matrix.md](kernel-matrix.md).

## What cannot be unit-tested in the kernel, and why

`BPF_PROG_TEST_RUN` runs a program on a synthetic input without attaching
it. It exists only for program types whose `bpf_prog_ops` define a
`test_run` callback. Per type, as of Linux 6.12:

| Program | Type | `test_run` | How it is tested instead |
|---|---|---|---|
| `rk_net_connect4/6`, `rk_net_sendmsg4/6` | `cgroup/sock_addr` | none (`cg_sock_addr_prog_ops`) | real connects in the VM verdict and conformance suites |
| `rk_exec_check`, `rk_file_open`, `rk_net_socket_create`, guard hooks | `lsm` | none (`lsm_prog_ops`) | real exec, open and socket calls in the VMs |
| `rk_exec_record` | `tp_btf` (raw tracepoint) | only fentry/fexit/fmod_ret have one in `tracing_prog_ops` | exec events checked end to end in the VMs |

Every enforcement hook is therefore tested by real operations in real
kernels. That is slower than `BPF_PROG_TEST_RUN` would be, but it also
proves the attachment and the verifier's acceptance on each kernel, which a
synthetic run never could.

## Repository and supply chain checks

Phase 11 ([design](design/phase-11.md)) adds checks on the repository
itself, so that what it promises stays true:

| Check | What fails it | Where |
|---|---|---|
| README claims (`tests/readme_claims.py`) | A README claim without an evidence link, an evidence link to an unknown criterion, a performance number or superlative outside the claims block | `ci.yml` / python |
| Evidence page | `docs/evidence.md` differs from what `traceability.py evidence` generates from `traceability.toml` | `ci.yml` / python (static check) |
| Workflow policy (`tests/test_workflows.py`) | An action not pinned by commit SHA, a workflow without read-only default permissions, a release workflow that no longer signs, attests or verifies every artifact | `ci.yml` / python |
| DCO (`.github/scripts/dco_check.py`) | A pull request commit without its author's `Signed-off-by` | `dco.yml`, pull requests |
| CodeQL | Static analysis findings in Rust, Go, Python and workflows | `codeql.yml` |
| OpenSSF Scorecard | Published score; see the design note for what it measures | `scorecard.yml`, `main` |
| Release verification | Any artifact or the image without a valid signature from the release workflow, provenance or SBOM: the release is not drafted | `release.yml`, tags |
| NRI fuzzing | A panic or inconsistency in the plugin's message handling (`FuzzDecodeReply`, `FuzzEncodeBind`) | `ci.yml` / go (seed corpus) |

After changing `tests/traceability.toml`, regenerate the evidence page:
`python3 tests/traceability.py evidence > docs/evidence.md`.

## Known gaps

- Coverage has no threshold yet. One will be set once a few runs show a
  stable baseline.
