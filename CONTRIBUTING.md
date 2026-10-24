# Contributing to Reality Kernel

Thank you for helping. This page covers how to build and test, what a pull
request needs, and how decisions are made. Everyone taking part follows the
[Code of Conduct](CODE_OF_CONDUCT.md).

**Security issues:** please do not open a public issue. See
[SECURITY.md](SECURITY.md).

## Your first contribution

New here? Welcome. A good way in:

1. **Pick an issue** labelled
   [`good first issue`](https://github.com/Keter-Lab/reality-kernel/issues?q=is%3Aopen+label%3A%22good+first+issue%22).
   Each one names the files to change and the test to add, and needs no
   root, kernel or VM: `cargo test` or `pytest` on a Linux machine (or WSL)
   is enough. Comment on it so nobody else picks it up.
2. **Ask early.** Questions go in the issue or in
   [Discussions](https://github.com/Keter-Lab/reality-kernel/discussions);
   there are no silly ones. Expect an answer within a few days.
3. **Open a pull request** early, even unfinished (mark it as a draft).
   CI runs everything, including the kernel suites in VMs, so you can see
   results without a kernel setup of your own.
4. **Sign off your commits** (`git commit -s`, see [Sign-off](#sign-off)).

All open work is on the public
[project board](https://github.com/orgs/Keter-Lab/projects/1).
`help wanted` issues are larger and say what background helps. Larger work
starts with a short plan in the issue. Interested in Google Summer of Code?
See [docs/gsoc.md](docs/gsoc.md).

## Building

Prerequisites: a stable Rust toolchain, clang/LLVM and libbpf headers (BPF
objects), libclang (bindgen), and Go for the NRI plugin.

```sh
rustup toolchain install stable
sudo apt-get install -y clang llvm libbpf-dev libclang-dev   # Debian/Ubuntu

cargo build --workspace            # userspace crates
cargo xtask build-sensor           # BPF objects (rk-bpf/build/<arch>/) and a sensor embedding them
cargo test --workspace             # unit, property and conformance tests (userspace)
(cd rk-nri && go vet ./... && go test -race ./...)   # NRI plugin
python3 -m pytest tests            # script and policy tests
```

Running the programs needs Linux 5.15 or newer with BTF
(`CONFIG_DEBUG_INFO_BTF=y`); exec and file rules need BPF LSM
(`rk doctor` says what is missing). The kernel integration suites run as
root in VMs on five kernels in CI (`kernel.yml`); you do not need a VM
locally. Opening a pull request runs them.

## What a pull request needs

1. **A focused change** with a clear description of what and why.
2. **Tests.** Every behaviour change comes with a test that fails without
   it. A change to an acceptance criterion's behaviour updates its tests in
   [tests/traceability.toml](tests/traceability.toml); how to add one is in
   [tests/README.md](tests/README.md#adding-an-acceptance-test). Changes to
   policy semantics add a conformance case, which both the userspace
   evaluator and the kernel must agree on.
3. **Clean checks.** `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `gofmt`, and the CI checks: lint, unit tests on x86_64 and arm64, Python,
   Go, the kernel matrix and traceability.
4. **Honest documentation.** Update the docs the change affects. A new
   claim in the README goes in its claims block with a link to the
   criterion that proves it; `tests/readme_claims.py` rejects performance
   numbers and superlatives anywhere else.
5. **A design note first** for significant changes: a new hook, a policy
   format change, anything touching the ABI or the pin layout. See
   [GOVERNANCE.md](GOVERNANCE.md#design-decisions).
6. **Signed-off commits** (below).

Kernel code (`rk-bpf/`, `rk-ebpf-common/`, the loader and pins in
`rk-sensor/`) follows the two-person review rule in
[GOVERNANCE.md](GOVERNANCE.md#how-changes-land).

Commit messages follow the existing style: `type(scope): summary` in the
imperative, for example `fix(rk-sensor): exit promptly on SIGTERM`.

## Sign-off

Every commit must carry a `Signed-off-by` line with the commit author's
name and email, certifying the
[Developer Certificate of Origin 1.1](https://developercertificate.org/):
that you wrote the change or otherwise have the right to submit it under
the project's licences. Git adds the line for you:

```sh
git commit -s -m "fix(rk-cli): ..."
```

The DCO check on pull requests names any commit without it. To fix the
commits on your branch:

```sh
git rebase --signoff main
git push --force-with-lease
```

Commits made by bots (`[bot]@users.noreply.github.com`) are exempt.

## Licensing

Contributions are licensed as the files they change: userspace code under
Apache-2.0 or MIT at the user's option, and the BPF programs in `rk-bpf/`
under GPL-2.0-only or MIT
([ADR-0012](docs/decisions/0012-bpf-licensing.md)).

## Where things are

[docs/architecture.md](docs/architecture.md) maps the components;
[docs/testing.md](docs/testing.md) explains the test layers;
[docs/decisions/](docs/decisions/README.md) records why things are the way
they are.
