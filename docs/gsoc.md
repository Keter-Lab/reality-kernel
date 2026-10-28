# Project ideas

Larger projects for contributors, open to anyone at any time. Each is sized
and scoped the way mentoring programmes such as Google Summer of Code expect
(hours, difficulty, skills, outcome), so they can also be proposed there if
Reality Kernel takes part in one.

Reality Kernel enforces policy for AI agents inside the Linux kernel: network,
exec and file rules decided in eBPF (BPF-LSM and cgroup hooks) before the
action happens, with a signed audit log. Every capability it claims is tied
to tests that run on five kernels in CI ([evidence](evidence.md)).

**Getting started:** read [CONTRIBUTING.md](../CONTRIBUTING.md#your-first-contribution),
pick a [good first issue](https://github.com/Keter-Lab/reality-kernel/issues?q=is%3Aopen+label%3A%22good+first+issue%22),
and say hello in [Discussions](https://github.com/Keter-Lab/reality-kernel/discussions).
What is planned and what is open is on the public
[project board](https://github.com/orgs/Keter-Lab/projects/1) and in
[ROADMAP.md](../ROADMAP.md).
A merged first contribution is the best way to start a larger project. You do not need
a kernel VM locally: CI runs the kernel suites on every pull request.

Each project follows the project's usual path: a design note in
`docs/design/` first, then code, then tests that prove it on every kernel.

---

## 1. Hostname rules and DNS query filtering

**Size:** 350 hours · **Difficulty:** hard · **Milestone:** v0.4.0 ([#54](https://github.com/Keter-Lab/reality-kernel/issues/54))

Network rules today are IP prefixes. Agents talk to hostnames
(`api.example.com`) whose addresses change, so learned policies go stale,
and an agent can still tunnel data out through DNS lookups. This project
adds hostname rules and DNS awareness: governed agents may only resolve
names their profile allows, and connections are allowed by the name they
resolved.

- **Skills:** Rust; C for eBPF (or willingness to learn); DNS protocol.
- **Outcome:** a design note comparing approaches (DNS snooping in a
  cgroup socket program vs. userspace resolution), hostname rules in the
  policy language, DNS query filtering, `rk policy suggest` emitting
  hostname rules, VM tests on all kernels including a DNS-exfiltration
  test that must fail.
- **Mentors:** Mohd Tabrez (@HunterX461), TBD

## 2. A "breakout suite" of agent sandbox escapes

**Size:** 175 hours · **Difficulty:** medium · **Milestone:** v0.5.0 groundwork ([#55](https://github.com/Keter-Lab/reality-kernel/issues/55))

Known ways agents escape sandboxes (DNS exfiltration, check-then-use races
on files, abusing an allowed binary's configuration, laundering data
through another process) become CI tests that must fail on every kernel.
Some already fail today (file rules are decided on file identity, not
path); the suite documents which, and gives later work a target.

- **Skills:** Rust; Linux internals (processes, IPC, filesystems);
  security-testing mindset.
- **Outcome:** a test suite in `tests/integration` with each escape as a
  named test linked to a criterion in `tests/traceability.toml`, and a
  write-up of which escapes are contained and which are not yet.
- **Mentors:** Mohd Tabrez (@HunterX461), TBD

## 3. arm64 kernels in the VM matrix

**Size:** 175 hours · **Difficulty:** medium

The kernel suites run on x86_64. arm64 objects are built and their layout
checked, but never loaded into an arm64 kernel, because GitHub's arm64
runners have no KVM. This project runs the VM suites on arm64 under QEMU
emulation (slow but free), e.g. as a nightly job.

- **Skills:** CI (GitHub Actions), QEMU, building Linux kernels; some Rust.
- **Outcome:** arm64 rows in `docs/kernel-matrix.md` backed by CI, with the
  traceability check extended to them.
- **Mentors:** Mohd Tabrez (@HunterX461), TBD

## 4. Kernel attack-surface reduction for agents

**Size:** 175 hours · **Difficulty:** medium-hard · **Research first**

Capable agents have chained kernel bugs to escape VMs. Most Linux
privilege-escalation exploits enter through subsystems a normal agent never
needs: user namespaces, io_uring, module autoloading through unusual socket
families, `perf_event_open`, `userfaultfd`, `keyctl`. This project studies
which BPF-LSM hooks can close each one, on which kernels (5.15 up), and
adds a profile setting that denies them, with tests.

- **Skills:** Linux security (LSM), C/eBPF, reading kernel source.
- **Outcome:** a design note with the per-kernel hook survey, the profile
  setting, and VM tests showing each surface denied for governed agents
  and untouched for others.
- **Mentors:** Mohd Tabrez (@HunterX461), TBD
