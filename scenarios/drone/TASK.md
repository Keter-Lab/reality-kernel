# Task: Drone companion-computer scenario + first benchmarks for Reality Kernel

## Goal
Run Reality Kernel (RK) as it would run on a drone's Linux companion computer, inside a VM
booted on a GitHub Actions runner, and prove three things:
1. The legitimate mission still works (companion.py reads telemetry from a simulated ArduPilot flight controller).
2. Three attacks that India's draft military drone security framework worries about are blocked:
   - exfiltrating telemetry to an unapproved server (port 9999),
   - executing a tampered copy of the flight binary,
   - launching an unapproved tool (`nc`) as a remote-shell stand-in.
3. RK's signed, hash-chained audit log records the denials and verifies cleanly.

Then record first overhead benchmarks: exec latency, connect latency, and telemetry rate, with and without RK.

## Files
- `.github/workflows/drone-sim.yml`: runner setup, KVM, virtme-ng, ArduPilot SITL build, runs the scenario in a VM with `lsm=...,bpf`, uploads results.
- `scenarios/drone/run.sh`: the scenario. Every attack runs first WITHOUT RK (must succeed) and then WITH RK (must be blocked).
- `scenarios/drone/companion.py`: stand-in mission software (MAVLink over tcp:127.0.0.1:5760).
- `scenarios/drone/bench.py`: micro-benchmarks, writes JSON lines to `results/bench-results.jsonl`.

## What you need to do
1. Fill in every `TODO`:
   - Build RK in the workflow the same way this repo's existing kernel CI does.
   - Start RK inside the VM with a drone policy, using this repo's real policy format and CLI. The policy must:
     - allow exec only of: the arducopter binary (by identity, not path), python3, /bin/true (used by the benchmark);
     - allow connect only to 127.0.0.1:5760 (MAVLink) and 127.0.0.1:7000 (benchmark listener);
     - deny everything else, including `curl`, `nc`, and port 9999.
   - Verify the audit chain with RK's own audit verification command, and make the script fail if verification fails.
   - Pick the current stable ArduPilot Copter tag.
2. Push to a branch and run the workflow (workflow_dispatch). Iterate on failures until it passes.
3. If the runner kernel lacks BPF-LSM, boot the kernel images this repo's existing CI already uses instead.
4. Add caching for the ArduPilot build once it works.

## Rules (important)
- NEVER make a check pass by weakening it. Do not loosen the policy beyond the list above, do not delete or skip attacks, do not change expected outcomes, and do not remove the no-enforcement baseline.
- If an attack is NOT blocked by RK, that is a real finding: report it clearly and stop, rather than adjusting the test.
- If the baseline run shows an attack failing WITHOUT RK, the test is broken: fix the test so it can succeed without enforcement.
- Keep all changes on a branch and open a PR summarizing what changed and why.

## Reporting
When the workflow passes, summarize in the PR:
- pass/fail for the mission, each attack (baseline and enforced), and audit verification;
- the benchmark numbers side by side (median, p95, p99 for exec and connect; msg/s for telemetry), with the overhead percentage;
- a clear note that these are CI VM numbers (x86, virtualized, noisy) and NOT real drone hardware results.
