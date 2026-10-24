# Roadmap

Reality Kernel ships in versioned milestones. Each feature gets a design
note in [docs/design](docs/design) before code, and is claimed only once its
tests pass on every supported kernel ([docs/evidence.md](docs/evidence.md)).
Plans change with what users run into; open an issue if something here
matters to you, or if something missing does.

The engineering plan that rebuilt the project as kernel enforcement is
complete as of v0.1.0 (design notes `phase-*`).

## v0.2.0 — Adoption

From nothing to an agent under an enforced, least-privilege profile in a few
commands, and a runbook a coding agent can follow
([design](docs/design/adoption.md)).

- TUN/TAP containment (done: [ADR-0017](docs/decisions/0017-tun-tap-containment.md))
- One-command install that verifies checksums and, with `cosign`, the
  release signature
- `rk init`: a starter profile that fits the host, in AUDIT
- `rk policy suggest`: an ENFORCE profile from the audit log, for a human
  to review and apply
- `docs/agents.md` and `llms.txt` for coding agents

## v0.3.0 — Egress by name

Network rules by hostname (`api.example.com`), so policies survive CDN
address changes, and DNS query filtering, so a governed agent can only
resolve names its profile allows. That also closes DNS tunnelling as an
exfiltration channel.

## v0.4.0 — Information-flow containment

Contain what an agent does with data, not only where it connects:

- taint on reading secret-class files, carried to child processes, files the
  agent writes and IPC (pipes, Unix sockets, shared memory);
- tainted processes reach only trusted destinations, with per-destination
  byte budgets;
- a credential broker, so an agent can use an API key it can never read;
- a "breakout suite" in CI: known sandbox escapes (DNS exfiltration,
  check-then-use races, abuse of an allowed binary's configuration,
  laundering through another process) as tests that must fail on every
  kernel.

Covert channels through a destination the policy allows cannot be closed in
general; the design notes will document what remains.

## Later

- Detect and contain: verify that every program and link stays attached,
  quarantine an agent automatically on tampering, attest the audit chain
  head off the host.
- Kernel-level deception for hostile agents (redirect, decoy, record).
- arm64 kernels in the VM matrix.
