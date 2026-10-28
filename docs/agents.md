# Setting up Reality Kernel with a coding agent

This page is a runbook. A person can follow it, and so can a coding agent
(Claude Code, Codex, Cursor and others): every step is a command with what
to expect. It takes a Linux host from nothing to an AI agent running under
an enforced, least-privilege profile. Design:
[docs/design/adoption.md](design/adoption.md).

## Paste this into your coding agent

```text
Set up Reality Kernel on this Linux host by following
https://github.com/Keter-Lab/reality-kernel/blob/main/docs/agents.md
step by step. Run each command yourself and show me its output. Stop and ask
me before step 5 (switching to enforce), and never loosen a policy or apply
one I have not seen.
```

## Rules for agents doing this setup

1. **Run outside any governed profile.** You are configuring the thing that
   will govern agents; do not run this setup under `rk run`. A governed agent
   cannot change policy anyway: `/etc/rk` is root-owned and the kernel denies
   it `bpf()`.
2. **Propose, never decide.** You may install, run `rk init`, run the user's
   agent under the AUDIT profile, and produce a suggestion. Switching a
   profile to ENFORCE, and any later loosening, is the human's decision:
   show the diff and wait.
3. **Never pipe a suggestion straight into `rk policy apply`.** Write it to a
   file, show it, show `rk policy diff`, then wait.
4. **Report failures as they are.** If a check fails, show the output and
   stop; do not work around a refused checksum or signature.

## 1. Check the host

```sh
uname -r                      # 5.15 or newer
cat /sys/kernel/security/lsm  # contains "bpf" for exec and file rules
```

Without `bpf` in that list only network rules can be enforced; everything
below still works and produces a network-only profile. To enable it, add
`lsm=<the current list>,bpf` to the kernel command line and reboot
([install.md](install.md)). Ask the user first.

## 2. Install

```sh
curl -fsSL https://realitykernel.dev/install.sh | sh
```

Expect `checksum ok`, then `signature ok` if `cosign` is installed (otherwise
a note that only the checksum was checked), then the package install and an
`rk doctor` report ending in `No blocking problem found.` The installer
refuses a package that does not match its checksum or signature; that is a
reason to stop, not to retry another way. Pin a version with
`sh install.sh --version X.Y.Z`. Manual install and verification:
[install.md](install.md), [releases.md](releases.md).

## 3. Start in AUDIT

```sh
sudo rk init
```

This writes `/etc/rk/policy.toml` with a profile named `agent`, in AUDIT,
launchable by the user who ran `sudo` (and by root), and applies it. With BPF LSM it
denies (in AUDIT: records) every connection and exec by default and protects
the user's secret files (`~/.ssh`, cloud credentials, `.netrc`, …). It
refuses to replace a policy that already defines profiles; `rk init --print`
shows the starter without changing anything.

## 4. Run the agent, then ask for a suggestion

```sh
rk run --profile agent -- <the agent's usual command>
```

Let it do its normal work: everything it does is allowed and recorded.
Cover the paths it really takes (a full task, not just start-up). Then:

```sh
sudo rk policy suggest --profile agent --out agent.toml
rk policy diff agent.toml
```

The suggestion is the whole policy file with the `agent` profile in ENFORCE,
allowing exactly the connections and executables seen. Its header lists what
needs a human: secret files the agent read (they stay denied), interpreters
(allowing one allows any script), public addresses that may change, raw
sockets or TUN/TAP attempts, and executables it could not locate (add
`--search DIR` for the agent's own tools). It never applies anything.

## 5. Enforce (the human's step)

Show the user `agent.toml` and the diff. Once they approve:

```sh
sudo install -m 0644 agent.toml /etc/rk/policy.toml
sudo systemctl reload rk-sensor
rk status
```

From now on, anything outside the profile fails with `EPERM` and is recorded
in the signed audit log (`rk audit tail`, `rk audit verify`). If something
legitimate breaks, go back to AUDIT (`mode = "audit"`), run the agent again,
and suggest again.

## Limits to tell the user

- Rules are by IP address until hostname rules arrive (v0.4.0,
  [ROADMAP.md](../ROADMAP.md)): a service behind a CDN can change address and
  break a learned rule.
- Reality Kernel enforces inside the kernel the agent runs on. An agent with
  a working kernel exploit is out of its reach; keep the kernel patched and,
  for hostile workloads, run it inside stronger isolation too
  ([threat-model.md](threat-model.md)).
