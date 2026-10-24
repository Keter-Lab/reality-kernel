# Design note: v0.2.0 "Adoption" — from zero to an enforced agent

Status: **ACCEPTED** (2026-10-24; scope agreed with the maintainer).
Milestone: v0.2.0. From here on, work ships as versioned milestones with
design notes named by feature; the eleven-phase engineering plan finished
with v0.1.0 (see [roadmap](../../ROADMAP.md)).

## 1. Problem

Installing Reality Kernel takes a release download, a checksum check, a
package install, then a hand-written policy in a TOML dialect most users
have never seen. A profile that is too strict breaks the agent; one that is
too loose protects nothing. Most people adopting agent tooling today work
through a coding agent, and nothing tells that agent how to do this safely.

## 2. Goal and acceptance criteria

Someone with a supported Linux host goes from nothing to an agent running
under an enforced, least-privilege profile in a few commands, and can hand
the whole procedure to a coding agent.

1. **Install:** one command downloads a release, verifies it and installs
   it. A package whose checksum does not match `SHA256SUMS` is refused.
   When `cosign` is present, the signature must be bound to this
   repository's release workflow at that tag, or the install is refused.
2. **Start:** `rk init` writes and applies a starter policy that fits the
   host: on a host without BPF-LSM it is network-only (the sensor would
   refuse anything else). It never overwrites an existing policy unless
   asked to, and keeps a backup when it does.
3. **Learn:** while the starter profile is in AUDIT, everything the agent
   does that the profile would deny is in the signed audit log.
4. **Suggest:** `rk policy suggest --profile NAME` turns that log into a
   complete ENFORCE profile and never applies it. It refuses a log that
   fails verification.
5. **Round trip:** after applying the suggestion, the connections and
   executables the agent used still work; anything unobserved is denied.
   Protected secret files stay denied, read or not: the suggestion lists
   the ones the agent read, and only a human removes a rule.
6. **Agents:** a runbook that a coding agent can follow end to end, with
   the safety rules stated: the setup agent runs ungoverned, and only a
   human approves switching to ENFORCE or loosening a profile.

## 3. Design

### 3.1 `install.sh`

A POSIX `sh` script, `public/install.sh`: one file, in the repository and
served by the website at `https://realitykernel.dev/install.sh`.

1. Resolves the version: `--version X.Y.Z`, else the tag `releases/latest`
   redirects to.
2. Detects the architecture (`amd64`/`arm64`) and the package format from
   the package manager (`dpkg` → deb, `rpm` → rpm). Anything else stops
   with the manual steps (static tarball). Inside a Kubernetes node it
   points to the Helm chart instead.
3. Downloads the package, `SHA256SUMS` and the package's `.sigstore.json`
   into a private temporary directory, and runs `sha256sum -c` on the
   package. A mismatch stops the install.
4. With `cosign` on `PATH`, runs `cosign verify-blob` with the identity
   pinned to `.../.github/workflows/release.yml@refs/tags/vX.Y.Z` and the
   GitHub OIDC issuer (the same check as `docs/releases.md`). Without it,
   it says plainly that only the checksum was checked and how to verify
   fully.
5. Installs with `dpkg -i` or `rpm -Uvh`, runs `rk doctor`, and prints the
   next step (`sudo rk init`).

`--from DIR` installs from local files (with the same checks), for offline
hosts and for CI. The script sends nothing anywhere except the downloads,
uses `set -eu`, and needs root only for the install itself.

### 3.2 `rk init`

1. Runs the same checks as `rk doctor`; a blocking finding stops it.
2. Generates the starter policy:
   - profile `agent`, **`mode = "audit"`**, `launchable_by` the invoking
     user (`SUDO_USER`), else root;
   - `network.default = "deny"` and, with BPF-LSM, `exec.default = "deny"`:
     in AUDIT every connection and exec outside the (empty) allow lists is
     recorded as `audit_would_deny`. This is the learning: no new sensor
     setting or kernel change is needed, and the records say honestly what
     ENFORCE would do;
   - with BPF-LSM, `files.deny` for the secret files that exist for that
     user (§3.4): reads of them are recorded too, so the suggestion knows
     which secrets the agent touches;
   - without BPF-LSM, network-only (`network.deny_raw_sockets = false`,
     `files.include = []`, no `[exec]`), matching what the sensor accepts.
3. Writes `/etc/rk/policy.toml` (refusing if it already defines a profile,
   unless `--force`, which first saves `policy.toml.bak.<timestamp>`) and
   applies it through the control socket, like `rk policy apply`.
4. Prints the next steps: `rk run --profile agent -- <agent command>`, then
   `rk policy suggest --profile agent`.

`rk init --print` writes the policy to stdout and touches nothing.

### 3.3 `rk policy suggest`

Reads the audit log (default `/var/log/rk/audit`), after verifying its hash
chain and signatures like `rk audit verify` (refusing on failure unless
`--no-verify`), and selects the decision records of the profile
(`policy.name`). Then:

| From | Suggested |
|---|---|
| exec records | `exec.allow` with the absolute path of each distinct executed file. Records name the file as passed to `execve` (possibly relative), and an interpreter's record carries the script's name, so files are matched by identity: the record's device and inode against the record's path when absolute, then the `PATH` directories and any `--search DIR`. A file that cannot be located is listed for the human, never guessed. Interpreters (`sh`, `bash`, `python3`, `node`, …) are allowed but called out: allowing one allows any script it runs |
| connect / sendmsg records | `network.allow` with one rule per destination address and protocol, listing the observed ports. Loopback is grouped. Public addresses are called out: a SaaS API behind a CDN changes address, and hostname rules arrive in v0.3.0 |
| file records | the `files.deny` entries from the starter profile, minus nothing: each one the agent read is listed with how often, so the human decides whether to allow it (a commented-out rule) or keep it denied |
| raw / packet socket, TUN/TAP records | never allowed automatically; listed for the human |

Output is a complete profile in `mode = "enforce"`, with `network.default`
and `exec.default` `"deny"` and a header comment giving the log range and
record counts, written to stdout or `--out FILE`. It is never applied; the
next step is `rk policy diff` then `rk policy apply`. `--since` limits the
window. A profile with no records is an error, not an empty allow list.

### 3.4 Secret files

A fixed, documented list, checked under the launching user's home:
`~/.ssh`, `~/.aws/credentials`, `~/.config/gcloud`, `~/.azure`,
`~/.kube/config`, `~/.docker/config.json`, `~/.config/gh/hosts.yml`,
`~/.netrc`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`. Only existing
paths are listed (file rules bind to file identity at apply time). This is
also the seed of the secret classes v0.4.0 builds on.

### 3.5 Agent runbook

`docs/agents.md`: the procedure as numbered commands with expected output,
written for a coding agent and readable by people, plus a short prompt to
paste into one. `public/llms.txt` points agents to it, and the README links
it. Rules it states:

- Run setup as the user, outside any governed profile. A governed agent
  cannot change its own policy (the guard denies `bpf()`; `/etc/rk` is
  root-owned).
- Propose, never decide: the agent may run `install.sh`, `rk init`, `rk run`
  and `rk policy suggest`, and show the diff. Switching to ENFORCE, and any
  later loosening, is the human's step.
- Never pipe a policy suggestion straight into `rk policy apply`.

## 4. Tests

| Test | Where | Shows |
|---|---|---|
| `adoption_round_trip` | VM suite, every kernel | init policy (`--print`) applied; an `rk run` workload connects to an allowed-to-be address, runs an executable and reads one secret file; `suggest` output applied; the same workload passes, an unobserved executable and connection are denied, an unread secret stays denied |
| `pkg_install_script` | package tests, Ubuntu and Rocky | `install.sh --from` installs the CI-built package; a tampered package is refused |
| `pkg_init_network_only` | package tests (BPF-LSM inactive) | `rk init` writes and applies a network-only profile |
| unit tests | `rk-cli` | starter-policy generation per host capability, suggestion aggregation, refusal on an unverifiable log, no overwrite without `--force` |
| `test_install_script_*` | Python | the script pins the release-workflow identity, checks before it installs, is POSIX `sh`, and (on the CI runner) refuses a tampered or unlisted package |

## 5. Not in scope

- Hostname rules (v0.3.0). Until then suggested public addresses can go
  stale, and the output says so.
- Kubernetes: `install.sh` points to the Helm chart; `suggest` works on pod
  records too, since they carry the profile name, but the walkthrough is
  for hosts.
- An MCP server: the runbook and `llms.txt` come first; a server is worth
  building once people use the runbook.
