# Policy language reference

Reality Kernel policy is a single TOML file, read by `rk-sensor` at start-up
(`/etc/rk/policy.toml` by default, or `--policy FILE`) and re-applied on
`SIGHUP` or with `rk policy apply`. It is parsed and compiled by
`rk-policy::net` into BPF map contents. Decisions are made in the kernel.

Every apply is **atomic**: the kernel sees either the old policy or the new one,
never a mix (ADR-0005). A file that fails to parse, compile or resolve is
rejected as a whole, and the active policy stays in place.

## Structure

```toml
[profiles.<name>]          # one table per profile
mode = "enforce"           # required: "enforce" | "audit"
launchable_by = ["root"]   # who may `rk run` agents under it

[profiles.<name>.network]  # optional; defaults shown below
[profiles.<name>.exec]     # optional; absent = exec policy inactive
[profiles.<name>.files]    # optional; defaults shown below

[[bindings]]               # static cgroup -> profile bindings (optional)
cgroup = "rk.slice/<name>"
profile = "<name>"

[kubernetes.namespaces.<ns>]  # namespaces that must be governed (optional)
default = "<name>"
allowed = ["<name>"]
```

Unknown keys are errors at every level, so a typo can't silently turn into a
missing protection.

## Profiles

| Key | Type | Default | Meaning |
|---|---|---|---|
| `mode` | `"enforce"` \| `"audit"` | required | `enforce` denies with `EPERM`; `audit` allows but reports `audit-would-deny` events with the same rule ids |
| `launchable_by` | list | `["root"]` | Who may start agents under this profile with `rk run`: `root`, `user:NAME`, `group:NAME`, `uid:N`, `gid:N`. An empty list means nobody |

**Names:** letters, digits, `-`, `_` and `.`, at most 64 characters. The name
`quarantine` is reserved (see "Built-in profiles").

Profile ids are allocated once and stay stable across reloads, so bindings
never need rewriting when the policy changes.

## `network` (Phase 2)

| Key | Type | Default | Meaning |
|---|---|---|---|
| `default` | `"allow"` \| `"deny"` | `"deny"` | Verdict when no rule matches |
| `include` | list of names | `["cloud-metadata"]` | Built-in deny lists. Remove only explicitly (`include = []`) |
| `nat64_equivalence` | bool | `true` | Also deny the `64:ff9b::/96` form of every IPv4 deny rule |
| `deny_raw_sockets` | bool | `true` | Deny the packet-injection surfaces that would bypass every network hook: raw (inet) and packet sockets, and creating or attaching to TUN/TAP devices (Phase 16). The name predates TUN/TAP and is kept for compatibility |
| `allow`, `deny` | list of rules | `[]` | See below |

Rule fields:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `cidr` | string | required | `a.b.c.d/n`, `x::y/n` or a bare address. Host bits must be zero |
| `ports` | list | all ports | `"443"`, `"8000-8100"`, `"*"` |
| `proto` | list | any | `"tcp"`, `"udp"`, `"other"`, `"any"` |

**Semantics:**
- **Deny rules always win** over allow rules.
- Within the deny rules, and then within the allow rules, the most specific
  matching prefix wins; ties go to file order.
- If nothing matches, `default` applies.
- IPv4 is handled as IPv4-mapped IPv6, so one rule set covers both families.
  As a consequence **`::/0` also covers IPv4**.
- One address range may be covered by at most 8 distinct port/protocol ranges,
  counting enclosing prefixes. More is a compile error that names the prefix.

```toml
[profiles.research-agent]
mode = "enforce"
network.default = "deny"

[[profiles.research-agent.network.allow]]
cidr = "10.20.0.0/16"
ports = ["443"]
proto = ["tcp"]

[[profiles.research-agent.network.deny]]
cidr = "10.20.5.0/24"
```

## `exec` (Phase 3)

Without an `exec` section, every exec is allowed, so profiles written before
Phase 3 keep working. With one, the profile is in allowlist mode by default.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `default` | `"allow"` \| `"deny"` | `"deny"` | Verdict for executables not in the allowlist |
| `allow` | list of absolute paths | `[]` | Executables, resolved to (device, inode) at apply time; symlinks followed |
| `allow_dirs` | list of absolute paths | `[]` | Every regular file directly inside, captured when the policy is applied (at most 4096 per profile). New files need a reload |
| `allow_unlinked` | bool | `false` | Allow executing files with no links (memfd, deleted while open). Every such exec is flagged in events |
| `require_hash` | bool | `false` | Not supported yet. A profile setting it is refused |

**Semantics:**
- Decisions are made on the file's identity, never its path. For a script, the
  script and its interpreter must **both** be allowed.
- A missing path is an apply error.
- A file replaced after apply (for example by `rename`) has a new identity and
  is denied until a reload re-resolves it.
- Allowing an interpreter allows whatever it runs. Script-level control belongs
  to the userspace engine.

## `files` (Phase 4)

| Key | Type | Default | Meaning |
|---|---|---|---|
| `include` | list of names | `["credentials"]` | Built-in file deny lists. Remove only explicitly (`include = []`) |
| `protect_exec_allowlist` | bool | `true` with an `exec` section, otherwise `false` | Deny write, truncate, delete, rename, link and setattr on every allow-listed executable |
| `deny` | list of rules | `[]` | See below |

Rule fields:

| Key | Type | Default | Meaning |
|---|---|---|---|
| `path` | absolute path | required | Resolved to (device, inode) at apply time; symlinks followed |
| `subtree` | bool | `false` | For a directory: also covers everything beneath it |
| `access` | list | required | `read`, `write`, `exec`, `create`, `delete`, `rename`, `truncate`, `link`, `setattr`, `all` |

**Semantics:**
- Every way of naming the same file (hard links, bind mounts, symlinks,
  relative paths, `/proc/self/fd`) gets the same verdict.
- Subtree rules are found by walking up to 32 parent directories. Deeper
  nesting **fails closed** in `enforce` mode.
- Several rules on the same file merge: access masks are combined, and the
  first rule's id is reported.
- An explicit path that doesn't exist fails the apply. A built-in list entry
  that's missing or inaccessible on the host is skipped and reported in the
  apply result (`skipped_files`) and the daemon log.

```toml
[[profiles.research-agent.files.deny]]
path = "/home/agent/.ssh"
subtree = true
access = ["all"]
```

## `bindings`

Static bindings attach an existing or to-be-created cgroup under `rk.slice/`
to a profile. Agents started with `rk run` are bound automatically and need no
entry here.

| Key | Type | Meaning |
|---|---|---|
| `cgroup` | string | Path relative to `/sys/fs/cgroup`. Must be under `rk.slice/`, where the hooks are attached, with plain name segments only |
| `profile` | string | An existing profile |

A cgroup may be bound only once. A cgroup bound to a profile that has never
been applied fails closed (enforce, deny everything).

## Built-in lists and profiles

| Name | Kind | Contents |
|---|---|---|
| `cloud-metadata` | network deny list | Cloud instance-metadata and credential endpoints (AWS, GCP, Azure, Alibaba, Tencent and others), each with a cited source. See `deploy/policy/cloud-metadata.toml` |
| `credentials` | file deny list | `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`, `/etc/sudoers.d/`, `/etc/ssh/`, `/root/.ssh/`. See `deploy/policy/credentials.toml` |
| `quarantine` | profile | Enforce mode: no exec, no network, no raw sockets. An agent is moved into it with one atomic update (`PolicyEngine::quarantine`). It can't be redefined or launched into |

## `kubernetes` (Phase 5b)

A pod selects the profile for all its containers, init containers and
sidecars included, with the annotation `realitykernel.dev/profile: NAME`.
`realitykernel.dev/session: ID` links its events to a session. Binding happens
in NRI `StartContainer`, after the container's process exists and before its
command runs. If the binding fails, the container doesn't start.

Any profile restricts more than none, so on an ordinary namespace an annotation
is honoured as is. A namespace listed here is always governed:

```toml
[kubernetes.namespaces.agents]
default = "research-agent"             # pods without an annotation
allowed = ["research-agent", "strict"]  # what an annotation may name
```

| Key | Default | Meaning |
|---|---|---|
| `default` | none | Profile for pods without an annotation. With no default, such pods are refused |
| `allowed` | `[default]` | Profiles an annotation may name; anything else is refused. Must contain `default` |

Unknown profiles and `quarantine` are refused in every namespace. Namespace
names follow Kubernetes rules (lowercase letters, digits, `-`, at most 63).
With the Helm chart, set these through the `namespaces` value, which the NRI
plugin also reads.

## Kernels without BPF LSM

Exec rules, file rules and raw-socket and TUN/TAP denial run in BPF-LSM programs. Where
`bpf` isn't in `/sys/kernel/security/lsm`, those programs would load but never
run, so `rk-sensor` refuses any profile that uses them, instead of reporting
protection that doesn't exist. `rk status` shows `bpf_lsm: inactive`. Either
boot with `lsm=...,bpf`, or make the profile network-only:

```toml
[profiles.web]
mode = "enforce"
network.deny_raw_sockets = false   # acknowledges raw sockets are not blocked
[profiles.web.files]
include = []                       # and no [exec] section
```

Raw sockets and TUN/TAP devices bypass connect rules, so also drop
`CAP_NET_RAW` from such workloads and give their users no persistent TUN/TAP
device.

## Rolling out a profile

`mode` has no default: a profile states whether it enforces. The recommended
rollout (ADR-0011):

`rk init` and `rk policy suggest` automate steps 1 to 3
([agents.md](agents.md)); by hand:

1. Write the profile with `mode = "audit"` and bind it. Nothing is blocked.
2. Watch what it would deny: `rk audit tail --verdict audit`, or
   `rk_rule_hits_total{verdict="audit_would_deny"}` in the metrics.
3. Adjust the rules until only the actions you mean to block appear.
4. Switch to `mode = "enforce"` and apply. The switch is atomic, like every
   apply.

## Operations

`rk-sensor` reads the policy file at start and on `SIGHUP`, and with
`--watch-policy` whenever its content changes (the Helm chart uses this for
ConfigMap updates). Every route uses the same atomic apply.

| Command | Effect |
|---|---|
| `rk policy apply FILE` | Atomic apply |
| `rk policy apply FILE --dry-run` | Parse, compile and resolve, then show the changes. Touches neither the kernel nor the filesystem, and fails exactly where an apply would |
| `rk policy diff FILE` | Show the changes from the active policy, line by line |
| `rk policy rollback` | Re-apply the previous policy atomically. Running it twice returns to the newer policy |

An apply that would remove a profile used by a running agent is refused.

## Errors

Every error names its location, for example
`profile `agent`, network.deny[2] 10.0.0.1/8: `10.0.0.1/8` has host bits set; did you mean `10.0.0.0/8`?`.
The policy that is already active is never affected by a rejected file.
