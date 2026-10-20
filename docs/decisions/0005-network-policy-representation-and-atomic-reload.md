# 0005. Network policy representation and atomic reload

Date: 2026-10-20 · Status: Accepted

## Context
Phase 2 requires per-agent egress policy decided in the kernel. The plan requires
that a policy reload is never half-applied, and that one source of truth defines
policy semantics for both the kernel and userspace.

## Decision
- **Format:** TOML (`serde_yaml` is unmaintained), parsed by `rk-policy::net`
  into a validated IR. Every rule has a unique id that is reported in kernel
  events.
- **Kernel representation:** two LPM tries (`rk_net_deny`, `rk_net_allow`). The
  key is `{prefixlen = 32 + cidr, scope = slot << 31 | profile, addr[16]}`, and
  IPv4 is stored IPv4-mapped. Deny is consulted first and always wins.
- **Flattening:** each trie entry carries its own port/protocol ranges followed
  by those of every covering shorter prefix, most specific first, at most 8. A
  single longest-prefix lookup therefore reproduces the reference semantics.
  `rk-policy::net::evaluate` is the reference, and a property test checks that
  the compiled lookup always agrees with it.
- **Atomic reload:** two generation slots. The sensor writes the inactive slot,
  then flips `rk_active_slot` with a single 4-byte array update, which is the
  commit point. A retired slot is cleared only at the next apply, at least 1 s
  after the flip. A failed apply never touches the active slot.
- **Stable profile ids** across reloads, so cgroup bindings are rewritten only
  when they change.
- **Fail closed:** a cgroup bound to a profile whose slot entry was never written
  is treated as ENFORCE with default deny.
- **Defaults:** the `cloud-metadata` deny list is included in every profile
  unless removed explicitly. NAT64 (`64:ff9b::/96`) equivalents of IPv4 deny
  rules are generated. Raw and packet sockets are denied by default.

## Consequences
- More than 8 distinct ranges covering one prefix is a compile error with a
  clear message, rather than silently wrong behaviour.
- `::/0` also covers IPv4 (stored mapped). This is documented in the policy
  reference (to be written with the Phase 2 integration tests).
- Hostname rules need a DNS-aware component and are out of scope (a future ADR).
