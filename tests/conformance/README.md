# Policy conformance corpus

docs/design/phase-8.md §3.2. Each `*.toml` file is one case: a policy with
one profile named `case`, one or more operations, and the verdict each must
get. The same files are checked by two engines:

- **userspace**: `rk-policy`'s reference evaluator (`connect` operations;
  `cargo test -p rk-policy conformance`);
- **kernel**: `rk-integration --conformance` in every kernel VM, which binds
  `case` to a cgroup and performs each operation for real.

A case passes only if both agree with `expect`. To add a regression case, add
a file; no code changes.

```toml
name = "short_snake_case"
description = "what this pins down"
setup = ["exec:/run/rk-conf/tool", "file:/run/rk-conf/secret"]  # optional fixtures
policy = """
[profiles.case]
mode = "enforce"
...
"""

[[op]]
kind = "connect"        # connect | exec | open
target = "10.99.0.5:80" # addr:port (connect) or path (exec, open)
proto = "udp"           # connect: udp | tcp (tcp only with expect = "deny")
access = "r"            # open: r | w | rw | o_trunc
expect = "deny"         # allow | deny | audit (audit = runs, reported as would-deny)
```

Addresses live in `10.99.0.0/24` and `fd99::/64`, which the kernel runner adds
to `lo`; other destinations are only ever expected to be denied, or allowed
with any non-EPERM error (unroutable is fine).
