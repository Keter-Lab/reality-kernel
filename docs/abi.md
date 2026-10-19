# Kernel/userspace ABI

Source of truth: `rk-bpf/include/rk_abi.h`. Rust types are generated from it by
bindgen at build time (`rk-ebpf-common/build.rs`), so the two sides cannot drift.

## Record format

Every record on `events_ringbuf` is:

| Offset | Size | Field |
|---|---|---|
| 0 | 48 | `struct rk_hdr` |
| 48 | 4 | `payload_len` (≤ `RK_SCRATCH_PAYLOAD_MAX` = 2048) |
| 52 | 4 | `_reserved`, must be 0 |
| 56 | `payload_len` | payload |

The record length must equal `56 + payload_len` exactly.

### `rk_hdr` (48 bytes, no implicit padding)

| Offset | Field | Notes |
|---|---|---|
| 0 | `ts_ns` | `bpf_ktime_get_boot_ns()` |
| 8 | `cgroup_id` | cgroup v2 id (the cgroup directory's inode number); 0 if the hook cannot read it |
| 16 | `policy_gen` | policy generation that made the decision; 0 if ungoverned |
| 24 | `pid`, `tgid` | 0 if the hook type cannot read them |
| 32 | `uid`, `gid` | |
| 40 | `type` | `enum rk_event_type` |
| 42 | `verdict` | `enum rk_verdict`: allow, deny, audit-would-deny |
| 43 | `abi` | `RK_ABI_VERSION` (currently 1) |
| 44 | `rule_id` | matching rule; 0 = default |

## Encoding rules

- Integers are in host byte order. IP addresses are raw network-order bytes;
  IPv4 is stored IPv4-mapped (`::ffff:a.b.c.d`). Ports are host order.
- `file_dev` uses the kernel's internal `dev_t` encoding (`MAJOR << 20 | MINOR`),
  not the userspace `st_dev` encoding.
- Strings follow the fixed body as `str_count` entries of `[u16 len][len bytes]`,
  with no NUL terminator. They are not guaranteed to be UTF-8 and are used for
  logs only; decisions are made on kernel objects.
- Bodies without trailing strings must end exactly at the end of the record.

## Decoder guarantees

`rk_sensor::decoder::decode` rejects, with a typed error and a counter per
error kind: short records, ABI mismatch, non-zero reserved field, oversized or
mismatched lengths, unknown event types and verdicts, short bodies, truncated
or over-counted strings, and trailing bytes. It contains no `unsafe` and is
fuzzed for 10 minutes in CI.

## Changing the ABI

Any change to a struct layout bumps `RK_ABI_VERSION`. Adding a new event type
or enum value does not. Both the C `_Static_assert`s and the Rust assertions in
`rk-ebpf-common/src/lib.rs` must be updated in the same commit.
