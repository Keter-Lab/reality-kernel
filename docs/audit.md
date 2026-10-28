# Audit log

Every enforced deny, audit-would-deny and self-protection decision the
kernel makes for a governed workload is written to a local, tamper-evident
audit log as an [OCSF 1.9.0](https://schema.ocsf.io/1.9.0/) record. This
page is the schema and format reference. Design:
[docs/design/phase-9.md](design/phase-9.md).

## Where it is

| | Default | Option |
|---|---|---|
| Segment files | `/var/log/rk/audit/<first-batch>.jsonl` | `--audit-dir DIR` (`off` disables) |
| Signing key | `/var/lib/rk/audit.key` (0600), public half in `audit.key.pub` | `--audit-key FILE` |
| Allowed decisions too | no | `--audit-allow` |

In Kubernetes the chart keeps both on the host (`audit.hostPath`,
`audit.keyHostPath`), so the chain continues across pod replacements.

The audit log never gates enforcement: if it cannot be opened or written,
the sensor keeps enforcing, logs the error, and reports it in `rk status`
(`audit_log no`) and in `rk_audit_write_errors_total`.

## Reading and verifying

```console
$ rk audit tail -n 5
2026-10-22T12:00:01.204Z DENY   Open 10.99.0.1:80/udp  rule 3 (agent) gen 7  pid 4312 /usr/bin/python3  session s-81
$ rk audit tail -f --verdict deny --session s-81
$ rk audit tail --json | jq .
$ rk audit verify --pubkey /var/lib/rk/audit.key.pub
audit log /var/log/rk/audit: 2 segments, 412 batches, 9120 records (0 recovered batches)
chain: batches 0..411, head 4c1d9a0be2f7a311, signed by 8f2c51d07a6e9b13
head: 412:4c1d9a0be2f7a3115e0b7d2c94a1f6e83b2d0c9f7a6e5d4c3b2a1908f7e6d5c4
VERIFIED
$ rk audit verify --pubkey /var/lib/rk/audit.key.pub --head 412:4c1d9a0be2f7a311...
```

`rk audit verify` exits 0 when everything verifies, 2 when it finds
evidence of tampering (each problem names the segment, line and batch), and
1 when it cannot run. It fails (exit 2):

- on an empty audit directory, or one with no batch that verifies (headers
  are not signed, so headers alone prove nothing);
- when a segment was moved aside as `<segment>.jsonl.forged` (below);
- when the chain does not start at batch 0 (the oldest segments were
  removed), unless you pass `--allow-pruned` because you removed them;
- when the signing key changes between segments. With `--pubkey`, every
  segment must be signed by a key given there; repeat `--pubkey` with the
  old and the new key to accept a key change you made. Without `--pubkey`
  the key named in the oldest segment is taken on trust (with a warning) and
  any change fails;
- with `--head SEQ:HASH`, when the chain does not pass through that head.

The files alone can only prove that they are consistent with themselves and
with the key they name. Trust needs two things recorded off the host:

- **the public key**, `/var/lib/rk/audit.key.pub`, copied when the sensor
  first starts, and passed with `--pubkey`;
- **the chain head**, recorded from time to time: the sensor exports it as
  `rk_audit_head_seq` and the `head_hash` label of `rk_audit_info`, and
  `rk audit verify` prints it as `head: SEQ:HASH`, only when the log
  verifies. `--head SEQ:HASH` (the
  full 64-digit hash) then proves the chain still reaches it, so removing
  the newest batches, or rewriting the chain up to that point, fails.

The sensor never rewrites a published `audit.key.pub`: if it does not match
the private key, or exists without it (for example after `dpkg --purge` and
a reinstall), the sensor refuses to open the audit log and says why. If the
key change is intended, move the old public key aside (keep it: it verifies
the older segments) and restart the sensor; then verify with both keys. The
sensor also refuses a key owned by another user, readable by group or others,
or in a directory others can write.

The sensor's own log (journald under systemd) carries operational messages
only. A line per decision is available for debugging with
`RUST_LOG=info,rk_sensor::pipeline=debug`; it is off by default because the
audit log already records every decision and, on a busy host, that many lines
would exceed journald's rate limit.

## File format

A segment is JSON Lines. It starts with a header line, then holds records,
each batch closed by a trailer line:

```json
{"rk_segment":{"seq":12,"prev":"<64 hex>","key_id":"8f2c51d07a6e9b13","public_key":"<64 hex>"}}
{ ...OCSF record... }
{ ...OCSF record... }
{"rk_batch":{"seq":12,"records":2,"prev":"<64 hex>","hash":"<64 hex>","sig":"<128 hex>","key_id":"8f2c51d07a6e9b13","v":2}}
```

- A batch is sealed every second or every 256 records, whichever comes
  first, and fsynced when sealed.
- `hash = SHA-256("rk-audit-v2" ‖ prev ‖ seq as 8 bytes big-endian ‖
  records as 8 bytes big-endian ‖ the batch's record lines exactly as
  written, newlines included)`. Trailers written by rk 0.2.0 and earlier
  have no `v` and use `"rk-audit-v1"` without the record count; they still
  verify. Changing a trailer's `v` changes the hash its signature must
  match, so it fails verification.
- `sig` is the Ed25519 signature of `hash` by the audit key; `key_id` is the
  first 8 bytes of SHA-256 of the public key.
- `prev` is the previous batch's hash, across segments and restarts; the
  first batch ever chains to 32 zero bytes.
- Hashing the bytes as written means nothing is re-serialised before
  hashing, so there is no canonical form to disagree on.

On start the sensor continues the chain from the last sealed batch of the
newest segment. Anything after it (a torn last line, the open batch of a run
that crashed, or lines someone else appended) is moved to
`<segment>.jsonl.unsealed` next to the segment, unsigned, and the sensor
logs a warning: it never signs records it did not write itself. Those
records are lost from the verified chain (at most one batch interval of a
crashed run); the file is kept for inspection and `rk audit verify` lists
it as a warning.

Recovery trusts only what verification would accept: the header on the
segment's first line, then batches whose sequence, chaining, record count,
hash and signature verify. A crash leaves only records and a torn line; a
header, trailer or malformed control line after the last batch that
verifies was written by someone else. Then nothing is cut: the segment is
left as it is, so `rk audit verify` reports the forged line, and the chain
continues in a new segment from the last batch that verified. A segment in
which no batch verified is moved aside whole to `<segment>.jsonl.forged`,
which `rk audit verify` reports as a problem.

Logs written by rk 0.2.0 and earlier may hold batches marked
`"recovered": true`, sealed at startup from such leftovers; they still
verify, with a warning that their records are not authenticated. In those
logs the marker sits outside the signed hash, so someone who can write the
log can remove it undetected; current batches can carry no such marker.

### What verification detects, and what it cannot

Detected: a modified, inserted, removed or reordered record or batch, a
removed segment in the middle of the chain, removed oldest segments (unless
`--allow-pruned`), a segment signed by a key that was not pinned or that
differs from the rest of the log, a forged batch, an empty log, and, with
`--head`, removal of the newest batches or a chain rewritten up to the
recorded head.

Not detectable from the files alone: which key and which chain are
authoritative. Someone who can write the audit directory and replaces the
whole log, signed with a key of their own, produces files that are
consistent with themselves; only the pinned public key and a recorded head
(above) catch that. Removal of batches newer than the last recorded head,
and re-signing with a stolen key (root on the host can read it), are not
detectable at all; the OTLP export, which ships records off the host as
they happen, is the mitigation for both.

## Records

All records carry `metadata` (`version` 1.9.0, `product` Reality Kernel,
`profiles` `security_control` and `host`), `time` (ms since the epoch, from
the kernel's boot-time stamp), `device.hostname` and `severity_id`.

| Kernel event | `class_uid` | `activity_id` |
|---|---|---|
| connect | 4001 Network Activity | 1 Open |
| unconnected UDP sendmsg | 4001 | 6 Traffic |
| raw or packet socket | 4001 | 99 "Socket Create" |
| TUN/TAP create / attach / queue re-attach | 4001 | 99 "TUN/TAP Create" / "TUN/TAP Attach" / "TUN/TAP Attach Queue" (`unmapped.rk.tun_op`) |
| exec | 1007 Process Activity | 1 Launch |
| file open / unlink / rename / link / create / setattr | 1001 File System Activity | 14 / 4 / 5 / 1 / 1 / 6 |
| self-protection | 1007 | 99 "Tamper" (`severity_id` 4 High) |
| lost events | 6008 Application Error | 1 General Error |

| Verdict | `action_id` | `disposition_id` | `severity_id` |
|---|---|---|---|
| deny | 2 Denied | 2 Blocked | 3 Medium |
| audit-would-deny | 1 Allowed | 15 Detected | 2 Low |
| allow (`--audit-allow`) | 1 Allowed | 1 Allowed | 1 Informational |

### Fields

| Field | Source |
|---|---|
| `policy.uid` | rule id; `0` when the profile default decided, `4294967295` when only a stale heartbeat denied |
| `policy.version` | policy generation that made the decision |
| `policy.name` | profile: the rule's profile, else the cgroup's bound profile |
| `policy.desc` | where the rule is in the policy text |
| `actor.process.pid` / `tid` | kernel tgid / pid |
| `actor.process.user.uid` | kernel uid |
| `actor.process.file.path`, `name` | process table (see `unmapped.rk.enrichment`) |
| `actor.process.parent_process.pid` | procfs |
| `actor.session.uid` | agent session of the cgroup (`rk run --session`, pod annotation) |
| `dst_endpoint.ip`, `port` | connect/sendmsg target (IPv4-mapped addresses shown as IPv4) |
| `connection_info.protocol_num` | IPPROTO_* |
| `process` (exec) | the executable that was run or refused, `cmd_line` for committed execs |
| `file.name`, `path` | the name the kernel reported (a path when it is absolute) |
| `unmapped.rk.verdict` | `deny`, `audit_would_deny`, `allow` |
| `unmapped.rk.rule_id`, `policy_gen`, `cgroup_id`, `gid` | from the kernel record |
| `unmapped.rk.enrichment` | `exec_record`, `procfs` or `unavailable` |
| `unmapped.rk.file_dev`, `file_ino` | exec and file identity (kernel `dev_t`) |
| `unmapped.rk.access` | file access requested: `read`, `write`, `exec`, `create`, `delete`, `rename`, `truncate`, `link`, `setattr` |
| `unmapped.rk.lost.kernel`, `.channel` | Application Error only: events lost in the kernel (ring buffer full, emission failed) and in the userspace pipeline |

Enrichment is best effort: the process may have exited before the record
was written. The decision fields (verdict, rule, generation, cgroup) always
come from the kernel record.

### Completeness

The kernel counts every governed decision by hook and verdict, whether or
not its event reaches userspace (`rk_decisions_total`). When an event is
lost, the next batch carries an Application Error record with the count, so
the log is complete by count even when it is not complete by content. Losses
from before the sensor started (counters of an adopted pin set) are the
baseline and are not recorded again.

## Example

```json
{"action":"Denied","action_id":2,"activity_id":1,"activity_name":"Open","actor":{"process":{"file":{"name":"python3","path":"/usr/bin/python3","type":"Executable File","type_id":8},"name":"python3","parent_process":{"pid":4300},"pid":4312,"session":{"uid":"s-81"},"tid":4312,"user":{"uid":"1000"}},"session":{"uid":"s-81"},"user":{"uid":"1000"}},"category_name":"Network Activity","category_uid":4,"class_name":"Network Activity","class_uid":4001,"connection_info":{"direction":"Outbound","direction_id":2,"protocol_name":"udp","protocol_num":17,"protocol_ver_id":4},"device":{"hostname":"node-a","type":"Server","type_id":1},"disposition":"Blocked","disposition_id":2,"dst_endpoint":{"ip":"10.99.0.1","port":80},"metadata":{"log_name":"audit","product":{"name":"Reality Kernel","vendor_name":"Keter Labs","version":"0.1.0"},"profiles":["security_control","host"],"version":"1.9.0"},"policy":{"desc":"network.deny[0] 10.99.0.1/32","name":"agent","uid":"3","version":"7"},"severity":"Medium","severity_id":3,"status":"Failure","status_id":2,"time":1792670401204,"type_name":"Network Activity: Open","type_uid":400101,"unmapped":{"rk":{"cgroup_id":9123,"enrichment":"exec_record","gid":1000,"policy_gen":7,"rule_id":3,"verdict":"deny"}}}
```
