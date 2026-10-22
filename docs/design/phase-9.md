# Design note: Phase 9 — observability and audit

Status: **ACCEPTED** (2026-10-22). All five decisions in §7 approved as recommended.
Branch: `phase-9-observability` (from `main` at e6ef3e6)
Plan reference: RealityKernel_Engineering_Plan.pdf, Phase 9 ("Operators can
see what was decided, why, and whether enforcement is really on").

## 1. Goal and acceptance criteria

Plan acceptance criteria (must pass in CI):

1. Every enforced or audit-would-deny decision appears in the audit log with
   its rule id.
2. Tampering with a stored audit batch is detected by verification.

Plan deliverables: a metrics endpoint, an audit log schema document, and a
Grafana dashboard. Added here (§5): metric names are checked against the
dashboard, emitted records are validated against the OCSF schema, and loss is
never silent.

## 2. What exists today

| Plan item | Status |
|---|---|
| Decisions reach userspace | Yes: every deny and audit-would-deny is a ring buffer record with `rule_id`, `policy_gen`, `cgroup_id`, pid/uid (`docs/abi.md`). Governed connects and sendmsgs emit every decision, allows included; exec emits denies plus a record of each committed exec; file and self-protection hooks emit denies only (corrected during the build, §8) |
| Audit log | No. The worker logs decoded events as `tracing` lines; nothing durable, structured or signed |
| Metrics | No endpoint. `rk status` shows the Phase 7 pipeline counters and heartbeat state |
| Loss accounting | Kernel: `RK_CNT_RINGBUF_DROP`. Userspace: the Phase 7 channel drop counter. Both counted, neither recorded in any log |
| Signing | `rk-signing` has an Ed25519 signer whose key is derived from a secret string, used by the legacy action proofs. Not suitable as is for audit batches (§3.3) |
| Session ↔ cgroup | `AgentRegistry::session_for_cgroup` (Phase 5) |
| Process table | Deferred to this phase (Phase 7, decision 4) |

## 3. Design

### 3.1 Pipeline

The Phase 7 worker stage gains three consumers, all behind it so the epoll
drain thread never blocks:

```
ring buffer → drain → channel → worker ─┬→ enrichment (session, process table)
                                        ├→ audit writer (OCSF JSON Lines, hash chain, signed batches)
                                        ├→ metrics (in-memory counters, /metrics)
                                        └→ OTLP exporter (optional, bounded queue, drops counted)
```

A slow or failing sink never back-pressures the kernel side. The audit writer
is the exception that matters: if it cannot write (disk full), it records the
failure in metrics and in the next batch it manages to write (§3.4), never
silently.

### 3.2 Audit records: OCSF 1.9.0

One JSON object per line, OCSF 1.9.0 (current at
schema.ocsf.io), with the `security_control`, `host` and `container`
profiles:

| Kernel event | OCSF class (`class_uid`) | `activity_id` |
|---|---|---|
| `NET_CONNECT`, `SENDMSG` | Network Activity (4001) | 1 Open; 6 Traffic for UDP sendmsg |
| `SOCK_CREATE` (raw) | Network Activity (4001) | 99 Other (`activity_name` "Socket Create") |
| `EXEC` decision | Process Activity (1007) | 1 Launch |
| `FILE_OPEN` / `FILE_DENY` | File System Activity (1001) | 14 Open, 1 Create, 4 Delete, 5 Rename, 6 Set Attributes |
| `TAMPER` | Process Activity (1007) | 99 Other, `severity_id` High |

Verdict mapping (`security_control` profile):

| Verdict | `action_id` | `disposition_id` |
|---|---|---|
| deny | 2 Denied | 2 Blocked |
| audit-would-deny | 1 Allowed | 15 Detected |
| allow (exec records) | 1 Allowed | 1 Allowed |

The decision context goes in standard fields where OCSF has them:
`policy.uid` = rule id, `policy.version` = policy generation, `policy.name`
= profile name, `actor.process` (pid, uid, executable from enrichment),
`container`/`metadata.labels` (cgroup id and path, Kubernetes pod when
bound), `actor.session.uid` = agent session. Fields with no OCSF home
(`rk.verdict`, `rk.cgroup_id`, `rk.enrichment`) go in `unmapped`.
`docs/audit.md` is the schema document: every field, its source, and an
example per class.

### 3.3 Tamper evidence: hash chain plus signed batches

- **Batches.** The writer appends records to the current segment
  (`/var/log/rk/audit/<start-time>.jsonl`) and closes a batch every second
  or every 256 records, whichever is first. A batch ends with one trailer
  line: `{"rk_batch": {seq, records, prev, hash, sig, key_id}}`.
- **Hash.** `hash = SHA-256("rk-audit-v1" ‖ prev ‖ seq ‖ the batch's record
  lines exactly as written, newlines included)`. Hashing the bytes on disk
  avoids canonicalisation entirely: the legacy signer's known problem is
  that Rust and Python serialise differently, and here nothing is
  re-serialised.
- **Chain.** `prev` is the previous batch's hash, across segment and restart
  boundaries; every segment starts with a header line naming the chain
  position and the signing key, and the first batch ever chains to zeros.
- **Signature.** Ed25519 over `hash`, with a dedicated audit key generated
  at first start from the OS RNG (`/var/lib/rk/audit.key`, 0600) and its
  public key published in `rk status`, `/metrics` (as a label on
  `rk_audit_info`) and `/var/lib/rk/audit.key.pub`. A small
  `AuditKey` type in `rk-audit` holds it (§8); the legacy secret-derived
  signer is not reused.
- **Verification.** `rk audit verify [--dir DIR] [--pubkey FILE]` recomputes every
  hash, checks every signature and the chain, and names the first bad
  batch. It detects a modified, inserted, reordered or deleted batch.

What it cannot detect on its own: an attacker with root on the host can
delete the newest batches (truncation) or steal the key and re-sign. Two
mitigations, both in this phase: the current chain head (seq and hash) is
exported in `/metrics` and `rk status`, so any external collector that
scraped it notices a rewind; and the OTLP export (§3.6) ships records off
the host as they are written. A hardware-backed key is Phase 11 material.

### 3.4 Completeness: loss is recorded, not just counted

Criterion 1 says every decision appears. Two places can lose one: the kernel
ring buffer (reserve fails when full) and the Phase 7 channel (drop on
overload). Both are already counted. Phase 9 makes them visible in the log
itself: whenever either counter advanced since the last batch, the writer
appends an OCSF Application Error record (decision 2) stating
how many decision events were lost and between which batch numbers. The
audit log is then complete by count even when it is not complete by
content, and `rk audit tail` shows them as `LOSS` lines.

To make "complete by count" checkable, the kernel counts every governed
decision: `rk_counters` grows per-hook × verdict counters (8 hook classes × 3
verdicts, per-CPU increments, no event layout change). The same counters
feed the metrics, so verdict rates are exact even for allows, which are not
emitted as events.

### 3.5 Metrics

A Prometheus endpoint served by the sensor (axum, already a workspace
dependency) on `127.0.0.1:9464/metrics` by default (`--metrics-addr`);
the Helm chart exposes it as a pod port with scrape annotations.

| Metric | Type | Labels |
|---|---|---|
| `rk_decisions_total` | counter | `hook`, `verdict` (kernel counters) |
| `rk_rule_hits_total` | counter | `rule_id`, `verdict`, `profile` (deny and audit only; from events) |
| `rk_events_lost_total` | counter | `stage` (`ringbuf`, `channel`, `otlp`) |
| `rk_decoder_errors_total` | counter | `kind` |
| `rk_policy_generation` | gauge | |
| `rk_heartbeat_age_seconds` | gauge | |
| `rk_enforcement_available` | gauge | `capability` (`network`, `lsm`) |
| `rk_audit_batches_total`, `rk_audit_write_errors_total` | counter | |
| `rk_audit_head_seq` | gauge | (with `rk_audit_info{key_id, head_hash}`) |

`rk_rule_hits_total` labels are bounded by the policy's rule count. Rule
text never becomes a label.

### 3.6 OpenTelemetry

Optional, off unless `--otlp-endpoint` is set. OTLP over HTTP/protobuf
(the `opentelemetry-otlp` crate with its `http-proto` and reqwest
features; no gRPC stack). Each agent session is a trace: the session's
trace id is derived from the session id, and `rk-agentd` passes a W3C
`TRACEPARENT` to the agent it launches, so an instrumented agent's own spans
join the same trace. Kernel decisions are span events on the session span,
carrying the same fields as the audit record. The export queue is bounded;
overflow is counted in `rk_events_lost_total{stage="otlp"}` and never
affects the audit log.

### 3.7 Process table (deferred from Phase 7)

Enrichment for `actor.process`: a bounded LRU (64 k entries) keyed by tgid,
filled from exec records (which the kernel already emits for every governed
exec) and, on a miss for a decision event only, from `/proc/<pid>/exe` and
`/proc/<pid>/stat` (ppid). Decision events are rare, so the procfs cost is
off the hot path. Enrichment is best-effort and says so: `rk.enrichment` is
`exec_record`, `procfs` or `unavailable` (the process already exited). The
decision itself (verdict, rule, cgroup, generation) always comes from the
kernel record and is exact. Exit-driven eviction is decision 4.

### 3.8 Operator commands

- `rk audit tail [-f] [-n N] [--json] [--verdict deny|audit|allow] [--session ID]`:
  human-readable lines by default.
- `rk audit verify [--dir DIR] [--pubkey FILE]`.
- `rk status` gains the audit head, key id, metrics address, loss counters
  and `enforcement available` per capability.

### 3.9 Grafana dashboard

`deploy/grafana/reality-kernel.json`: decisions by verdict and hook, top
denied rules, loss by stage, policy generation and heartbeat age, and
enforcement availability per node.

## 4. ABI and compatibility

- `enum rk_counter` grows by 24 entries (`RK_CNT_DECISION_BASE + hook * 3 +
  verdict`); `RK_CNT_MAX` changes, so the ABI layout test is updated. The
  event header and payloads are unchanged, so `RK_ABI_VERSION` stays 1.
- The new object has a different hash, so a running sensor's pins are
  replaced rather than adopted on upgrade (Phase 6 rules). Continuity across
  upgrades is Phase 10.
- Counting adds one per-CPU increment per governed decision; the Phase 7
  budget gate measures it.

## 5. Tests

| Criterion | Test |
|---|---|
| Every deny and audit-would-deny is in the audit log with its rule id | `vm:audit_every_decision_logged`: drives N network, exec and file decisions in enforce and audit mode with known rule ids; every one appears exactly once with the right `policy.uid`, verdict mapping and session; the kernel decision counters match the record count |
| Loss is recorded | `vm:audit_records_loss`: with the Phase 6 `rk_emitfail` object, decisions still count in the kernel, and the log contains loss records whose totals match |
| Tampering is detected | unit: `audit_verify_detects_modified_record`, `_deleted_batch`, `_reordered_batches`, `_bad_signature`, `_inserted_batch`; `vm:audit_tamper_detected`: flips one byte in a stored segment, `rk audit verify` fails naming that batch |
| Records are valid OCSF 1.9.0 | unit: `ocsf_records_validate`, against a vendored subset of the 1.9.0 class definitions (required attributes, enum values) |
| Metrics are served and move | `vm:metrics_endpoint_serves`: scrape before and after a deny; `rk_decisions_total{verdict="deny"}` and the rule hit counter increase; `rk_enforcement_available` matches the kernel |
| Dashboard matches the exporter | py: `test_dashboard_metrics_exist` |
| Process table | unit: LRU bound, exec-record fill, procfs fallback, `unavailable` marking |
| OTLP export | unit: span events against an in-process OTLP/HTTP collector; queue overflow counted |

All of them go into `tests/traceability.toml` under phase 9.

## 6. Out of scope

Hardware-backed audit keys and remote attestation of the log (Phase 11).
SIEM-specific integrations beyond OCSF and OTLP. Upgrade continuity (Phase
10).

## 7. Decisions requested from the reviewer

1. **OCSF 1.9.0 as the audit schema.** Recommended: it is the plan's
   suggestion, vendor-neutral, and ingested natively by the major SIEMs
   and security lakes. The alternative is a bespoke schema with an OCSF
   mapping later.
2. **Loss records use OCSF Application Error (6008) with the counts in
   `unmapped`.** Recommended: it is the closest class for "the producer lost
   data", and it keeps loss in the same stream as the decisions. The
   alternative is a separate loss file, which a log shipper could miss.
3. **Kernel decision counters per hook × verdict** (§3.4). Recommended: it
   makes "complete by count" checkable and the verdict metrics exact, for
   one per-CPU increment per decision. The alternative is metrics from
   events only, which cannot count allows or detect loss independently.
4. **Process table eviction by LRU, no new exit program.** Recommended: an
   exit tracepoint would fire for every process on the host, governed or
   not, to save a few kilobytes of LRU; procfs fallback covers forked
   children. The alternative is a `sched_process_exit` program emitting
   `RK_EV_EXIT` for governed cgroups.
5. **OTLP over HTTP/protobuf only, no gRPC exporter.** Recommended: it
   keeps the gRPC stack (today's Dependabot alerts) out of the sensor, and
   every OTLP collector accepts HTTP. The alternative adds tonic.

## 8. Implementation notes (recorded during the build)

- **Crate.** The record format, hash chain, writer, verifier, signing key
  and `rk audit tail` rendering live in a new crate, `rk-audit`, shared by
  the sensor (writer) and `rk` (tail, verify). The audit key is
  `rk_audit::key::AuditKey` rather than an addition to `rk-signing`, which
  keeps the legacy signer untouched.
- **What is logged.** Every deny, audit-would-deny and tamper decision.
  Allows (network allows, committed execs) only with `--audit-allow`, since
  governed connects emit every decision. Committed exec records always feed
  the process table.
- **Loss stages.** `rk_events_lost_total{stage}` is `kernel` (ring buffer
  drops plus scratch misses, which is how emission fails in
  `rk_emitfail.bpf.o`), `channel` and `otlp`. Losses already counted when
  the sensor starts (adopted pins) are the baseline, not new loss records.
- **OTLP.** OTLP over HTTP with the JSON encoding the OTLP specification
  defines, built directly rather than through the `opentelemetry-otlp`
  crate: fewer dependencies and no SDK API churn. The sensor uses `reqwest`
  without a TLS stack, so the static musl build stays pure Rust; the
  endpoint must be plain `http://` to a node-local collector, which owns
  TLS to the backend (an `https://` endpoint is refused at startup). Each
  decision is a zero-duration span whose parent is the session span, rather
  than a span event on it: spans are exported as decisions happen, and a
  session span is never "finished" by the sensor.
- **Kubernetes.** The chart mounts the audit directory and the key from the
  host and exposes the metrics port with scrape annotations (`audit.*`,
  `metrics.*`, `otlp.endpoint` values).
