#!/usr/bin/env bash
# Runs inside the vmtest guest (host rootfs shared read-only; /run is tmpfs).
#
#   selftest.sh <rk-sensor binary> <bpf object dir> <bpftool binary> [rk-integration] [rk]
#
# 1. rk-sensor --selftest: loads every embedded program, runs the functional
#    checks and prints the JSON report between markers for the host to extract.
# 2. Negative control: the kernel verifier must reject reject_infinite_loop.
# 3. Positive control: bpftool must load rk_selftest.bpf.o, so a broken bpftool
#    can never make step 2 pass.
# 4. rk-integration: the verdict suite, then (with rk) the Phase 5 agent suite.
# Exits non-zero if any step fails.
set -u

sensor="$1"
bpf_dir="$2"
bpftool="$3"
integration="${4:-}"
rk_cli="${5:-}"
rc=0

mountpoint -q /sys/kernel/security || mount -t securityfs securityfs /sys/kernel/security
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
export TMPDIR=/run

echo "kernel: $(uname -r)"
echo "cmdline: $(cat /proc/cmdline)"
echo "active LSMs: $(cat /sys/kernel/security/lsm 2>/dev/null || echo unreadable)"

echo "===RK_SELFTEST_BEGIN==="
"$sensor" --selftest
selftest_rc=$?
echo "===RK_SELFTEST_END==="
echo "selftest exit code: $selftest_rc"
[ "$selftest_rc" -eq 0 ] || rc=1

neg_log="$("$bpftool" prog load "$bpf_dir/reject_infinite_loop.bpf.o" /sys/fs/bpf/rk_negative 2>&1)"
neg_rc=$?
if [ "$neg_rc" -eq 0 ]; then
    echo "FAIL negative control: the unbounded loop was accepted; the verifier gate is broken"
    rc=1
elif grep -Eqi 'infinite loop|back-edge|too large|too complex' <<<"$neg_log"; then
    echo "PASS negative control: rejected by the verifier"
    grep -Ei 'infinite loop|back-edge|too large|too complex' <<<"$neg_log" | head -3
else
    echo "FAIL negative control: load failed for a reason other than the verifier:"
    tail -n 20 <<<"$neg_log"
    rc=1
fi

if pos_log="$("$bpftool" prog loadall "$bpf_dir/rk_selftest.bpf.o" /sys/fs/bpf/rk_positive 2>&1)"; then
    echo "PASS positive control: bpftool loaded rk_selftest.bpf.o"
else
    echo "FAIL positive control: bpftool could not load rk_selftest.bpf.o:"
    tail -n 40 <<<"$pos_log"
    rc=1
fi

if [ -n "$integration" ]; then
    if [ -x "$integration" ]; then
        # rk-integration prints its own report markers on stdout; its per-test
        # progress goes to stderr, merged here so the CI log shows where a
        # run stopped.
        "$integration" 2>&1
        integ_rc=$?
        echo "rk-integration exit code: $integ_rc"
        [ "$integ_rc" -eq 0 ] || rc=1

        # Phase 8: the policy conformance corpus, checked by the real kernel
        # (the same files rk-policy checks in userspace).
        "$integration" --conformance "$(dirname "$0")/../conformance" 2>&1
        conf_rc=$?
        echo "conformance exit code: $conf_rc"
        [ "$conf_rc" -eq 0 ] || rc=1
    else
        echo "FAIL integration binary given but not executable: $integration"
        rc=1
    fi
fi

if [ -n "$rk_cli" ]; then
    # Phase 5: the daemon, driven through the rk CLI. Runs after
    # rk-integration has exited so only the daemon's programs are attached.
    if [ -x "$integration" ] && [ -x "$rk_cli" ]; then
        "$integration" --agent-suite "$sensor" "$rk_cli" "$bpftool" 2>&1
        agent_rc=$?
        echo "agent suite exit code: $agent_rc"
        [ "$agent_rc" -eq 0 ] || rc=1
    else
        echo "FAIL agent suite needs executable rk-integration and rk: $integration $rk_cli"
        rc=1
    fi
fi

if [ -x "$integration" ]; then
    # Phase 6: resilience suite. Runs after agent suite.
    "$integration" --resilience-suite "$sensor" "$bpftool" 2>&1
    resilience_rc=$?
    echo "resilience suite exit code: $resilience_rc"
    [ "$resilience_rc" -eq 0 ] || rc=1

    # Phase 9: observability suite (audit log, metrics, verify, loss).
    if [ -x "$rk_cli" ]; then
        "$integration" --observability-suite "$sensor" "$rk_cli" 2>&1
        obs_rc=$?
        echo "observability suite exit code: $obs_rc"
        [ "$obs_rc" -eq 0 ] || rc=1
    else
        echo "FAIL observability suite needs executable rk: $rk_cli"
        rc=1
    fi

    # Phase 10: upgrade suite. rk-sensor-next embeds a different object
    # (rk-bpf/build/<arch>-next), so switching between them is a real upgrade.
    sensor_next="$(dirname "$sensor")/rk-sensor-next"
    if [ -x "$sensor_next" ] && [ -x "$rk_cli" ]; then
        "$integration" --upgrade-suite "$sensor" "$sensor_next" "$rk_cli" 2>&1
        up_rc=$?
        echo "upgrade suite exit code: $up_rc"
        [ "$up_rc" -eq 0 ] || rc=1
    else
        echo "FAIL upgrade suite needs executable rk-sensor-next and rk: $sensor_next $rk_cli"
        rc=1
    fi

    # Phase 7: benchmarks, last, once nothing else is attached. The report
    # is checked against tests/bench/budget.json by the bench-report job.
    "$integration" --bench "$bpftool" 2>&1
    bench_rc=$?
    echo "bench exit code: $bench_rc"
    [ "$bench_rc" -eq 0 ] || rc=1
fi

exit "$rc"
