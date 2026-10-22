#!/usr/bin/env bash
# Phase 10 package suite (docs/design/phase-10.md §7): install, upgrade and
# uninstall of the deb or rpm on a systemd host, run as root on that host.
#
#   tests/packaging/run.sh deb|rpm DIST_DIR
#
# DIST_DIR holds the release-1 package, the release-2 package (its sensor
# embeds the `next` object, so the upgrade replaces the running object) and
# rk-integration (the gap probe). Each test prints START/PASS/FAIL on stderr;
# the JSON report goes to stdout between ===RK_PKG_BEGIN=== and ===RK_PKG_END===.
set -uo pipefail

FORMAT="${1:?deb|rpm}"
DIST="${2:?dist dir}"
PROBE="$DIST/rk-integration"
CG=/sys/fs/cgroup/rk.slice/pkg-test
DENY=10.99.0.1:80
KEY=/var/lib/rk/audit.key
results=()

log() { echo "[rk-pkg] $*" >&2; }

record() { # name passed detail
    results+=("$(jq -cn --arg n "$1" --argjson p "$2" --arg d "$3" '{name:$n, passed:$p, detail:$d}')")
}

run_test() { # name function
    local name="$1" out rc start=$SECONDS
    log "START $name"
    out="$("$2" 2>&1)"
    rc=$?
    if [ "$rc" -eq 0 ]; then
        log "PASS $name ($((SECONDS - start))s)"
        record "$name" true "$(tail -n 1 <<<"$out")"
    else
        log "FAIL $name ($((SECONDS - start))s)"
        sed 's/^/    /' <<<"$out" >&2
        record "$name" false "$(tail -n 5 <<<"$out" | tr '\n' ' ')"
    fi
}

# Each test runs in its own subshell (run_test's $(...)), so exit ends the
# test, not the suite.
fail() {
    echo "$*"
    exit 1
}

pkg_file() { # release
    case "$FORMAT" in
        deb) ls "$DIST"/reality-kernel_*-"$1"_amd64.deb ;;
        rpm) ls "$DIST"/reality-kernel-*-"$1".x86_64.rpm ;;
    esac 2>/dev/null | head -n 1
}

install_pkg() {
    case "$FORMAT" in
        deb) dpkg -i "$1" ;;
        rpm) rpm -Uvh "$1" ;;
    esac
}

remove_pkg() {
    case "$FORMAT" in
        deb) dpkg --purge reality-kernel ;;
        rpm) rpm -e reality-kernel ;;
    esac
}

installed() {
    case "$FORMAT" in
        deb) dpkg-query -W -f='${Version}' reality-kernel 2>/dev/null ;;
        rpm) rpm -q --qf '%{VERSION}-%{RELEASE}' reality-kernel 2>/dev/null ;;
    esac
}

journal() { journalctl -u rk-sensor --no-pager -o cat 2>/dev/null; }

wait_ready() { # service active and answering `rk status`, within 30 s
    for _ in $(seq 1 60); do
        if systemctl is-active --quiet rk-sensor && rk status --json >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    systemctl status rk-sensor --no-pager 2>&1 | tail -n 15
    journal | tail -n 30
    return 1
}

generation() { rk status --json 2>/dev/null | jq -r '.generation // 0'; }

wait_generation() { # at least $1, within 15 s
    local g
    for _ in $(seq 1 30); do
        g="$(generation)"
        [ "${g:-0}" -ge "$1" ] && return 0
        sleep 0.5
    done
    return 1
}

audit_verifies() {
    rk audit verify --pubkey "$KEY.pub" 2>&1 | grep -q '^VERIFIED$'
}

# The runner kernel has no BPF LSM: network rules only (docs/policy.md).
policy() {
    cat <<'POLICY'
[profiles.pkg-enforce]
mode = "enforce"
launchable_by = ["root"]
network.default = "allow"
network.deny_raw_sockets = false
files.include = []

[[profiles.pkg-enforce.network.deny]]
cidr = "10.99.0.1/32"
proto = ["udp", "tcp"]

[[bindings]]
cgroup = "rk.slice/pkg-test"
profile = "pkg-enforce"
POLICY
}

t_fresh_install() {
    local pkg out code g0
    pkg="$(pkg_file 1)"
    [ -n "$pkg" ] || fail "no release-1 $FORMAT package in $DIST"
    install_pkg "$pkg" || fail "installing $pkg failed"
    wait_ready || fail "service not ready after install"
    mkdir -p "$CG"
    g0="$(generation)"
    policy >/etc/rk/policy.toml
    systemctl reload rk-sensor || fail "reload failed"
    wait_generation $((g0 + 1)) || fail "policy not applied: $(journal | tail -n 5)"

    "$PROBE" --child "$CG/cgroup.procs" udp_connect "$DENY" eperm \
        || fail "connect from the bound cgroup was not denied"
    # `rk run` under the unit's bounded capabilities: launch, then deny. From
    # /, which the agent (another user) can enter: rk passes the caller's cwd.
    (cd / && rk run --profile pkg-enforce -- /bin/true) || fail "rk run could not launch an agent"
    if out="$(cd / && rk run --profile pkg-enforce -- /bin/bash -c 'exec 3<>/dev/udp/10.99.0.1/80' 2>&1)"; then
        fail "agent connect was not denied: $out"
    fi
    grep -qi "not permitted" <<<"$out" || fail "agent failed for another reason: $out"

    sleep 2 # one audit batch interval
    audit_verifies || fail "audit log does not verify: $(rk audit verify 2>&1 | tail -n 5)"
    rk audit tail -n 50 --verdict deny | grep -q "DENY" || fail "no deny in the audit log"
    out="$(rk doctor --json)"
    code=$?
    [ "$code" -eq 0 ] || fail "rk doctor exited $code: $out"
    echo "installed $(installed); bound-cgroup and agent connects denied; audit log verified; rk doctor ok ($(jq -r '[.checks[] | select(.status == "warn") | .name] | join(",")' <<<"$out") warn)"
}

t_unit_verifies() {
    local out rc
    # Only findings about this unit count: verify also loads its dependencies.
    out="$(systemd-analyze verify /usr/lib/systemd/system/rk-sensor.service 2>&1)"
    rc=$?
    if [ "$rc" -ne 0 ] && grep -q "rk-sensor" <<<"$out"; then
        fail "systemd-analyze verify: $out"
    fi
    echo "unit verifies; $(systemd-analyze security rk-sensor.service --no-pager 2>/dev/null | tail -n 1)"
}

t_upgrade() {
    local pkg before probe ok tries
    pkg="$(pkg_file 2)"
    [ -n "$pkg" ] || fail "no release-2 $FORMAT package in $DIST"
    before="$(installed)"
    "$PROBE" --child "$CG/cgroup.procs" gap_probe "$DENY" 15000 >/tmp/rk-probe.json 2>/tmp/rk-probe.err &
    probe=$!
    sleep 1
    install_pkg "$pkg" || fail "upgrading to $pkg failed"
    for _ in $(seq 1 60); do
        journal | grep -q "replaced the running object without a gap" && break
        sleep 0.5
    done
    journal | grep -q "replaced the running object without a gap" \
        || fail "the upgrade did not replace the running object: $(journal | tail -n 20)"
    wait "$probe" || fail "gap probe failed: $(cat /tmp/rk-probe.err)"
    ok="$(jq -r .net_ok /tmp/rk-probe.json)"
    tries="$(jq -r .net_tries /tmp/rk-probe.json)"
    [ "$ok" -eq 0 ] || fail "$ok of $tries denied connects got through during the upgrade"
    [ "$tries" -ge 1000 ] || fail "the probe made only $tries attempts"
    wait_ready || fail "service not ready after the upgrade"
    sleep 2
    audit_verifies || fail "audit chain broken by the upgrade: $(rk audit verify 2>&1 | tail -n 5)"
    echo "upgraded $before -> $(installed): 0 of $tries denied connects got through; audit chain intact"
}

t_uninstall() {
    remove_pkg || fail "removing the package failed"
    systemctl is-active --quiet rk-sensor && fail "service still running"
    [ -e /sys/fs/bpf/rk ] && fail "pins still present"
    "$PROBE" --child "$CG/cgroup.procs" udp_connect "$DENY" ok \
        || fail "connects are still denied after removal"
    [ -e "$KEY" ] && fail "private audit key left behind"
    [ -e "$KEY.pub" ] || fail "public audit key removed"
    ls /var/log/rk/audit/*.jsonl >/dev/null 2>&1 || fail "audit logs removed"
    echo "removed: no pins, cgroup no longer governed, private key gone, audit logs and public key kept"
}

ip link set lo up 2>/dev/null
ip addr add 10.99.0.1/24 dev lo 2>/dev/null
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

run_test pkg_fresh_install_enforces t_fresh_install
run_test pkg_unit_verifies t_unit_verifies
run_test pkg_upgrade_keeps_enforcement t_upgrade
run_test pkg_uninstall_removes_everything t_uninstall

echo "===RK_PKG_BEGIN==="
printf '%s\n' "${results[@]}" | jq -s .
echo "===RK_PKG_END==="
printf '%s\n' "${results[@]}" | jq -se 'all(.passed)' >/dev/null
