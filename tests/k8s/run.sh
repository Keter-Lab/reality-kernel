#!/usr/bin/env bash
# Phase 5b Kubernetes suite (docs/design/phase-5b.md §8), run against a kind
# cluster that already has the reality-kernel and rk-probe:ci images loaded.
#
#   tests/k8s/run.sh <kind node container>
#
# Each test prints START/PASS/FAIL on stderr; the JSON report goes to stdout
# between ===RK_K8S_BEGIN=== and ===RK_K8S_END===. Exits non-zero on failure.
set -uo pipefail

NODE="${1:?kind node container name}"
HERE="$(cd "$(dirname "$0")" && pwd)"
CHART="$HERE/../../deploy/helm/reality-kernel"
NS=reality-kernel
PROBE=/usr/local/bin/rk-integration
DENY=10.99.0.1:80
results=()

log() { echo "[rk-k8s] $*" >&2; }

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

fail() { echo "$*"; return 1; }

rk() { kubectl -n "$NS" exec ds/rk -c rk-sensor -- /usr/local/bin/rk "$@"; }
status_json() { rk status --json; }
generation() { status_json | jq -r .generation; }
containers() { status_json | jq -r .containers; }
daemon_events() {
    kubectl -n "$NS" logs ds/rk -c rk-sensor --tail=-1 \
        | jq -Rc 'fromjson? | select(.fields.message? == "event") | .fields'
}

# Daemon, plugin and containerd NRI logs, saved for the CI artifact. Taken
# before the restart test too, since replacing the pod loses its logs.
LOGS="${RK_K8S_LOGS:-k8s-logs}"
dump_logs() { # label
    mkdir -p "$LOGS"
    kubectl -n "$NS" logs ds/rk -c rk-sensor --tail=-1 2>&1         | grep -v '"message":"event"' > "$LOGS/$1-rk-sensor.log" || true
    kubectl -n "$NS" logs ds/rk -c rk-nri --tail=-1 > "$LOGS/$1-rk-nri.log" 2>&1 || true
    docker exec "$NODE" journalctl -u containerd --no-pager 2>&1         | grep -iE 'nri|plugin .*(clos|fail|timeout)' > "$LOGS/$1-containerd-nri.log" || true
}

# pod NAME NAMESPACE ANNOTATIONS_JSON PROBE_ARGS... (one probe container)
pod() {
    local name="$1" ns="$2" ann="$3"
    shift 3
    jq -n --arg name "$name" --arg ns "$ns" --argjson ann "$ann" --arg probe "$PROBE" \
        --args '{
          apiVersion: "v1", kind: "Pod",
          metadata: {name: $name, namespace: $ns, annotations: $ann},
          spec: {restartPolicy: "Never", terminationGracePeriodSeconds: 1,
                 containers: [{name: "probe", image: "rk-probe:ci", imagePullPolicy: "Never",
                               command: ([$probe, "--agent-probe"] + $ARGS.positional),
                               env: [{name: "RK_PROBE_IN_POD", value: "1"}]}]}
        }' "$@" | kubectl apply -f - >/dev/null
}

# Waits until the pod finishes or a container fails to start; prints the phase.
wait_done() { # name namespace
    local i phase
    for i in $(seq 1 90); do
        phase="$(kubectl -n "$2" get pod "$1" -o jsonpath='{.status.phase}' 2>/dev/null)"
        case "$phase" in Succeeded|Failed) echo "$phase"; return 0 ;; esac
        sleep 2
    done
    echo "timeout($phase)"
}

wait_running() { # name namespace
    kubectl -n "$2" wait --for=jsonpath='{.status.phase}'=Running "pod/$1" --timeout=120s >/dev/null
}

# Every container state message of a pod, for start errors from rk-nri.
pod_messages() { # name namespace
    kubectl -n "$2" get pod "$1" -o json \
        | jq -r '[.status.containerStatuses[]?, .status.initContainerStatuses[]?
                  | .state[]?.message?, .lastState[]?.message?] | map(select(. != null)) | join(" | ")'
}

pod_ident_cgroup() { # name namespace -> cgroup id printed by the probe
    kubectl -n "$2" logs "$1" | sed -n 's/.*cgroup_id=\([0-9]*\).*/\1/p' | head -n 1
}

wait_generation_above() { # generation
    local i g
    for i in $(seq 1 90); do
        g="$(generation)"
        [ -n "$g" ] && [ "$g" -gt "$1" ] && { echo "$g"; return 0; }
        sleep 2
    done
    return 1
}

expect_refused() { # name namespace want-substring
    local phase msg
    phase="$(wait_done "$1" "$2")"
    msg="$(pod_messages "$1" "$2")"
    [ "$phase" = Failed ] || fail "phase $phase, expected Failed (start refused); messages: $msg"
    grep -q "reality-kernel" <<<"$msg" || fail "no rk-nri refusal in pod status: $msg"
    grep -q "$3" <<<"$msg" || fail "refusal does not mention '$3': $msg"
    echo "refused: $msg"
}

# --------------------------------------------------------------------------

t_governed_first_instruction() {
    pod gov1 default '{"realitykernel.dev/profile":"k8s-net","realitykernel.dev/session":"k8s-sess-1"}' \
        connect "$DENY" eperm
    local phase id
    phase="$(wait_done gov1 default)"
    [ "$phase" = Succeeded ] || fail "phase $phase: $(kubectl logs gov1 2>&1 | tail -3) $(pod_messages gov1 default)"
    id="$(pod_ident_cgroup gov1 default)"
    [ -n "$id" ] || fail "no ident line in pod logs"
    local i
    for i in $(seq 1 15); do
        if daemon_events | jq -e --argjson id "$id" \
            'select(.cgroup_id == $id and .verdict == 1 and .session_id == "k8s-sess-1")' >/dev/null; then
            echo "first connect denied with EPERM; deny event carries cgroup $id and session k8s-sess-1"
            return 0
        fi
        sleep 1
    done
    fail "no deny event for cgroup $id with session k8s-sess-1 in the daemon log"
}

t_exec_session_governed() {
    kubectl exec hold1 -- "$PROBE" --agent-probe connect "$DENY" eperm >/dev/null \
        || fail "kubectl exec session was not governed"
    echo "a kubectl exec session in a governed pod is denied too"
}

t_unannotated_unaffected() {
    pod plain1 default '{}' connect "$DENY" notdenied
    local phase
    phase="$(wait_done plain1 default)"
    [ "$phase" = Succeeded ] || fail "phase $phase: $(kubectl logs plain1 2>&1 | tail -3)"
    echo "unannotated pod in an ordinary namespace reached $DENY"
}

t_namespace_default() {
    pod nsdef1 agents '{}' connect "$DENY" eperm
    local phase
    phase="$(wait_done nsdef1 agents)"
    [ "$phase" = Succeeded ] || fail "phase $phase: $(kubectl -n agents logs nsdef1 2>&1 | tail -3) $(pod_messages nsdef1 agents)"
    echo "unannotated pod in namespace agents got its default profile"
}

t_disallowed_refused() {
    pod bad1 agents '{"realitykernel.dev/profile":"k8s-open"}' noop
    expect_refused bad1 agents "not allowed in namespace"
}

t_unknown_refused() {
    pod bad2 default '{"realitykernel.dev/profile":"no-such-profile"}' noop
    expect_refused bad2 default "unknown profile"
}

t_init_and_sidecar() {
    jq -n --arg probe "$PROBE" --arg deny "$DENY" '
      def c(n): {name: n, image: "rk-probe:ci", imagePullPolicy: "Never",
                 command: [$probe, "--agent-probe", "connect", $deny, "eperm"],
                 env: [{name: "RK_PROBE_IN_POD", value: "1"}]};
      {apiVersion: "v1", kind: "Pod",
       metadata: {name: "multi1", namespace: "default",
                  annotations: {"realitykernel.dev/profile": "k8s-net"}},
       spec: {restartPolicy: "Never", terminationGracePeriodSeconds: 1,
              initContainers: [c("init")], containers: [c("main"), c("sidecar")]}}' \
        | kubectl apply -f - >/dev/null
    local phase
    phase="$(wait_done multi1 default)"
    [ "$phase" = Succeeded ] || fail "phase $phase: $(pod_messages multi1 default)"
    echo "init container, main container and sidecar were all denied"
}

t_removal_unbinds() {
    local base during after i
    base="$(containers)"
    pod hold2 default '{"realitykernel.dev/profile":"k8s-net"}' hold 600000
    wait_running hold2 default || fail "hold2 not running"
    during="$(containers)"
    [ "$during" -eq $((base + 1)) ] || fail "bound containers $base -> $during, expected +1"
    kubectl delete pod hold2 --wait=true --timeout=60s >/dev/null
    for i in $(seq 1 30); do
        after="$(containers)"
        [ "$after" -eq "$base" ] && { echo "bound containers $base -> $during -> $after"; return 0; }
        sleep 1
    done
    fail "bound containers stayed at $after after removal (baseline $base)"
}

t_lsm_rules_refused() {
    if status_json | jq -e '.capabilities[] | select(.name == "bpf_lsm") | .ok' >/dev/null; then
        echo "BPF LSM is active on this runner: refusal covered by unit test lsm_rules_refused_without_bpf_lsm"
        return 0
    fi
    local before i
    before="$(generation)"
    helm upgrade rk "$CHART" -n "$NS" -f "$HERE/values-ci.yaml" -f "$HERE/values-ci-lsm.yaml" >/dev/null \
        || fail "helm upgrade failed"
    for i in $(seq 1 90); do
        if kubectl -n "$NS" logs ds/rk -c rk-sensor --tail=-1 \
            | jq -Re 'fromjson? | select((.fields.message? // "") | startswith("changed policy rejected")) | .fields.error
                     | contains("BPF LSM is not active")' >/dev/null 2>&1; then
            [ "$(generation)" = "$before" ] || fail "generation moved although the policy was refused"
            helm upgrade rk "$CHART" -n "$NS" -f "$HERE/values-ci.yaml" >/dev/null
            wait_generation_above "$before" >/dev/null || fail "restoring the CI policy did not apply"
            echo "policy with an exec rule refused without BPF LSM; generation stayed $before"
            return 0
        fi
        sleep 2
    done
    fail "no refusal logged for a policy with exec rules"
}

t_configmap_update() {
    local pod_before restarts_before before after
    pod_before="$(kubectl -n "$NS" get pods -l app.kubernetes.io/name=reality-kernel -o jsonpath='{.items[0].metadata.name}')"
    restarts_before="$(kubectl -n "$NS" get pod "$pod_before" -o jsonpath='{.status.containerStatuses[?(@.name=="rk-sensor")].restartCount}')"
    before="$(generation)"
    kubectl exec hold1 -- "$PROBE" --agent-probe connect 10.99.0.2:80 notdenied >/dev/null \
        || fail "10.99.0.2 denied before the update"
    helm upgrade rk "$CHART" -n "$NS" -f "$HERE/values-ci-b.yaml" >/dev/null || fail "helm upgrade failed"
    after="$(wait_generation_above "$before")" || fail "generation stayed $before after the ConfigMap update"
    kubectl exec hold1 -- "$PROBE" --agent-probe connect 10.99.0.2:80 eperm >/dev/null \
        || fail "10.99.0.2 still allowed at generation $after"
    [ "$(kubectl -n "$NS" get pods -l app.kubernetes.io/name=reality-kernel -o jsonpath='{.items[0].metadata.name}')" = "$pod_before" ] \
        || fail "the DaemonSet pod was replaced"
    [ "$(kubectl -n "$NS" get pod "$pod_before" -o jsonpath='{.status.containerStatuses[?(@.name=="rk-sensor")].restartCount}')" = "$restarts_before" ] \
        || fail "rk-sensor restarted"
    helm upgrade rk "$CHART" -n "$NS" -f "$HERE/values-ci.yaml" >/dev/null
    wait_generation_above "$after" >/dev/null || fail "restoring the CI policy did not apply"
    echo "generation $before -> $after without a restart; the running pod's verdict for 10.99.0.2 flipped"
}

t_restart_resyncs() {
    # Phase 6: pins outlive the sensor, so a running governed pod must stay
    # denied *while* the DaemonSet pod is replaced, not only afterwards.
    local old allowed=0 denied=0 out i
    old="$(kubectl -n "$NS" get pods -l app.kubernetes.io/name=reality-kernel -o jsonpath='{.items[0].metadata.name}')"
    kubectl -n "$NS" delete pod "$old" --wait=false >/dev/null
    for i in $(seq 1 60); do
        if out="$(kubectl exec hold1 -- "$PROBE" --agent-probe connect "$DENY" eperm 2>&1)"; then
            denied=$((denied + 1))
        elif grep -q "expected EPERM" <<<"$out"; then
            allowed=$((allowed + 1))
        fi
        if ! kubectl -n "$NS" get pod "$old" >/dev/null 2>&1 \
            && kubectl -n "$NS" rollout status ds/rk --timeout=1s >/dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    [ "$allowed" -eq 0 ] || fail "$allowed probes reached $DENY during the restart (protection paused)"
    [ "$denied" -ge 1 ] || fail "no probe completed during the restart"
    kubectl -n "$NS" rollout status ds/rk --timeout=180s >/dev/null || fail "DaemonSet did not come back"
    for i in $(seq 1 30); do
        if [ "$(containers 2>/dev/null || echo 0)" -ge 1 ] \
            && kubectl exec hold1 -- "$PROBE" --agent-probe connect "$DENY" eperm >/dev/null 2>&1; then
            echo "denied throughout the DaemonSet pod restart ($denied probes, none allowed); rebound after ($(containers) bound)"
            return 0
        fi
        sleep 2
    done
    fail "the running pod was not rebound after the daemon restarted"
}

sensor_pid() {
    docker exec "$NODE" sh -c 'for p in /proc/[0-9]*; do
        [ "$(cat "$p/comm" 2>/dev/null)" = rk-sensor ] && echo "${p#/proc/}"; done' | head -n 1
}

t_daemon_down_fails_closed() {
    local pid out rc=0
    pid="$(sensor_pid)"
    [ -n "$pid" ] || fail "rk-sensor process not found on $NODE"
    docker exec "$NODE" kill -STOP "$pid"
    pod down1 default '{"realitykernel.dev/profile":"k8s-net"}' noop
    # Not exempt: the plugin cannot know whether `default` has rules now.
    pod down2 default '{}' noop
    # kube-system is exempt (chart default), so it can still heal.
    pod down3 kube-system '{}' noop
    local out2 rc2=0 phase3
    out="$(expect_refused down1 default "not started")" || rc=1
    out2="$(expect_refused down2 default "not started")" || rc2=1
    phase3="$(wait_done down3 kube-system)"
    docker exec "$NODE" kill -CONT "$pid"
    kubectl -n kube-system delete pod down3 --wait=false >/dev/null 2>&1 || true
    [ "$rc" -eq 0 ] || fail "annotated pod: $out"
    [ "$rc2" -eq 0 ] || fail "unannotated pod in a non-exempt namespace: $out2"
    [ "$phase3" = Succeeded ] || fail "unannotated pod in exempt kube-system did not start: $phase3 $(pod_messages down3 kube-system)"
    echo "daemon stopped: annotated and non-exempt pods refused, exempt kube-system pod started ($out)"
}

t_daemon_replies_fast() {
    # rk-nri warns when a reply takes over a quarter of its 1s budget; NRI
    # drops a plugin that exceeds its 2s timeout and starts containers ungoverned.
    local slow
    slow="$(kubectl -n "$NS" logs ds/rk -c rk-nri --tail=-1 | grep -c 'slow rk-sensor reply' || true)"
    [ "$slow" -eq 0 ] || fail "$slow slow daemon replies: $(kubectl -n "$NS" logs ds/rk -c rk-nri --tail=-1 | grep 'slow rk-sensor reply' | head -3)"
    echo "every daemon reply within a quarter of rk-nri's budget ($(kubectl -n "$NS" logs ds/rk -c rk-nri --tail=-1 | grep -c ' in [0-9]*ms') timed binds)"
}

t_chart_renders() {
    helm lint "$CHART" -f "$HERE/values-ci.yaml" >/dev/null || fail "helm lint failed"
    helm lint "$CHART" >/dev/null || fail "helm lint (default values) failed"
    helm template rk "$CHART" -n "$NS" | kubectl apply --dry-run=server -f - >/dev/null \
        || fail "rendered chart rejected by the API server"
    helm template rk "$CHART" -n "$NS" --set failurePolicy=Sometimes >/dev/null 2>&1 \
        && fail "schema accepted failurePolicy=Sometimes"
    echo "lint passes; rendered manifests accepted by the API server; schema rejects bad values"
}

# --------------------------------------------------------------------------

log "precondition: NRI socket in $NODE"
docker exec "$NODE" test -S /var/run/nri/nri.sock || {
    log "containerd on $NODE has no NRI socket"
    record precondition_nri false "no /var/run/nri/nri.sock on the kind node"
}

kubectl create namespace agents >/dev/null
log "installing the chart"
if ! helm install rk "$CHART" -n "$NS" --create-namespace -f "$HERE/values-ci.yaml" >/dev/null \
    || ! kubectl -n "$NS" rollout status ds/rk --timeout=180s >&2; then
    record chart_install false "helm install or rollout failed"
    kubectl -n "$NS" describe pods >&2 || true
    kubectl -n "$NS" logs ds/rk --all-containers --tail=50 >&2 || true
else
    # Long-running governed pod used by several tests.
    pod hold1 default '{"realitykernel.dev/profile":"k8s-net"}' hold 600000
    wait_running hold1 default || log "hold1 did not start: $(pod_messages hold1 default)"

    run_test k8s_pod_governed_from_first_instruction t_governed_first_instruction
    dump_logs after-first-test
    run_test k8s_exec_session_governed t_exec_session_governed
    run_test k8s_unannotated_pod_unaffected t_unannotated_unaffected
    run_test k8s_namespace_default_applied t_namespace_default
    run_test k8s_disallowed_profile_refused t_disallowed_refused
    run_test k8s_unknown_profile_refused t_unknown_refused
    run_test k8s_init_and_sidecar_governed t_init_and_sidecar
    run_test k8s_container_removal_unbinds t_removal_unbinds
    run_test apply_rejects_lsm_rules_without_bpf_lsm t_lsm_rules_refused
    run_test k8s_configmap_update_applies t_configmap_update
    dump_logs before-restart
    run_test k8s_daemon_restart_resyncs t_restart_resyncs
    run_test k8s_daemon_replies_fast t_daemon_replies_fast
    run_test k8s_daemon_down_fails_closed t_daemon_down_fails_closed
    run_test helm_chart_renders t_chart_renders
fi

dump_logs end
echo "===RK_K8S_BEGIN==="
printf '%s\n' "${results[@]}" | jq -s .
echo "===RK_K8S_END==="
printf '%s\n' "${results[@]}" | jq -se 'all(.passed)' >/dev/null
