# Design note: Phase 5b — Kubernetes governance

Status: **ACCEPTED** (2026-10-21). All four decisions in §9 approved as recommended.
Implementation notes (found while building; reflected below): the daemon
enters PID 1's cgroup namespace so container cgroup paths resolve from a pod;
raw-socket denial is part of the §6 honesty check; while the daemon is
unreachable, pods that could not be governed anyway still start (§5); and
rk-nri registers with NRI only once the daemon answers.
Branch: `phase-5b-k8s` (from `main` at ec3acc2)
Plan reference: RealityKernel_Engineering_Plan.pdf, Phase 5 ("Kubernetes: a
DaemonSet plus pod annotation (realitykernel.dev/profile) or an NRI plugin that
maps pod cgroups to profiles"; deliverable "Helm values for profiles").

## 1. Goal and scope

A pod annotated `realitykernel.dev/profile: NAME` runs every one of its
containers under that profile **from the container's first instruction**,
with the same guarantee `rk run` gives locally (Phase 5a). Namespaces can make a
profile mandatory. Deployed with a Helm chart.

In scope: an NRI plugin, daemon support for container bindings, namespace rules
in the policy, the Helm chart, container images for CI, a kind-based CI job, and
one honesty fix found while designing this (§6).

Out of scope: published images and signed releases (Phase 10), pinned maps that
survive a daemon restart (Phase 6; see §5), CRI runtimes other than containerd
in CI (CRI-O also implements NRI and should work, but is untested).

## 2. Why NRI, and why at `StartContainer`

A DaemonSet that watches the API server and binds cgroups after a pod starts
always loses a race: the container runs before the binding exists. NRI is
called by the runtime itself, synchronously, during container creation.

What containerd guarantees, verified in its source
(`internal/cri/server/container_start.go`, `containerd/nri` `pkg/adaptation`):

1. `container.NewTask(...)` creates the task. The runtime has made the
   container's cgroup and its init process, which is parked before `exec` of
   the user command. The pid is known.
2. `c.nri.StartContainer(...)` calls every plugin **synchronously**. The first
   plugin error is returned.
3. On error, containerd aborts with "NRI container start failed", deletes the
   task and marks the container exited. **No user code has run.**
4. Only then does `task.Start()` run the container's command.

So binding the container's cgroup in our `StartContainer` handler means the
first instruction is governed, and any failure to bind is fail-closed: the
container does not start. NRI is enabled by default from containerd 2.0
(socket `/var/run/nri/nri.sock`); on 1.7 it must be switched on in the
containerd config, which the chart documents.

## 3. Architecture

```
kubelet ──CRI──> containerd ──NRI (ttrpc)──> rk-nri ──agentd socket──> rk-sensor ──maps──> kernel
                                              (DaemonSet pod, two containers)
```

- **`rk-nri`** (new, Go, ~300 lines): an external NRI plugin built on the
  official stub `github.com/containerd/nri/pkg/stub`. It holds no policy.
  For each container it sends one request to the daemon and returns the
  daemon's verdict to containerd.
- **`rk-sensor`** gains a `BindContainer` / `UnbindContainer` request on the
  existing agentd socket (JSON over `SOCK_SEQPACKET`, peer authenticated with
  `SO_PEERCRED`, root only). All policy decisions stay in the daemon.

The plugin is Go because NRI's plugin protocol (ttrpc multiplexed over one
socket, with the plugin also serving calls) only has a maintained
implementation in Go. There is no Rust NRI library, and reimplementing the
protocol would be the riskiest code in the phase for no security gain. See
decision 1.

### Request handling (`StartContainer`)

1. `rk-nri` gets the pod (namespace, name, uid, annotations) and the container
   (id, name, pid) from NRI. It sends
   `BindContainer { pid, namespace, pod, pod_uid, container, annotations }`.
2. The daemon resolves the profile (§4). With no profile, it replies
   `NotGoverned` and the container starts untouched.
3. Otherwise the daemon reads `/proc/<pid>/cgroup` to get the container's
   cgroup, checks it is under the Kubernetes cgroup root (§5), stats it for the
   cgroup id, and binds it with the same single map update as `rk run`. An
   optional `realitykernel.dev/session` annotation sets the session id (§5 of
   the Phase 5 note).
4. Any error (unknown profile, profile not allowed in the namespace, cgroup
   outside the root, daemon unreachable) is returned to containerd, which fails
   the start.

`StopContainer` and `RemoveContainer` unbind. NRI's `Synchronize` call, made
whenever the plugin (re)connects, lists every running container. The plugin
rebinds them all, which also covers a daemon restart (§5).

## 4. Choosing the profile: annotation plus namespace rules

Any profile is more restrictive than no profile, so on an ordinary namespace an
annotation can only add restrictions and is honoured as is. The risk is a
namespace that **must** be governed: there, a pod must not pick a weaker
profile or drop the annotation. The policy gets a `kubernetes` section:

```toml
[kubernetes.namespaces.agents]
default = "research-agent"            # used when the pod has no annotation
allowed = ["research-agent", "strict"] # an annotation must name one of these
                                       # (defaults to [default])
```

| Namespace | Annotation | Result |
|---|---|---|
| not listed | none | not governed |
| not listed | `P` (exists) | governed by `P` |
| listed | none | governed by `default`; **refused** if there is no default |
| listed | `P` in `allowed` | governed by `P` |
| listed | `P` not in `allowed` | **start refused** |
| any | unknown profile | **start refused** |

The quarantine profile can't be selected by annotation. `rk policy diff` and
`--dry-run` report changes to the `kubernetes` section like any other.

## 5. Daemon changes

- **Hooks at the Kubernetes cgroup root.** The network (`sock_addr`) programs
  are attached to `rk.slice` today, so they never see pods. The daemon also
  attaches them to the Kubernetes root: auto-detected (`kubepods.slice` for the
  systemd cgroup driver, `kubepods` for cgroupfs), or set with
  `--k8s-cgroup-root`. LSM programs are global and need no change.
- **Bindings outside `rk.slice`.** `BindContainer` may bind cgroups under the
  Kubernetes root only. Static `[[bindings]]` stay restricted to `rk.slice`.
- **Restarts.** Maps are not pinned until Phase 6, so between a daemon restart
  and the plugin's resync running containers are ungoverned. The resync is
  automatic and tested (§8), and the gap is documented, not hidden. Phase 6 pins
  the maps and closes it.
- **Readiness means protecting.** The DaemonSet pod is Ready only when the
  daemon answers *and* `rk-nri` has completed NRI registration (it writes a
  ready file after the stub's `Start` returns, and removes it when the
  connection ends). The first kind run caught the gap: a pod created right
  after `rollout status` started before registration finished. Containers
  that start before a node's plugin registers are not governed, as before
  installation. Clusters that need governance from node boot should keep new
  nodes tainted until this pod is Ready.
- **Fail-closed by default** if the daemon is unreachable: the plugin refuses
  every container that could be governed, meaning annotated pods and pods in
  a namespace with rules (the plugin gets that list from the same Helm values
  as the policy). Other pods start, since they would not be governed anyway,
  so a daemon crash can't stop `kube-system` from healing. A Helm
  value `failurePolicy: Ignore` lets clusters choose availability over
  enforcement, with a warning on each skipped container. See decision 3.

## 6. Capability honesty (fix found during design)

The daemon's `status` hardcodes `bpf_lsm: ok`. On a kernel where `bpf` isn't
in the active LSM list, which includes the GitHub runner kernel used by kind,
LSM programs load and attach but are never called. Exec and file rules would
then silently not be enforced.

The fix: at startup the daemon reads `/sys/kernel/security/lsm`. Without `bpf`:

- `rk status` and `rk doctor` report `bpf_lsm: inactive`, and how to enable it
  (`lsm=...,bpf` on the kernel command line).
- `rk policy apply` **rejects** any policy with exec or file rules, with a
  clear error. Network-only policies still work, since cgroup hooks don't need
  the LSM.

This applies to `rk run` hosts as much as to Kubernetes nodes.

## 7. Deployment

- **Helm chart** `deploy/helm/reality-kernel`: a DaemonSet with two containers
  (`rk-sensor` privileged; `rk-nri` root, unprivileged otherwise). It mounts
  host `/sys/fs/cgroup`, `/sys/kernel/btf`, `/sys/kernel/security`,
  `/var/run/nri` and a shared `emptyDir` for the agentd socket, with `hostPID`
  so `/proc/<pid>/cgroup` resolves. The policy comes from `values.policy`
  (TOML), rendered into a ConfigMap mounted as a file. Restarting the pod on a
  policy change would open the restart gap of §5, so the daemon gets
  `--watch-policy`: it notices the kubelet's update of the mounted file and
  applies it with the usual atomic flip, no restart. A rejected policy leaves
  the active one in place and is logged. Values: `profiles` (inline TOML), `namespaces`,
  `failurePolicy`, `k8sCgroupRoot`, `image.*`, `nodeSelector`, `tolerations`.
  The README states host requirements (kernel, BTF, containerd ≥ 2.0 or 1.7 with
  NRI on, BPF LSM for exec and file rules).
- **Images** for CI: static musl binaries on `gcr.io/distroless/static`, built
  in the job and loaded with `kind load`. Publishing is Phase 10.

## 8. Tests (each acceptance criterion maps to a named test)

New CI job `k8s` (kind, pinned kind version and node image with containerd 2.x,
on the GitHub runner kernel). A test script drives `kubectl` and prints the
same named PASS/FAIL JSON report as the VM suites. The probe image is
`rk-integration` in `--agent-probe` mode. The runner kernel has no BPF LSM, so
the job checks network enforcement (cgroup hooks), as planned in the Phase 5
note. Exec and file enforcement in containers uses the same LSM path the VM
matrix already tests.

| Criterion | Test |
|---|---|
| An annotated pod is governed from its first instruction | `k8s_pod_governed_from_first_instruction`: the container's first action, a connect to a denied address, fails with EPERM, and the deny event carries the container's cgroup |
| Children and `kubectl exec` sessions are governed | `k8s_exec_session_governed` |
| An unannotated pod in an ordinary namespace is untouched | `k8s_unannotated_pod_unaffected` |
| Namespace default applies without an annotation | `k8s_namespace_default_applied` |
| A disallowed profile is refused | `k8s_disallowed_profile_refused` (pod fails to start, rk error in the pod events) |
| An unknown profile is refused | `k8s_unknown_profile_refused` |
| All containers, init containers included, are bound | `k8s_init_and_sidecar_governed` |
| Removal unbinds | `k8s_container_removal_unbinds` (binding gone from the kernel map) |
| Daemon restart resyncs | `k8s_daemon_restart_resyncs` (running pod governed again after the DaemonSet pod restarts) |
| Fail closed when the daemon is down | `k8s_daemon_down_fails_closed` |
| Capability honesty (§6) | `apply_rejects_lsm_rules_without_bpf_lsm` (kind job) and a unit test; VM matrix keeps proving the LSM path |
| Policy updates apply without a restart | `k8s_configmap_update_applies` (generation advances, the pod's verdict flips, the DaemonSet pod is not restarted) |
| Chart renders and validates | `helm_chart_renders` (`helm lint`, `helm template`, schema validation) |

Plugin unit tests (`go test`) cover request mapping and error propagation;
`go vet` runs in the lint job.

## 9. Decisions requested from the reviewer

1. **Write `rk-nri` in Go with the official NRI stub.** Recommended: it is the
   only maintained NRI implementation, the plugin holds no policy, and all
   decisions stay in the Rust daemon. Alternative: Rust with `ttrpc` and
   reimplemented multiplexing, which is weeks of protocol work with more risk.
2. **Bind at `StartContainer`** (after the task exists, before its command
   runs). Recommended: containerd calls it synchronously and aborts the start on
   error, so it gives the `rk run` guarantee with nothing added to the runtime.
3. **Fail closed by default** when the daemon is unreachable, with a
   `failurePolicy: Ignore` opt-out. Recommended: a security control that turns
   off when its daemon crashes isn't one.
4. **Namespace rules in the policy file** (`[kubernetes.namespaces.*]`), not
   in Kubernetes objects. Recommended: one reviewed artefact holds all policy,
   and `diff` and `dry-run` cover it. A CRD can come later.
