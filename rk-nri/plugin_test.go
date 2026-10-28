package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/containerd/nri/pkg/api"
)

// The exact strings of rk-agentd's nri_wire_contract test.
func TestWireContract(t *testing.T) {
	got, err := encodeBind(BindRequest{
		Pid: 42, Namespace: "agents", Pod: "p", PodUID: "u", Container: "c", ContainerID: "id1",
		Annotations: map[string]string{profileAnnotation: "strict"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"BindContainer":{"pid":42,"namespace":"agents","pod":"p","pod_uid":"u","container":"c","container_id":"id1","annotations":{"realitykernel.dev/profile":"strict"}}}`
	if string(got) != want {
		t.Fatalf("bind:\n got %s\nwant %s", got, want)
	}
	got, _ = encodeUnbind("id1")
	if string(got) != `{"UnbindContainer":{"container_id":"id1"}}` {
		t.Fatalf("unbind: %s", got)
	}
	// A nil map must still encode as an object.
	got, _ = encodeBind(BindRequest{})
	if !strings.Contains(string(got), `"annotations":{}`) {
		t.Fatalf("nil annotations: %s", got)
	}

	cases := map[string]Reply{
		`{"ContainerBound":{"cgroup_id":7,"profile":"strict"}}`: {Kind: "ContainerBound", CgroupID: 7, Profile: "strict"},
		`"NotGoverned"`:             {Kind: "NotGoverned"},
		`"ContainerUnbound"`:        {Kind: "ContainerUnbound"},
		`{"Error":{"message":"m"}}`: {Kind: "Error", Message: "m"},
	}
	for in, want := range cases {
		got, err := decodeReply([]byte(in))
		if err != nil || got != want {
			t.Errorf("decode %s = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{`{}`, `{"a":{},"b":{}}`, `7`, ``} {
		if _, err := decodeReply([]byte(bad)); err == nil {
			t.Errorf("decode %q: want error", bad)
		}
	}
}

type fakeDaemon struct {
	reply   Reply
	err     error
	binds   []BindRequest
	unbinds []string
}

func (f *fakeDaemon) Bind(r BindRequest) (Reply, error) {
	f.binds = append(f.binds, r)
	return f.reply, f.err
}

func (f *fakeDaemon) Unbind(id string) (Reply, error) {
	f.unbinds = append(f.unbinds, id)
	return Reply{Kind: "ContainerUnbound"}, nil
}

func pod(annotations map[string]string) *api.PodSandbox {
	return &api.PodSandbox{Id: "pod1", Name: "web", Uid: "uid1", Namespace: "agents", Annotations: annotations}
}

func ctr(state api.ContainerState) *api.Container {
	return &api.Container{Id: "c1", PodSandboxId: "pod1", Name: "app", Pid: 99, State: state}
}

func TestStartContainerOutcomes(t *testing.T) {
	ctx := context.Background()
	unreachable := errors.New("dial: no such file")
	for _, tc := range []struct {
		name     string
		reply    Reply
		err      error
		failOpen bool
		wantErr  string
	}{
		{name: "bound", reply: Reply{Kind: "ContainerBound", Profile: "strict"}},
		{name: "not governed", reply: Reply{Kind: "NotGoverned"}},
		{name: "refused", reply: Reply{Kind: "Error", Message: "unknown profile `x`"}, wantErr: "refused: unknown profile"},
		{name: "refused even when failing open", reply: Reply{Kind: "Error", Message: "nope"}, failOpen: true, wantErr: "refused"},
		{name: "daemon down fails closed", err: unreachable, wantErr: "not started"},
		{name: "daemon down, failurePolicy Ignore", err: unreachable, failOpen: true},
		{name: "unknown reply", reply: Reply{Kind: "SignalSuccess"}, wantErr: "unexpected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &fakeDaemon{reply: tc.reply, err: tc.err}
			p := &plugin{daemon: d, failOpen: tc.failOpen}
			err := p.StartContainer(ctx, pod(map[string]string{profileAnnotation: "strict", "other": "x"}), ctr(api.ContainerState_CONTAINER_CREATED))
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error %v, want containing %q", err, tc.wantErr)
			}
			r := d.binds[0]
			if r.Pid != 99 || r.Namespace != "agents" || r.Pod != "web" || r.PodUID != "uid1" ||
				r.Container != "app" || r.ContainerID != "c1" {
				t.Fatalf("request %+v", r)
			}
			// Only Reality Kernel annotations are sent.
			if len(r.Annotations) != 1 || r.Annotations[profileAnnotation] != "strict" {
				t.Fatalf("annotations %v", r.Annotations)
			}
		})
	}
}

func TestSynchronizeRebindsOnlyRunning(t *testing.T) {
	d := &fakeDaemon{reply: Reply{Kind: "Error", Message: "x"}}
	p := &plugin{daemon: d}
	running := ctr(api.ContainerState_CONTAINER_RUNNING)
	stopped := &api.Container{Id: "c2", PodSandboxId: "pod1", State: api.ContainerState_CONTAINER_STOPPED}
	orphan := &api.Container{Id: "c3", PodSandboxId: "gone", State: api.ContainerState_CONTAINER_RUNNING}
	updates, err := p.Synchronize(context.Background(), []*api.PodSandbox{pod(nil)}, []*api.Container{running, stopped, orphan})
	if err != nil || updates != nil {
		t.Fatalf("Synchronize = %v, %v", updates, err)
	}
	// Synchronize replies before rebinding (NRI times it out like any call).
	p.resync.Wait()
	if len(d.binds) != 1 || d.binds[0].ContainerID != "c1" {
		t.Fatalf("binds %+v", d.binds)
	}
}

func TestStopAndRemoveUnbind(t *testing.T) {
	d := &fakeDaemon{}
	p := &plugin{daemon: d}
	c := ctr(api.ContainerState_CONTAINER_RUNNING)
	if _, err := p.StopContainer(context.Background(), pod(nil), c); err != nil {
		t.Fatal(err)
	}
	if err := p.RemoveContainer(context.Background(), pod(nil), c); err != nil {
		t.Fatal(err)
	}
	if len(d.unbinds) != 2 || d.unbinds[0] != "c1" {
		t.Fatalf("unbinds %v", d.unbinds)
	}
}

// While the daemon is down, only unannotated pods in an exempt namespace
// start. Every other namespace is refused, including one the plugin has never
// heard of: its rules may have been added after the plugin started.
func TestDaemonDownRefusesAllButExemptNamespaces(t *testing.T) {
	d := &fakeDaemon{err: errors.New("dial: connection refused")}
	p := &plugin{daemon: d, exempt: namespaceSet("kube-system, reality-kernel")}
	c := ctr(api.ContainerState_CONTAINER_CREATED)
	for _, ns := range []string{"kube-system", "reality-kernel"} {
		plain := &api.PodSandbox{Id: "pod1", Namespace: ns}
		if err := p.StartContainer(context.Background(), plain, c); err != nil {
			t.Fatalf("unannotated pod in exempt namespace %s refused: %v", ns, err)
		}
	}
	for _, ns := range []string{"agents", "default", "added-to-the-policy-later"} {
		plain := &api.PodSandbox{Id: "pod1", Namespace: ns}
		err := p.StartContainer(context.Background(), plain, c)
		if err == nil || !strings.Contains(err.Error(), "not started") {
			t.Fatalf("unannotated pod in namespace %s started while the daemon was down: %v", ns, err)
		}
	}
	annotated := &api.PodSandbox{Id: "pod1", Namespace: "kube-system",
		Annotations: map[string]string{profileAnnotation: "strict"}}
	if err := p.StartContainer(context.Background(), annotated, c); err == nil {
		t.Fatal("annotated pod in an exempt namespace started while the daemon was down")
	}
	// No exempt set: nothing starts while the daemon is down.
	strict := &plugin{daemon: d}
	if err := strict.StartContainer(context.Background(), &api.PodSandbox{Id: "pod1", Namespace: "kube-system"}, c); err == nil {
		t.Fatal("pod started with no exempt namespaces while the daemon was down")
	}
}

func TestNamespaceSet(t *testing.T) {
	got := namespaceSet(" kube-system,,reality-kernel ,")
	if len(got) != 2 || !got["kube-system"] || !got["reality-kernel"] {
		t.Fatalf("namespaceSet = %v", got)
	}
	if len(namespaceSet("")) != 0 {
		t.Fatal("empty list is not empty")
	}
}

// Synchronize must answer without waiting for the daemon.
func TestSynchronizeDoesNotBlockOnDaemon(t *testing.T) {
	release := make(chan struct{})
	d := &blockingDaemon{release: release}
	p := &plugin{daemon: d}
	done := make(chan struct{})
	go func() {
		p.Synchronize(context.Background(), []*api.PodSandbox{pod(nil)},
			[]*api.Container{ctr(api.ContainerState_CONTAINER_RUNNING)})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Synchronize blocked on a slow daemon")
	}
	close(release)
	p.resync.Wait()
}

type blockingDaemon struct{ release chan struct{} }

func (b *blockingDaemon) Bind(BindRequest) (Reply, error) {
	<-b.release
	return Reply{Kind: "NotGoverned"}, nil
}

func (b *blockingDaemon) Unbind(string) (Reply, error) { return Reply{Kind: "ContainerUnbound"}, nil }
