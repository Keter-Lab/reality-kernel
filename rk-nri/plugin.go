package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/containerd/nri/pkg/api"
)

// daemon is the rk-sensor side; an interface so tests can fake it.
type daemon interface {
	Bind(BindRequest) (Reply, error)
	Unbind(containerID string) (Reply, error)
}

// plugin holds no policy: rk-sensor decides, rk-nri relays the decision to
// containerd (docs/design/phase-5b.md §3).
type plugin struct {
	daemon daemon
	// failOpen starts containers whose binding failed because the daemon was
	// unreachable (Helm failurePolicy: Ignore). Policy refusals always fail.
	failOpen bool
	// governed lists the namespaces with rules in the policy (rendered from
	// the same Helm values). While the daemon is unreachable, a pod that is
	// neither annotated nor in one of them could not be governed anyway, so it
	// starts: otherwise a daemon crash would stop kube-system from healing.
	governed map[string]bool
	// resync tracks background rebinds started by Synchronize.
	resync sync.WaitGroup
}

func bindRequest(pod *api.PodSandbox, ctr *api.Container) BindRequest {
	annotations := map[string]string{}
	for _, key := range []string{profileAnnotation, sessionAnnotation} {
		if v, ok := pod.GetAnnotations()[key]; ok {
			annotations[key] = v
		}
	}
	return BindRequest{
		Pid:         ctr.GetPid(),
		Namespace:   pod.GetNamespace(),
		Pod:         pod.GetName(),
		PodUID:      pod.GetUid(),
		Container:   ctr.GetName(),
		ContainerID: ctr.GetId(),
		Annotations: annotations,
	}
}

// bind returns nil when the container may start.
func (p *plugin) bind(pod *api.PodSandbox, ctr *api.Container) error {
	req := bindRequest(pod, ctr)
	where := fmt.Sprintf("%s/%s container %s", req.Namespace, req.Pod, req.Container)
	start := time.Now()
	reply, err := p.daemon.Bind(req)
	took := time.Since(start).Round(time.Millisecond)
	if took > callBudget/4 {
		log.Printf("WARNING: slow rk-sensor reply for %s: %s", where, took)
	}
	if err != nil {
		if _, annotated := req.Annotations[profileAnnotation]; !annotated && !p.governed[req.Namespace] {
			return nil
		}
		if p.failOpen {
			log.Printf("WARNING: starting %s ungoverned (failurePolicy Ignore): %v", where, err)
			return nil
		}
		return fmt.Errorf("reality-kernel: %s not started (after %s): %w", where, took, err)
	}
	switch reply.Kind {
	case "ContainerBound":
		log.Printf("bound %s to profile %s (cgroup %d) in %s", where, reply.Profile, reply.CgroupID, took)
		return nil
	case "NotGoverned":
		return nil
	case "Error":
		return fmt.Errorf("reality-kernel: %s refused: %s", where, reply.Message)
	default:
		return fmt.Errorf("reality-kernel: %s: unexpected daemon response %q", where, reply.Kind)
	}
}

// StartContainer runs after the container's task exists and before its
// command starts; an error makes containerd abort the start.
func (p *plugin) StartContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) error {
	return p.bind(pod, ctr)
}

// Synchronize rebinds running containers whenever the plugin (re)connects,
// which covers an rk-sensor restart. It replies at once and rebinds in the
// background: NRI applies its request timeout to Synchronize too and drops a
// plugin that exceeds it, and containers started while the plugin is dropped
// are not governed. The containers listed are already running, so failures
// are logged; they cannot be refused any more.
func (p *plugin) Synchronize(_ context.Context, pods []*api.PodSandbox, ctrs []*api.Container) ([]*api.ContainerUpdate, error) {
	byID := make(map[string]*api.PodSandbox, len(pods))
	for _, pod := range pods {
		byID[pod.GetId()] = pod
	}
	type pair struct {
		pod *api.PodSandbox
		ctr *api.Container
	}
	var running []pair
	for _, ctr := range ctrs {
		pod, ok := byID[ctr.GetPodSandboxId()]
		if ok && ctr.GetState() == api.ContainerState_CONTAINER_RUNNING {
			running = append(running, pair{pod, ctr})
		}
	}
	p.resync.Add(1)
	go func() {
		defer p.resync.Done()
		for _, r := range running {
			if err := p.bind(r.pod, r.ctr); err != nil {
				log.Printf("resync: %v", err)
			}
		}
	}()
	return nil, nil
}

func (p *plugin) unbind(ctr *api.Container) {
	reply, err := p.daemon.Unbind(ctr.GetId())
	if err != nil {
		log.Printf("unbind %s: %v", ctr.GetId(), err)
	} else if reply.Kind == "Error" {
		log.Printf("unbind %s: %s", ctr.GetId(), reply.Message)
	}
}

func (p *plugin) StopContainer(_ context.Context, _ *api.PodSandbox, ctr *api.Container) ([]*api.ContainerUpdate, error) {
	p.unbind(ctr)
	return nil, nil
}

func (p *plugin) RemoveContainer(_ context.Context, _ *api.PodSandbox, ctr *api.Container) error {
	p.unbind(ctr)
	return nil
}
