// rk-nri: NRI plugin binding Kubernetes containers to Reality Kernel
// profiles before their first instruction (docs/design/phase-5b.md).
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"time"

	"github.com/containerd/nri/pkg/stub"
)

func main() {
	agentd := flag.String("agentd-socket", "/run/rk/agentd.sock", "rk-sensor agentd socket")
	nriSocket := flag.String("nri-socket", "/var/run/nri/nri.sock", "containerd NRI socket")
	name := flag.String("name", "reality-kernel", "NRI plugin name")
	idx := flag.String("idx", "10", "NRI plugin index (ordering among plugins)")
	failurePolicy := flag.String("failure-policy", "Fail", "Fail or Ignore when rk-sensor is unreachable")
	exemptList := flag.String("exempt-namespaces", "kube-system",
		"comma-separated namespaces whose unannotated pods may start while rk-sensor is unreachable; all others are refused")
	// Accepted so an older chart's arguments still parse; no longer used.
	governedList := flag.String("governed-namespaces", "", "deprecated and ignored: see -exempt-namespaces")
	readyFile := flag.String("ready-file", "/run/rk/nri.ready", "exists while registered with NRI")
	checkReady := flag.Bool("check-ready", false, "exit 0 if registered with NRI (readiness probe)")
	flag.Parse()

	if *checkReady {
		if _, err := os.Stat(*readyFile); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if *failurePolicy != "Fail" && *failurePolicy != "Ignore" {
		log.Fatalf("-failure-policy must be Fail or Ignore, got %q", *failurePolicy)
	}
	if *governedList != "" {
		log.Printf("WARNING: -governed-namespaces is ignored: while rk-sensor is unreachable, " +
			"every namespace not in -exempt-namespaces is refused")
	}
	failOpen := *failurePolicy == "Ignore"
	if failOpen {
		log.Printf("WARNING: -failure-policy Ignore: while rk-sensor is unreachable, containers " +
			"that should be governed start UNGOVERNED. Use Fail (the default) unless availability " +
			"must win over enforcement")
	}
	d := socketDaemon{path: *agentd}
	p := &plugin{daemon: d, failOpen: failOpen, exempt: namespaceSet(*exemptList)}
	// A file left by a previous instance must not report readiness.
	_ = os.Remove(*readyFile)

	// Register with NRI only once rk-sensor answers, so a node that is still
	// starting does not refuse containers. Until then nothing is governed,
	// exactly as before installation, and the pod is not Ready.
	for {
		conn, err := net.Dial("unixpacket", *agentd)
		if err == nil {
			conn.Close()
			break
		}
		log.Printf("waiting for rk-sensor at %s: %v", *agentd, err)
		time.Sleep(time.Second)
	}

	// The runtime closes the connection when it restarts; reconnect, and
	// Synchronize rebinds everything that is running.
	for {
		s, err := stub.New(p,
			stub.WithPluginName(*name),
			stub.WithPluginIdx(*idx),
			stub.WithSocketPath(*nriSocket),
		)
		if err != nil {
			log.Fatalf("create NRI plugin: %v", err)
		}
		// Start returns once the plugin is registered and configured: from
		// then on every container start passes through StartContainer.
		if err := s.Start(context.Background()); err != nil {
			log.Printf("NRI registration failed: %v", err)
		} else {
			if err := os.WriteFile(*readyFile, nil, 0o644); err != nil {
				log.Printf("write %s: %v", *readyFile, err)
			}
			log.Printf("registered with NRI at %s", *nriSocket)
			s.Wait()
			_ = os.Remove(*readyFile)
			log.Printf("NRI connection ended")
		}
		time.Sleep(2 * time.Second)
	}
}
