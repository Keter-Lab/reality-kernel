// rk-nri: NRI plugin binding Kubernetes containers to Reality Kernel
// profiles before their first instruction (docs/design/phase-5b.md).
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"strings"
	"time"

	"github.com/containerd/nri/pkg/stub"
)

func main() {
	agentd := flag.String("agentd-socket", "/run/rk/agentd.sock", "rk-sensor agentd socket")
	nriSocket := flag.String("nri-socket", "/var/run/nri/nri.sock", "containerd NRI socket")
	name := flag.String("name", "reality-kernel", "NRI plugin name")
	idx := flag.String("idx", "10", "NRI plugin index (ordering among plugins)")
	failurePolicy := flag.String("failure-policy", "Fail", "Fail or Ignore when rk-sensor is unreachable")
	governedList := flag.String("governed-namespaces", "", "comma-separated namespaces with rules in the policy")
	flag.Parse()

	if *failurePolicy != "Fail" && *failurePolicy != "Ignore" {
		log.Fatalf("-failure-policy must be Fail or Ignore, got %q", *failurePolicy)
	}
	governed := map[string]bool{}
	for _, ns := range strings.Split(*governedList, ",") {
		if ns = strings.TrimSpace(ns); ns != "" {
			governed[ns] = true
		}
	}
	d := socketDaemon{path: *agentd}
	p := &plugin{daemon: d, failOpen: *failurePolicy == "Ignore", governed: governed}

	// Register with NRI only once rk-sensor answers, so a node that is still
	// starting does not refuse containers. Until then nothing is governed,
	// exactly as before installation.
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
		if err := s.Run(context.Background()); err != nil {
			log.Printf("NRI connection ended: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
}
