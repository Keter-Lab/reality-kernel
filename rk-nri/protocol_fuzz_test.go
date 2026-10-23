package main

import (
	"encoding/json"
	"reflect"
	"testing"
	"unicode/utf8"
)

// Daemon responses arrive on a socket: malformed input must give an error,
// never a panic, and only valid JSON may be accepted
// (docs/design/phase-11.md §4). `go test` runs the seeds; `go test -fuzz`
// explores further.
func FuzzDecodeReply(f *testing.F) {
	for _, seed := range []string{
		`"NotGoverned"`,
		`"ContainerUnbound"`,
		`{"ContainerBound":{"cgroup_id":42,"profile":"strict"}}`,
		`{"Error":{"message":"no such profile"}}`,
		`{"ContainerBound":null}`,
		`{"ContainerBound":[]}`,
		`{}`,
		`{"A":1,"B":2}`,
		`[]`,
		`null`,
		``,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := decodeReply(data); err != nil {
			return
		}
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatalf("accepted invalid JSON %q", data)
		}
	})
}

// Any bind request survives the wire encoding unchanged.
func FuzzEncodeBind(f *testing.F) {
	f.Add(uint32(42), "agents", "p", "u", "c", "id1", "strict")
	f.Fuzz(func(t *testing.T, pid uint32, ns, pod, uid, ctr, id, profile string) {
		for _, s := range []string{ns, pod, uid, ctr, id, profile} {
			if !utf8.ValidString(s) {
				return // JSON carries text; Kubernetes names are UTF-8.
			}
		}
		req := BindRequest{
			Pid: pid, Namespace: ns, Pod: pod, PodUID: uid, Container: ctr, ContainerID: id,
			Annotations: map[string]string{profileAnnotation: profile},
		}
		data, err := encodeBind(req)
		if err != nil {
			t.Fatal(err)
		}
		var back struct {
			BindContainer BindRequest `json:"BindContainer"`
		}
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatalf("encoding is not valid JSON: %v", err)
		}
		if !reflect.DeepEqual(back.BindContainer, req) {
			t.Fatalf("round trip changed the request: %+v -> %+v", req, back.BindContainer)
		}
	})
}
