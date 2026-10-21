// Wire protocol with rk-sensor's agentd socket: one JSON message per
// SOCK_SEQPACKET datagram, serde's externally tagged enum encoding.
// rk-agentd/src/protocol.rs (test nri_wire_contract) pins the same strings.

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

const (
	profileAnnotation = "realitykernel.dev/profile"
	sessionAnnotation = "realitykernel.dev/session"

	maxMessage = 1 << 20
	// Below NRI's default plugin request timeout (2s), so a hung daemon is
	// answered with our refusal rather than a runtime timeout.
	ioTimeout = time.Second
)

// BindRequest is Request::BindContainer.
type BindRequest struct {
	Pid         uint32            `json:"pid"`
	Namespace   string            `json:"namespace"`
	Pod         string            `json:"pod"`
	PodUID      string            `json:"pod_uid"`
	Container   string            `json:"container"`
	ContainerID string            `json:"container_id"`
	Annotations map[string]string `json:"annotations"`
}

type unbindRequest struct {
	ContainerID string `json:"container_id"`
}

// Reply is the part of a daemon Response that rk-nri acts on.
type Reply struct {
	// Kind is the Response variant: ContainerBound, NotGoverned,
	// ContainerUnbound or Error.
	Kind     string
	CgroupID uint64
	Profile  string
	Message  string
}

func encodeBind(req BindRequest) ([]byte, error) {
	if req.Annotations == nil {
		// serde rejects null for a map.
		req.Annotations = map[string]string{}
	}
	return json.Marshal(struct {
		BindContainer BindRequest `json:"BindContainer"`
	}{req})
}

func encodeUnbind(containerID string) ([]byte, error) {
	return json.Marshal(struct {
		UnbindContainer unbindRequest `json:"UnbindContainer"`
	}{unbindRequest{containerID}})
}

func decodeReply(data []byte) (Reply, error) {
	var unit string
	if err := json.Unmarshal(data, &unit); err == nil {
		return Reply{Kind: unit}, nil
	}
	var tagged map[string]json.RawMessage
	if err := json.Unmarshal(data, &tagged); err != nil || len(tagged) != 1 {
		return Reply{}, fmt.Errorf("malformed daemon response %q", data)
	}
	for kind, body := range tagged {
		var fields struct {
			CgroupID uint64 `json:"cgroup_id"`
			Profile  string `json:"profile"`
			Message  string `json:"message"`
		}
		if err := json.Unmarshal(body, &fields); err != nil {
			return Reply{}, fmt.Errorf("malformed %s response: %w", kind, err)
		}
		return Reply{Kind: kind, CgroupID: fields.CgroupID, Profile: fields.Profile, Message: fields.Message}, nil
	}
	panic("unreachable")
}

// socketDaemon talks to rk-sensor over its agentd socket, one connection per
// request.
type socketDaemon struct {
	path string
}

func (d socketDaemon) call(msg []byte) (Reply, error) {
	conn, err := net.DialTimeout("unixpacket", d.path, ioTimeout)
	if err != nil {
		return Reply{}, fmt.Errorf("rk-sensor unreachable at %s: %w", d.path, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(ioTimeout)); err != nil {
		return Reply{}, err
	}
	if _, err := conn.Write(msg); err != nil {
		return Reply{}, fmt.Errorf("send to rk-sensor: %w", err)
	}
	buf := make([]byte, maxMessage)
	n, err := conn.Read(buf)
	if err != nil {
		return Reply{}, fmt.Errorf("read from rk-sensor: %w", err)
	}
	return decodeReply(buf[:n])
}

func (d socketDaemon) Bind(req BindRequest) (Reply, error) {
	msg, err := encodeBind(req)
	if err != nil {
		return Reply{}, err
	}
	return d.call(msg)
}

func (d socketDaemon) Unbind(containerID string) (Reply, error) {
	msg, err := encodeUnbind(containerID)
	if err != nil {
		return Reply{}, err
	}
	return d.call(msg)
}
