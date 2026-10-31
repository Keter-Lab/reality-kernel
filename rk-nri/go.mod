module github.com/Keter-Lab/reality-kernel/rk-nri

go 1.26.0

// The toolchain CI and releases build with; setup-go reads it.
toolchain go1.27.3

require github.com/containerd/nri v0.12.5

// govulncheck, pinned here and run with `go tool govulncheck` in CI.
tool golang.org/x/vuln/cmd/govulncheck

require golang.org/x/vuln v1.9.0 // indirect

require (
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/ttrpc v1.2.7 // indirect
	github.com/knqyf263/go-plugin v0.9.0 // indirect
	github.com/opencontainers/runtime-spec v1.3.0 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/tetratelabs/wazero v1.11.0 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/telemetry v0.0.0-20261010193011-f71dc92da45e // indirect
	golang.org/x/tools v0.52.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
	google.golang.org/grpc v1.84.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
