# Runtime image for prebuilt static binaries (musl Rust, CGO_ENABLED=0 Go).
# The build context holds bin/ with the binaries; see .github/workflows/k8s.yml.
FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY bin/ /usr/local/bin/
