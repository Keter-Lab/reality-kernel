#!/usr/bin/env bash
# Installs cosign and syft at pinned versions, checksum-verified against the
# projects' published checksum files (docs/design/phase-11.md §4).
set -euo pipefail

COSIGN_VERSION=v3.1.3
COSIGN_SHA256=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71
SYFT_VERSION=1.52.0
SYFT_SHA256=caeedb81fb0491615f1ebd1761e4145d41ee86dd2cc7bf80669f9f5ad9d6133d

dir="$(mktemp -d)"
curl -sSfL -o "$dir/cosign" "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
echo "${COSIGN_SHA256}  $dir/cosign" | sha256sum -c -
sudo install -m 0755 "$dir/cosign" /usr/local/bin/cosign

curl -sSfL -o "$dir/syft.tar.gz" "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz"
echo "${SYFT_SHA256}  $dir/syft.tar.gz" | sha256sum -c -
tar -xzf "$dir/syft.tar.gz" -C "$dir" syft
sudo install -m 0755 "$dir/syft" /usr/local/bin/syft

cosign version
syft version
