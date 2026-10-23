#!/usr/bin/env bash
# Builds the deb and rpm packages from prebuilt static binaries
# (docs/design/phase-10.md §5).
#
#   deploy/packaging/build.sh ARCH BINDIR VERSION RELEASE OUTDIR
#
# ARCH is amd64 or arm64; BINDIR holds rk-sensor and rk. Needs nfpm on PATH.
set -euo pipefail

arch="${1:?amd64|arm64}"
bindir="$(cd "${2:?bindir}" && pwd)"
version="${3:?version}"
release="${4:?release}"
out="${5:?outdir}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

case "$arch" in amd64 | arm64) ;; *) echo "unsupported arch $arch" >&2; exit 64 ;; esac
for bin in rk-sensor rk; do
    [ -x "$bindir/$bin" ] || { echo "missing $bindir/$bin" >&2; exit 66; }
done

mkdir -p "$out"
cfg="$(mktemp)"
trap 'rm -f "$cfg"' EXIT
sed -e "s|@ARCH@|$arch|g" -e "s|@VERSION@|$version|g" -e "s|@RELEASE@|$release|g" \
    -e "s|@BINDIR@|$bindir|g" -e "s|@ROOT@|$root|g" "$here/nfpm.yaml.in" >"$cfg"
for packager in deb rpm; do
    nfpm package --config "$cfg" --packager "$packager" --target "$out/"
done
ls -l "$out"
