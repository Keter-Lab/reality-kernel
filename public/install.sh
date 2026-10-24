#!/bin/sh
# Reality Kernel installer (docs/install.md, docs/design/adoption.md §3.1).
#
#   curl -fsSL https://realitykernel.dev/install.sh | sh
#   sh install.sh [--version X.Y.Z] [--from DIR] [--dry-run]
#
# Downloads a release package for this host (deb or rpm), checks it against
# the release's SHA256SUMS and, when cosign is installed, checks its Sigstore
# signature against this repository's release workflow at that tag. Any
# failed check stops the install. Sends nothing anywhere; downloads only from
# github.com. --from DIR installs from local files with the same checks.
set -eu

REPO="Keter-Lab/reality-kernel"
ISSUER="https://token.actions.githubusercontent.com"

say() { printf 'rk-install: %s\n' "$*" >&2; }
die() {
    say "error: $*"
    exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
    sed -n '2,11p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'
}

version=""
from=""
dry_run=0
while [ $# -gt 0 ]; do
    case "$1" in
        --version) [ $# -ge 2 ] || die "--version needs a value"; version="$2"; shift 2 ;;
        --version=*) version="${1#*=}"; shift ;;
        --from) [ $# -ge 2 ] || die "--from needs a directory"; from="$2"; shift 2 ;;
        --from=*) from="${1#*=}"; shift ;;
        --dry-run) dry_run=1; shift ;;
        -h | --help) usage; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
done
version="${version#v}"

[ "$(uname -s)" = Linux ] || die "Reality Kernel runs on Linux only"
case "$(uname -m)" in
    x86_64 | amd64) deb_arch=amd64; rpm_arch=x86_64 ;;
    aarch64 | arm64) deb_arch=arm64; rpm_arch=aarch64 ;;
    *) die "unsupported architecture $(uname -m): amd64 and arm64 are built" ;;
esac
if [ -n "${KUBERNETES_SERVICE_HOST:-}" ]; then
    die "this looks like a Kubernetes pod: install with the Helm chart instead (docs/install.md)"
fi
if have dpkg && have apt-get; then
    format=deb
elif have rpm && { have dnf || have yum || have zypper; }; then
    format=rpm
else
    die "no dpkg or rpm here: install the static tarball by hand (docs/install.md)"
fi
have sha256sum || die "sha256sum is required (coreutils)"

if [ "$(id -u)" -eq 0 ]; then
    sudo=""
else
    have sudo || die "run as root, or install sudo"
    sudo="sudo"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

package_name() { # version
    case "$format" in
        deb) echo "reality-kernel_$1-1_$deb_arch.deb" ;;
        rpm) echo "reality-kernel-$1-1.$rpm_arch.rpm" ;;
    esac
}

if [ -n "$from" ]; then
    [ -d "$from" ] || die "--from $from: not a directory"
    if [ -z "$version" ]; then
        # The only release-1 package of this format and architecture.
        case "$format" in
            deb) pattern="reality-kernel_*-1_$deb_arch.deb" ;;
            rpm) pattern="reality-kernel-*-1.$rpm_arch.rpm" ;;
        esac
        found=""
        for f in "$from"/$pattern; do
            [ -e "$f" ] || continue
            [ -z "$found" ] || die "several packages in $from: pick one with --version"
            found="$(basename "$f")"
        done
        [ -n "$found" ] || die "no $format package for $deb_arch in $from"
        case "$format" in
            deb) version="${found#reality-kernel_}"; version="${version%-1_$deb_arch.deb}" ;;
            rpm) version="${found#reality-kernel-}"; version="${version%-1.$rpm_arch.rpm}" ;;
        esac
    fi
    pkg="$(package_name "$version")"
    for f in "$pkg" SHA256SUMS; do
        [ -f "$from/$f" ] || die "$from/$f is missing"
        cp "$from/$f" "$tmp/$f"
    done
    if [ -f "$from/$pkg.sigstore.json" ]; then
        cp "$from/$pkg.sigstore.json" "$tmp/"
    fi
else
    have curl || die "curl is required"
    if [ -z "$version" ]; then
        latest="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")" \
            || die "cannot reach github.com to find the latest release"
        version="${latest##*/v}"
        case "$version" in
            [0-9]*.[0-9]*.[0-9]*) ;;
            *) die "could not work out the latest version from $latest (use --version)" ;;
        esac
    fi
    pkg="$(package_name "$version")"
    base="https://github.com/$REPO/releases/download/v$version"
    say "downloading Reality Kernel $version ($pkg)"
    for f in "$pkg" SHA256SUMS "$pkg.sigstore.json"; do
        curl -fsSL --proto '=https' --tlsv1.2 -o "$tmp/$f" "$base/$f" \
            || die "download failed: $base/$f"
    done
fi

# 1. Checksum: the package must be listed in SHA256SUMS and match it.
grep -E "^[0-9a-f]{64}  $pkg\$" "$tmp/SHA256SUMS" >"$tmp/sum" \
    || die "$pkg is not listed in SHA256SUMS"
(cd "$tmp" && sha256sum -c sum >/dev/null 2>&1) \
    || die "$pkg does not match its SHA256SUMS entry: refusing to install"
say "checksum ok"

# 2. Signature: bound to this repository's release workflow at this tag.
identity="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/v$version"
if have cosign && [ -n "$from" ] && [ ! -f "$tmp/$pkg.sigstore.json" ]; then
    say "no $pkg.sigstore.json in $from: only the checksum was checked"
elif have cosign; then
    [ -f "$tmp/$pkg.sigstore.json" ] || die "cosign is installed but $pkg.sigstore.json is missing"
    cosign verify-blob --bundle "$tmp/$pkg.sigstore.json" \
        --certificate-identity "$identity" \
        --certificate-oidc-issuer "$ISSUER" "$tmp/$pkg" >/dev/null 2>&1 \
        || die "$pkg is not signed by $identity: refusing to install"
    say "signature ok: signed by the release workflow at v$version"
else
    say "cosign not found: only the checksum was checked, which catches a damaged"
    say "download but not a forged release. To check the signature too, install"
    say "cosign and run this again, or follow docs/releases.md."
fi

if [ "$dry_run" -eq 1 ]; then
    say "dry run: $pkg verified, not installed"
    exit 0
fi

# 3. Install.
case "$format" in
    deb) installed="$(dpkg-query -W -f='${Version}' reality-kernel 2>/dev/null || true)" ;;
    rpm) installed="$(rpm -q --qf '%{VERSION}-%{RELEASE}' reality-kernel 2>/dev/null || true)" ;;
esac
if [ "$installed" = "$version-1" ]; then
    say "Reality Kernel $version is already installed"
else
    say "installing $pkg"
    case "$format" in
        deb) $sudo dpkg -i "$tmp/$pkg" ;;
        rpm) $sudo rpm -Uvh "$tmp/$pkg" ;;
    esac
fi

if have rk; then
    rk doctor || say "rk doctor found problems: see above"
fi
if have rk && rk help init >/dev/null 2>&1; then
    cat >&2 <<'NEXT'

Next:
  sudo rk init                                   # a starter policy in AUDIT
  rk run --profile agent -- <your agent command>
  sudo rk policy suggest --profile agent --out agent.toml
Guide: https://github.com/Keter-Lab/reality-kernel/blob/main/docs/agents.md
NEXT
else
    # Releases before 0.2.0 have no `rk init`.
    cat >&2 <<'NEXT'

Next: define a profile in /etc/rk/policy.toml (docs/policy.md), then
  sudo systemctl reload rk-sensor
  rk run --profile <name> -- <your agent command>
Guide: https://github.com/Keter-Lab/reality-kernel/blob/main/docs/install.md
NEXT
fi
