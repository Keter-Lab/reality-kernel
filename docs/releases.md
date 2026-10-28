# Releases

How Reality Kernel is versioned and released, how long a release is
supported, and how to check that what you downloaded was built by this
repository. Changes per release: [CHANGELOG.md](../CHANGELOG.md).

## What a release contains

A release `vX.Y.Z` is built by [`release.yml`](../.github/workflows/release.yml)
from the tag, on GitHub-hosted runners, and contains:

| File | What |
|---|---|
| `reality-kernel_X.Y.Z-1_{amd64,arm64}.deb` | Debian and Ubuntu packages |
| `reality-kernel-X.Y.Z-1.{x86_64,aarch64}.rpm` | RHEL, Rocky, Alma and Fedora packages |
| `reality-kernel-X.Y.Z-linux-{amd64,arm64}.tar.gz` | Static binaries, systemd unit, example policy, docs |
| `reality-kernel-X.Y.Z.tgz` | Helm chart |
| `reality-kernel-X.Y.Z.spdx.json` | SPDX SBOM, from the Rust and Go lock files the release was built from |
| `SHA256SUMS` | Checksums of the artifacts above |
| `*.sigstore.json` | A Sigstore signature bundle for every file |
| `reality-kernel-X.Y.Z.intoto.jsonl` | The SLSA build provenance bundle, for offline verification |

And the image `ghcr.io/keter-lab/reality-kernel:X.Y.Z` (linux/amd64,
linux/arm64), signed, with its SBOM and provenance attached as attestations.

Before the release is drafted, the workflow verifies every signature,
provenance attestation and SBOM attestation it produced, with the same
commands as below. A release with a gap is never drafted.

## Verifying a release

You need [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
2.0 or newer and the [GitHub CLI](https://cli.github.com/). Nothing to
trust in advance: signatures are keyless and bound to this repository's
release workflow at that tag.

```sh
VERSION=0.3.0
gh release download "v$VERSION" --repo Keter-Lab/reality-kernel
IDENTITY="https://github.com/Keter-Lab/reality-kernel/.github/workflows/release.yml@refs/tags/v$VERSION"
ISSUER=https://token.actions.githubusercontent.com

# 1. Checksums
sha256sum -c SHA256SUMS

# 2. Signature: signed by this repository's release workflow, at this tag
f="reality-kernel_${VERSION}-1_amd64.deb"
cosign verify-blob --bundle "$f.sigstore.json" \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$f"

# 3. SLSA build provenance and SBOM attestations
gh attestation verify "$f" --repo Keter-Lab/reality-kernel
gh attestation verify "$f" --repo Keter-Lab/reality-kernel \
  --predicate-type https://spdx.dev/Document/v2.3

# Offline, with the provenance bundle from the release
gh attestation verify "$f" --repo Keter-Lab/reality-kernel \
  --bundle "reality-kernel-$VERSION.intoto.jsonl"
```

The container image:

```sh
IMAGE=ghcr.io/keter-lab/reality-kernel:$VERSION
cosign verify "$IMAGE" --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER"
cosign verify-attestation "$IMAGE" --type spdxjson \
  --certificate-identity "$IDENTITY" --certificate-oidc-issuer "$ISSUER" > /dev/null
gh attestation verify "oci://$IMAGE" --repo Keter-Lab/reality-kernel
```

To admit only signed images to a cluster, use a Sigstore admission
controller (for example the Sigstore policy-controller or Kyverno) with the
same identity and issuer.

## Versioning

[Semantic Versioning](https://semver.org/):

| Component | Version | Notes |
|---|---|---|
| Sensor, kernel programs, CLI, NRI plugin, Helm chart, image | one version, from `Cargo.toml` | Released together; the release workflow refuses a tag that differs from the workspace version |
| Website | not versioned | |

While the version is 0.x:

- a **patch** release (0.1.1) fixes bugs and security issues. It never
  changes the policy format, the agentd protocol, the audit record format
  or the pin layout in an incompatible way;
- a **minor** release (0.2.0) may. Every incompatible change is listed in
  the changelog under "Changed" or "Removed" with what to do about it.

Upgrades within a supported line are tested in CI: the new sensor replaces
the old kernel programs make-before-break, without a protection gap
([ADR-0015](decisions/0015-make-before-break-upgrades.md)).

From 1.0 on, an incompatible change needs a major version.

## Cadence and support

- Minor releases when a body of work lands; patch releases as needed, and
  promptly for security fixes ([SECURITY.md](../SECURITY.md)).
- While the version is 0.x, the latest minor version is supported: it
  receives bug and security fixes. Upgrade to the newest patch release of it.
- From 1.0 on, the previous minor version also receives security fixes for
  six months after a new minor version is released.

## Making a release (maintainers)

1. In a pull request: set the version in `Cargo.toml` (`[workspace.package]`)
   and `deploy/helm/reality-kernel/Chart.yaml`, and move the changelog's
   "Unreleased" entries under the new version with today's date. Merge it.
2. Tag the merge commit on `main` and push the tag:

   ```sh
   git switch main && git pull
   git tag -a v0.3.0 -m "Reality Kernel 0.3.0"
   git push origin v0.3.0
   ```

3. The Release workflow builds, signs, attests, verifies and drafts the
   release. Review the draft (files, notes) and publish it.

If a job fails for a transient reason (a network error, a registry
timeout), use **Re-run failed jobs** on the workflow run: it re-runs from
the same tag. If the failure needs a code change, and the release has not
been published, delete the draft release and the tag
(`git push --delete origin v0.1.0`, `git tag -d v0.1.0`), fix it on `main`
through a pull request, and tag again. A published release and its tag are
never changed: a fix ships as the next patch version.
