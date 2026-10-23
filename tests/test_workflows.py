"""Supply-chain properties of the GitHub workflows (docs/design/phase-11.md §4).

The release workflow only runs on tags, so these static checks are what
keep a later edit from silently dropping a signature, attestation or
verification step.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))


def top_level_block(text, key):
    """The lines of a top-level YAML key, up to the next top-level key."""
    m = re.search(rf"^{key}:.*(?:\n(?:[ #].*|))*", text, re.MULTILINE)
    return m.group(0) if m else None


def test_actions_pinned_by_commit_sha():
    unpinned = []
    for wf in WORKFLOWS:
        for n, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            m = re.search(r"\buses:\s*(\S+)", line)
            if m and not m.group(1).startswith(("./", "docker://")):
                if not re.search(r"@[0-9a-f]{40}$", m.group(1)):
                    unpinned.append(f"{wf.name}:{n}: {m.group(1)}")
    assert WORKFLOWS
    assert unpinned == []


def test_default_token_permissions_are_read_only():
    for wf in WORKFLOWS:
        block = top_level_block(wf.read_text(encoding="utf-8"), "permissions")
        assert block is not None, f"{wf.name}: no top-level permissions"
        assert "write" not in block, f"{wf.name}: write scope at the top level"


def test_release_signs_attests_and_verifies_every_artifact():
    text = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    required = [
        # every file signed, one SBOM, provenance and SBOM attestations
        'for f in dist/*; do\n            cosign sign-blob --yes --bundle "$f.sigstore.json" "$f"',
        "syft scan dir:sbom-src",
        "actions/attest-build-provenance@",
        "subject-checksums: dist/SHA256SUMS",
        "actions/attest-sbom@",
        # the image signed and its SBOM attached
        'cosign sign --yes "$IMAGE@$digest"',
        "cosign attest --yes --type spdxjson",
        # everything verified against this repository's release workflow
        r"identity='^https://github\.com/Keter-Lab/reality-kernel/\.github/workflows/release\.yml@refs/tags/v.*$'",
        "for f in $(awk '{print $2}' dist/SHA256SUMS); do",
        "cosign verify-blob --bundle",
        'gh attestation verify "dist/$f" --repo "$GITHUB_REPOSITORY"\n',
        "--predicate-type https://spdx.dev/Document/v2.3",
        'cosign verify "$IMAGE:$VERSION"',
        "cosign verify-attestation",
        'gh attestation verify "oci://$IMAGE:$VERSION"',
    ]
    missing = [r for r in required if r not in text]
    assert missing == []
    # Nothing is drafted before it is verified.
    assert text.index("- name: Verify every artifact") < text.index("- name: Draft the GitHub release")
