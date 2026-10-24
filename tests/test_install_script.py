"""The one-command installer, public/install.sh (docs/design/adoption.md §3.1).

Served unchanged by the website at https://realitykernel.dev/install.sh.
"""

import hashlib
import pathlib
import platform
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "public" / "install.sh"


def text():
    return SCRIPT.read_text(encoding="utf-8")


def test_install_script_pins_the_release_identity():
    t = text()
    # Same identity and issuer as docs/releases.md: a package signed by any
    # other workflow, repository or tag is refused.
    assert 'REPO="Keter-Lab/reality-kernel"' in t
    assert 'identity="https://github.com/$REPO/.github/workflows/release.yml@refs/tags/v$version"' in t
    assert 'ISSUER="https://token.actions.githubusercontent.com"' in t
    assert "--certificate-identity \"$identity\"" in t
    releases = (ROOT / "docs" / "releases.md").read_text(encoding="utf-8")
    assert ".github/workflows/release.yml@refs/tags/v$VERSION" in releases


def test_install_script_checks_before_it_installs():
    t = text()
    checksum = t.index("sha256sum -c")
    signature = t.index("cosign verify-blob")
    install = t.index('dpkg -i "$tmp/$pkg"')
    assert checksum < signature < install
    assert t.index('rpm -Uvh "$tmp/$pkg"') > signature
    # A dry run stops after the checks.
    assert t.index('if [ "$dry_run" -eq 1 ]') < install


def test_install_script_is_posix_sh():
    t = text()
    assert t.startswith("#!/bin/sh\n")
    assert "set -eu" in t
    code = "\n".join(l for l in t.splitlines() if not l.lstrip().startswith("#"))
    for bashism in ("[[", "<<<", "function ", "local ", "$'"):
        assert bashism not in code, bashism
    sh = shutil.which("sh")
    if sh:
        subprocess.run([sh, "-n", str(SCRIPT)], check=True)


@pytest.mark.skipif(
    platform.system() != "Linux"
    or platform.machine() not in ("x86_64", "amd64")
    or not (shutil.which("dpkg") and shutil.which("apt-get") and shutil.which("sha256sum")),
    reason="needs a Debian-family x86_64 host (the CI runner)",
)
def test_install_script_refuses_a_tampered_package(tmp_path):
    name = "reality-kernel_9.9.9-1_amd64.deb"
    good = tmp_path / "good"
    good.mkdir()
    (good / name).write_bytes(b"not really a package\n")
    digest = hashlib.sha256((good / name).read_bytes()).hexdigest()
    (good / "SHA256SUMS").write_text(f"{digest}  {name}\n")
    run = lambda d: subprocess.run(  # noqa: E731
        ["sh", str(SCRIPT), "--from", str(d), "--dry-run"],
        capture_output=True,
        text=True,
    )
    ok = run(good)
    assert ok.returncode == 0, ok.stderr
    assert "checksum ok" in ok.stderr
    assert "verified, not installed" in ok.stderr

    bad = tmp_path / "bad"
    shutil.copytree(good, bad)
    with open(bad / name, "ab") as f:
        f.write(b"x")
    refused = run(bad)
    assert refused.returncode != 0
    assert "does not match its SHA256SUMS entry" in refused.stderr

    unlisted = tmp_path / "unlisted"
    shutil.copytree(good, unlisted)
    (unlisted / "SHA256SUMS").write_text(f"{digest}  something-else.deb\n")
    refused = run(unlisted)
    assert refused.returncode != 0
    assert "not listed in SHA256SUMS" in refused.stderr
