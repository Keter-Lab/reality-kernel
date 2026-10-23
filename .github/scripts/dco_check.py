#!/usr/bin/env python3
"""DCO check (docs/design/phase-11.md decision 4): every commit in BASE..HEAD
carries a `Signed-off-by:` line with its author's email. Commits by bots
(autofix, Dependabot) are exempt. Standard library only.

    dco_check.py BASE HEAD
"""

import re
import subprocess
import sys

BOT = re.compile(r"\[bot\]@users\.noreply\.github\.com$")
SIGNOFF = re.compile(r"^Signed-off-by: .+ <([^>]+)>\s*$", re.MULTILINE)


def unsigned(commits):
    """(sha, author, email, message) -> the commits missing the author's sign-off."""
    bad = []
    for sha, author, email, message in commits:
        if BOT.search(email):
            continue
        if email.lower() not in (e.lower() for e in SIGNOFF.findall(message)):
            bad.append((sha, author, email))
    return bad


def commits_between(base, head):
    out = subprocess.run(
        ["git", "log", "--no-merges", "--format=%H%x00%an%x00%ae%x00%B%x1e", f"{base}..{head}"],
        check=True, capture_output=True, text=True,
    ).stdout
    for record in filter(str.strip, out.split("\x1e")):
        sha, author, email, message = record.strip("\n").split("\x00", 3)
        yield sha, author, email, message


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    bad = unsigned(commits_between(argv[1], argv[2]))
    for sha, author, email in bad:
        print(f"::error::commit {sha[:12]} by {author} <{email}> has no matching Signed-off-by line "
              "(use `git commit -s`; see CONTRIBUTING.md)")
    print(f"{len(bad)} commit(s) without sign-off" if bad else "every commit is signed off")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
