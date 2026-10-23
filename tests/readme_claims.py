#!/usr/bin/env python3
"""README claims check (docs/design/phase-11.md §5).

- Every list item between `<!-- claims:begin -->` and `<!-- claims:end -->`
  in README.md links to at least one `docs/evidence.md#<criterion>`.
- Every `evidence.md#<criterion>` link in README.md and docs/*.md names a
  criterion that exists in tests/traceability.toml.
- Outside the claims blocks and code blocks, README.md states no performance
  number and none of the listed superlatives.

    readme_claims.py [ROOT]

Exits 1 on any problem. Standard library only.
"""

import pathlib
import re
import sys
import tomllib

EVIDENCE = re.compile(r"evidence\.md#([A-Za-z0-9_-]+)")
PERF_NUMBER = re.compile(
    r"\d+(?:[.,]\d+)?\s*(?:ms|µs|us|ns|%|x faster|×|events/s|ops/s|req/s)\b|"
    r"[<>≤≥~]\s*\d+(?:\.\d+)?\s*(?:ms|µs|us|ns)\b",
    re.IGNORECASE,
)
SUPERLATIVES = (
    "sub-millisecond", "zero overhead", "zero perceptible", "no overhead", "guarantee",
    "unbreakable", "bulletproof", "impossible to bypass", "cannot be bypassed",
    "military-grade", "blazing", "100% secure",
)


def criteria(root):
    with open(root / "tests" / "traceability.toml", "rb") as f:
        return {c["id"] for c in tomllib.load(f).get("criterion", [])}


def strip_code(text):
    """The prose: fenced code blocks, inline code and URLs removed (badge
    URLs are full of percent-encoded characters)."""
    text = re.sub(r"^```.*?^```", "", text, flags=re.MULTILINE | re.DOTALL)
    text = re.sub(r"`[^`\n]*`", "", text)
    return re.sub(r"\(\S+?\)|https?://\S+", "", text)


def claims_blocks(text):
    return re.findall(r"<!-- claims:begin -->(.*?)<!-- claims:end -->", text, flags=re.DOTALL)


def check(root):
    known = criteria(root)
    problems = []
    readme = (root / "README.md").read_text(encoding="utf-8")

    blocks = claims_blocks(readme)
    if not blocks:
        problems.append("README.md has no claims block")
    for block in blocks:
        for item in re.findall(r"^- (.+)$", block, flags=re.MULTILINE):
            if not EVIDENCE.search(item):
                problems.append(f"claim without evidence: {item[:80]}")

    for path in [root / "README.md", *sorted((root / "docs").glob("*.md"))]:
        for crit in EVIDENCE.findall(path.read_text(encoding="utf-8")):
            if crit not in known:
                problems.append(f"{path.relative_to(root)}: evidence link to unknown criterion `{crit}`")

    outside = strip_code(re.sub(r"<!-- claims:begin -->.*?<!-- claims:end -->", "", readme, flags=re.DOTALL))
    for m in PERF_NUMBER.finditer(outside):
        problems.append(f"performance number outside the claims block: `{m.group(0)}`")
    lowered = outside.lower()
    for word in SUPERLATIVES:
        if word in lowered:
            problems.append(f"unsupported superlative in README.md: `{word}`")
    return problems


def main(argv):
    root = pathlib.Path(argv[1]) if len(argv) > 1 else pathlib.Path(__file__).resolve().parents[1]
    problems = check(root)
    for p in problems:
        print(f"::error::{p}")
    print(f"{len(problems)} problem(s)" if problems else "every README claim links to evidence")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
