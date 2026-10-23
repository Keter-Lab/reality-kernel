"""Unit tests for tests/readme_claims.py (docs/design/phase-11.md §5)."""

import importlib.util
import pathlib

_spec = importlib.util.spec_from_file_location(
    "readme_claims", pathlib.Path(__file__).parent / "readme_claims.py"
)
rc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rc)

TOML = '[[criterion]]\nphase = "2"\nid = "net-enforce-eperm"\ntext = "t"\ntests = ["ci:x"]\n'


def repo(tmp_path, readme, doc=""):
    (tmp_path / "tests").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / "tests" / "traceability.toml").write_text(TOML)
    (tmp_path / "README.md").write_text(readme, encoding="utf-8")
    (tmp_path / "docs" / "threat-model.md").write_text(doc, encoding="utf-8")
    return tmp_path


GOOD = """# X

Prose without numbers.

<!-- claims:begin -->
- Denies connects. [evidence](docs/evidence.md#net-enforce-eperm)
<!-- claims:end -->

```sh
time rk run   # 3 ms in a code block is fine
```
"""


def test_readme_claims_have_evidence():
    """The real README and docs pass."""
    assert rc.check(pathlib.Path(__file__).resolve().parents[1]) == []


def test_good_readme_passes(tmp_path):
    assert rc.check(repo(tmp_path, GOOD)) == []


def test_claim_without_evidence_fails(tmp_path):
    bad = GOOD.replace("- Denies connects.", "- Blocks everything.\n- Denies connects.")
    assert any("claim without evidence" in p for p in rc.check(repo(tmp_path, bad)))


def test_unknown_criterion_fails_in_readme_and_docs(tmp_path):
    problems = rc.check(repo(tmp_path, GOOD, doc="see [x](evidence.md#no-such-thing)"))
    assert any("unknown criterion `no-such-thing`" in p for p in problems)


def test_urls_are_not_prose(tmp_path):
    badge = GOOD + "\n[![k](https://img.shields.io/badge/kernels%205.15%E2%80%936.18-x)](https://example.com/a%20b)\n"
    assert rc.check(repo(tmp_path, badge)) == []


def test_numbers_and_superlatives_outside_claims_fail(tmp_path):
    bad = GOOD.replace("Prose without numbers.", "Decides in < 1ms with zero overhead, 40% faster.")
    problems = rc.check(repo(tmp_path, bad))
    assert any("performance number" in p for p in problems)
    assert any("zero overhead" in p for p in problems)
