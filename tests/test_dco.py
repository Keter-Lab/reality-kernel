"""Unit tests for .github/scripts/dco_check.py."""

import importlib.util
import pathlib

_path = pathlib.Path(__file__).resolve().parents[1] / ".github" / "scripts" / "dco_check.py"
_spec = importlib.util.spec_from_file_location("dco_check", _path)
dco = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dco)

ME = "tabrez@realitykernel.dev"


def test_signed_off_commits_pass():
    commits = [("a" * 40, "Mohd Tabrez", ME, f"feat: x\n\nSigned-off-by: Mohd Tabrez <{ME}>\n")]
    assert dco.unsigned(commits) == []


def test_missing_or_foreign_sign_off_fails():
    commits = [
        ("b" * 40, "Mohd Tabrez", ME, "feat: no trailer\n"),
        ("c" * 40, "Mohd Tabrez", ME, "feat: x\n\nSigned-off-by: Someone <else@example.com>\n"),
    ]
    assert [sha[0] for sha, _, _ in dco.unsigned(commits)] == ["b", "c"]


def test_bot_commits_are_exempt():
    bot = "41898282+github-actions[bot]@users.noreply.github.com"
    assert dco.unsigned([("d" * 40, "github-actions[bot]", bot, "chore: autofix\n")]) == []
