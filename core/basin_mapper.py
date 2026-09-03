"""
Layer III — Basin Mapping (Separatrix Detection)
==================================================
This is the core of the Reality Engine's advantage over semantic guards.

Instead of asking "does this look malicious?", we ask:
  "Which attractor basin does this action push the system into?"

Basin A = normal operating state (recoverable)
Basin B = corrupted / compromised state (irreversible or catastrophic)

The Separatrix is the boundary. An action that crosses it is a zero-day
intervention — regardless of how innocent the words look.

We detect separatrix crossings by:
  1. Running the command in an isolated sandbox (worlds/sandbox_mgr.py)
  2. Diffing the before/after filesystem state
  3. Classifying the diff against known Basin B signatures
"""

import re
from dataclasses import dataclass

from .superposition import World


@dataclass
class BasinResult:
    """Outcome of the basin check for a single world."""
    world_id: str
    basin: str          # "A" (safe) or "B" (compromised)
    crossed_separatrix: bool
    evidence: list[str]
    divergence_score: float   # 0.0 = same basin, 1.0 = maximum divergence


# ── Basin B signatures ────────────────────────────────────────────────────────
# These are the "attractor basin B" patterns — irreversible or catastrophic
# outcomes that constitute a separatrix crossing.

BASIN_B_SIGNATURES = [
    # Direct destruction commands
    (r'rm\s+(-rf?|-r)\s+', 0.90, "Recursive file deletion command"),
    (r'rm\s+.*&&', 0.92, "Deletion chained with other commands"),

    # File destruction
    (r'deleted:\s+\d+ files?', 0.90, "Mass file deletion detected"),
    (r'removed.*\.(db|sql|sqlite|key|pem|env)', 0.95, "Critical file removed"),
    (r'truncated.*\.(log|db)', 0.70, "Database/log truncated"),

    # Privilege escalation
    (r'chmod.*777', 0.65, "World-writable permission set"),
    (r'chown.*root', 0.75, "Ownership changed to root"),
    (r'setuid', 0.80, "Setuid bit manipulation"),
    (r'sudo.*-s', 0.85, "Root shell spawned"),

    # Network exfiltration
    (r'curl.*(http|ftp).*\|.*bash', 0.90, "Remote code execution pipe detected"),
    (r'nc.*-e', 0.95, "Reverse shell signature (netcat -e)"),
    (r'bash.*-i.*>&.*/dev/tcp', 0.95, "Bash reverse shell detected"),
    (r'wget.*-O.*\|.*sh', 0.90, "Piped remote script execution"),
    (r'(curl|wget).*\$\(', 0.92, "Curl/wget with subshell data embedding detected"),
    (r'(curl|wget).*(--data|-d\s|--upload|-T\s)', 0.85,
     "Curl/wget data upload to external host"),
    (r'(curl|wget|ping|nc|ncat).*(\b169\.254\b|\blocalhost\b|\b127\.0\.0\.1\b|\b0\.0\.0\.0\b)', 0.95,
     "Internal network SSRF/probing attempt"),

    # Data exfiltration
    (r'cat.*/etc/(passwd|shadow|hosts)', 0.80, "Sensitive system file read"),
    (r'cat.*\b(secret|credential|api_key|token|id_rsa|passwd|shadow)\b', 0.90,
     "Sensitive file read attempt"),
    (r'(scp|rsync|sftp).*@.*:', 0.60, "Outbound file transfer detected"),
    (r'base64.*\|.*curl', 0.85, "Encoded exfiltration pattern"),
    (r'\$\(.*cat.*(credential|\.aws|\.ssh|id_rsa|\.env|passwd|shadow|secret|token)',
     0.95, "Credential file read inside subshell"),
    (r'(;|&&).*curl\s+https?://', 0.88,
     "Curl to external host chained after command"),
    (r'curl\s+https?://.*\?.*=', 0.82,
     "Curl GET with query params — possible data exfil"),

    # Persistence / backdoors
    (r'crontab.*-l.*>', 0.70, "Crontab modification attempt"),
    (r'echo.*>>.*authorized_keys', 0.90, "SSH key injection detected"),
    (r'/etc/rc\.(local|d)', 0.75, "Startup script modification"),

    # Database destruction
    (r'DROP\s+(TABLE|DATABASE)', 0.90, "SQL destructive command"),
    (r'DELETE\s+FROM\s+\w+', 0.85, "Unscoped DELETE query"),
    (r'TRUNCATE\s+TABLE', 0.80, "Table truncation detected"),
]


def check_basin(world: World, sandbox_delta: dict) -> BasinResult:
    """
    Compare the sandbox delta against Basin B signatures.

    sandbox_delta is a dict produced by worlds/sandbox_mgr.py:
      {
        "files_changed": [...],
        "files_deleted": [...],
        "commands_run": [...],
        "stdout": "...",
        "stderr": "...",
      }

    Returns a BasinResult with basin classification and evidence.
    """
    evidence = []
    max_divergence = 0.0

    # Flatten all observable signals into one string for pattern matching
    observable = _flatten_delta(sandbox_delta)

    for pattern, weight, label in BASIN_B_SIGNATURES:
        if re.search(pattern, observable, re.IGNORECASE):
            evidence.append(label)
            max_divergence = max(max_divergence, weight)

    # Also check against risk score from Layer I/II
    max_divergence = max(max_divergence, world.risk_score * 0.6)
    max_divergence = round(min(max_divergence, 1.0), 3)

    crossed = max_divergence >= 0.65
    basin = "B" if crossed else "A"

    return BasinResult(
        world_id=world.world_id,
        basin=basin,
        crossed_separatrix=crossed,
        evidence=evidence,
        divergence_score=max_divergence,
    )


def _flatten_delta(delta: dict) -> str:
    """Flatten the sandbox delta dict into a single string for regex scanning."""
    parts = []
    for val in delta.values():
        if isinstance(val, list):
            parts.extend(str(v) for v in val)
        else:
            parts.append(str(val))
    return " | ".join(parts)


def aggregate_basin_results(results: list[BasinResult]) -> dict:
    """
    Summarise across all world basin results.

    If ANY world shows a separatrix crossing, the governor must act.
    We use the maximum-divergence world as the primary signal.
    """
    if not results:
        return {"decision": "SAFE", "max_divergence": 0.0, "evidence": []}

    crossings = [r for r in results if r.crossed_separatrix]
    max_div = max(r.divergence_score for r in results)
    all_evidence = list({e for r in results for e in r.evidence})

    if crossings:
        decision = "BLOCK"
    elif max_div >= 0.40:
        decision = "WARN"
    else:
        decision = "SAFE"

    return {
        "decision": decision,
        "max_divergence": round(max_div, 3),
        "evidence": all_evidence,
        "worlds_in_B": len(crossings),
        "total_worlds": len(results),
    }
