"""
Layer IV — Reflexive Collapse (The Governor)
=============================================
The engine accounts for its OWN footprint as a perturbative force.

The Governor is the inhibitory layer — the pre-frontal cortex.
When Layer III signals a separatrix crossing, Layer IV:
  1. Blocks the action (SIGKILL or API rejection)
  2. Logs the incident with cryptographic proof
  3. Returns a "Reflexive Rejection" — an explanation that does NOT
     reveal the detection logic (so adversaries can't tune around it)
  4. Optionally requests human approval for borderline cases

This is "Reflexive" because the engine recognises that its own
intervention changes the system state — blocking the action IS an
action, and it should be treated as such (logged, auditable, reversible).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import signal
import sys
import time
from dataclasses import dataclass


@dataclass
class GovernorDecision:
    """The final output of the Reality Engine for a given agent action."""
    action_id: str
    timestamp: float
    original_command: str
    prime_intent: str
    verdict: str          # ALLOW | WARN | BLOCK
    confidence: float
    evidence: list[str]
    worlds_evaluated: int
    worlds_in_basin_b: int
    max_divergence: float
    proof_hash: str = ""         # SHA256 of the decision record
    agent_pid: int | None = None


# ── ANSI colours for CLI output ───────────────────────────────────────────────
_RED    = "\033[38;5;196m"
_AMBER  = "\033[38;5;214m"
_GREEN  = "\033[38;5;82m"
_CYAN   = "\033[38;5;51m"
_WHITE  = "\033[97m"
_DIM    = "\033[2m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"


def evaluate(
    command: str,
    prime_intent: str,
    basin_summary: dict,
    worlds_count: int,
    static_floor: float = 0.0,
    evidence_count: int = 0,
    agent_pid: int | None = None,
    suppress_audit: bool = False,
) -> GovernorDecision:
    """
    Layer IV: Make the final ALLOW / WARN / BLOCK decision and
    optionally kill the agent process.

    suppress_audit=True: skip the governor-level audit write.
    Set by api.py so the richer API-layer entry (with key_hint /
    session_id / agent_id) is the single source of truth.
    """
    decision_str = basin_summary.get("decision", "SAFE")
    max_div      = basin_summary.get("max_divergence", 0.0)
    evidence     = basin_summary.get("evidence", [])
    worlds_b     = basin_summary.get("worlds_in_B", 0)

    verdict    = _map_decision(decision_str, max_div)
    
    total_evidence_count = evidence_count + len(evidence)
    confidence = _compute_confidence(max_div, worlds_b, worlds_count, static_floor, total_evidence_count)

    action_id = hashlib.sha256(
        f"{command}:{prime_intent}:{time.time()}".encode()
    ).hexdigest()[:12]

    decision = GovernorDecision(
        action_id=action_id,
        timestamp=time.time(),
        original_command=command,
        prime_intent=prime_intent,
        verdict=verdict,
        confidence=confidence,
        evidence=evidence,
        worlds_evaluated=worlds_count,
        worlds_in_basin_b=worlds_b,
        max_divergence=max_div,
        agent_pid=agent_pid,
    )

    # Generate proof hash (tamper-evident log)
    record = {
        "id": action_id,
        "ts": decision.timestamp,
        "cmd": command,
        "intent": prime_intent,
        "verdict": verdict,
        "div": max_div,
    }
    decision.proof_hash = hashlib.sha256(
        json.dumps(record, sort_keys=True).encode()
    ).hexdigest()

    # Write tamper-evident audit log
    # (suppress when API layer writes its own richer entry)
    _write_audit_log(
        record | {"proof": decision.proof_hash, "verdict": verdict},
        suppress=suppress_audit,
    )

    # Act on the decision
    if verdict == "BLOCK" and agent_pid:
        _terminate_agent(agent_pid)

    return decision


def _map_decision(decision_str: str, max_div: float) -> str:
    if decision_str == "BLOCK" or max_div >= 0.90:
        return "BLOCK"
    elif decision_str == "WARN" or max_div >= 0.50:
        return "WARN"
    return "ALLOW"


def _compute_confidence(max_div: float, worlds_b: int, total: int, static_floor: float, evidence_count: int) -> float:
    """Confidence in the block decision (0.0-1.0)."""
    if total == 0:
        return max(static_floor, 0.0)
    world_ratio = worlds_b / total
    evidence_factor = min(evidence_count * 0.05, 0.15)
    raw_calculated = (max_div * 0.60) + (world_ratio * 0.40) + evidence_factor
    return round(min(max(raw_calculated, static_floor), 1.0), 3)


def _write_audit_log(record: dict, suppress: bool = False):
    """Append decision record to tamper-evident JSONL audit log.

    suppress=True is passed by api.py so that the richer API-level audit
    entry (which includes key_hint, session_id, agent_id) is the single
    source of truth, and we don't write a duplicate governor-level entry
    that lacks that context.
    """
    if suppress:
        return
    try:
        with open("rk_audit.jsonl", "a") as f:
            json.dump(record, f, sort_keys=True)
            f.write("\n")
    except OSError as e:
        print(f"[rk-α] audit-log write skipped: {e}", file=sys.stderr)


def _terminate_agent(pid: int):
    """Send SIGKILL to the agent process."""
    # already dead, or not ours to kill — safe to ignore
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.kill(pid, signal.SIGKILL)


def render_decision(decision: GovernorDecision) -> str:
    """
    Render the Governor decision to a rich terminal string.
    Matches the 'DM Mono' / dark aesthetic of the Reality Engine paper.
    """
    lines = []

    # Header
    lines.append(f"\n{_DIM}{'─'*64}{_RESET}")
    lines.append(
        f"{_BOLD}{_CYAN}[ RK-α · GOVERNOR DECISION ]{_RESET}  "
        f"{_DIM}id:{decision.action_id}  ts:{decision.timestamp:.2f}{_RESET}"
    )
    lines.append(f"{_DIM}{'─'*64}{_RESET}")

    # Intent vs command
    lines.append(
        f"  {_DIM}PRIME INTENT{_RESET}  "
        f"{_WHITE}{decision.prime_intent}{_RESET}"
    )
    lines.append(
        f"  {_DIM}INTERCEPTED {_RESET}  "
        f"{_WHITE}{decision.original_command}{_RESET}"
    )
    lines.append("")

    # World statistics
    lines.append(
        f"  {_DIM}WORLDS      {_RESET}  "
        f"{_WHITE}{decision.worlds_evaluated}{_RESET} evaluated  "
        f"{_AMBER if decision.worlds_in_basin_b > 0 else _GREEN}"
        f"{decision.worlds_in_basin_b} in Basin B{_RESET}"
    )
    div_colour = _RED if decision.max_divergence >= 0.65 else _AMBER
    lines.append(
        f"  {_DIM}DIVERGENCE  {_RESET}  "
        f"{_divergence_bar(decision.max_divergence)}  "
        f"{div_colour}{decision.max_divergence:.3f}{_RESET}"
    )
    lines.append("")

    # Evidence
    if decision.evidence:
        lines.append(f"  {_DIM}EVIDENCE{_RESET}")
        for e in decision.evidence:
            lines.append(f"    {_AMBER}⚠{_RESET}  {e}")
        lines.append("")

    # Verdict banner
    if decision.verdict == "BLOCK":
        lines.append(
            f"  {_RED}{_BOLD}█ REFLEXIVE COLLAPSE TRIGGERED{_RESET}"
        )
        lines.append(
            f"  {_RED}  Action blocked. Confidence: {decision.confidence:.0%}{_RESET}"
        )
        if decision.agent_pid:
            lines.append(
                f"  {_DIM}  SIGKILL → PID {decision.agent_pid}{_RESET}"
            )
    elif decision.verdict == "WARN":
        lines.append(
            f"  {_AMBER}{_BOLD}▲ SUSPICIOUS TRAJECTORY — HUMAN REVIEW REQUIRED{_RESET}"
        )
        lines.append(
            f"  {_AMBER}  Action paused. Confidence: {decision.confidence:.0%}{_RESET}"
        )
    elif "REJECT" in decision.verdict:
        lines.append(
            f"  {_RED}{_BOLD}█ COMMAND REJECTED{_RESET}"
        )
        lines.append(
            f"  {_RED}  {decision.verdict}{_RESET}"
        )
    else:
        lines.append(
            f"  {_GREEN}{_BOLD}✓ BASIN A — ACTION PERMITTED{_RESET}"
        )
        lines.append(
            f"  {_GREEN}  No separatrix crossing detected.{_RESET}"
        )

    # Proof hash
    lines.append("")
    lines.append(
        f"  {_DIM}PROOF   {decision.proof_hash[:40]}...{_RESET}"
    )
    lines.append(f"{_DIM}{'─'*64}{_RESET}\n")

    return "\n".join(lines)


def _divergence_bar(score: float, width: int = 20) -> str:
    filled = int(score * width)
    empty  = width - filled
    if score >= 0.65:
        colour = _RED
    elif score >= 0.40:
        colour = _AMBER
    else:
        colour = _GREEN
    return f"{colour}{'█'*filled}{'░'*empty}{_RESET}"
