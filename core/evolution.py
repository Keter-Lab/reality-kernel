"""
Layer II — Evolutionary Selection
====================================
Worlds compete. Low-fitness worlds are eliminated.
Surviving worlds are mutated to cover adjacent hypotheses.

Fixes in v0.3.1:
  - _semantic_alignment replaced with _intent_schema_match():
    Extracts a structured intent schema (allowed operation types, allowed
    data scope) from the prime_intent, maps the command onto the same schema,
    and computes a deterministic set-intersection score.
    This is the "intent vector / set-intersection" described in the pitch.
    It is NOT another LLM call — it is pure rule-based classification.
  - mutate_worlds() is now a real implementation: SUSPICIOUS worlds
    spawn an escalated variant (H_DESTROY) added to the world list.
    Previously this was a stub that only wrote a note.
"""

import re

from .superposition import HYPOTHESES, World, _initial_risk

ELIMINATION_THRESHOLD  = 0.15
CRITICAL_RISK_THRESHOLD = 0.80


# ── Intent schema ─────────────────────────────────────────────────────────────
# Operation categories — map intent keywords and command tokens to types.
# This is the "permitted operation type" dimension of the intent vector.

_OP_READ    = {"read", "show", "list", "display", "cat", "view", "get",
               "fetch", "check", "inspect", "ls", "find", "search",
               "grep", "summarise", "summarize", "describe", "print",
               "log", "logs", "status", "tail", "head"}

_OP_WRITE   = {"write", "create", "update", "edit", "modify", "save",
               "append", "insert", "add", "set", "configure", "change"}

_OP_DELETE  = {"delete", "remove", "clean", "tidy", "purge", "wipe",
               "drop", "truncate", "rm", "erase", "clear"}

_OP_EXECUTE = {"run", "execute", "start", "launch", "deploy", "migrate",
               "install", "build", "compile", "test", "script", "bash",
               "python", "sh"}

_OP_NETWORK = {"send", "upload", "post", "transfer", "sync", "curl",
               "wget", "nc", "connect", "tunnel", "forward", "export",
               "push"}

_ALL_OP_SETS = {
    "READ":    _OP_READ,
    "WRITE":   _OP_WRITE,
    "DELETE":  _OP_DELETE,
    "EXECUTE": _OP_EXECUTE,
    "NETWORK": _OP_NETWORK,
}

# Scope keywords — what data/resource class is authorised
_SCOPE_LOG  = {"log", "logs", "error", "app", "access", "audit"}
_SCOPE_DB   = {"database", "db", "table", "record", "migration", "sql",
               "postgres", "mysql", "sqlite"}
_SCOPE_CONFIG = {"config", "configuration", "settings", "env", "environment",
                 "server", "json", "yaml", "ini"}
_SCOPE_CODE = {"code", "script", "file", "directory", "folder", "src",
               "source", "git", "repo", "build"}
_SCOPE_CRED = {"credential", "credentials", "secret", "key", "token",
               "password", "auth", "pem", "rsa", "ssh", "api_key"}
_SCOPE_NET  = {"network", "server", "connectivity", "connection", "host",
               "ping", "port", "socket", "tunnel"}

_ALL_SCOPE_SETS = {
    "LOGS":   _SCOPE_LOG,
    "DB":     _SCOPE_DB,
    "CONFIG": _SCOPE_CONFIG,
    "CODE":   _SCOPE_CODE,
    "CRED":   _SCOPE_CRED,
    "NET":    _SCOPE_NET,
}


def _tokenise(text: str) -> set:
    stops = {"the","a","an","to","in","on","of","and","or","for",
             "with","my","it","is","this","that","all","me","please",
             "can","you","i","we"}
    return set(re.findall(r'\b\w+\b', text.lower())) - stops


def _classify_ops(tokens: set) -> set:
    """Return the set of operation types present in a token set."""
    found = set()
    for op_name, op_set in _ALL_OP_SETS.items():
        if tokens & op_set:
            found.add(op_name)
    return found


def _classify_scope(tokens: set) -> set:
    """Return the set of data scope classes present in a token set."""
    found = set()
    for scope_name, scope_set in _ALL_SCOPE_SETS.items():
        if tokens & scope_set:
            found.add(scope_name)
    return found


def _intent_schema_match(command: str, prime_intent: str) -> float:
    """
    Deterministic intent-schema alignment score (0.0 – 0.30).

    1. Parse prime_intent → permitted_ops (set), permitted_scope (set)
    2. Parse command      → requested_ops (set), requested_scope (set)
    3. Compute:
         op_match    = |intent_ops ∩ cmd_ops|    / max(|intent_ops|, 1)
         scope_match = |intent_scope ∩ cmd_scope| / max(|intent_scope|, 1)
    4. Return weighted sum.

    This is set-intersection on structured schemas — not keyword frequency
    and not an LLM opinion.  You cannot sweet-talk a set intersection.
    """
    intent_tokens  = _tokenise(prime_intent)
    command_tokens = _tokenise(command)

    intent_ops   = _classify_ops(intent_tokens)
    command_ops  = _classify_ops(command_tokens)
    intent_scope = _classify_scope(intent_tokens)
    command_scope= _classify_scope(command_tokens)

    # If intent has no parseable ops/scope, fall back to 0 bonus
    if not intent_ops and not intent_scope:
        return 0.0

    op_overlap    = len(intent_ops & command_ops)
    scope_overlap = len(intent_scope & command_scope)

    op_score    = op_overlap    / max(len(intent_ops), 1)
    scope_score = scope_overlap / max(len(intent_scope), 1)

    # Escalation: command requests ops not in intent (scope creep signal)
    excess_ops   = command_ops - intent_ops
    excess_scope = command_scope - intent_scope

    # Penalise excess — DELETE not in intent is a red flag
    excess_penalty = 0.0
    if "DELETE" in excess_ops:
        excess_penalty += 0.15
    if "NETWORK" in excess_ops:
        excess_penalty += 0.15
    if "EXECUTE" in excess_ops and "EXECUTE" not in intent_ops:
        excess_penalty += 0.10
    if "CRED" in excess_scope:
        excess_penalty += 0.10

    raw_bonus = (op_score * 0.15) + (scope_score * 0.15) - excess_penalty
    return round(max(-0.20, min(raw_bonus, 0.30)), 3)


# ── Fitness ────────────────────────────────────────────────────────────────────

def compute_fitness(world: World) -> float:
    alignment_bonus    = _intent_schema_match(world.command, world.prime_intent)
    hypothesis_penalty = world.hypothesis["risk_prior"] * 0.4
    fitness = (1.0 - world.risk_score) + alignment_bonus - hypothesis_penalty
    return round(max(0.0, min(1.0, fitness)), 3)


def run_selection(worlds: list[World]) -> list[World]:
    for w in worlds:
        if not w.alive:
            continue
        w.fitness = compute_fitness(w)
        if w.risk_score >= CRITICAL_RISK_THRESHOLD:
            w.verdict = "CRITICAL"
        elif w.fitness < ELIMINATION_THRESHOLD:
            w.alive   = False
            w.verdict = "ELIMINATED"
        elif w.risk_score >= 0.5:
            w.verdict = "SUSPICIOUS"
        else:
            w.verdict = "SAFE"
    return worlds


def mutate_worlds(worlds: list[World]) -> list[World]:
    """
    Layer II mutation.

    Adversarial Escalation: If any world is flagged as SUSPICIOUS or CRITICAL,
    we ensure the destructive hypothesis (H_DESTROY) is fully activated and
    evaluated, even if it was previously eliminated or suppressed.
    """
    import hashlib
    import time

    signals = [w for w in worlds if w.alive and w.verdict in ("SUSPICIOUS", "CRITICAL")]
    if not signals:
        return worlds

    destroy_hyp = next(h for h in HYPOTHESES if h["id"] == "H_DESTROY")

    # Check if we already have a healthy H_DESTROY world.
    # BUG FIX from v0.4.1: ensure we don't spawn redundant worlds if one is
    # already active.
    has_active_destroy = any(
        w.alive and w.hypothesis["id"] == "H_DESTROY" for w in worlds
    )

    if not has_active_destroy:
        # Spawn a new high-risk world to test the separatrix boundary
        seed = f"MUT:ESC:{time.time()}"
        wid = hashlib.sha256(seed.encode()).hexdigest()[:12]
        mutant = World(
            world_id=wid,
            hypothesis=destroy_hyp,
            command=signals[0].command,
            prime_intent=signals[0].prime_intent,
        )
        # Ensure it starts with high risk prior
        mutant.risk_score = max(_initial_risk(mutant.command, destroy_hyp), 0.75)
        mutant.verdict = "MUTATED"
        worlds.append(mutant)

    return worlds
