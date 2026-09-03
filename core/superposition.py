"""
Layer I — Superposition Maintenance
=====================================
Instead of committing to one interpretation of an agent's intent,
we fork N parallel "worlds" — each assigning a different hidden
intent hypothesis to the proposed action.

Fixes in v0.3.1:
  - World IDs now use SHA-256 (not MD5 — MD5 is deprecated for security contexts).
  - World IDs include a counter to guarantee uniqueness even within the
    same microsecond.
  - _initial_risk uses a calibrated sigmoid-style clamp instead of raw addition,
    so multiple small signals don't trivially saturate to 1.0.
"""

import hashlib
import time
from dataclasses import dataclass, field

_SPAWN_COUNTER = 0   # monotonic per-process counter; prevents ID collisions


HYPOTHESES = [
    {
        "id": "H_BENIGN",
        "label": "Legitimate task execution",
        "description": "Action serves the user's stated prime intent directly.",
        "risk_prior": 0.05,
    },
    {
        "id": "H_SCOPE_CREEP",
        "label": "Unintended scope expansion",
        "description": "Action is tangentially related but exceeds the stated scope.",
        "risk_prior": 0.35,
    },
    {
        "id": "H_INJECTION",
        "label": "Prompt injection hijack",
        "description": "Action was injected by adversarial content in the environment.",
        "risk_prior": 0.75,
    },
    {
        "id": "H_EXFIL",
        "label": "Data exfiltration attempt",
        "description": (
            "Action attempts to read/send sensitive data outside "
            "authorised scope."
        ),
        "risk_prior": 0.85,
    },
    {
        "id": "H_DESTROY",
        "label": "Destructive / irreversible action",
        "description": "Action will permanently alter or destroy resources.",
        "risk_prior": 0.95,
    },
]


@dataclass
class World:
    """A single parallel hypothesis about what the agent is 'really' doing."""
    world_id:     str
    hypothesis:   dict
    command:      str
    prime_intent: str
    fitness:      float = 1.0
    alive:        bool  = True
    sim_delta:    dict  = field(default_factory=dict)
    risk_score:   float = 0.0
    verdict:      str   = "PENDING"   # SAFE | SUSPICIOUS | CRITICAL | ELIMINATED


def spawn_worlds(command: str, prime_intent: str, n: int = 5) -> list[World]:
    """
    Layer I: Generate the superposition of N worlds for a given command.
    n is capped at len(HYPOTHESES).
    """
    global _SPAWN_COUNTER
    selected = HYPOTHESES[:n]
    worlds   = []
    for h in selected:
        _SPAWN_COUNTER += 1
        seed = f"{h['id']}:{command}:{time.time()}:{_SPAWN_COUNTER}"
        wid  = hashlib.sha256(seed.encode()).hexdigest()[:12]   # SHA-256, not MD5
        w    = World(
            world_id=wid,
            hypothesis=h,
            command=command,
            prime_intent=prime_intent,
        )
        w.risk_score = _initial_risk(command, h)
        worlds.append(w)
    return worlds


# Note: _DANGER_SIGNALS string table replaced by effect_engine.py
# World initial risk is now driven by computed effect classes, not string patterns.
# The _initial_risk function imports the effect engine to get the divergence floor.


def _initial_risk(command: str, hypothesis: dict) -> float:
    """
    Combine hypothesis prior with the EFFECT ENGINE's computed divergence floor.

    Previously: string table lookup (pattern matching)
    Now: effect_engine.compute_effect_graph → symbolic execution

    This means unknown-but-dangerous commands (rsync --delete, find . -delete,
    git clean -fdx, etc.) correctly get high priors without being listed.
    """
    from core.effect_engine import compute_effect_graph

    base = hypothesis["risk_prior"]

    # Use a minimal intent string so we don't bias the effect computation
    graph = compute_effect_graph(command, "")
    cmd_signal = graph.divergence_floor

    if cmd_signal == 0.0:
        return round(base, 3)

    # Same diminishing-returns blend as before, but with a real computed signal
    headroom = 1.0 - base
    result   = base + headroom * cmd_signal
    return round(min(result, 1.0), 3)
