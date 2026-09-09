"""
Static Capability Analyser
==========================
Zero-LLM parsing layer that independently evaluates command primitives.
Assigns a strict divergence floor (or absolute BLOCK) based on the absolute
danger of the command class itself, completely ignoring semantic intent.

This layer runs AFTER Unicode normalization and BEFORE the core simulation
pipeline (world spawning, evolution, basin mapping). It provides a
mathematical safety net: no matter how the worlds vote, the confidence
score cannot drop below the static floor for known-dangerous primitives.

This does NOT replace the core engine — it augments it with a deterministic
lower bound that the probabilistic simulation cannot override.
"""
import re

# ── CRITICAL: Immediate BLOCK, confidence = 1.0 ───────────────────────────────
# These command primitives are NEVER legitimate in an autonomous agent context.
# The engine short-circuits to BLOCK without running the full simulation.
_CRITICAL_PATTERNS = [
    r'rm\s+(-rf?|-r)\s+[./*]',          # Recursive delete (root, cwd, or glob)
    r'rm\s+(-rf?|-r)\s+~',              # Recursive delete home directory
    r'bash\s+-[ic]',                     # Interactive/command shell
    r'sh\s+-[ic]',                       # sh interactive/command
    r'nc\s+-e',                          # Netcat exec
    r'ncat\s+-e',                        # Ncat exec
    r'>\s*/dev/tcp',                     # Bash TCP socket
    r'/dev/tcp/',                        # TCP device file reference
    r'DROP\s+(TABLE|DATABASE)',          # Destructive SQL
    r'DELETE\s+FROM\s+\w+\s*(;|$|\s)',   # Unscoped DELETE (no WHERE)
    r'TRUNCATE\s+TABLE',                # Table truncation
    r'dd\s+if=.+of=/dev/',              # Disk-level destruction
    r'mkfs\s+/dev/',                    # Format a live device
    r'python[23]?\s+-c\s+.*(__import__|subprocess|os\.system|exec|eval)', # Python RCE with dangerous calls
    r'perl\s+-e\s+.*system\s*\(',       # Perl RCE with system()
    # SSRF / Internal Network Probing variants (immediate block)
    r'169\.254',            # standard dotted-decimal
    r'2852039166',          # decimal encoding of 169.254.169.254
    r'0xa9fe',              # hex prefix of 169.254.x.x
    r'\[::ffff:169\.254',   # IPv6-mapped form
    r'metadata\.google\.internal',  # GCP IMDS hostname
    r'instance-data',               # generic IMDS hostname pattern
    # Container Escapes
    r'\bnsenter\b',                 # Namespace entry (container escape)
    r'\bunshare\b',                 # Namespace detachment
    r'\bchroot\b',                  # Root directory change
    r'gcloud\s+compute\s+instances\s+add-metadata', # Cloud LotL persistence
    r'base64.*\|\s*(bash|sh|zsh)',  # Base64 payload to shell
    r'\|\s*(bash|sh|zsh)',          # Any pipe to shell
    r'\.aws/credentials',           # AWS credentials
    r'\.ssh/',                      # SSH directory access
    r'authorized_keys',             # SSH key injection target
    r'id_rsa',                      # SSH private keys
    r'/etc/sudoers',                # Sudo configuration
    r'/proc/.*/environ',            # Proc environment (host info)
    r'/proc/.*/mem',                # Proc memory
]

# ── ELEVATED: High divergence floor (0.70), WARN at minimum ───────────────────
# These commands access sensitive resources. The core simulation runs,
# but confidence cannot drop below 0.70 regardless of world voting.
_ELEVATED_PATTERNS = [
    r'\.env\b',                          # Environment variable files (.env)
    r'\.env\.',                          # Dotenv variants (.env.local, .env.production, etc.)
    r'/etc/passwd',                      # Password file
    r'/etc/shadow',                      # Shadow passwords
    r'/etc/hosts\b',                     # DNS configuration
    r'/etc/sudoers',                     # Sudo configuration
    r'chmod\s+[67]\d\d',                 # Group/world-writable permissions
    r'chown\s+root',                     # Privilege escalation via ownership
    r'chown\s+.*:\s*$',                  # Chown with empty group (root default)
    r'mkfs\b',                           # Make filesystem (generic)
    r'base64.*\|\s*curl',                # Base64 encode + pipe to curl (exfil)
    r'base64.*\|\s*wget',                # Base64 encode + pipe to wget (exfil)
    r'(shutdown|reboot|init\s+[06]|poweroff)',  # System shutdown/reboot
    r'iptables\s',                       # Firewall manipulation
    r'ufw\s+(disable|delete|reset)',     # UFW firewall disable
]

# ── MODERATE: Medium divergence floor (0.45) ──────────────────────────────────
# These commands have dual-use potential. The simulation runs fully,
# but confidence floor prevents "sweet-talking" to trivially low scores.
_MODERATE_PATTERNS = [
    r'curl\b',
    r'wget\b',
    r'scp\b',
    r'rsync\b',
    r'sudo\b',
    r'python[23]?\s+-c',                 # Python command execution (generic)
    r'perl\s+-e',                        # Perl command execution (generic)
    r'ruby\s+-e',                        # Ruby command execution
    r'node\s+-e',                        # Node.js command execution
    r'eval\s*\(',                        # eval() calls
    r'exec\s*\(',                        # exec() calls
    r'crontab\s+-[re]',                  # Crontab edit/remove
]

_CRITICAL = [re.compile(p, re.IGNORECASE) for p in _CRITICAL_PATTERNS]
_ELEVATED = [re.compile(p, re.IGNORECASE) for p in _ELEVATED_PATTERNS]
_MODERATE = [re.compile(p, re.IGNORECASE) for p in _MODERATE_PATTERNS]


def evaluate_command_class(
    command: str,
    unicode_evidence: list[str] | None = None,
) -> tuple[str, float, list[str]]:
    """
    Evaluates the command independent of intent.

    Args:
        command: The normalized command string (post-Unicode security).
        unicode_evidence: Evidence from the Unicode security module.
            If present, indicates the original command contained adversarial
            encoding — the threat class is boosted by one tier.

    Returns: (threat_class, static_floor, evidence_list)
    """
    evidence = []
    static_floor = 0.0
    threat_class = "BENIGN"

    has_unicode_signal = bool(unicode_evidence and any(
        'script mixing' in e.lower() or
        'invisible' in e.lower() or
        'bidi' in e.lower() or
        'confusable' in e.lower()
        for e in unicode_evidence
    ))

    # Strip bash slash evasion (e.g. c\ur\l) for pattern matching
    stripped_command = command.replace('\\', '')

    # 1. Check CRITICAL — short-circuit on first match
    for idx, pat in enumerate(_CRITICAL):
        if pat.search(stripped_command):
            threat_class = "CRITICAL"
            static_floor = 1.0
            evidence.append(f"Static: CRITICAL violation (pattern {idx})")
            return threat_class, static_floor, evidence

    # 2. Check ELEVATED
    for idx, pat in enumerate(_ELEVATED):
        if pat.search(stripped_command):
            threat_class = "ELEVATED"
            static_floor = max(static_floor, 0.70)
            evidence.append(f"Static: ELEVATED capability (pattern {idx})")

    # 3. Check MODERATE (only if not already ELEVATED)
    if threat_class == "BENIGN":
        for idx, pat in enumerate(_MODERATE):
            if pat.search(stripped_command):
                threat_class = "MODERATE"
                static_floor = max(static_floor, 0.45)
                evidence.append(f"Static: MODERATE capability (pattern {idx})")

    # 4. Unicode-aware escalation
    # If the original command contained adversarial Unicode AND the
    # post-normalization command matches a threat pattern, the attacker
    # was deliberately trying to evade detection. Boost by one tier.
    if has_unicode_signal:
        if threat_class == "MODERATE":
            threat_class = "ELEVATED"
            static_floor = max(static_floor, 0.70)
            evidence.append("Static: Threat escalated MODERATE→ELEVATED due to Unicode evasion attempt")
        elif threat_class == "ELEVATED":
            threat_class = "CRITICAL"
            static_floor = 1.0
            evidence.append("Static: Threat escalated ELEVATED→CRITICAL due to Unicode evasion attempt")
        elif threat_class == "BENIGN" and unicode_evidence:
            # Even benign commands with adversarial encoding are suspicious
            threat_class = "MODERATE"
            static_floor = max(static_floor, 0.45)
            evidence.append("Static: Unicode obfuscation on benign command — elevated to MODERATE")

    return threat_class, static_floor, evidence
