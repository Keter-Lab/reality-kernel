"""
Unicode Security Module
========================
Production-grade Unicode normalization and adversarial detection layer.

This module sits BEFORE the Reality Engine's core simulation pipeline.
It normalizes adversarial Unicode encoding attempts (homoglyphs, zero-width
characters, bidi overrides, fullwidth substitutions) so that the downstream
pattern matching, world simulation, and basin mapping operate on clean ASCII
representations of the actual command being executed.

This is a *pre-processing* layer — it does NOT make allow/block decisions.
It returns the cleaned command + evidence strings that feed into the
Static Analyser and ultimately the Governor's confidence formula.
"""

import re
import unicodedata

# ── Comprehensive Confusable Character Map ─────────────────────────────────────
# Maps visually similar characters from other scripts to their Latin equivalents.
# Sources: Unicode TR39 Confusables, OWASP Unicode Security Guide, CVE databases.
#
# Format: { non-latin_char : latin_equivalent }

_CONFUSABLES = {
    # Cyrillic → Latin (most common attack vector)
    '\u0430': 'a',   # а → a
    '\u0431': 'b',   # б → b  (lowercase, approximate)
    '\u0432': 'v',   # в → v
    '\u0433': 'r',   # г → r  (visual similarity in some fonts)
    '\u0435': 'e',   # е → e
    '\u0437': 'z',   # з → z  (approximate)
    '\u0438': 'u',   # и → u  (approximate)
    '\u043a': 'k',   # к → k
    '\u043c': 'm',   # м → m
    '\u043d': 'n',   # н → n  (approximate)
    '\u043e': 'o',   # о → o
    '\u043f': 'n',   # п → n  (approximate)
    '\u0440': 'p',   # р → p
    '\u0441': 'c',   # с → c
    '\u0442': 't',   # т → t  (approximate in some fonts)
    '\u0443': 'y',   # у → y
    '\u0445': 'x',   # х → x
    '\u044c': 'b',   # ь → b  (approximate)
    '\u0455': 's',   # ѕ → s  (Macedonian)
    '\u0456': 'i',   # і → i  (Ukrainian/Belarusian)
    '\u0458': 'j',   # ј → j  (Serbian)
    '\u04bb': 'h',   # һ → h  (Bashkir/Chuvash)
    '\u0501': 'd',   # ԁ → d  (Komi)
    '\u051b': 'q',   # ԛ → q  (Kurdish)
    '\u051d': 'w',   # ԝ → w  (Abkhaz)

    # Greek → Latin
    '\u0391': 'A',   # Α → A
    '\u0392': 'B',   # Β → B
    '\u0395': 'E',   # Ε → E
    '\u0396': 'Z',   # Ζ → Z
    '\u0397': 'H',   # Η → H
    '\u0399': 'I',   # Ι → I
    '\u039a': 'K',   # Κ → K
    '\u039c': 'M',   # Μ → M
    '\u039d': 'N',   # Ν → N
    '\u039f': 'O',   # Ο → O
    '\u03a1': 'P',   # Ρ → P
    '\u03a4': 'T',   # Τ → T
    '\u03a5': 'Y',   # Υ → Y
    '\u03a7': 'X',   # Χ → X
    '\u03b1': 'a',   # α → a
    '\u03b2': 'b',   # β → b  (approximate)
    '\u03b5': 'e',   # ε → e  (approximate)
    '\u03b9': 'i',   # ι → i
    '\u03ba': 'k',   # κ → k
    '\u03bd': 'v',   # ν → v
    '\u03bf': 'o',   # ο → o
    '\u03c1': 'p',   # ρ → p
    '\u03c4': 't',   # τ → t
    '\u03c5': 'u',   # υ → u  (approximate)
    '\u03c7': 'x',   # χ → x

    # Other confusable scripts
    '\u0261': 'g',   # ɡ → g  (IPA)
    '\u210e': 'h',   # ℎ → h  (Planck constant)
    '\u2113': 'l',   # ℓ → l  (script small l)
    '\u2134': 'o',   # ℴ → o  (script small o)

    # Armenian confusables
    '\u0570': 'h',   # հ → h
    '\u0578': 'n',   # ո → n
    '\u057d': 's',   # ս → s
    '\u0585': 'o',   # օ → o
}

# Build a single-pass translation table for maximum performance
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)

# ── Fullwidth ASCII → ASCII ────────────────────────────────────────────────────
# Fullwidth characters (U+FF01–U+FF5E) map to ASCII (U+0021–U+007E).
# NFKD normalization handles these, but we do it explicitly for clarity.
_FULLWIDTH_TABLE = str.maketrans(
    {chr(0xFF01 + i): chr(0x21 + i) for i in range(94)}
)

# ── Invisible / Adversarial Characters ─────────────────────────────────────────
# These characters are invisible or alter text rendering direction.
# They MUST be stripped before any pattern matching occurs.
_INVISIBLE_CHARS = set([
    '\u200b',   # Zero-Width Space
    '\u200c',   # Zero-Width Non-Joiner
    '\u200d',   # Zero-Width Joiner
    '\u2060',   # Word Joiner
    '\ufeff',   # BOM / Zero-Width No-Break Space
    '\u00ad',   # Soft Hyphen (invisible in most contexts)
    '\u034f',   # Combining Grapheme Joiner
    '\u061c',   # Arabic Letter Mark
    '\u180e',   # Mongolian Vowel Separator
])

# Bidi control characters — used for RTL override attacks
_BIDI_CONTROLS = set([
    '\u202a',   # Left-to-Right Embedding
    '\u202b',   # Right-to-Left Embedding
    '\u202c',   # Pop Directional Formatting
    '\u202d',   # Left-to-Right Override
    '\u202e',   # Right-to-Left Override  ← PRIMARY ATTACK VECTOR
    '\u2066',   # Left-to-Right Isolate
    '\u2067',   # Right-to-Left Isolate
    '\u2068',   # First Strong Isolate
    '\u2069',   # Pop Directional Isolate
])

# Tag characters (completely invisible, used for language tagging)
_TAG_RANGE = range(0xE0001, 0xE0080)

# Combined set for fast lookup
_ALL_STRIP = _INVISIBLE_CHARS | _BIDI_CONTROLS | set(chr(c) for c in _TAG_RANGE)


def _detect_script_mixing(token: str) -> bool:
    """
    Returns True if a single token contains characters from multiple
    non-Common Unicode scripts (e.g., Latin + Cyrillic in one word).

    Real shell commands are 100% ASCII. Mixed-script tokens are inherently
    adversarial in a shell context.
    """
    scripts = set()
    for ch in token:
        cat = unicodedata.category(ch)
        if cat.startswith('L'):  # Letter characters only
            try:
                name = unicodedata.name(ch, '')
                # Extract script from Unicode name (e.g., "CYRILLIC SMALL LETTER A")
                if 'CYRILLIC' in name:
                    scripts.add('Cyrillic')
                elif 'GREEK' in name:
                    scripts.add('Greek')
                elif 'LATIN' in name:
                    scripts.add('Latin')
                elif 'ARMENIAN' in name:
                    scripts.add('Armenian')
                elif 'CHEROKEE' in name:
                    scripts.add('Cherokee')
                else:
                    # Basic ASCII letters are Latin
                    if 'A' <= ch <= 'Z' or 'a' <= ch <= 'z':
                        scripts.add('Latin')
            except ValueError:
                pass
    return len(scripts) > 1


def normalize_command(raw_command: str) -> tuple[str, list[str]]:
    """
    Comprehensive Unicode normalization for shell commands.

    This function sits at the very front of the Reality Engine pipeline,
    BEFORE any pattern matching, world simulation, or basin mapping.

    Returns:
        (normalized_command, evidence_list)

    The normalized command is safe for downstream regex/pattern matching.
    The evidence list feeds into the Static Analyser and Governor.
    """
    evidence = []
    command = raw_command

    # ── Phase 1: Strip invisible characters ────────────────────────────────
    invisible_found = []
    cleaned = []
    for ch in command:
        if ch in _ALL_STRIP:
            invisible_found.append(f'U+{ord(ch):04X}')
        else:
            cleaned.append(ch)

    if invisible_found:
        command = ''.join(cleaned)
        unique_chars = list(set(invisible_found))[:5]  # Cap evidence length
        evidence.append(
            f"Invisible/control characters stripped: {', '.join(unique_chars)}"
            f"{' (and more)' if len(set(invisible_found)) > 5 else ''}"
        )

    # Check for bidi specifically (higher severity)
    bidi_found = [ch for ch in raw_command if ch in _BIDI_CONTROLS]
    if bidi_found:
        evidence.append(
            "RTL/Bidi override characters detected — possible visual spoofing attack"
        )

    # ── Phase 2: Fullwidth → ASCII ─────────────────────────────────────────
    before_fw = command
    command = command.translate(_FULLWIDTH_TABLE)
    if command != before_fw:
        evidence.append("Fullwidth ASCII characters normalized to standard ASCII")

    # ── Phase 3: Script-mixing detection (BEFORE transliteration) ──────────
    tokens = command.split()
    mixed_tokens = []
    for token in tokens:
        if _detect_script_mixing(token):
            # Truncate for evidence readability
            display = token[:30] + ('…' if len(token) > 30 else '')
            mixed_tokens.append(display)

    if mixed_tokens:
        evidence.append(
            f"Unicode script mixing detected in token(s): {', '.join(mixed_tokens[:3])}"
        )

    # ── Phase 4: Confusable character transliteration ──────────────────────
    before_confusable = command
    command = command.translate(_CONFUSABLE_TABLE)
    if command != before_confusable:
        # Count how many characters were transliterated
        diff_count = sum(1 for a, b in zip(before_confusable, command) if a != b)
        evidence.append(
            f"Confusable characters transliterated: {diff_count} char(s) "
            f"from non-Latin scripts mapped to Latin equivalents"
        )

    # ── Phase 5: NFKD normalization (accents, compatibility forms) ─────────
    before_nfkd = command
    command = ''.join(
        c for c in unicodedata.normalize('NFKD', command)
        if not unicodedata.combining(c)
    )
    if command != before_nfkd:
        evidence.append("NFKD normalization applied — combining diacritics stripped")

    # ── Phase 6: Non-ASCII residue detection ───────────────────────────────
    non_ascii = [ch for ch in command if ord(ch) > 127]
    if non_ascii:
        samples = [f'U+{ord(ch):04X}' for ch in set(non_ascii)][:3]
        evidence.append(
            f"Non-ASCII residue after normalization: {', '.join(samples)} — "
            f"unusual for shell commands"
        )

    return command, evidence
