use std::collections::HashSet;

use unicode_normalization::UnicodeNormalization;

fn confusable_map(ch: char) -> Option<char> {
    Some(match ch {
        // Cyrillic
        '\u{0430}' => 'a', '\u{0431}' => 'b', '\u{0432}' => 'v', '\u{0433}' => 'r',
        '\u{0435}' => 'e', '\u{0437}' => 'z', '\u{0438}' => 'u', '\u{043A}' => 'k',
        '\u{043C}' => 'm', '\u{043D}' => 'n', '\u{043E}' => 'o', '\u{043F}' => 'n',
        '\u{0440}' => 'p', '\u{0441}' => 'c', '\u{0442}' => 't', '\u{0443}' => 'y',
        '\u{0445}' => 'x', '\u{044C}' => 'b', '\u{0455}' => 's', '\u{0456}' => 'i',
        '\u{0458}' => 'j', '\u{04BB}' => 'h', '\u{0501}' => 'd', '\u{051B}' => 'q', '\u{051D}' => 'w',
        // Greek
        '\u{0391}' => 'A', '\u{0392}' => 'B', '\u{0395}' => 'E', '\u{0396}' => 'Z',
        '\u{0397}' => 'H', '\u{0399}' => 'I', '\u{039A}' => 'K', '\u{039C}' => 'M',
        '\u{039D}' => 'N', '\u{039F}' => 'O', '\u{03A1}' => 'P', '\u{03A4}' => 'T',
        '\u{03A5}' => 'Y', '\u{03A7}' => 'X', '\u{03B1}' => 'a', '\u{03B2}' => 'b',
        '\u{03B5}' => 'e', '\u{03B9}' => 'i', '\u{03BA}' => 'k', '\u{03BD}' => 'v',
        '\u{03BF}' => 'o', '\u{03C1}' => 'p', '\u{03C4}' => 't', '\u{03C5}' => 'u', '\u{03C7}' => 'x',
        // Other
        '\u{0261}' => 'g', '\u{210E}' => 'h', '\u{2113}' => 'l', '\u{2134}' => 'o',
        // Armenian
        '\u{0570}' => 'h', '\u{0578}' => 'n', '\u{057D}' => 's', '\u{0585}' => 'o',
        _ => return None,
    })
}

fn is_invisible_or_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}'
            | '\u{200C}'
            | '\u{200D}'
            | '\u{2060}'
            | '\u{FEFF}'
            | '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{202A}'
            | '\u{202B}'
            | '\u{202C}'
            | '\u{202D}'
            | '\u{202E}'
            | '\u{2066}'
            | '\u{2067}'
            | '\u{2068}'
            | '\u{2069}'
    ) || ('\u{E0001}'..='\u{E007F}').contains(&ch)
}

fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{202A}'
            | '\u{202B}'
            | '\u{202C}'
            | '\u{202D}'
            | '\u{202E}'
            | '\u{2066}'
            | '\u{2067}'
            | '\u{2068}'
            | '\u{2069}'
    )
}

fn fullwidth_to_ascii(ch: char) -> char {
    let c = ch as u32;
    if (0xFF01..=0xFF5E).contains(&c) {
        char::from_u32(0x21 + (c - 0xFF01)).unwrap_or(ch)
    } else {
        ch
    }
}

fn detect_script_mixing(token: &str) -> bool {
    let mut scripts = HashSet::new();
    for ch in token.chars() {
        if ch.is_alphabetic() {
            if ch.is_ascii_alphabetic() {
                scripts.insert("Latin");
            } else {
                let cp = ch as u32;
                if (0x0400..=0x052F).contains(&cp) {
                    scripts.insert("Cyrillic");
                } else if (0x0370..=0x03FF).contains(&cp) {
                    scripts.insert("Greek");
                } else if (0x0530..=0x058F).contains(&cp) {
                    scripts.insert("Armenian");
                }
            }
        }
    }
    scripts.len() > 1
}

pub fn normalize_command(raw_command: &str) -> (String, Vec<String>) {
    let mut evidence = Vec::new();
    let mut command = raw_command.to_string();

    // Phase 1
    let mut invisible_found: Vec<String> = Vec::new();
    let mut cleaned = String::new();
    for ch in command.chars() {
        if is_invisible_or_control(ch) {
            invisible_found.push(format!("U+{:04X}", ch as u32));
        } else {
            cleaned.push(ch);
        }
    }
    if !invisible_found.is_empty() {
        command = cleaned;
        let uniq: HashSet<String> = invisible_found.into_iter().collect();
        let mut uniq_vec: Vec<String> = uniq.into_iter().collect();
        uniq_vec.sort();
        let samples: Vec<String> = uniq_vec.iter().take(5).cloned().collect();
        evidence.push(format!(
            "Invisible/control characters stripped: {}{}",
            samples.join(", "),
            if uniq_vec.len() > 5 { " (and more)" } else { "" }
        ));
    }

    if raw_command.chars().any(is_bidi_control) {
        evidence.push(
            "RTL/Bidi override characters detected — possible visual spoofing attack".to_string(),
        );
    }

    // Phase 2
    let before_fw = command.clone();
    command = command.chars().map(fullwidth_to_ascii).collect();
    if command != before_fw {
        evidence.push("Fullwidth ASCII characters normalized to standard ASCII".to_string());
    }

    // Phase 3
    let mixed_tokens: Vec<String> = command
        .split_whitespace()
        .filter(|t| detect_script_mixing(t))
        .map(|t| {
            let mut s: String = t.chars().take(30).collect();
            if t.chars().count() > 30 {
                s.push('…');
            }
            s
        })
        .collect();
    if !mixed_tokens.is_empty() {
        evidence.push(format!(
            "Unicode script mixing detected in token(s): {}",
            mixed_tokens.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
        ));
    }

    // Phase 4
    let before_confusable = command.clone();
    command = command
        .chars()
        .map(|c| confusable_map(c).unwrap_or(c))
        .collect::<String>();
    if command != before_confusable {
        let diff_count = before_confusable
            .chars()
            .zip(command.chars())
            .filter(|(a, b)| a != b)
            .count();
        evidence.push(format!(
            "Confusable characters transliterated: {diff_count} char(s) from non-Latin scripts mapped to Latin equivalents"
        ));
    }

    // Phase 5
    let before_nfkd = command.clone();
    command = command
        .nfkd()
        .filter(|c| !unicode_normalization::char::is_combining_mark(*c))
        .collect();
    if command != before_nfkd {
        evidence.push("NFKD normalization applied — combining diacritics stripped".to_string());
    }

    // Phase 6
    let non_ascii: HashSet<char> = command.chars().filter(|c| (*c as u32) > 127).collect();
    if !non_ascii.is_empty() {
        let mut samples: Vec<String> = non_ascii
            .into_iter()
            .map(|c| format!("U+{:04X}", c as u32))
            .collect();
        samples.sort();
        evidence.push(format!(
            "Non-ASCII residue after normalization: {} — unusual for shell commands",
            samples.into_iter().take(3).collect::<Vec<_>>().join(", ")
        ));
    }

    (command, evidence)
}
