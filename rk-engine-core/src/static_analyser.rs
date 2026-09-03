use regex::Regex;

pub fn evaluate_command_class(
    command: &str,
    unicode_evidence: Option<&[String]>,
) -> (String, f64, Vec<String>) {
    let mut evidence = Vec::new();
    let mut static_floor = 0.0;
    let mut threat_class = "BENIGN".to_string();

    let has_unicode_signal = unicode_evidence
        .map(|arr| {
            arr.iter().any(|e| {
                let l = e.to_lowercase();
                l.contains("script mixing")
                    || l.contains("invisible")
                    || l.contains("bidi")
                    || l.contains("confusable")
            })
        })
        .unwrap_or(false);

    let stripped_command = command.replace('\\', "");

    for (idx, pat) in critical_patterns().iter().enumerate() {
        if Regex::new(&format!("(?i){pat}")).unwrap().is_match(&stripped_command) {
            threat_class = "CRITICAL".to_string();
            static_floor = 1.0;
            evidence.push(format!("Static: CRITICAL violation (pattern {idx})"));
            return (threat_class, static_floor, evidence);
        }
    }

    for (idx, pat) in elevated_patterns().iter().enumerate() {
        if Regex::new(&format!("(?i){pat}")).unwrap().is_match(&stripped_command) {
            threat_class = "ELEVATED".to_string();
            static_floor = static_floor.max(0.70);
            evidence.push(format!("Static: ELEVATED capability (pattern {idx})"));
        }
    }

    if threat_class == "BENIGN" {
        for (idx, pat) in moderate_patterns().iter().enumerate() {
            if Regex::new(&format!("(?i){pat}")).unwrap().is_match(&stripped_command) {
                threat_class = "MODERATE".to_string();
                static_floor = static_floor.max(0.45);
                evidence.push(format!("Static: MODERATE capability (pattern {idx})"));
            }
        }
    }

    if has_unicode_signal {
        match threat_class.as_str() {
            "MODERATE" => {
                threat_class = "ELEVATED".to_string();
                static_floor = static_floor.max(0.70);
                evidence.push("Static: Threat escalated MODERATE→ELEVATED due to Unicode evasion attempt".to_string());
            }
            "ELEVATED" => {
                threat_class = "CRITICAL".to_string();
                static_floor = 1.0;
                evidence.push("Static: Threat escalated ELEVATED→CRITICAL due to Unicode evasion attempt".to_string());
            }
            "BENIGN" if unicode_evidence.is_some() => {
                threat_class = "MODERATE".to_string();
                static_floor = static_floor.max(0.45);
                evidence.push("Static: Unicode obfuscation on benign command — elevated to MODERATE".to_string());
            }
            _ => {}
        }
    }

    (threat_class, static_floor, evidence)
}

pub fn critical_patterns() -> Vec<&'static str> {
    vec![
        r"rm\s+(-rf?|-r)\s+[./*]",
        r"rm\s+(-rf?|-r)\s+~",
        r"bash\s+-[ic]",
        r"sh\s+-[ic]",
        r"nc\s+-e",
        r"ncat\s+-e",
        r">\s*/dev/tcp",
        r"/dev/tcp/",
        r"DROP\s+(TABLE|DATABASE)",
        r"DELETE\s+FROM\s+\w+\s*(;|$|\s)",
        r"TRUNCATE\s+TABLE",
        r"dd\s+if=.+of=/dev/",
        r"mkfs\s+/dev/",
        r"python[23]?\s+-c\s+.*(__import__|subprocess|os\.system|exec|eval)",
        r"perl\s+-e\s+.*system\s*\(",
        r"169\.254",
        r"2852039166",
        r"0xa9fe",
        r"\[::ffff:169\.254",
        r"metadata\.google\.internal",
        r"instance-data",
        r"\bnsenter\b",
        r"\bunshare\b",
        r"\bchroot\b",
        r"gcloud\s+compute\s+instances\s+add-metadata",
        r"base64.*\|\s*(bash|sh|zsh)",
        r"\|\s*(bash|sh|zsh)",
        r"\.aws/credentials",
        r"\.ssh/",
        r"authorized_keys",
        r"id_rsa",
        r"/etc/sudoers",
        r"/proc/.*/environ",
        r"/proc/.*/mem",
    ]
}

pub fn elevated_patterns() -> Vec<&'static str> {
    vec![
        r"\.env\b",
        r"\.env\.",
        r"/etc/passwd",
        r"/etc/shadow",
        r"/etc/hosts\b",
        r"/etc/sudoers",
        r"chmod\s+[67]\d\d",
        r"chown\s+root",
        r"chown\s+.*:\s*$",
        r"mkfs\b",
        r"base64.*\|\s*curl",
        r"base64.*\|\s*wget",
        r"(shutdown|reboot|init\s+[06]|poweroff)",
        r"iptables\s",
        r"ufw\s+(disable|delete|reset)",
    ]
}

pub fn moderate_patterns() -> Vec<&'static str> {
    vec![
        r"curl\b",
        r"wget\b",
        r"scp\b",
        r"rsync\b",
        r"sudo\b",
        r"python[23]?\s+-c",
        r"perl\s+-e",
        r"ruby\s+-e",
        r"node\s+-e",
        r"eval\s*\(",
        r"exec\s*\(",
        r"crontab\s+-[re]",
    ]
}
