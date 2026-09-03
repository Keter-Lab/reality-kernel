use crate::superposition::World;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasinResult {
    pub world_id: String,
    pub basin: String,
    pub crossed_separatrix: bool,
    pub evidence: Vec<String>,
    pub divergence_score: f64,
}

pub fn basin_b_signatures() -> Vec<(&'static str, f64, &'static str)> {
    vec![
        (r"rm\s+(-rf?|-r)\s+", 0.90, "Recursive file deletion command"),
        (r"rm\s+.*&&", 0.92, "Deletion chained with other commands"),
        (r"deleted:\s+\d+ files?", 0.90, "Mass file deletion detected"),
        (r"removed.*\.(db|sql|sqlite|key|pem|env)", 0.95, "Critical file removed"),
        (r"truncated.*\.(log|db)", 0.70, "Database/log truncated"),
        (r"chmod.*777", 0.65, "World-writable permission set"),
        (r"chown.*root", 0.75, "Ownership changed to root"),
        (r"setuid", 0.80, "Setuid bit manipulation"),
        (r"sudo.*-s", 0.85, "Root shell spawned"),
        (r"curl.*(http|ftp).*\|.*bash", 0.90, "Remote code execution pipe detected"),
        (r"nc.*-e", 0.95, "Reverse shell signature (netcat -e)"),
        (r"bash.*-i.*>&.*/dev/tcp", 0.95, "Bash reverse shell detected"),
        (r"wget.*-O.*\|.*sh", 0.90, "Piped remote script execution"),
        (r"(curl|wget).*\$\(", 0.92, "Curl/wget with subshell data embedding detected"),
        (r"(curl|wget).*(--data|-d\s|--upload|-T\s)", 0.85, "Curl/wget data upload to external host"),
        (r"(curl|wget|ping|nc|ncat).*(\b169\.254\b|\blocalhost\b|\b127\.0\.0\.1\b|\b0\.0\.0\.0\b)", 0.95, "Internal network SSRF/probing attempt"),
        (r"cat.*/etc/(passwd|shadow|hosts)", 0.80, "Sensitive system file read"),
        (r"cat.*\b(secret|credential|api_key|token|id_rsa|passwd|shadow)\b", 0.90, "Sensitive file read attempt"),
        (r"(scp|rsync|sftp).*@.*:", 0.60, "Outbound file transfer detected"),
        (r"base64.*\|.*curl", 0.85, "Encoded exfiltration pattern"),
        (r"\$\(.*cat.*(credential|\.aws|\.ssh|id_rsa|\.env|passwd|shadow|secret|token)", 0.95, "Credential file read inside subshell"),
        (r"(;|&&).*curl\s+https?://", 0.88, "Curl to external host chained after command"),
        (r"curl\s+https?://.*\?.*=", 0.82, "Curl GET with query params — possible data exfil"),
        (r"crontab.*-l.*>", 0.70, "Crontab modification attempt"),
        (r"echo.*>>.*authorized_keys", 0.90, "SSH key injection detected"),
        (r"/etc/rc\.(local|d)", 0.75, "Startup script modification"),
        (r"DROP\s+(TABLE|DATABASE)", 0.90, "SQL destructive command"),
        (r"DELETE\s+FROM\s+\w+", 0.85, "Unscoped DELETE query"),
        (r"TRUNCATE\s+TABLE", 0.80, "Table truncation detected"),
    ]
}

pub fn check_basin(world: &World, sandbox_delta: &serde_json::Value) -> BasinResult {
    let observable = flatten_delta(sandbox_delta);
    let mut evidence = Vec::new();
    let mut max_div: f64 = 0.0;

    for (pattern, weight, label) in basin_b_signatures() {
        if Regex::new(&format!("(?i){pattern}")).unwrap().is_match(&observable) {
            evidence.push(label.to_string());
            max_div = max_div.max(weight);
        }
    }

    max_div = (max_div.max(world.risk_score * 0.6)).min(1.0);
    max_div = (max_div * 1000.0).round() / 1000.0;

    let crossed = max_div >= 0.65;
    BasinResult {
        world_id: world.world_id.clone(),
        basin: if crossed { "B" } else { "A" }.to_string(),
        crossed_separatrix: crossed,
        evidence,
        divergence_score: max_div,
    }
}

fn flatten_delta(delta: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    if let Some(obj) = delta.as_object() {
        for v in obj.values() {
            if let Some(arr) = v.as_array() {
                for e in arr { parts.push(e.to_string()); }
            } else {
                parts.push(v.to_string());
            }
        }
    }
    parts.join(" | ")
}

pub fn aggregate_basin_results(results: &[BasinResult]) -> serde_json::Value {
    if results.is_empty() {
        return serde_json::json!({"decision":"SAFE","max_divergence":0.0,"evidence": []});
    }
    let crossings: Vec<&BasinResult> = results.iter().filter(|r| r.crossed_separatrix).collect();
    let max_div = results.iter().map(|r| r.divergence_score).fold(0.0, f64::max);
    let mut all_evidence = std::collections::BTreeSet::new();
    for r in results { for e in &r.evidence { all_evidence.insert(e.clone()); } }

    let decision = if !crossings.is_empty() {
        "BLOCK"
    } else if max_div >= 0.40 {
        "WARN"
    } else {
        "SAFE"
    };

    serde_json::json!({
        "decision": decision,
        "max_divergence": ((max_div*1000.0).round()/1000.0),
        "evidence": all_evidence.into_iter().collect::<Vec<_>>(),
        "worlds_in_B": crossings.len(),
        "total_worlds": results.len()
    })
}
