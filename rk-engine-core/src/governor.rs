use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub verdict: String,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub worlds_evaluated: usize,
    pub worlds_in_basin_b: usize,
    pub max_divergence: f64,
    pub action_id: String,
    pub proof_hash: String,
}

pub fn map_decision(decision_str: &str, max_div: f64) -> String {
    if decision_str == "BLOCK" || max_div >= 0.90 {
        "BLOCK".to_string()
    } else if decision_str == "WARN" || max_div >= 0.50 {
        "WARN".to_string()
    } else {
        "ALLOW".to_string()
    }
}

pub fn compute_confidence(max_div: f64, worlds_b: usize, total: usize, static_floor: f64, evidence_count: usize) -> f64 {
    if total == 0 {
        return static_floor.max(0.0);
    }
    let world_ratio = worlds_b as f64 / total as f64;
    let evidence_factor = ((evidence_count as f64) * 0.05).min(0.15);
    let raw_calculated = (max_div * 0.60) + (world_ratio * 0.40) + evidence_factor;
    ((raw_calculated.clamp(static_floor, 1.0)) * 1000.0).round() / 1000.0
}

pub fn evaluate(
    command: &str,
    prime_intent: &str,
    basin_summary: &serde_json::Value,
    worlds_count: usize,
    static_floor: f64,
    evidence_count: usize,
) -> AnalysisResult {
    let decision_str = basin_summary.get("decision").and_then(|v| v.as_str()).unwrap_or("SAFE");
    let max_div = basin_summary.get("max_divergence").and_then(|v| v.as_f64()).unwrap_or(0.0);
    let evidence = basin_summary
        .get("evidence")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect::<Vec<_>>())
        .unwrap_or_default();
    let worlds_b = basin_summary.get("worlds_in_B").and_then(|v| v.as_u64()).unwrap_or(0) as usize;

    let verdict = map_decision(decision_str, max_div);
    let confidence = compute_confidence(max_div, worlds_b, worlds_count, static_floor, evidence_count + evidence.len());

    let ts = now_secs();
    let action_seed = format!("{}:{}:{}", command, prime_intent, ts);
    let action_id = hex12(&action_seed).or_else(|| Some(Uuid::new_v4().simple().to_string()[..12].to_string())).unwrap();

    let record = serde_json::json!({
        "id": action_id,
        "ts": ts,
        "cmd": command,
        "intent": prime_intent,
        "verdict": verdict,
        "div": max_div,
    });
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_string(&record).unwrap_or_default().as_bytes());
    let proof_hash = hex::encode(hasher.finalize());

    AnalysisResult {
        verdict,
        confidence,
        evidence,
        worlds_evaluated: worlds_count,
        worlds_in_basin_b: worlds_b,
        max_divergence: max_div,
        action_id,
        proof_hash,
    }
}

fn now_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn hex12(payload: &str) -> Option<String> {
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    let digest = hex::encode(hasher.finalize());
    Some(digest[..12].to_string())
}
