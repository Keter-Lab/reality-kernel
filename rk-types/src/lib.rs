use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LeastAgencyPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_tools: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_egress: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only_paths: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CheckRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prime_intent: Option<String>,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<LeastAgencyPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CheckResponse {
    pub action_id: String,
    pub verdict: String,
    pub confidence: f64,
    pub worlds_evaluated: usize,
    pub worlds_in_basin_b: usize,
    pub max_divergence: f64,
    pub evidence: Vec<String>,
    pub proof_hash: String,
    pub latency_ms: f64,
    pub credits_consumed: i64,
    pub credits_remaining: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ed25519_signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ed25519_pubkey: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScanEntry {
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub prime_intent: String,
    #[serde(default)]
    pub label: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScanRequest {
    #[serde(default)]
    pub commands: Vec<ScanEntry>,
    #[serde(default = "default_fail_on")]
    pub fail_on: String,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<LeastAgencyPolicy>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScanResult {
    pub label: String,
    pub verdict: String,
    pub evidence: Vec<String>,
    pub proof_hash: String,
    pub action_id: String,
    pub fail: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScanResponse {
    pub policy_pass: bool,
    pub fail_on: String,
    pub total_entries: usize,
    pub violations: usize,
    pub credits_consumed: i64,
    pub credits_remaining: i64,
    pub results: Vec<ScanResult>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OverrideRequest {
    pub action_id: String,
    pub decision: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OverrideResponse {
    pub ok: bool,
    pub verdict: String,
    pub override_action_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning_level: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DirectOverrideRequest {
    pub action_id: String,
    pub decision: String,
    pub token: String,
    pub expires: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WebhookRequest {
    #[serde(default)]
    pub url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenRequest {
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default = "default_token_ttl")]
    pub ttl: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenResponse {
    pub token: String,
    pub expires_at: i64,
    pub scopes: Vec<String>,
    pub agent_id: String,
    pub session_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuditLogEntry {
    pub key_hash: String,
    pub action_id: String,
    pub command: String,
    pub prime_intent: String,
    pub session_id: String,
    pub agent_id: String,
    pub verdict: String,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub proof_hash: String,
    pub cost: i64,
    pub credits_after: i64,
    pub fast_path: bool,
    pub client_ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ed25519_signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ed25519_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ts: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MeResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub key_masked: String,
    pub credits_used: i64,
    pub credits_limit: i64,
    pub credits_remaining: i64,
    pub pct_used: f64,
    pub low_credits: bool,
    #[serde(default)]
    pub top_up_log: Vec<serde_json::Value>,
    #[serde(default)]
    pub discord_webhook: String,
    #[serde(default)]
    pub strict_mode: bool,
    #[serde(default)]
    pub retention_days: i64,
    #[serde(default)]
    pub siem_url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VersionResponse {
    pub api_version: String,
    pub fast_path_cost: i64,
    pub full_engine_cost: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HealthResponse {
    pub ok: bool,
    pub ts: f64,
    pub version: String,
}

fn default_token_ttl() -> i64 {
    3600
}

fn default_fail_on() -> String {
    "BLOCK".to_string()
}
