use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;
use tracing::error;

const RETRY_DELAYS_MS: [u64; 3] = [100, 500, 2000];
const CIRCUIT_FAIL_THRESHOLD: usize = 5;
const CIRCUIT_OPEN_SECS: u64 = 30;
const WAL_PATH: &str = "/var/lib/rk/wal.jsonl";

#[derive(Debug, Error)]
pub enum SupabaseError {
    #[error("supabase circuit open")]
    CircuitOpen,
    #[error("transport: {0}")]
    Transport(String),
    #[error("http status {0}: {1}")]
    Http(u16, String),
    #[error("serialization: {0}")]
    Serialization(String),
    #[error("wal: {0}")]
    Wal(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRow {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRow {
    pub key_hash: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub credits_limit: i64,
    #[serde(default)]
    pub credits_used: i64,
    #[serde(default)]
    pub key_prefix: String,
    #[serde(default)]
    pub key_suffix: String,
    #[serde(default)]
    pub strict_mode: bool,
    #[serde(default)]
    pub retention_days: i64,
    #[serde(default)]
    pub discord_webhook: String,
    #[serde(default)]
    pub top_up_log: Vec<serde_json::Value>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub company: Option<String>,
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub siem_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id: String,
    pub cumulative_reads: i64,
    pub cumulative_sensitive: i64,
    pub network_egress_count: i64,
    pub last_activity: f64,
    pub recent_commands: Vec<String>,
}

#[derive(Debug, Clone)]
struct CircuitState {
    consecutive_failures: usize,
    open_until: Option<Instant>,
}

#[derive(Clone)]
pub struct RkSupabaseClient {
    url: String,
    service_key: String,
    http: Client,
    circuit: Arc<Mutex<CircuitState>>,
}

impl RkSupabaseClient {
    pub fn new(url: &str, service_key: &str) -> Self {
        let client = Self {
            url: url.trim_end_matches('/').to_string(),
            service_key: service_key.to_string(),
            http: Client::new(),
            circuit: Arc::new(Mutex::new(CircuitState {
                consecutive_failures: 0,
                open_until: None,
            })),
        };

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let replay_client = client.clone();
            handle.spawn(async move {
                if let Err(err) = replay_client.replay_wal_on_startup().await {
                    error!("wal_replay_startup_failed: {err}");
                }
            });
        }

        client
    }

    pub fn base_url(&self) -> &str {
        &self.url
    }

    pub async fn replay_wal_on_startup(&self) -> Result<(), SupabaseError> {
        if !Path::new(WAL_PATH).exists() {
            return Ok(());
        }
        let content = fs::read_to_string(WAL_PATH)
            .await
            .map_err(|e| SupabaseError::Wal(e.to_string()))?;
        if content.trim().is_empty() {
            return Ok(());
        }
        let mut kept = Vec::new();
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let row: AuditRow = serde_json::from_str(line)
                .map_err(|e| SupabaseError::Serialization(e.to_string()))?;
            if let Err(err) = self.insert_audit(row.clone()).await {
                kept.push(line.to_string());
                error!("wal_replay_failed: {err}");
            }
        }
        if kept.is_empty() {
            fs::remove_file(WAL_PATH).await.ok();
        } else {
            fs::write(WAL_PATH, kept.join("\n") + "\n")
                .await
                .map_err(|e| SupabaseError::Wal(e.to_string()))?;
        }
        Ok(())
    }

    pub async fn insert_audit(&self, row: AuditRow) -> Result<(), SupabaseError> {
        let endpoint = format!("{}/rest/v1/audit_log", self.url);
        let body = serde_json::to_value(&row)
            .map_err(|e| SupabaseError::Serialization(e.to_string()))?;
        let send_res = self.request_with_retry("POST", &endpoint, Some(body)).await;
        if let Err(err) = &send_res {
            self.append_to_wal(&row).await?;
            error!("insert_audit_failed_after_retries: {err}");
        }
        send_res.map(|_| ())
    }

    pub async fn deduct_credits(&self, key_hash: &str, cost: i64) -> Result<i64, SupabaseError> {
        let endpoint = format!("{}/rest/v1/rpc/deduct_credits", self.url);
        let body = serde_json::json!({"p_key_hash": key_hash, "p_cost": cost});
        let value = self.request_with_retry("POST", &endpoint, Some(body)).await?;
        value
            .as_i64()
            .ok_or_else(|| SupabaseError::Serialization("deduct_credits response is not int".into()))
    }

    pub async fn recent_audit(&self, key_hash: &str, limit: usize) -> Result<Vec<AuditRow>, SupabaseError> {
        let endpoint = format!(
            "{}/rest/v1/audit_log?key_hash=eq.{}&order=ts.desc&limit={}",
            self.url, key_hash, limit
        );
        let value = self.request_with_retry("GET", &endpoint, None).await?;
        serde_json::from_value(value).map_err(|e| SupabaseError::Serialization(e.to_string()))
    }

    pub async fn get_audit_action(&self, key_hash: &str, action_id: &str) -> Result<Option<AuditRow>, SupabaseError> {
        let endpoint = format!(
            "{}/rest/v1/audit_log?key_hash=eq.{}&action_id=eq.{}&select=*",
            self.url, key_hash, action_id
        );
        let value = self.request_with_retry("GET", &endpoint, None).await?;
        let rows: Vec<AuditRow> = serde_json::from_value(value)
            .map_err(|e| SupabaseError::Serialization(e.to_string()))?;
        Ok(rows.into_iter().next())
    }

    pub async fn purge_old_audit(&self, key_hash: &str, cutoff_iso: &str) -> Result<(), SupabaseError> {
        let endpoint = format!(
            "{}/rest/v1/audit_log?key_hash=eq.{}&ts=lt.{}",
            self.url, key_hash, cutoff_iso
        );
        self.request_with_retry("DELETE", &endpoint, None).await?;
        Ok(())
    }

    pub async fn get_api_key(&self, key_hash: &str) -> Result<Option<ApiKeyRow>, SupabaseError> {
        let endpoint = format!("{}/rest/v1/api_keys?key_hash=eq.{}&select=*", self.url, key_hash);
        let value = self.request_with_retry("GET", &endpoint, None).await?;
        let rows: Vec<ApiKeyRow> = serde_json::from_value(value)
            .map_err(|e| SupabaseError::Serialization(e.to_string()))?;
        Ok(rows.into_iter().next())
    }

    pub async fn patch_api_key(
        &self,
        key_hash: &str,
        patch: serde_json::Value,
    ) -> Result<(), SupabaseError> {
        let endpoint = format!("{}/rest/v1/api_keys?key_hash=eq.{}", self.url, key_hash);
        self.request_with_retry("PATCH", &endpoint, Some(patch)).await?;
        Ok(())
    }

    pub async fn get_session_state(&self, session_id: &str) -> Result<Option<SessionState>, SupabaseError> {
        let endpoint = format!(
            "{}/rest/v1/session_states?session_id=eq.{}&select=*",
            self.url, session_id
        );
        let value = self.request_with_retry("GET", &endpoint, None).await?;
        let rows: Vec<SessionState> = serde_json::from_value(value)
            .map_err(|e| SupabaseError::Serialization(e.to_string()))?;
        Ok(rows.into_iter().next())
    }

    pub async fn upsert_session_state(&self, state: &SessionState) -> Result<(), SupabaseError> {
        let endpoint = format!("{}/rest/v1/session_states", self.url);
        let body = serde_json::to_value(state)
            .map_err(|e| SupabaseError::Serialization(e.to_string()))?;
        self.request_with_retry("POST", &endpoint, Some(body)).await?;
        Ok(())
    }

    async fn append_to_wal(&self, row: &AuditRow) -> Result<(), SupabaseError> {
        if let Some(parent) = Path::new(WAL_PATH).parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| SupabaseError::Wal(e.to_string()))?;
        }
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .open(WAL_PATH)
            .await
            .map_err(|e| SupabaseError::Wal(e.to_string()))?;
        let line = serde_json::to_string(row)
            .map_err(|e| SupabaseError::Serialization(e.to_string()))?;
        f.write_all(line.as_bytes())
            .await
            .map_err(|e| SupabaseError::Wal(e.to_string()))?;
        f.write_all(b"\n")
            .await
            .map_err(|e| SupabaseError::Wal(e.to_string()))?;
        Ok(())
    }

    async fn request_with_retry(
        &self,
        method: &str,
        url: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, SupabaseError> {
        self.ensure_circuit_closed()?;

        let mut last_err: Option<SupabaseError> = None;
        for delay in RETRY_DELAYS_MS {
            let req = match method {
                "GET" => self.http.get(url),
                "POST" => self.http.post(url),
                "PATCH" => self.http.patch(url),
                "DELETE" => self.http.delete(url),
                _ => {
                    return Err(SupabaseError::Transport(format!(
                        "unsupported method {method}"
                    )))
                }
            }
            .header("apikey", &self.service_key)
            .header("Authorization", format!("Bearer {}", self.service_key))
            .header("Content-Type", "application/json")
            .header("Prefer", "return=representation");

            let req = if let Some(ref b) = body { req.json(b) } else { req };
            match req.send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        self.record_success();
                        let text = resp
                            .text()
                            .await
                            .map_err(|e| SupabaseError::Transport(e.to_string()))?;
                        if text.trim().is_empty() {
                            return Ok(serde_json::Value::Null);
                        }
                        let v = serde_json::from_str(&text)
                            .map_err(|e| SupabaseError::Serialization(e.to_string()))?;
                        return Ok(v);
                    }
                    let status = resp.status();
                    let body_text = resp.text().await.unwrap_or_default();
                    last_err = Some(SupabaseError::Http(status.as_u16(), body_text));
                    self.record_failure();
                }
                Err(e) => {
                    last_err = Some(SupabaseError::Transport(e.to_string()));
                    self.record_failure();
                }
            }
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        Err(last_err.unwrap_or_else(|| SupabaseError::Transport("unknown retry failure".into())))
    }

    fn ensure_circuit_closed(&self) -> Result<(), SupabaseError> {
        let mut state = self.circuit.lock().expect("circuit lock poisoned");
        if let Some(until) = state.open_until {
            if Instant::now() < until {
                error!("supabase_circuit_open");
                return Err(SupabaseError::CircuitOpen);
            }
            state.open_until = None;
            state.consecutive_failures = 0;
        }
        Ok(())
    }

    fn record_success(&self) {
        let mut state = self.circuit.lock().expect("circuit lock poisoned");
        state.consecutive_failures = 0;
        state.open_until = None;
    }

    fn record_failure(&self) {
        let mut state = self.circuit.lock().expect("circuit lock poisoned");
        state.consecutive_failures += 1;
        if state.consecutive_failures >= CIRCUIT_FAIL_THRESHOLD {
            state.open_until = Some(Instant::now() + Duration::from_secs(CIRCUIT_OPEN_SECS));
            error!("supabase_circuit_open");
        }
    }
}
