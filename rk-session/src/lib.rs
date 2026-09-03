use chrono::Utc;
use regex::Regex;
use rk_supabase::{RkSupabaseClient, SessionState};
use tracing::error;

pub async fn update_and_check_session(
    session_id: &str,
    command: &str,
    supabase: &RkSupabaseClient,
) -> (bool, Vec<String>) {
    if session_id.is_empty() {
        return (false, vec![]);
    }

    let mut state = SessionState {
        session_id: session_id.to_string(),
        cumulative_reads: 0,
        cumulative_sensitive: 0,
        network_egress_count: 0,
        last_activity: now_secs(),
        recent_commands: vec![],
    };

    if let Err(e) = apply_existing_state(session_id, supabase, &mut state).await {
        error!("session read failure: {e}");
        return (
            false,
            vec!["session_read_failed: using safe default, manual review recommended".to_string()],
        );
    }

    let cmd_lower = command.to_lowercase();

    let is_read = has_any_word(&cmd_lower, &["cat", "ls", "head", "tail", "grep", "find"]);
    let is_sensitive = [".env", "/etc/passwd", "/etc/shadow", "id_rsa", "secret", "credential", "token", "base64"]
        .iter()
        .any(|w| cmd_lower.contains(w));
    let is_network = has_any_word(&cmd_lower, &["curl", "wget", "nc", "scp", "rsync", "ssh", "telnet", "ftp", "sftp"]);

    if is_read {
        state.cumulative_reads += 1;
    }
    if is_sensitive {
        state.cumulative_sensitive += 1;
    }
    if is_network {
        let internal_pat = Regex::new(r"(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+|127\.\d+\.\d+\.\d+|localhost)").unwrap();
        if !internal_pat.is_match(&cmd_lower) {
            state.network_egress_count += 1;
        }
    }

    state.recent_commands.push(command.chars().take(100).collect());
    if state.recent_commands.len() > 10 {
        state.recent_commands = state.recent_commands[state.recent_commands.len() - 10..].to_vec();
    }
    state.last_activity = now_secs();

    if let Err(e) = supabase.upsert_session_state(&state).await {
        error!("session upsert failed: {e}");
    }

    let mut evidence = Vec::new();
    if state.cumulative_sensitive >= 3 {
        evidence.push(format!(
            "Session Rule: High volume of sensitive reads ({}) within session",
            state.cumulative_sensitive
        ));
    }
    if state.cumulative_reads >= 10 {
        evidence.push(format!(
            "Session Rule: Reconnaissance pattern detected ({}) reads",
            state.cumulative_reads
        ));
    }
    if is_network && state.network_egress_count > 0 && state.cumulative_sensitive > 0 {
        evidence.push(
            "Session Rule: Network egress attempted following sensitive reads (Slow-Drip Exfiltration Chain)".to_string(),
        );
    }

    (!evidence.is_empty(), evidence)
}

async fn apply_existing_state(
    session_id: &str,
    supabase: &RkSupabaseClient,
    state: &mut SessionState,
) -> Result<(), String> {
    let maybe = supabase
        .get_session_state(session_id)
        .await
        .map_err(|e| e.to_string())?;
    if let Some(existing) = maybe {
        *state = existing;
        let current = now_secs();
        let hours_passed = (current - state.last_activity) / 3600.0;
        if hours_passed >= 6.0 {
            state.cumulative_reads = 0;
            state.cumulative_sensitive = 0;
            state.network_egress_count = 0;
        } else if hours_passed >= 1.0 {
            state.cumulative_reads = ((state.cumulative_reads as f64) * 0.5).floor() as i64;
            state.cumulative_sensitive = ((state.cumulative_sensitive as f64) * 0.5).floor() as i64;
            state.network_egress_count = ((state.network_egress_count as f64) * 0.5).floor() as i64;
        }
    }
    Ok(())
}

fn has_any_word(text: &str, words: &[&str]) -> bool {
    words.iter().any(|w| Regex::new(&format!(r"\b{}\b", regex::escape(w))).unwrap().is_match(text))
}

fn now_secs() -> f64 {
    Utc::now().timestamp_millis() as f64 / 1000.0
}
