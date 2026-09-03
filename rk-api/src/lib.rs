use axum::{
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use rk_engine_core::analyse;
use rk_policy::{verify_least_agency_policy, LeastAgencyPolicy as PolicyCore};
use rk_session::update_and_check_session;
use rk_signing::RkSigner;
use rk_supabase::{ApiKeyRow, AuditRow, RkSupabaseClient, SupabaseError};
use rk_types::{
    CheckRequest, CheckResponse, DirectOverrideRequest, HealthResponse, MeResponse, OverrideRequest,
    OverrideResponse, ScanRequest, ScanResponse, ScanResult, TokenRequest, TokenResponse,
    VersionResponse, WebhookRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::Arc,
    time::{Duration as StdDuration, Instant},
};
use tokio::sync::Mutex;
use tower_http::{
    compression::CompressionLayer,
    cors::{AllowOrigin, CorsLayer},
    set_header::SetResponseHeaderLayer,
};
use tracing::{error, warn};

type HmacSha256 = Hmac<Sha256>;

const API_VERSION: &str = "0.4.2-ELITE";
const FAST_PATH_COST: i64 = 1;
const FULL_ENGINE_COST: i64 = 5;
const LOW_CREDIT_THRESHOLD: f64 = 0.10;
const DEMO_RATE_WINDOW: u64 = 60;
const CHECK_WINDOW: u64 = 60;
const IDEMP_TTL_SECS: u64 = 300;

#[derive(Clone)]
pub struct AppState {
    supabase: RkSupabaseClient,
    signer: Arc<RkSigner>,
    server_secret: Arc<Vec<u8>>,
    discord_notify_block: bool,
    demo_rpm: usize,
    check_burst_pm: usize,
    demo_calls: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
    check_calls: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
    idempotency_cache: Arc<Mutex<HashMap<(String, String), IdempotentEntry>>>,
}

#[derive(Clone)]
struct IdempotentEntry {
    expires_at: Instant,
    body: serde_json::Value,
    credit_headers: HashMap<String, String>,
}

#[derive(Serialize)]
struct ErrorBody {
    detail: String,
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    detail: String,
}

impl ApiError {
    fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: detail.into(),
        }
    }

    fn internal_logged(context: &str, err: impl std::fmt::Display) -> Self {
        error!("{context}: {err}");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal error. Please retry.",
        )
    }

    fn generic_supabase(err: SupabaseError, context: &str) -> Self {
        error!("supabase {context}: {err}");
        Self::new(
            StatusCode::BAD_GATEWAY,
            "Upstream service unavailable. Please retry.",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(ErrorBody { detail: self.detail })).into_response()
    }
}

pub fn app_from_env() -> Result<Router, ApiError> {
    let supabase_url = std::env::var("SUPABASE_URL").unwrap_or_default();
    let supabase_key = std::env::var("SUPABASE_SERVICE_KEY").unwrap_or_default();
    if supabase_url.trim().is_empty() || supabase_key.trim().is_empty() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable. Supabase environment variables are missing.",
        ));
    }

    let rk_secret = std::env::var("RK_SECRET_KEY").unwrap_or_default();
    let signer = Arc::new(RkSigner::new(&rk_secret));

    let server_secret = std::env::var("SERVER_SECRET")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("RK_SECRET_KEY").ok())
        .unwrap_or_else(|| "dev-fallback-secret-12345".to_string())
        .into_bytes();

    let discord_notify_block = std::env::var("DISCORD_NOTIFY_BLOCK")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let demo_rpm = std::env::var("RK_DEMO_RPM")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(10);
    let check_burst_pm = std::env::var("RK_CHECK_BURST")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(120);

    let state = AppState {
        supabase: RkSupabaseClient::new(&supabase_url, &supabase_key),
        signer,
        server_secret: Arc::new(server_secret),
        discord_notify_block,
        demo_rpm,
        check_burst_pm,
        demo_calls: Arc::new(Mutex::new(HashMap::new())),
        check_calls: Arc::new(Mutex::new(HashMap::new())),
        idempotency_cache: Arc::new(Mutex::new(HashMap::new())),
    };

    Ok(build_router(state))
}

pub fn build_router(state: AppState) -> Router {
    let cors = strict_cors_layer();

    Router::new()
        .route("/", get(root))
        .route("/healthz", get(healthz))
        .route("/v1/version", get(version))
        .route("/v1/pubkey", get(pubkey))
        .route("/v1/me", get(me))
        .route("/v1/audit", get(audit))
        .route("/v1/token", post(token))
        .route("/v1/check", post(check))
        .route("/v1/scan", post(scan))
        .route("/v1/demo", post(demo))
        .route("/v1/override", post(override_verdict))
        .route("/v1/override/direct", post(override_direct))
        .route("/v1/webhook", post(save_webhook))
        .route("/v1/webhook/test", post(test_webhook))
        .with_state(state)
        .layer(middleware::from_fn(security_middleware))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=63072000"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'none'"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(CompressionLayer::new())
        .layer(cors)
}

fn strict_cors_layer() -> CorsLayer {
    let from_env = std::env::var("ALLOWED_ORIGINS")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| {
            "https://realitykernel.dev,https://www.realitykernel.dev,https://rk-alpha-portal.vercel.app"
                .to_string()
        });

    let mut allowed = vec![];
    for raw in from_env.split(',') {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed == "*" {
            continue;
        }
        if let Ok(v) = HeaderValue::from_str(trimmed) {
            allowed.push(v);
        }
    }

    CorsLayer::new()
        .allow_credentials(false)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            http::header::AUTHORIZATION,
            http::header::CONTENT_TYPE,
            HeaderName::from_static("idempotency-key"),
        ])
        .allow_origin(AllowOrigin::list(allowed))
}

use http::header::HeaderName;

async fn security_middleware(req: axum::extract::Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    resp.headers_mut().insert(
        HeaderName::from_static("x-rk-api-version"),
        HeaderValue::from_static(API_VERSION),
    );
    resp
}

async fn root() -> impl IntoResponse {
    Json(json!({"name":"Reality Kernel API","version":API_VERSION,"edge":"axum"}))
}

async fn healthz() -> impl IntoResponse {
    Json(HealthResponse {
        ok: true,
        ts: Utc::now().timestamp_millis() as f64 / 1000.0,
        version: API_VERSION.to_string(),
    })
}

async fn version() -> impl IntoResponse {
    Json(VersionResponse {
        api_version: API_VERSION.to_string(),
        fast_path_cost: FAST_PATH_COST,
        full_engine_cost: FULL_ENGINE_COST,
    })
}

async fn pubkey(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(json!({
        "algorithm": "Ed25519",
        "public_key": state.signer.public_key_b64(),
        "encoding": "base64-raw",
        "sign_data_format": "{action_id}:{proof_hash}:{verdict}:{confidence}",
        "version": API_VERSION
    })))
}

#[derive(Clone)]
struct AuthContext {
    key_hash: String,
    row: ApiKeyRow,
    limit: i64,
    agent_id: String,
    session_id: String,
    scopes: Vec<String>,
    is_session_token: bool,
}

async fn auth_from_headers(state: &AppState, headers: &HeaderMap) -> Result<AuthContext, ApiError> {
    let auth = headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if !auth.starts_with("Bearer ") {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "Authorization header must be: Bearer <your-api-key>",
        ));
    }
    let raw = auth.trim_start_matches("Bearer ").trim();
    if raw.starts_with("rk_session_") {
        return auth_session_token(state, raw).await;
    }

    if raw.len() < 16 || raw.len() > 256 {
        return Err(ApiError::new(StatusCode::UNAUTHORIZED, "Invalid API key."));
    }
    let key_hash = hash_key(raw);
    let row = state
        .supabase
        .get_api_key(&key_hash)
        .await
        .map_err(|e| ApiError::generic_supabase(e, "get_api_key"))?
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "Invalid API key."))?;

    validate_key_status(&row)?;
    let limit = row.credits_limit;
    if limit > 0 && row.credits_used >= limit {
        return Err(ApiError::new(
            StatusCode::PAYMENT_REQUIRED,
            "Credit limit reached. Please top up.",
        ));
    }

    Ok(AuthContext {
        key_hash,
        row,
        limit,
        agent_id: String::new(),
        session_id: String::new(),
        scopes: vec![],
        is_session_token: false,
    })
}

async fn auth_session_token(state: &AppState, raw: &str) -> Result<AuthContext, ApiError> {
    let parts: Vec<&str> = raw.split('_').collect();
    if parts.len() != 4 {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "Malformed session token structure.",
        ));
    }

    let payload_hex = parts[2];
    let sig_hex = parts[3];
    let expected_sig = hmac_hex(&state.server_secret, payload_hex.as_bytes())
        .map_err(|e| ApiError::internal_logged("session_hmac", e))?;
    if !constant_time_eq(&expected_sig, sig_hex) {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "Invalid session token signature.",
        ));
    }

    let payload_bytes = hex::decode(payload_hex)
        .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "Malformed session token payload."))?;
    let payload: SessionTokenPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "Malformed session token payload."))?;

    if Utc::now().timestamp() > payload.exp {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "Session token has expired.",
        ));
    }

    let row = state
        .supabase
        .get_api_key(&payload.key_hash)
        .await
        .map_err(|e| ApiError::generic_supabase(e, "get_api_key(session)"))?
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "Session key owner not found."))?;

    validate_key_status(&row)?;
    let limit = row.credits_limit;
    if limit > 0 && row.credits_used >= limit {
        return Err(ApiError::new(
            StatusCode::PAYMENT_REQUIRED,
            "Credit limit reached. Please top up.",
        ));
    }

    Ok(AuthContext {
        key_hash: payload.key_hash,
        row,
        limit,
        agent_id: payload.agent_id.unwrap_or_default(),
        session_id: payload.session_id.unwrap_or_default(),
        scopes: payload.scopes.unwrap_or_default(),
        is_session_token: true,
    })
}

fn validate_key_status(row: &ApiKeyRow) -> Result<(), ApiError> {
    match row.status.as_str() {
        "suspended" => Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "This API key has been suspended.",
        )),
        "revoked" => Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "This API key has been revoked.",
        )),
        _ => Ok(()),
    }
}

#[derive(Deserialize)]
struct SessionTokenPayload {
    key_hash: String,
    exp: i64,
    agent_id: Option<String>,
    session_id: Option<String>,
    scopes: Option<Vec<String>>,
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> Result<impl IntoResponse, ApiError> {
    let auth = auth_from_headers(&state, &headers).await?;
    if auth.is_session_token {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Session tokens cannot access configuration endpoints.",
        ));
    }

    let used = auth.row.credits_used;
    let limit = auth.limit;
    let remaining = (limit - used).max(0);

    Ok(Json(MeResponse {
        name: auth.row.name.clone(),
        email: auth.row.email.clone(),
        company: auth.row.company.clone(),
        plan: auth.row.plan.clone(),
        status: Some(auth.row.status.clone()),
        created_at: auth.row.created_at.clone(),
        expires_at: auth.row.expires_at.clone(),
        key_masked: format!("{}…{}", auth.row.key_prefix, auth.row.key_suffix),
        credits_used: used,
        credits_limit: limit,
        credits_remaining: remaining,
        pct_used: if limit > 0 {
            ((used as f64 / limit as f64) * 1000.0).round() / 10.0
        } else {
            0.0
        },
        low_credits: limit > 0 && (remaining as f64) < (limit as f64 * LOW_CREDIT_THRESHOLD),
        top_up_log: auth.row.top_up_log.clone(),
        discord_webhook: auth.row.discord_webhook.clone(),
        strict_mode: auth.row.strict_mode,
        retention_days: auth.row.retention_days,
        siem_url: auth.row.siem_url.clone().unwrap_or_default(),
    }))
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<usize>,
}

async fn audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let auth = auth_from_headers(&state, &headers).await?;
    if auth.is_session_token {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Session tokens cannot access audit logs.",
        ));
    }
    let limit = query.limit.unwrap_or(50).clamp(1, 200);

    if auth.row.retention_days > 0 {
        let cutoff = (Utc::now() - Duration::days(auth.row.retention_days)).to_rfc3339();
        state
            .supabase
            .purge_old_audit(&auth.key_hash, &cutoff)
            .await
            .map_err(|e| ApiError::generic_supabase(e, "purge_old_audit"))?;
    }

    let rows = state
        .supabase
        .recent_audit(&auth.key_hash, limit)
        .await
        .map_err(|e| ApiError::generic_supabase(e, "recent_audit"))?;

    Ok(Json(json!({"entries": rows, "count": rows.len()})))
}

async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TokenRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let auth = auth_from_headers(&state, &headers).await?;
    if auth.is_session_token {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Cannot generate a session token using another session token.",
        ));
    }

    let now = Utc::now().timestamp();
    let payload = json!({
        "key_hash": auth.key_hash,
        "agent_id": truncate(&body.agent_id, 120),
        "session_id": truncate(&body.session_id, 120),
        "scopes": body.scopes,
        "exp": now + body.ttl,
    });
    let payload_json = serde_json::to_string(&payload)
        .map_err(|e| ApiError::internal_logged("token_serialize", e))?;
    let payload_hex = hex::encode(payload_json.as_bytes());
    let sig = hmac_hex(&state.server_secret, payload_hex.as_bytes())
        .map_err(|e| ApiError::internal_logged("token_hmac", e))?;

    Ok(Json(TokenResponse {
        token: format!("rk_session_{payload_hex}_{sig}"),
        expires_at: now + body.ttl,
        scopes: body.scopes,
        agent_id: body.agent_id,
        session_id: body.session_id,
    }))
}

async fn check(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CheckRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let auth = auth_from_headers(&state, &headers).await?;

    enforce_check_rate_limit(&state, &auth.key_hash).await?;

    let command = body.command.clone().unwrap_or_default();
    let prime_intent = body.prime_intent.clone().unwrap_or_default();

    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|h| h.to_str().ok())
        .map(|s| truncate(s.trim(), 128))
        .unwrap_or_default();

    if !idempotency_key.is_empty() {
        if let Some((payload, credit_headers)) = idempotent_get(&state, &auth.key_hash, &idempotency_key).await {
            return Ok(with_headers(Json(payload), credit_headers, true));
        }
    }

    let policy_violation = verify_policy_violation(&command, body.policy.as_ref(), &auth.scopes);
    if let Some(violation) = policy_violation {
        let out = policy_block_flow(&state, &auth, &body, &headers, &command, &prime_intent, &violation).await?;
        if !idempotency_key.is_empty() {
            idempotent_put(&state, &auth.key_hash, &idempotency_key, &out.0, &out.1).await;
        }
        return Ok(with_headers(Json(out.0), out.1, false));
    }

    let is_fast = rk_engine_core::is_fast_path(&command);
    let cost = if is_fast { FAST_PATH_COST } else { FULL_ENGINE_COST };

    if auth.limit > 0 && auth.row.credits_used + cost > auth.limit {
        return Err(ApiError::new(
            StatusCode::PAYMENT_REQUIRED,
            "Insufficient credits for this operation.",
        ));
    }

    let start = Instant::now();
    let session_ledger_id = format!("{}_{}", auth.key_hash, if auth.agent_id.is_empty() { "default" } else { &auth.agent_id });
    let (is_escalated, session_evidence) = update_and_check_session(&session_ledger_id, &command, &state.supabase).await;

    let mut decision = analyse(&command, &prime_intent, 5);

    if is_escalated && decision.verdict == "ALLOW" {
        decision.verdict = "WARN".to_string();
        decision.confidence = decision.confidence.max(0.65);
    }
    if is_escalated
        && decision.verdict == "WARN"
        && session_evidence.iter().any(|e| e.contains("Slow-Drip"))
    {
        decision.verdict = "BLOCK".to_string();
        decision.confidence = 1.0;
    }

    if !session_evidence.is_empty() {
        decision.evidence.extend(session_evidence);
    }

    if auth.row.strict_mode && decision.confidence >= 0.85 && decision.verdict != "BLOCK" {
        decision.verdict = "BLOCK".to_string();
        decision
            .evidence
            .push("Strict Mode Enforcement: Confidence >= 85% automatically blocked.".to_string());
    }

    let latency_ms = ((start.elapsed().as_secs_f64() * 1000.0) * 10.0).round() / 10.0;

    let new_used = state
        .supabase
        .deduct_credits(&auth.key_hash, cost)
        .await
        .map_err(|e| ApiError::generic_supabase(e, "deduct_credits"))?;

    let prev_hash = previous_hash(&state, &auth.key_hash).await?;
    let policy_str = policy_json_string(body.policy.as_ref());
    let proof_hash = RkSigner::compute_proof_hash(
        &decision.action_id,
        &command,
        &prime_intent,
        &decision.verdict,
        decision.confidence,
        &policy_str,
        &prev_hash,
    );

    let mut evidence = decision.evidence.clone();
    if !prev_hash.is_empty() {
        evidence.push(format!("prev_hash:{prev_hash}"));
    }

    let sign_payload = RkSigner::signing_payload(
        &decision.action_id,
        &proof_hash,
        &decision.verdict,
        decision.confidence,
    );
    let signature = state
        .signer
        .sign(&sign_payload)
        .map_err(|e| ApiError::internal_logged("ed25519_sign", e))?;

    let remaining = remaining(auth.limit, new_used);

    let audit_row = AuditRow {
        key_hash: auth.key_hash.clone(),
        action_id: decision.action_id.clone(),
        command: command.clone(),
        prime_intent: prime_intent.clone(),
        session_id: truncate(
            if body.session_id.is_empty() {
                &auth.session_id
            } else {
                &body.session_id
            },
            120,
        ),
        agent_id: truncate(
            if body.agent_id.is_empty() {
                &auth.agent_id
            } else {
                &body.agent_id
            },
            120,
        ),
        verdict: decision.verdict.clone(),
        confidence: decision.confidence,
        evidence: evidence.clone(),
        proof_hash: proof_hash.clone(),
        cost,
        credits_after: remaining,
        fast_path: is_fast,
        client_ip: client_ip(&headers),
        ed25519_signature: Some(signature.clone()),
        ed25519_pubkey: Some(state.signer.public_key_b64().to_string()),
        ts: None,
    };

    state
        .supabase
        .insert_audit(audit_row)
        .await
        .map_err(|e| ApiError::generic_supabase(e, "insert_audit"))?;

    notify_discord_if_needed(
        &state,
        &auth.row.discord_webhook,
        &decision.verdict,
        &decision.action_id,
        &command,
        &prime_intent,
        decision.confidence,
        decision.max_divergence,
        decision.worlds_evaluated,
        &evidence,
        &body.session_id,
        &body.agent_id,
    );

    let out = CheckResponse {
        action_id: decision.action_id,
        verdict: decision.verdict,
        confidence: decision.confidence,
        worlds_evaluated: decision.worlds_evaluated,
        worlds_in_basin_b: decision.worlds_in_basin_b,
        max_divergence: decision.max_divergence,
        evidence: decision.evidence,
        proof_hash,
        latency_ms,
        credits_consumed: cost,
        credits_remaining: remaining,
        ed25519_signature: Some(signature),
        ed25519_pubkey: Some(state.signer.public_key_b64().to_string()),
    };

    let out_json = serde_json::to_value(&out).map_err(|e| ApiError::internal_logged("check_serialize", e))?;
    let credit_headers = credit_headers(auth.limit, new_used);

    if !idempotency_key.is_empty() {
        idempotent_put(&state, &auth.key_hash, &idempotency_key, &out_json, &credit_headers).await;
    }

    Ok(with_headers(Json(out_json), credit_headers, false))
}

async fn policy_block_flow(
    state: &AppState,
    auth: &AuthContext,
    body: &CheckRequest,
    headers: &HeaderMap,
    command: &str,
    intent: &str,
    violation: &str,
) -> Result<(serde_json::Value, HashMap<String, String>), ApiError> {
    let ts = Utc::now().timestamp_millis();
    let action_id = hex::encode(Sha256::digest(format!("POLICY_BLOCK:{command}:{ts}").as_bytes()))[..12]
        .to_string();

    let prev_hash = previous_hash(state, &auth.key_hash).await?;
    let policy_str = policy_json_string(body.policy.as_ref());

    let proof_hash = RkSigner::compute_proof_hash(
        &action_id,
        command,
        intent,
        "BLOCK",
        1.0,
        &policy_str,
        &prev_hash,
    );

    let new_used = state
        .supabase
        .deduct_credits(&auth.key_hash, FAST_PATH_COST)
        .await
        .map_err(|e| ApiError::generic_supabase(e, "deduct_credits(policy_block)"))?;

    let remaining = remaining(auth.limit, new_used);
    let mut evidence = vec![violation.to_string()];
    if !prev_hash.is_empty() {
        evidence.push(format!("prev_hash:{prev_hash}"));
    }

    let sign_payload = RkSigner::signing_payload(&action_id, &proof_hash, "BLOCK", 1.0);
    let signature = state
        .signer
        .sign(&sign_payload)
        .map_err(|e| ApiError::internal_logged("policy_sign", e))?;

    let row = AuditRow {
        key_hash: auth.key_hash.clone(),
        action_id: action_id.clone(),
        command: command.to_string(),
        prime_intent: intent.to_string(),
        session_id: truncate(
            if body.session_id.is_empty() {
                &auth.session_id
            } else {
                &body.session_id
            },
            120,
        ),
        agent_id: truncate(
            if body.agent_id.is_empty() {
                &auth.agent_id
            } else {
                &body.agent_id
            },
            120,
        ),
        verdict: "BLOCK".to_string(),
        confidence: 1.0,
        evidence: evidence.clone(),
        proof_hash: proof_hash.clone(),
        cost: FAST_PATH_COST,
        credits_after: remaining,
        fast_path: true,
        client_ip: client_ip(headers),
        ed25519_signature: Some(signature.clone()),
        ed25519_pubkey: Some(state.signer.public_key_b64().to_string()),
        ts: None,
    };

    state
        .supabase
        .insert_audit(row)
        .await
        .map_err(|e| ApiError::generic_supabase(e, "insert_audit(policy_block)"))?;

    let response = CheckResponse {
        action_id,
        verdict: "BLOCK".to_string(),
        confidence: 1.0,
        worlds_evaluated: 0,
        worlds_in_basin_b: 0,
        max_divergence: 1.0,
        evidence: vec![violation.to_string()],
        proof_hash,
        latency_ms: 0.1,
        credits_consumed: FAST_PATH_COST,
        credits_remaining: remaining,
        ed25519_signature: Some(signature),
        ed25519_pubkey: Some(state.signer.public_key_b64().to_string()),
    };

    let body = serde_json::to_value(response).map_err(|e| ApiError::internal_logged("policy_block_serialize", e))?;
    Ok((body, credit_headers(auth.limit, new_used)))
}

async fn scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ScanRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let auth = auth_from_headers(&state, &headers).await?;

    if body.commands.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "commands list must not be empty.",
        ));
    }
    if body.commands.len() > 50 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "commands list exceeds max_length 50.",
        ));
    }

    let mut total_cost = 0i64;
    let mut violations = 0usize;
    let mut last_used = auth.row.credits_used;
    let mut results = vec![];

    for entry in &body.commands {
        let command = entry.command.trim().to_string();
        let intent = entry.prime_intent.trim().to_string();
        let label = if entry.label.is_empty() {
            truncate(&command, 60)
        } else {
            entry.label.clone()
        };

        let policy_violation = verify_policy_violation(&command, body.policy.as_ref(), &auth.scopes);
        let (verdict, confidence, evidence, action_id, proof_hash, cost) = if let Some(v) = policy_violation {
            let cost = FAST_PATH_COST;
            if auth.limit > 0 && auth.row.credits_used + total_cost + cost > auth.limit {
                return Err(ApiError::new(
                    StatusCode::PAYMENT_REQUIRED,
                    "Insufficient credits to complete scan.",
                ));
            }
            last_used = state
                .supabase
                .deduct_credits(&auth.key_hash, cost)
                .await
                .map_err(|e| ApiError::generic_supabase(e, "deduct_credits(scan/policy)"))?;
            let p = hex::encode(Sha256::digest(
                format!("POLICY_BLOCK:{}:{}:{}", truncate(&command, 200), truncate(&intent, 200), Utc::now().timestamp_millis())
                    .as_bytes(),
            ));
            ("BLOCK".to_string(), 1.0, vec![v], p[..12].to_string(), p, cost)
        } else {
            let is_fast = rk_engine_core::is_fast_path(&command);
            let cost = if is_fast { FAST_PATH_COST } else { FULL_ENGINE_COST };
            if auth.limit > 0 && auth.row.credits_used + total_cost + cost > auth.limit {
                return Err(ApiError::new(
                    StatusCode::PAYMENT_REQUIRED,
                    "Insufficient credits to complete scan.",
                ));
            }
            last_used = state
                .supabase
                .deduct_credits(&auth.key_hash, cost)
                .await
                .map_err(|e| ApiError::generic_supabase(e, "deduct_credits(scan)"))?;

            let mut d = analyse(&command, &intent, 5);
            if auth.row.strict_mode && d.confidence >= 0.85 && d.verdict != "BLOCK" {
                d.verdict = "BLOCK".to_string();
                d.evidence.push(
                    "Strict Mode Enforcement: Confidence >= 85% automatically blocked.".to_string(),
                );
            }

            let p = hex::encode(Sha256::digest(
                format!("{}:{}:{}:{}:{}", d.action_id, truncate(&command, 200), truncate(&intent, 200), d.verdict, d.confidence)
                    .as_bytes(),
            ));
            (d.verdict, d.confidence, d.evidence, d.action_id, p, cost)
        };

        total_cost += cost;

        let sign_payload = RkSigner::signing_payload(&action_id, &proof_hash, &verdict, confidence);
        let signature = state
            .signer
            .sign(&sign_payload)
            .map_err(|e| ApiError::internal_logged("scan_sign", e))?;

        state
            .supabase
            .insert_audit(AuditRow {
                key_hash: auth.key_hash.clone(),
                action_id: action_id.clone(),
                command: command.clone(),
                prime_intent: intent.clone(),
                session_id: truncate(
                    if body.session_id.is_empty() {
                        &auth.session_id
                    } else {
                        &body.session_id
                    },
                    120,
                ),
                agent_id: truncate(
                    if body.agent_id.is_empty() {
                        &auth.agent_id
                    } else {
                        &body.agent_id
                    },
                    120,
                ),
                verdict: verdict.clone(),
                confidence,
                evidence: evidence.clone(),
                proof_hash: proof_hash.clone(),
                cost,
                credits_after: last_used,
                fast_path: rk_engine_core::is_fast_path(&command),
                client_ip: client_ip(&headers),
                ed25519_signature: Some(signature),
                ed25519_pubkey: Some(state.signer.public_key_b64().to_string()),
                ts: None,
            })
            .await
            .map_err(|e| ApiError::generic_supabase(e, "insert_audit(scan)"))?;

        let fail = matches_fail(&body.fail_on, &verdict);
        if fail {
            violations += 1;
        }

        results.push(ScanResult {
            label,
            verdict,
            evidence,
            proof_hash,
            action_id,
            fail,
        });
    }

    let remaining = remaining(auth.limit, last_used);
    let response = ScanResponse {
        policy_pass: violations == 0,
        fail_on: body.fail_on.clone(),
        total_entries: results.len(),
        violations,
        credits_consumed: total_cost,
        credits_remaining: remaining,
        results,
    };

    let payload = serde_json::to_value(response).map_err(|e| ApiError::internal_logged("scan_serialize", e))?;
    Ok(with_headers(Json(payload), credit_headers(auth.limit, last_used), false))
}

async fn override_verdict(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<OverrideRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let auth = auth_from_headers(&state, &headers).await?;
    if auth.is_session_token {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Session tokens cannot override verdicts.",
        ));
    }

    let orig = state
        .supabase
        .get_audit_action(&auth.key_hash, &body.action_id)
        .await
        .map_err(|e| ApiError::generic_supabase(e, "get_audit_action"))?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Action not found or access denied."))?;

    let verdict = if body.decision == "approved" {
        "WARN_APPROVED"
    } else {
        "WARN_REJECTED"
    }
    .to_string();

    let override_action_id = hex::encode(Sha256::digest(
        format!("OVERRIDE:{}:{}:{}", body.action_id, verdict, Utc::now().timestamp_millis()).as_bytes(),
    ))[..12]
        .to_string();

    let proof_hash = hex::encode(Sha256::digest(
        format!("{override_action_id}:override:{}:{verdict}:1.0::{}", body.action_id, orig.proof_hash).as_bytes(),
    ));

    let mut evidence = vec![
        format!("override_of:{}", body.action_id),
        format!("prev_hash:{}", orig.proof_hash),
    ];
    let warning_level = if orig.confidence > 0.60 && body.decision == "approved" {
        evidence.push("Critical override: high-confidence WARN approved by operator".to_string());
        Some("critical".to_string())
    } else {
        Some("standard".to_string())
    };

    let signature = state
        .signer
        .sign(&RkSigner::signing_payload(&override_action_id, &proof_hash, &verdict, 1.0))
        .map_err(|e| ApiError::internal_logged("override_sign", e))?;

    state
        .supabase
        .insert_audit(AuditRow {
            key_hash: auth.key_hash,
            action_id: override_action_id.clone(),
            command: orig.command,
            prime_intent: orig.prime_intent,
            session_id: orig.session_id,
            agent_id: orig.agent_id,
            verdict: verdict.clone(),
            confidence: 1.0,
            evidence,
            proof_hash,
            cost: 0,
            credits_after: 0,
            fast_path: true,
            client_ip: orig.client_ip,
            ed25519_signature: Some(signature),
            ed25519_pubkey: Some(state.signer.public_key_b64().to_string()),
            ts: None,
        })
        .await
        .map_err(|e| ApiError::generic_supabase(e, "insert_audit(override)"))?;

    Ok(Json(OverrideResponse {
        ok: true,
        verdict,
        override_action_id,
        warning_level,
    }))
}

async fn override_direct(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DirectOverrideRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let auth = auth_from_headers(&state, &headers).await?;
    if auth.is_session_token {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Session tokens cannot override verdicts.",
        ));
    }

    let expires = body
        .expires
        .parse::<i64>()
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "Invalid expiration format"))?;
    if Utc::now().timestamp() > expires {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "Token expired"));
    }

    let payload = format!("{}:{}:{}", body.action_id, body.decision, body.expires);
    let expected = hmac_hex(&state.server_secret, payload.as_bytes())
        .map_err(|e| ApiError::internal_logged("override_hmac", e))?;
    if !constant_time_eq(&expected, &body.token) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Invalid cryptographic token",
        ));
    }

    let orig = state
        .supabase
        .get_audit_action(&auth.key_hash, &body.action_id)
        .await
        .map_err(|e| ApiError::generic_supabase(e, "get_audit_action(direct)"))?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "Action not found or access denied."))?;

    let verdict = if body.decision == "approved" {
        "WARN_APPROVED"
    } else {
        "WARN_REJECTED"
    }
    .to_string();

    let override_action_id = hex::encode(Sha256::digest(
        format!("OVERRIDE:{}:{}:{}", body.action_id, verdict, Utc::now().timestamp_millis()).as_bytes(),
    ))[..12]
        .to_string();

    let proof_hash = hex::encode(Sha256::digest(
        format!("{override_action_id}:direct-override:{}:{verdict}:1.0::{}", body.action_id, orig.proof_hash)
            .as_bytes(),
    ));

    let signature = state
        .signer
        .sign(&RkSigner::signing_payload(&override_action_id, &proof_hash, &verdict, 1.0))
        .map_err(|e| ApiError::internal_logged("override_direct_sign", e))?;

    state
        .supabase
        .insert_audit(AuditRow {
            key_hash: auth.key_hash,
            action_id: override_action_id.clone(),
            command: orig.command,
            prime_intent: orig.prime_intent,
            session_id: orig.session_id,
            agent_id: orig.agent_id,
            verdict: verdict.clone(),
            confidence: 1.0,
            evidence: vec![
                format!("direct_override_of:{}", body.action_id),
                format!("prev_hash:{}", orig.proof_hash),
            ],
            proof_hash,
            cost: 0,
            credits_after: 0,
            fast_path: true,
            client_ip: orig.client_ip,
            ed25519_signature: Some(signature),
            ed25519_pubkey: Some(state.signer.public_key_b64().to_string()),
            ts: None,
        })
        .await
        .map_err(|e| ApiError::generic_supabase(e, "insert_audit(direct_override)"))?;

    Ok(Json(json!({"ok": true, "verdict": verdict, "override_action_id": override_action_id})))
}

async fn save_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<WebhookRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let auth = auth_from_headers(&state, &headers).await?;
    if auth.is_session_token {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Session tokens cannot modify webhooks.",
        ));
    }
    let webhook = validate_discord_webhook(&body.url)?;

    state
        .supabase
        .patch_api_key(&auth.key_hash, json!({"discord_webhook": webhook}))
        .await
        .map_err(|e| ApiError::generic_supabase(e, "patch_api_key(webhook)"))?;

    Ok(Json(json!({"ok": true})))
}

async fn test_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<WebhookRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let auth = auth_from_headers(&state, &headers).await?;
    if auth.is_session_token {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Session tokens cannot test webhooks.",
        ));
    }

    let webhook = validate_discord_webhook(&body.url)?;
    notify_discord_if_needed(
        &state,
        &webhook,
        "WARN",
        "test-action-id",
        "reality_kernel --verify-integration",
        "Verify that Reality Kernel can successfully push alerts to this Discord channel.",
        1.0,
        1.0,
        5,
        &["This is a test alert requested from the Reality Kernel dashboard.".to_string()],
        "test-session",
        "Dashboard User",
    );

    Ok(Json(json!({"ok": true})))
}

async fn demo(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CheckRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let command = body.command.unwrap_or_default();
    let intent = body.prime_intent.unwrap_or_default();
    let ip = client_ip(&headers);

    enforce_demo_rate_limit(&state, &ip).await?;

    let start = Instant::now();
    let decision = analyse(&command, &intent, 5);
    let latency_ms = ((start.elapsed().as_secs_f64() * 1000.0) * 10.0).round() / 10.0;

    Ok(Json(json!({
        "action_id": decision.action_id,
        "verdict": decision.verdict,
        "status": if ["BLOCK", "WARN"].contains(&decision.verdict.as_str()) { "blocked" } else { "allowed" },
        "confidence": decision.confidence,
        "worlds_evaluated": decision.worlds_evaluated,
        "worlds_in_basin_b": decision.worlds_in_basin_b,
        "max_divergence": decision.max_divergence,
        "evidence": decision.evidence,
        "proof_hash": decision.proof_hash,
        "latency_ms": latency_ms
    })))
}

async fn enforce_check_rate_limit(state: &AppState, key: &str) -> Result<(), ApiError> {
    let mut lock = state.check_calls.lock().await;
    let q = lock.entry(key.to_string()).or_insert_with(VecDeque::new);
    prune(q, CHECK_WINDOW);
    if q.len() >= state.check_burst_pm {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded per key.",
        ));
    }
    q.push_back(Instant::now());
    Ok(())
}

async fn enforce_demo_rate_limit(state: &AppState, key: &str) -> Result<(), ApiError> {
    let mut lock = state.demo_calls.lock().await;
    let q = lock.entry(key.to_string()).or_insert_with(VecDeque::new);
    prune(q, DEMO_RATE_WINDOW);
    if q.len() >= state.demo_rpm {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "Demo rate limit exceeded.",
        ));
    }
    q.push_back(Instant::now());
    Ok(())
}

fn prune(q: &mut VecDeque<Instant>, window_secs: u64) {
    let cutoff = Instant::now() - StdDuration::from_secs(window_secs);
    while matches!(q.front(), Some(ts) if *ts < cutoff) {
        q.pop_front();
    }
}

async fn idempotent_get(
    state: &AppState,
    key_hash: &str,
    idem: &str,
) -> Option<(serde_json::Value, HashMap<String, String>)> {
    let mut lock = state.idempotency_cache.lock().await;
    lock.retain(|_, v| v.expires_at > Instant::now());
    lock.get(&(key_hash.to_string(), idem.to_string()))
        .map(|entry| (entry.body.clone(), entry.credit_headers.clone()))
}

async fn idempotent_put(
    state: &AppState,
    key_hash: &str,
    idem: &str,
    body: &serde_json::Value,
    credit_headers: &HashMap<String, String>,
) {
    let mut lock = state.idempotency_cache.lock().await;
    lock.insert(
        (key_hash.to_string(), idem.to_string()),
        IdempotentEntry {
            expires_at: Instant::now() + StdDuration::from_secs(IDEMP_TTL_SECS),
            body: body.clone(),
            credit_headers: credit_headers.clone(),
        },
    );
}

fn verify_policy_violation(
    command: &str,
    policy: Option<&rk_types::LeastAgencyPolicy>,
    scopes: &[String],
) -> Option<String> {
    let mapped = policy.map(|p| PolicyCore {
        allowed_tools: p.allowed_tools.clone(),
        allowed_egress: p.allowed_egress.clone(),
        read_only_paths: p.read_only_paths.clone(),
    });
    verify_least_agency_policy(command, mapped.as_ref(), scopes)
}

async fn previous_hash(state: &AppState, key_hash: &str) -> Result<String, ApiError> {
    let rows = state
        .supabase
        .recent_audit(key_hash, 1)
        .await
        .map_err(|e| ApiError::generic_supabase(e, "recent_audit(previous_hash)"))?;
    Ok(rows
        .first()
        .map(|r| r.proof_hash.clone())
        .unwrap_or_default())
}

fn policy_json_string(policy: Option<&rk_types::LeastAgencyPolicy>) -> String {
    policy
        .and_then(|p| serde_json::to_string(p).ok())
        .unwrap_or_default()
}

fn hash_key(raw: &str) -> String {
    hex::encode(Sha256::digest(raw.as_bytes()))
}

fn hmac_hex(secret: &[u8], payload: &[u8]) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|e| e.to_string())?;
    mac.update(payload);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut out = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        out |= x ^ y;
    }
    out == 0
}

fn credit_headers(limit: i64, used: i64) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("X-RK-Credits-Limit".to_string(), limit.to_string());
    m.insert("X-RK-Credits-Used".to_string(), used.to_string());
    m.insert(
        "X-RK-Credits-Remaining".to_string(),
        remaining(limit, used).to_string(),
    );
    m
}

fn remaining(limit: i64, used: i64) -> i64 {
    if limit <= 0 {
        0
    } else {
        (limit - used).max(0)
    }
}

fn with_headers<T: IntoResponse>(payload: T, headers: HashMap<String, String>, replay: bool) -> Response {
    let mut response = payload.into_response();
    for (k, v) in headers {
        if let (Ok(name), Ok(value)) = (HeaderName::from_str(&k), HeaderValue::from_str(&v)) {
            response.headers_mut().insert(name, value);
        }
    }
    if replay {
        response.headers_mut().insert(
            HeaderName::from_static("x-rk-idempotent-replay"),
            HeaderValue::from_static("true"),
        );
    }
    response
}

fn matches_fail(fail_on: &str, verdict: &str) -> bool {
    match fail_on {
        "BLOCK" => verdict == "BLOCK",
        "WARN" => ["WARN", "WARN_APPROVED", "WARN_REJECTED"].contains(&verdict),
        "BLOCK_WARN" => {
            ["BLOCK", "WARN", "WARN_APPROVED", "WARN_REJECTED"].contains(&verdict)
        }
        _ => verdict == "BLOCK",
    }
}

fn validate_discord_webhook(url: &str) -> Result<String, ApiError> {
    let cleaned = url.trim();
    if cleaned.is_empty() {
        return Ok(String::new());
    }
    let parsed = reqwest::Url::parse(cleaned)
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "Webhook URL must be a valid Discord HTTPS webhook."))?;
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    let allowed = [
        "discord.com",
        "discordapp.com",
        "canary.discord.com",
        "ptb.discord.com",
    ];
    if parsed.scheme() != "https"
        || !allowed.contains(&host.as_str())
        || !parsed.path().starts_with("/api/webhooks/")
    {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Webhook URL must be a valid Discord HTTPS webhook.",
        ));
    }
    Ok(cleaned.to_string())
}

#[allow(clippy::too_many_arguments)]
fn notify_discord_if_needed(
    state: &AppState,
    webhook_url: &str,
    verdict: &str,
    action_id: &str,
    command: &str,
    prime_intent: &str,
    confidence: f64,
    max_divergence: f64,
    worlds_evaluated: usize,
    evidence: &[String],
    session_id: &str,
    agent_id: &str,
) {
    if webhook_url.trim().is_empty() {
        return;
    }
    if verdict != "WARN" && !(verdict == "BLOCK" && state.discord_notify_block) {
        return;
    }

    let payload = json!({
        "username": "Reality Kernel",
        "embeds": [{
            "title": if verdict == "WARN" { "WARN — Human Review Required" } else { "BLOCK — Reflexive Collapse Triggered" },
            "fields": [
                {"name": "System Command", "value": format!("```{}```", truncate(command, 200)), "inline": false},
                {"name": "Prime Intent", "value": format!("*{}*", truncate(prime_intent, 200)), "inline": false},
                {"name": "Confidence", "value": format!("{:.0}%", confidence * 100.0), "inline": true},
                {"name": "Max Divergence", "value": format!("{max_divergence:.3}"), "inline": true},
                {"name": "Worlds Evaluated", "value": worlds_evaluated.to_string(), "inline": true},
                {"name": "Evidence", "value": evidence.iter().take(3).cloned().collect::<Vec<_>>().join("\n"), "inline": false},
                {"name": "Action ID", "value": action_id, "inline": true},
                {"name": "Session", "value": truncate(session_id, 40), "inline": true},
                {"name": "Agent", "value": truncate(agent_id, 40), "inline": true}
            ]
        }]
    });

    let webhook = webhook_url.to_string();
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        if let Err(e) = client.post(webhook).json(&payload).send().await {
            warn!("discord notify failed (non-fatal): {e}");
        }
    });
}

fn client_ip(headers: &HeaderMap) -> String {
    let xff = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    if !xff.is_empty() {
        let mut first: Option<String> = None;
        for raw in xff.split(',') {
            let ip = raw.trim();
            if ip.is_empty() {
                continue;
            }
            if first.is_none() {
                first = Some(ip.to_string());
            }
            if let Ok(addr) = IpAddr::from_str(ip) {
                if !is_private_ip(addr) {
                    return truncate(ip, 64);
                }
            }
        }
        if let Some(ip) = first {
            return truncate(&ip, 64);
        }
    }

    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(|v| truncate(v, 64))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4 == Ipv4Addr::new(0, 0, 0, 0)
                || v4 == Ipv4Addr::new(255, 255, 255, 255)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6 == Ipv6Addr::LOCALHOST
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}
