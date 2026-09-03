use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("invalid signing key material")]
    InvalidKey,
    #[error("signing failed: {0}")]
    SignFailed(String),
}

pub struct RkSigner {
    signing_key: SigningKey,
    public_key_b64: String,
}

impl RkSigner {
    pub fn new(secret_key: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(format!("rk_ed25519_v1:{secret_key}").as_bytes());
        let digest = hasher.finalize();
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&digest[..32]);

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying: VerifyingKey = signing_key.verifying_key();
        let public_key_b64 = STANDARD.encode(verifying.as_bytes());

        Self {
            signing_key,
            public_key_b64,
        }
    }

    pub fn sign(&self, payload: &str) -> Result<String, SigningError> {
        let sig = self.signing_key.sign(payload.as_bytes());
        Ok(STANDARD.encode(sig.to_bytes()))
    }

    pub fn public_key_b64(&self) -> &str {
        &self.public_key_b64
    }

    pub fn compute_proof_hash(
        action_id: &str,
        cmd: &str,
        intent: &str,
        verdict: &str,
        confidence: f64,
        policy: &str,
        prev_hash: &str,
    ) -> String {
        let payload = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            action_id,
            trunc(cmd, 500),
            trunc(intent, 500),
            verdict,
            confidence,
            policy,
            prev_hash
        );
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn signing_payload(action_id: &str, proof_hash: &str, verdict: &str, confidence: f64) -> String {
        format!("{action_id}:{proof_hash}:{verdict}:{confidence}")
    }
}

fn trunc(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}
