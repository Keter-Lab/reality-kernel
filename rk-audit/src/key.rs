//! The audit signing key (docs/design/phase-9.md §3.3).
//!
//! A dedicated Ed25519 key, generated on first start from the kernel RNG and
//! stored as its 32-byte seed, readable by root only. It is not derived from
//! any configured secret.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use sha2::{Digest as _, Sha256};

pub const SEED_LEN: usize = 32;

pub struct AuditKey {
    signing: SigningKey,
}

impl AuditKey {
    pub fn from_seed(seed: [u8; SEED_LEN]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// A fresh key from the kernel RNG.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; SEED_LEN];
        let mut filled = 0;
        while filled < SEED_LEN {
            // SAFETY: writes at most SEED_LEN - filled bytes into `seed`.
            let n = unsafe {
                libc::getrandom(seed[filled..].as_mut_ptr().cast(), SEED_LEN - filled, 0)
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err).context("getrandom");
            }
            filled += n as usize;
        }
        Ok(Self::from_seed(seed))
    }

    /// Loads the key at `path`, creating it (0600, directory 0700) and its
    /// public half at `<path>.pub` when it does not exist. An existing key
    /// readable by anyone but its owner is refused.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        match fs::read(path) {
            Ok(bytes) => {
                let mode = fs::metadata(path)?.permissions().mode();
                if mode & 0o077 != 0 {
                    bail!(
                        "{}: audit key is accessible to group or others (mode {:o})",
                        path.display(),
                        mode & 0o777
                    );
                }
                let seed: [u8; SEED_LEN] = bytes.as_slice().try_into().with_context(|| {
                    format!("{}: expected a {SEED_LEN}-byte key", path.display())
                })?;
                let key = Self::from_seed(seed);
                key.write_public(&public_path(path))?;
                Ok(key)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = Self::generate()?;
                if let Some(dir) = path.parent() {
                    fs::create_dir_all(dir)?;
                    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
                }
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .with_context(|| format!("create {}", path.display()))?;
                file.write_all(&key.signing.to_bytes())?;
                file.sync_all()?;
                key.write_public(&public_path(path))?;
                Ok(key)
            }
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    fn write_public(&self, path: &Path) -> Result<()> {
        let text = format!("{}\n", hex::encode(self.public_key()));
        if fs::read_to_string(path).ok().as_deref() != Some(text.as_str()) {
            fs::write(path, text).with_context(|| format!("write {}", path.display()))?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
        }
        Ok(())
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn key_id(&self) -> String {
        key_id(&self.public_key())
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

/// `<key>.pub`.
pub fn public_path(key: &Path) -> PathBuf {
    let mut p = key.as_os_str().to_owned();
    p.push(".pub");
    PathBuf::from(p)
}

/// Short identifier of a public key: the first 8 bytes of its SHA-256, hex.
pub fn key_id(public_key: &[u8; 32]) -> String {
    hex::encode(&Sha256::digest(public_key)[..8])
}

/// Parses a public key file or argument: 64 hex digits, surrounding space ignored.
pub fn parse_public_key(text: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(text.trim()).context("public key is not hex")?;
    bytes
        .as_slice()
        .try_into()
        .ok()
        .context("public key must be 32 bytes")
}

pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    key.verify(message, &Signature::from_bytes(signature))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let key = AuditKey::from_seed([7; 32]);
        let sig = key.sign(b"hash");
        assert!(verify(&key.public_key(), b"hash", &sig));
        assert!(!verify(&key.public_key(), b"hasH", &sig));
        assert!(!verify(
            &AuditKey::from_seed([8; 32]).public_key(),
            b"hash",
            &sig
        ));
        assert_eq!(key.key_id().len(), 16);
    }

    #[test]
    fn generated_keys_differ() {
        let a = AuditKey::generate().unwrap();
        let b = AuditKey::generate().unwrap();
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn load_or_create_persists_and_refuses_open_permissions() {
        let dir = std::env::temp_dir().join(format!("rk-audit-key-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("audit.key");
        let first = AuditKey::load_or_create(&path).unwrap();
        let again = AuditKey::load_or_create(&path).unwrap();
        assert_eq!(first.public_key(), again.public_key());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let published = fs::read_to_string(public_path(&path)).unwrap();
        assert_eq!(parse_public_key(&published).unwrap(), first.public_key());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(AuditKey::load_or_create(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
