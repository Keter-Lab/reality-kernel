//! The audit signing key (docs/design/phase-9.md §3.3).
//!
//! A dedicated Ed25519 key, generated on first start from the kernel RNG and
//! stored as its 32-byte seed, readable by root only. It is not derived from
//! any configured secret.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
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
    /// readable by anyone but its owner, owned by another user, or in a
    /// directory others can write is refused. A published `<path>.pub` is
    /// never rewritten: one that disagrees with the private key, or one that
    /// exists without it, is an error, because the published key is what
    /// verifiers trust (docs/audit.md).
    pub fn load_or_create(path: &Path) -> Result<Self> {
        let public = public_path(path);
        match fs::read(path) {
            Ok(bytes) => {
                check_location(path)?;
                let seed: [u8; SEED_LEN] = bytes.as_slice().try_into().with_context(|| {
                    format!("{}: expected a {SEED_LEN}-byte key", path.display())
                })?;
                let key = Self::from_seed(seed);
                key.publish(&public)?;
                Ok(key)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if public.exists() {
                    bail!(
                        "{}: a published audit public key exists without its private key {}; \
                         refusing to generate a new key that would replace it. If the key \
                         change is intended, move the old public key aside (keep it to verify \
                         the older segments) and start again",
                        public.display(),
                        path.display()
                    );
                }
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
                key.publish(&public)?;
                Ok(key)
            }
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    /// Writes the public half to `path` unless it is there already; refuses
    /// to replace a different one.
    fn publish(&self, path: &Path) -> Result<()> {
        match fs::read_to_string(path) {
            Ok(existing) => {
                let published = parse_public_key(&existing).with_context(|| {
                    format!("{}: published audit public key is unreadable", path.display())
                })?;
                if published != self.public_key() {
                    bail!(
                        "{}: published audit public key {} does not match the private key {}; \
                         refusing to overwrite it. Either the private key or the published key \
                         was replaced: find out which before restoring one of them",
                        path.display(),
                        key_id(&published),
                        self.key_id()
                    );
                }
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o644)
                    .open(path)
                    .with_context(|| format!("create {}", path.display()))?;
                file.write_all(format!("{}\n", hex::encode(self.public_key())).as_bytes())?;
                file.sync_all()?;
                // The mode given to open() is filtered by the umask.
                fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
                Ok(())
            }
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
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

/// An existing key must be private to its owner, owned by the user that uses
/// it (root, for the sensor), and in a directory no one else can write:
/// otherwise someone else could have read it, or could swap in their own.
fn check_location(path: &Path) -> Result<()> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let meta = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        bail!(
            "{}: audit key is accessible to group or others (mode {:o})",
            path.display(),
            mode & 0o777
        );
    }
    if meta.uid() != euid {
        bail!(
            "{}: audit key is owned by uid {}, not by uid {euid} that uses it",
            path.display(),
            meta.uid()
        );
    }
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let dmeta = fs::metadata(dir).with_context(|| format!("stat {}", dir.display()))?;
    let dmode = dmeta.permissions().mode();
    if dmeta.uid() != euid || dmode & 0o022 != 0 {
        bail!(
            "{}: the audit key's directory must be owned by uid {euid} and writable by no one \
             else (owner uid {}, mode {:o})",
            dir.display(),
            dmeta.uid(),
            dmode & 0o777
        );
    }
    Ok(())
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

    #[test]
    fn published_public_key_is_never_rewritten() {
        let dir = std::env::temp_dir().join(format!("rk-audit-pub-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("audit.key");
        let first = AuditKey::load_or_create(&path).unwrap();
        let public = public_path(&path);

        // The private key replaced: the published key disagrees, and stays.
        let other = AuditKey::from_seed([3; 32]);
        fs::write(&path, other.signing.to_bytes()).unwrap();
        let err = AuditKey::load_or_create(&path).err().unwrap().to_string();
        assert!(err.contains("does not match the private key"), "{err}");
        let published = parse_public_key(&fs::read_to_string(&public).unwrap()).unwrap();
        assert_eq!(published, first.public_key());

        // The private key removed: no new key replaces the published one.
        fs::remove_file(&path).unwrap();
        let err = AuditKey::load_or_create(&path).err().unwrap().to_string();
        assert!(err.contains("without its private key"), "{err}");
        assert!(!path.exists());

        // Moved aside on purpose: a new key is generated and published.
        fs::rename(&public, dir.join("audit.key.pub.old")).unwrap();
        let new = AuditKey::load_or_create(&path).unwrap();
        let published = parse_public_key(&fs::read_to_string(&public).unwrap()).unwrap();
        assert_eq!(published, new.public_key());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_in_a_directory_others_can_write_is_refused() {
        let dir = std::env::temp_dir().join(format!("rk-audit-keydir-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("audit.key");
        AuditKey::load_or_create(&path).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        let err = AuditKey::load_or_create(&path).err().unwrap().to_string();
        assert!(err.contains("writable by no one else"), "{err}");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(AuditKey::load_or_create(&path).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }
}
