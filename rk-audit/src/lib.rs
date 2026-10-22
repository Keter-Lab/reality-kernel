//! Reality Kernel audit log (docs/design/phase-9.md §3.2–3.3, docs/audit.md).
//!
//! - [`ocsf`] builds one OCSF 1.9.0 record per kernel decision.
//! - [`chain`] writes records to segment files in hash-chained batches, each
//!   sealed by an Ed25519 signature, and verifies them.
//! - [`key`] holds the audit signing key.
//! - [`tail`] renders records for `rk audit tail`.

pub mod chain;
pub mod key;
pub mod ocsf;
pub mod tail;

/// Default directory of the segment files.
pub const DEFAULT_DIR: &str = "/var/log/rk/audit";
/// Default location of the audit signing key (its public half is `<key>.pub`).
pub const DEFAULT_KEY: &str = "/var/lib/rk/audit.key";
