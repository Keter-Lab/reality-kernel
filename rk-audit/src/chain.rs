//! Hash-chained, signed batches of audit records (docs/design/phase-9.md §3.3).
//!
//! A directory holds segment files, `<first-seq>.jsonl` with the sequence
//! zero-padded so that name order is chain order. Each segment starts with a
//! header line naming the chain position and the public key, then holds
//! record lines, each batch closed by a trailer line:
//!
//! ```text
//! {"rk_segment":{"seq":12,"prev":"<hex>","key_id":"..","public_key":"<hex>"}}
//! {...OCSF record...}
//! {...OCSF record...}
//! {"rk_batch":{"seq":12,"records":2,"prev":"<hex>","hash":"<hex>","sig":"<hex>","key_id":".."}}
//! ```
//!
//! `hash = SHA-256("rk-audit-v1" ‖ prev ‖ seq as 8 bytes big-endian ‖ the
//! batch's record lines exactly as written, newlines included)`, and `sig`
//! is the Ed25519 signature of `hash`. Hashing the bytes on disk means
//! nothing is ever re-serialised, so there is no canonical form to get wrong.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::key::{self, AuditKey};

const DOMAIN: &[u8] = b"rk-audit-v1";

/// Hash of the chain position before the first batch.
pub const GENESIS: [u8; 32] = [0; 32];

pub fn batch_hash(prev: &[u8; 32], seq: u64, records: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(prev);
    h.update(seq.to_be_bytes());
    h.update(records);
    h.finalize().into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentHeader {
    pub seq: u64,
    pub prev: String,
    pub key_id: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trailer {
    pub seq: u64,
    pub records: u64,
    pub prev: String,
    pub hash: String,
    pub sig: String,
    pub key_id: String,
    /// Sealed at startup: records a previous writer wrote but did not seal.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub recovered: bool,
}

/// The control lines, as they appear in a segment.
#[derive(Debug, Serialize, Deserialize)]
enum Control {
    #[serde(rename = "rk_segment")]
    Segment(SegmentHeader),
    #[serde(rename = "rk_batch")]
    Batch(Trailer),
}

/// What a line of a segment is.
enum Line {
    Segment(SegmentHeader),
    Batch(Trailer),
    Record,
    /// A control key with a malformed body, or not a JSON object at all.
    Invalid(String),
}

fn classify(line: &[u8]) -> Line {
    let value: serde_json::Value = match serde_json::from_slice(line) {
        Ok(v) => v,
        Err(e) => return Line::Invalid(format!("not JSON: {e}")),
    };
    let Some(obj) = value.as_object() else {
        return Line::Invalid("not a JSON object".into());
    };
    if obj.contains_key("rk_segment") || obj.contains_key("rk_batch") {
        return match serde_json::from_value::<Control>(value) {
            Ok(Control::Segment(h)) => Line::Segment(h),
            Ok(Control::Batch(t)) => Line::Batch(t),
            Err(e) => Line::Invalid(format!("malformed control line: {e}")),
        };
    }
    Line::Record
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s).ok()?.as_slice().try_into().ok()
}

fn hex64(s: &str) -> Option<[u8; 64]> {
    hex::decode(s).ok()?.as_slice().try_into().ok()
}

/// Position of the chain: the last sealed batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    /// Sequence number the next batch gets.
    pub next_seq: u64,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
pub struct WriterOptions {
    /// A batch is sealed once it holds this many records...
    pub batch_records: usize,
    /// ...or once its first record is this old (checked by [`Writer::tick`]).
    pub batch_interval: Duration,
    /// A new segment is started after a seal once the current one is larger.
    pub segment_bytes: u64,
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            batch_records: 256,
            batch_interval: Duration::from_secs(1),
            segment_bytes: 64 << 20,
        }
    }
}

pub fn segment_name(first_seq: u64) -> String {
    format!("{first_seq:020}.jsonl")
}

/// Segment files of `dir`, in chain order.
pub fn segments(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    out.sort();
    Ok(out)
}

/// Appends records to the newest segment and seals them into batches.
pub struct Writer {
    dir: PathBuf,
    key: AuditKey,
    opts: WriterOptions,
    out: BufWriter<File>,
    segment_len: u64,
    head: Head,
    /// Record lines of the open batch, as written.
    pending: Vec<u8>,
    pending_records: u64,
    batch_started: Option<Instant>,
}

impl Writer {
    /// Opens `dir` (created 0750 if needed). Continues the chain of the
    /// newest segment, first sealing any records a previous writer left
    /// unsealed, then starts a new segment for this writer.
    pub fn open(dir: &Path, key: AuditKey, opts: WriterOptions) -> Result<Self> {
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o750))?;
        let mut existing = segments(dir)?;
        let head = loop {
            match existing.pop() {
                None => {
                    break Head {
                        next_seq: 0,
                        hash: GENESIS,
                    }
                }
                Some(last) => match recover(&last, &key)? {
                    Some(head) => break head,
                    // Empty after cutting a torn line: nothing verifiable.
                    None => fs::remove_file(&last)?,
                },
            }
        };
        let (out, segment_len) = start_segment(dir, &key, head)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            key,
            opts,
            out,
            segment_len,
            head,
            pending: Vec::new(),
            pending_records: 0,
            batch_started: None,
        })
    }

    pub fn head(&self) -> Head {
        self.head
    }

    pub fn key_id(&self) -> String {
        self.key.key_id()
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.public_key()
    }

    /// Appends one record (a JSON object without control keys).
    pub fn append(&mut self, record: &serde_json::Value) -> Result<()> {
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        self.out.write_all(&line)?;
        self.segment_len += line.len() as u64;
        self.pending.extend_from_slice(&line);
        self.pending_records += 1;
        self.batch_started.get_or_insert_with(Instant::now);
        if self.pending_records as usize >= self.opts.batch_records {
            self.seal()?;
        }
        Ok(())
    }

    /// Seals the open batch if it is older than the batch interval.
    pub fn tick(&mut self) -> Result<()> {
        if self
            .batch_started
            .is_some_and(|t| t.elapsed() >= self.opts.batch_interval)
        {
            self.seal()?;
        }
        Ok(())
    }

    /// Seals the open batch, if any, and makes it durable.
    pub fn seal(&mut self) -> Result<()> {
        if self.pending_records == 0 {
            return Ok(());
        }
        let trailer = sign_batch(&self.key, self.head, &self.pending, self.pending_records, false);
        let line = control_line(&Control::Batch(trailer.clone()))?;
        self.out.write_all(&line)?;
        self.out.flush()?;
        self.out.get_ref().sync_data()?;
        self.segment_len += line.len() as u64;
        self.head = Head {
            next_seq: self.head.next_seq + 1,
            hash: hex32(&trailer.hash).expect("own hash is valid hex"),
        };
        self.pending.clear();
        self.pending_records = 0;
        self.batch_started = None;
        if self.segment_len >= self.opts.segment_bytes {
            let (out, len) = start_segment(&self.dir, &self.key, self.head)?;
            self.out = out;
            self.segment_len = len;
        }
        Ok(())
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.seal();
    }
}

fn control_line(c: &Control) -> Result<Vec<u8>> {
    let mut line = serde_json::to_vec(c)?;
    line.push(b'\n');
    Ok(line)
}

fn sign_batch(key: &AuditKey, head: Head, records: &[u8], count: u64, recovered: bool) -> Trailer {
    let hash = batch_hash(&head.hash, head.next_seq, records);
    Trailer {
        seq: head.next_seq,
        records: count,
        prev: hex::encode(head.hash),
        hash: hex::encode(hash),
        sig: hex::encode(key.sign(&hash)),
        key_id: key.key_id(),
        recovered,
    }
}

fn start_segment(dir: &Path, key: &AuditKey, head: Head) -> Result<(BufWriter<File>, u64)> {
    // A segment of this name exists only if it holds a header and nothing
    // else (no batch was sealed in it, or its first seq would be behind us;
    // leftovers would have been sealed by `recover`), so it is replaced.
    let path = dir.join(segment_name(head.next_seq));
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o640)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    let mut out = BufWriter::new(file);
    let header = control_line(&Control::Segment(SegmentHeader {
        seq: head.next_seq,
        prev: hex::encode(head.hash),
        key_id: key.key_id(),
        public_key: hex::encode(key.public_key()),
    }))?;
    out.write_all(&header)?;
    out.flush()?;
    Ok((out, header.len() as u64))
}

/// Reads the chain head from the newest segment. A torn final line (a crash
/// mid-write) is cut off; records after the last trailer are sealed into a
/// batch marked `recovered`. `None` when nothing is left of the segment.
fn recover(path: &Path, key: &AuditKey) -> Result<Option<Head>> {
    let mut data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if let Some(end) = data.iter().rposition(|&b| b == b'\n') {
        if end + 1 != data.len() {
            data.truncate(end + 1);
            let f = OpenOptions::new().write(true).open(path)?;
            f.set_len(data.len() as u64)?;
        }
    } else {
        return Ok(None);
    }
    let mut head = None;
    let mut unsealed = Vec::new();
    let mut unsealed_records = 0u64;
    for line in data.split_inclusive(|&b| b == b'\n') {
        match classify(&line[..line.len() - 1]) {
            Line::Segment(h) => {
                let hash = hex32(&h.prev).context("segment header: bad prev")?;
                head = Some(Head {
                    next_seq: h.seq,
                    hash,
                });
            }
            Line::Batch(t) => {
                let hash = hex32(&t.hash).context("batch trailer: bad hash")?;
                head = Some(Head {
                    next_seq: t.seq + 1,
                    hash,
                });
                unsealed.clear();
                unsealed_records = 0;
            }
            Line::Record | Line::Invalid(_) => {
                unsealed.extend_from_slice(line);
                unsealed_records += 1;
            }
        }
    }
    let Some(mut head) = head else {
        bail!("{}: no segment header; refusing to guess the chain position", path.display());
    };
    if unsealed_records > 0 {
        let trailer = sign_batch(key, head, &unsealed, unsealed_records, true);
        let mut f = OpenOptions::new().append(true).open(path)?;
        f.write_all(&control_line(&Control::Batch(trailer.clone()))?)?;
        f.sync_data()?;
        head = Head {
            next_seq: head.next_seq + 1,
            hash: hex32(&trailer.hash).expect("own hash is valid hex"),
        };
    }
    Ok(Some(head))
}

/// A verification failure: evidence of tampering or corruption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Problem {
    pub segment: String,
    /// 1-based line number within the segment.
    pub line: usize,
    pub seq: Option<u64>,
    pub what: String,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Report {
    pub segments: usize,
    pub batches: u64,
    pub records: u64,
    pub recovered_batches: u64,
    /// Sequence number of the first batch present (earlier segments may have
    /// been removed by retention).
    pub first_seq: Option<u64>,
    /// Next sequence number and hash after the last verified batch.
    pub head_seq: Option<u64>,
    pub head_hash: Option<String>,
    pub key_ids: Vec<String>,
    /// Records after the last batch of the newest segment: the writer's open
    /// batch, not yet sealed. Not a failure.
    pub unsealed_tail: u64,
    pub warnings: Vec<String>,
    pub problems: Vec<Problem>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Verifies the segments of `dir`. With `pinned`, every segment must be
/// signed by that key.
pub fn verify_dir(dir: &Path, pinned: Option<[u8; 32]>) -> Result<Report> {
    let mut loaded = Vec::new();
    for path in segments(dir)? {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        loaded.push((name, fs::read(&path).with_context(|| format!("read {}", path.display()))?));
    }
    Ok(verify_segments(&loaded, pinned))
}

/// Verifies segments given as `(name, contents)` in chain order.
pub fn verify_segments(segments: &[(String, Vec<u8>)], pinned: Option<[u8; 32]>) -> Report {
    let mut r = Report {
        segments: segments.len(),
        ..Report::default()
    };
    // Chain position after the last batch; None before the first header.
    let mut head: Option<Head> = None;
    let mut last_key: Option<[u8; 32]> = None;

    for (index, (name, data)) in segments.iter().enumerate() {
        let newest = index + 1 == segments.len();
        let problem = |r: &mut Report, line: usize, seq: Option<u64>, what: String| {
            r.problems.push(Problem {
                segment: name.clone(),
                line,
                seq,
                what,
            })
        };
        let mut key: Option<[u8; 32]> = None;
        let mut pending: Vec<u8> = Vec::new();
        let mut pending_records = 0u64;
        let mut pending_from = 0usize;

        let mut lines: Vec<&[u8]> = data.split_inclusive(|&b| b == b'\n').collect();
        if lines.last().is_some_and(|l| !l.ends_with(b"\n")) {
            let torn = lines.pop().unwrap_or_default();
            if newest {
                r.warnings.push(format!(
                    "{name}: torn final line of {} bytes (writer interrupted mid-write)",
                    torn.len()
                ));
            } else {
                problem(&mut r, lines.len() + 1, None, "torn line inside the chain".into());
            }
        }

        for (i, line) in lines.iter().enumerate() {
            let lineno = i + 1;
            let body = &line[..line.len() - 1];
            match classify(body) {
                Line::Segment(h) => {
                    if i != 0 {
                        problem(&mut r, lineno, Some(h.seq), "segment header inside a segment".into());
                        continue;
                    }
                    let (Some(prev), Ok(pk)) = (hex32(&h.prev), key::parse_public_key(&h.public_key)) else {
                        problem(&mut r, lineno, Some(h.seq), "malformed segment header".into());
                        continue;
                    };
                    if let Some(pin) = pinned {
                        if pk != pin {
                            problem(
                                &mut r,
                                lineno,
                                Some(h.seq),
                                format!("signed by key {}, not the pinned key", key::key_id(&pk)),
                            );
                        }
                    } else if last_key.is_some_and(|k| k != pk) {
                        r.warnings.push(format!("{name}: signing key changed to {}", key::key_id(&pk)));
                    }
                    let id = key::key_id(&pk);
                    if !r.key_ids.contains(&id) {
                        r.key_ids.push(id);
                    }
                    key = Some(pk);
                    last_key = Some(pk);
                    match head {
                        None => {
                            r.first_seq = Some(h.seq);
                            if h.seq != 0 {
                                r.warnings.push(format!(
                                    "chain starts at batch {}: earlier segments are not present",
                                    h.seq
                                ));
                            }
                            head = Some(Head {
                                next_seq: h.seq,
                                hash: prev,
                            });
                        }
                        Some(hd) if hd.next_seq != h.seq || hd.hash != prev => problem(
                            &mut r,
                            lineno,
                            Some(h.seq),
                            format!(
                                "segment does not continue the chain: expected batch {} after {}",
                                hd.next_seq,
                                hex::encode(&hd.hash[..8])
                            ),
                        ),
                        Some(_) => {}
                    }
                }
                Line::Batch(t) => {
                    let Some(hd) = head else {
                        problem(&mut r, lineno, Some(t.seq), "batch before any segment header".into());
                        continue;
                    };
                    let mut bad = Vec::new();
                    if t.seq != hd.next_seq {
                        bad.push(format!("sequence {} where {} was expected", t.seq, hd.next_seq));
                    }
                    if hex32(&t.prev) != Some(hd.hash) {
                        bad.push("does not chain to the previous batch".to_string());
                    }
                    if t.records != pending_records {
                        bad.push(format!(
                            "claims {} records, {} present",
                            t.records, pending_records
                        ));
                    }
                    let stated = hex32(&t.hash);
                    let computed = batch_hash(&hd.hash, t.seq, &pending);
                    if stated != Some(computed) {
                        bad.push("content does not match its hash (modified, inserted or removed records)".into());
                    }
                    let signed = match (key, stated, hex64(&t.sig)) {
                        (Some(k), Some(h), Some(sig)) => key::verify(&k, &h, &sig),
                        _ => false,
                    };
                    if !signed {
                        bad.push("signature does not verify".into());
                    }
                    if bad.is_empty() {
                        r.batches += 1;
                        r.records += pending_records;
                        if t.recovered {
                            r.recovered_batches += 1;
                        }
                    } else {
                        problem(&mut r, lineno, Some(t.seq), format!("batch {}: {}", t.seq, bad.join("; ")));
                    }
                    // Resynchronise on the stated position so one bad batch
                    // is reported once, not as a cascade.
                    head = Some(Head {
                        next_seq: t.seq + 1,
                        hash: stated.unwrap_or(computed),
                    });
                    pending.clear();
                    pending_records = 0;
                }
                Line::Record => {
                    if pending_records == 0 {
                        pending_from = lineno;
                    }
                    pending.extend_from_slice(line);
                    pending_records += 1;
                }
                Line::Invalid(why) => {
                    problem(&mut r, lineno, None, why);
                    pending.extend_from_slice(line);
                    pending_records += 1;
                }
            }
        }
        if key.is_none() {
            problem(&mut r, 1, None, "segment has no header".into());
        }
        if pending_records > 0 {
            if newest {
                r.unsealed_tail = pending_records;
            } else {
                problem(
                    &mut r,
                    pending_from,
                    None,
                    format!("{pending_records} records after the last batch are not sealed"),
                );
            }
        }
    }
    if let Some(hd) = head {
        r.head_seq = Some(hd.next_seq);
        r.head_hash = Some(hex::encode(hd.hash));
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tempdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rk-audit-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn opts() -> WriterOptions {
        WriterOptions {
            batch_records: 3,
            batch_interval: Duration::from_secs(3600),
            segment_bytes: 1 << 30,
        }
    }

    /// Writes `n` records in batches of three, then seals.
    fn write(dir: &Path, n: usize) -> Writer {
        let mut w = Writer::open(dir, AuditKey::from_seed([5; 32]), opts()).unwrap();
        for i in 0..n {
            w.append(&json!({"class_uid": 4001, "n": i})).unwrap();
        }
        w.seal().unwrap();
        w
    }

    fn load(dir: &Path) -> Vec<(String, Vec<u8>)> {
        segments(dir)
            .unwrap()
            .iter()
            .map(|p| (p.file_name().unwrap().to_string_lossy().into_owned(), fs::read(p).unwrap()))
            .collect()
    }

    fn edit(segs: &mut [(String, Vec<u8>)], from: &str, to: &str) {
        let text = String::from_utf8(segs[0].1.clone()).unwrap();
        assert!(text.contains(from), "{from} not in segment");
        segs[0].1 = text.replacen(from, to, 1).into_bytes();
    }

    #[test]
    fn untouched_chain_verifies() {
        let dir = tempdir("ok");
        let w = write(&dir, 7);
        let pk = w.public_key();
        drop(w);
        let r = verify_dir(&dir, Some(pk)).unwrap();
        assert!(r.ok(), "{:?}", r.problems);
        assert_eq!((r.batches, r.records, r.first_seq, r.head_seq), (3, 7, Some(0), Some(3)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_verify_detects_modified_record() {
        let dir = tempdir("modified");
        drop(write(&dir, 6));
        let mut segs = load(&dir);
        edit(&mut segs, "\"n\":4", "\"n\":5");
        let r = verify_segments(&segs, None);
        assert_eq!(r.problems.len(), 1, "{:?}", r.problems);
        assert_eq!(r.problems[0].seq, Some(1));
        assert!(r.problems[0].what.contains("does not match its hash"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_verify_detects_deleted_batch() {
        let dir = tempdir("deleted");
        drop(write(&dir, 9));
        let mut segs = load(&dir);
        // Remove batch 1: its three records and its trailer.
        let text = String::from_utf8(segs[0].1.clone()).unwrap();
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        let kept: String = lines
            .iter()
            .enumerate()
            .filter(|(i, _)| !(5..=8).contains(i))
            .map(|(_, l)| *l)
            .collect();
        segs[0].1 = kept.into_bytes();
        let r = verify_segments(&segs, None);
        assert!(!r.ok());
        assert!(r.problems.iter().any(|p| p.seq == Some(2) && p.what.contains("sequence 2 where 1")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_verify_detects_reordered_batches() {
        let dir = tempdir("reordered");
        drop(write(&dir, 6));
        let mut segs = load(&dir);
        let text = String::from_utf8(segs[0].1.clone()).unwrap();
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        // header, batch 0 (lines 1-4), batch 1 (lines 5-8): swap the batches.
        let swapped: String = [&lines[..1], &lines[5..9], &lines[1..5]].concat().concat();
        segs[0].1 = swapped.into_bytes();
        let r = verify_segments(&segs, None);
        assert!(!r.ok());
        assert_eq!(r.problems[0].seq, Some(1));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_verify_detects_inserted_batch() {
        let dir = tempdir("inserted");
        drop(write(&dir, 3));
        let mut segs = load(&dir);
        // A forger without the key adds a batch with a correct hash.
        let other = AuditKey::from_seed([9; 32]);
        let text = String::from_utf8(segs[0].1.clone()).unwrap();
        let last: Trailer = match classify(text.lines().next_back().unwrap().as_bytes()) {
            Line::Batch(t) => t,
            _ => panic!("no trailer"),
        };
        let head = Head {
            next_seq: last.seq + 1,
            hash: hex32(&last.hash).unwrap(),
        };
        let forged = b"{\"class_uid\":4001,\"n\":99}\n".to_vec();
        let t = sign_batch(&other, head, &forged, 1, false);
        let mut data = segs[0].1.clone();
        data.extend_from_slice(&forged);
        data.extend_from_slice(&control_line(&Control::Batch(t)).unwrap());
        segs[0].1 = data;
        let r = verify_segments(&segs, None);
        assert_eq!(r.problems.len(), 1);
        assert!(r.problems[0].what.contains("signature does not verify"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_verify_detects_bad_signature_and_pinned_key() {
        let dir = tempdir("sig");
        drop(write(&dir, 3));
        let mut segs = load(&dir);
        let text = String::from_utf8(segs[0].1.clone()).unwrap();
        let sig_at = text.find("\"sig\":\"").unwrap() + 7;
        let flipped = if &text[sig_at..sig_at + 1] == "0" { "1" } else { "0" };
        segs[0].1 = format!("{}{}{}", &text[..sig_at], flipped, &text[sig_at + 1..]).into_bytes();
        assert!(verify_segments(&segs, None).problems[0].what.contains("signature"));

        let other = AuditKey::from_seed([1; 32]).public_key();
        assert!(!verify_dir(&dir, Some(other)).unwrap().ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reopening_continues_the_chain_and_seals_leftovers() {
        let dir = tempdir("reopen");
        let mut w = write(&dir, 4);
        // An unsealed record and a torn line, as after a crash.
        w.append(&json!({"class_uid": 4001, "n": "late"})).unwrap();
        w.out.flush().unwrap();
        std::mem::forget(w);
        let newest = segments(&dir).unwrap().pop().unwrap();
        let mut f = OpenOptions::new().append(true).open(&newest).unwrap();
        f.write_all(b"{\"class_uid\":40").unwrap();
        drop(f);

        drop(write(&dir, 2));
        let r = verify_dir(&dir, None).unwrap();
        assert!(r.ok(), "{:?}", r.problems);
        assert_eq!(r.segments, 2);
        assert_eq!(r.recovered_batches, 1);
        assert_eq!(r.records, 7);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn deleting_the_middle_segment_is_detected() {
        let dir = tempdir("segments");
        drop(write(&dir, 3));
        drop(write(&dir, 3));
        drop(write(&dir, 3));
        let segs = load(&dir);
        assert_eq!(segs.len(), 3);
        let r = verify_segments(&[segs[0].clone(), segs[2].clone()], None);
        assert!(r.problems.iter().any(|p| p.what.contains("does not continue the chain")));
        // Retention removing the oldest is reported, not a failure.
        let r = verify_segments(&segs[1..], None);
        assert!(r.ok(), "{:?}", r.problems);
        assert_eq!(r.first_seq, Some(1));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_batch_is_an_unsealed_tail_not_a_problem() {
        let dir = tempdir("tail");
        let mut w = write(&dir, 3);
        w.append(&json!({"class_uid": 4001})).unwrap();
        w.out.flush().unwrap();
        let r = verify_dir(&dir, None).unwrap();
        assert!(r.ok());
        assert_eq!(r.unsealed_tail, 1);
        drop(w);
        let _ = fs::remove_dir_all(&dir);
    }
}
