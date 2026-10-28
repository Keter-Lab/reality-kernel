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
    /// Sealed at startup by rk 0.2 and earlier: records a previous writer
    /// wrote but did not seal. No longer written (they are set aside, see
    /// [`Discarded`]); still read so old logs verify. Outside the hash.
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

impl Head {
    /// Parses `SEQ:HASH`, the chain head as the sensor exports it:
    /// `rk_audit_head_seq` and the `head_hash` label of `rk_audit_info`
    /// (64 hex digits).
    pub fn parse(text: &str) -> Result<Self> {
        let (seq, hash) = text
            .trim()
            .split_once(':')
            .context("expected SEQ:HASH (rk_audit_head_seq and rk_audit_info's head_hash)")?;
        Ok(Self {
            next_seq: seq
                .parse::<u64>()
                .with_context(|| format!("head sequence {seq:?} is not a number"))?,
            hash: hex32(hash).context("head hash must be 64 hex digits")?,
        })
    }
}

/// Lines a previous writer left after its last sealed batch, found when a
/// [`Writer`] opened the directory. They are moved to `path` (named
/// `<segment>.unsealed`, which is not a segment) instead of being sealed:
/// sealing them would sign whatever anyone had appended to the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discarded {
    pub path: PathBuf,
    /// Complete lines set aside (a torn last line is included, not counted).
    pub lines: u64,
    pub bytes: u64,
}

/// Marks files of [`Discarded`] lines.
const DISCARDED_MARK: &str = ".jsonl.unsealed";

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
    discarded: Vec<Discarded>,
}

impl Writer {
    /// Opens `dir` (created 0750 if needed). Continues the chain from the
    /// last sealed batch of the newest segment, then starts a new segment for
    /// this writer. Anything after that batch (the open batch of a writer
    /// that crashed, or lines someone else appended) is moved aside
    /// unsigned, never sealed: see [`Writer::discarded`].
    pub fn open(dir: &Path, key: AuditKey, opts: WriterOptions) -> Result<Self> {
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o750))?;
        let mut existing = segments(dir)?;
        let mut discarded = Vec::new();
        let head = loop {
            match existing.pop() {
                None => {
                    break Head {
                        next_seq: 0,
                        hash: GENESIS,
                    }
                }
                Some(last) => {
                    // Otherwise nothing verifiable was left in it: continue
                    // from the segment before.
                    if let Some(head) = recover(&last, &mut discarded)? {
                        break head;
                    }
                }
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
            discarded,
        })
    }

    /// What [`Writer::open`] set aside: report it, the lines are not part of
    /// the verified chain.
    pub fn discarded(&self) -> &[Discarded] {
        &self.discarded
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
        let trailer = sign_batch(&self.key, self.head, &self.pending, self.pending_records);
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

fn sign_batch(key: &AuditKey, head: Head, records: &[u8], count: u64) -> Trailer {
    let hash = batch_hash(&head.hash, head.next_seq, records);
    Trailer {
        seq: head.next_seq,
        records: count,
        prev: hex::encode(head.hash),
        hash: hex::encode(hash),
        sig: hex::encode(key.sign(&hash)),
        key_id: key.key_id(),
        recovered: false,
    }
}

fn start_segment(dir: &Path, key: &AuditKey, head: Head) -> Result<(BufWriter<File>, u64)> {
    // A segment of this name exists only if it holds a header and nothing
    // else (no batch was sealed in it, or its first seq would be behind us;
    // leftovers were moved aside by `recover`), so it is replaced.
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

/// Reads the chain head from the newest segment: its last sealed batch, or
/// its header. Whatever follows (a torn line from a crash mid-write, the
/// open batch of a writer that crashed, or lines appended by someone else)
/// is moved to a `.unsealed` file next to it and cut off, so the segment
/// ends sealed and the chain continues without this writer signing bytes it
/// did not write. A segment with no complete line is moved aside whole and
/// `None` returned.
fn recover(path: &Path, discarded: &mut Vec<Discarded>) -> Result<Option<Head>> {
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if data.is_empty() {
        // Created, header not yet written: nothing to keep.
        fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
        return Ok(None);
    }
    let mut head = None;
    // Bytes up to the end of the last header or trailer, and the complete
    // lines after it.
    let mut sealed_end = 0usize;
    let mut unsealed_lines = 0u64;
    let mut offset = 0usize;
    for line in data.split_inclusive(|&b| b == b'\n') {
        offset += line.len();
        let Some(body) = line.strip_suffix(b"\n") else {
            // Torn final line: set aside with the rest.
            break;
        };
        match classify(body) {
            Line::Segment(h) => {
                let hash = hex32(&h.prev).context("segment header: bad prev")?;
                head = Some(Head {
                    next_seq: h.seq,
                    hash,
                });
                sealed_end = offset;
                unsealed_lines = 0;
            }
            Line::Batch(t) => {
                let hash = hex32(&t.hash).context("batch trailer: bad hash")?;
                head = Some(Head {
                    next_seq: t.seq + 1,
                    hash,
                });
                sealed_end = offset;
                unsealed_lines = 0;
            }
            Line::Record | Line::Invalid(_) => unsealed_lines += 1,
        }
    }
    if head.is_none() && data.contains(&b'\n') {
        bail!(
            "{}: no segment header; refusing to guess the chain position",
            path.display()
        );
    }
    if sealed_end == data.len() {
        return Ok(head);
    }
    let aside = discarded_path(path);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o640)
        .open(&aside)
        .with_context(|| format!("create {}", aside.display()))?;
    f.write_all(&data[sealed_end..])?;
    f.sync_all()?;
    // Durable copy first: a crash from here on finds the lines again and
    // sets them aside again, to a second file.
    if head.is_some() {
        let seg = OpenOptions::new().write(true).open(path)?;
        seg.set_len(sealed_end as u64)?;
        seg.sync_all()?;
    } else {
        fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
    }
    discarded.push(Discarded {
        path: aside,
        lines: unsealed_lines,
        bytes: (data.len() - sealed_end) as u64,
    });
    Ok(head)
}

/// `<segment>.unsealed`, or `<segment>.unsealed.N` when that is taken.
fn discarded_path(segment: &Path) -> PathBuf {
    let mut n = 0u32;
    loop {
        let mut name = segment.as_os_str().to_owned();
        name.push(".unsealed");
        if n > 0 {
            name.push(format!(".{n}"));
        }
        let path = PathBuf::from(name);
        if !path.exists() {
            return path;
        }
        n += 1;
    }
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
    /// An expected head was given and the chain passes through it.
    pub head_anchored: bool,
    pub warnings: Vec<String>,
    pub problems: Vec<Problem>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// What verification is told from outside the log. The files alone can
/// only show that they are consistent with themselves; these anchor them.
#[derive(Debug, Clone, Default)]
pub struct Expect {
    /// Keys the segments may be signed by (more than one across a key
    /// rotation). Empty: the key named by the first segment present is
    /// taken on trust, and any later change of key is a problem.
    pub keys: Vec<[u8; 32]>,
    /// A chain head recorded earlier (the sensor exports it in its metrics):
    /// the chain must pass through it, so removing the newest batches, or
    /// rewriting the chain up to it, fails.
    pub head: Option<Head>,
    /// Accept a chain whose oldest segments were removed. Without it a chain
    /// that does not start at batch 0 fails.
    pub allow_pruned: bool,
}

impl Expect {
    pub fn pinned(key: Option<[u8; 32]>) -> Self {
        Self {
            keys: key.into_iter().collect(),
            ..Self::default()
        }
    }
}

/// Verifies the segments of `dir`. With `pinned`, every segment must be
/// signed by that key.
pub fn verify_dir(dir: &Path, pinned: Option<[u8; 32]>) -> Result<Report> {
    verify_dir_with(dir, &Expect::pinned(pinned))
}

/// Verifies the segments of `dir` against what `expect` says.
pub fn verify_dir_with(dir: &Path, expect: &Expect) -> Result<Report> {
    let mut loaded = Vec::new();
    for path in segments(dir)? {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        loaded.push((
            name,
            fs::read(&path).with_context(|| format!("read {}", path.display()))?,
        ));
    }
    let mut r = verify_segments_with(&loaded, expect);
    let mut aside: Vec<(String, u64)> = fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.contains(DISCARDED_MARK) {
                return None;
            }
            Some((name, e.metadata().ok()?.len()))
        })
        .collect();
    aside.sort();
    for (name, len) in aside {
        r.warnings.push(format!(
            "{name}: {len} bytes a previous writer left unsealed, set aside at startup and not \
             part of the verified chain"
        ));
    }
    Ok(r)
}

/// Verifies segments given as `(name, contents)` in chain order.
pub fn verify_segments(segments: &[(String, Vec<u8>)], pinned: Option<[u8; 32]>) -> Report {
    verify_segments_with(segments, &Expect::pinned(pinned))
}

/// A problem with the log as a whole rather than with one line.
fn global_problem(r: &mut Report, what: String) {
    r.problems.push(Problem {
        segment: String::new(),
        line: 0,
        seq: None,
        what,
    });
}

/// Notes that the chain reached position `at`, for the expected head check:
/// `Some(true)` once `at` is the expected head, `Some(false)` if the same
/// position was reached with another hash.
fn note_position(expected: Option<Head>, at: Head, seen: &mut Option<bool>) {
    if let Some(want) = expected {
        if want.next_seq == at.next_seq {
            *seen = Some(seen.unwrap_or(true) && want.hash == at.hash);
        }
    }
}

/// Verifies segments given as `(name, contents)` in chain order against
/// what `expect` says.
pub fn verify_segments_with(segments: &[(String, Vec<u8>)], expect: &Expect) -> Report {
    let mut r = Report {
        segments: segments.len(),
        ..Report::default()
    };
    if segments.is_empty() {
        global_problem(
            &mut r,
            "no audit segments: an empty log proves nothing (removed, or never written)".into(),
        );
        return r;
    }
    if expect.keys.is_empty() {
        r.warnings.push(
            "no signing key pinned: the log is checked only against the key it names itself".into(),
        );
    }
    // Chain position after the last batch; None before the first header.
    let mut head: Option<Head> = None;
    let mut last_key: Option<[u8; 32]> = None;
    let mut anchor_seen: Option<bool> = None;

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
                problem(
                    &mut r,
                    lines.len() + 1,
                    None,
                    "torn line inside the chain".into(),
                );
            }
        }

        for (i, line) in lines.iter().enumerate() {
            let lineno = i + 1;
            let body = &line[..line.len() - 1];
            match classify(body) {
                Line::Segment(h) => {
                    if i != 0 {
                        problem(
                            &mut r,
                            lineno,
                            Some(h.seq),
                            "segment header inside a segment".into(),
                        );
                        continue;
                    }
                    let (Some(prev), Ok(pk)) =
                        (hex32(&h.prev), key::parse_public_key(&h.public_key))
                    else {
                        problem(
                            &mut r,
                            lineno,
                            Some(h.seq),
                            "malformed segment header".into(),
                        );
                        continue;
                    };
                    if !expect.keys.is_empty() {
                        if !expect.keys.contains(&pk) {
                            problem(
                                &mut r,
                                lineno,
                                Some(h.seq),
                                format!("signed by key {}, not a pinned key", key::key_id(&pk)),
                            );
                        }
                    } else if let Some(before) = last_key.filter(|k| *k != pk) {
                        // Whoever can write the directory can start a
                        // segment under a key of their own; only a key the
                        // verifier was given is a rotation.
                        problem(
                            &mut r,
                            lineno,
                            Some(h.seq),
                            format!(
                                "signing key changed from {} to {}: pin every legitimate key to \
                                 accept a rotation",
                                key::key_id(&before),
                                key::key_id(&pk)
                            ),
                        );
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
                                let what = format!(
                                    "chain starts at batch {}: earlier segments are not present",
                                    h.seq
                                );
                                if expect.allow_pruned {
                                    r.warnings.push(what);
                                } else {
                                    problem(
                                        &mut r,
                                        lineno,
                                        Some(h.seq),
                                        format!(
                                            "{what} (removed by retention or by tampering; \
                                             accept it only if you pruned them)"
                                        ),
                                    );
                                }
                            } else if prev != GENESIS {
                                problem(
                                    &mut r,
                                    lineno,
                                    Some(h.seq),
                                    "batch 0 does not start from the genesis hash".into(),
                                );
                            }
                            let at = Head {
                                next_seq: h.seq,
                                hash: prev,
                            };
                            note_position(expect.head, at, &mut anchor_seen);
                            head = Some(at);
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
                        problem(
                            &mut r,
                            lineno,
                            Some(t.seq),
                            "batch before any segment header".into(),
                        );
                        continue;
                    };
                    let mut bad = Vec::new();
                    if t.seq != hd.next_seq {
                        bad.push(format!(
                            "sequence {} where {} was expected",
                            t.seq, hd.next_seq
                        ));
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
                        note_position(
                            expect.head,
                            Head {
                                next_seq: t.seq + 1,
                                hash: computed,
                            },
                            &mut anchor_seen,
                        );
                    } else {
                        problem(
                            &mut r,
                            lineno,
                            Some(t.seq),
                            format!("batch {}: {}", t.seq, bad.join("; ")),
                        );
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
    if r.recovered_batches > 0 {
        r.warnings.push(format!(
            "{} batches were sealed by startup recovery (rk 0.2 and earlier): the writer that \
             signed them did not write them, so their records are not authenticated",
            r.recovered_batches
        ));
    }
    if let Some(want) = expect.head {
        let short = hex::encode(&want.hash[..8]);
        match anchor_seen {
            Some(true) => r.head_anchored = true,
            Some(false) => global_problem(
                &mut r,
                format!(
                    "the chain does not pass through the expected head {}:{short}: the batches \
                     before it were rewritten",
                    want.next_seq
                ),
            ),
            None => {
                let why = match (r.first_seq, head) {
                    (Some(first), _) if want.next_seq < first => {
                        format!("it is older than the oldest segment present (batch {first})")
                    }
                    (_, Some(hd)) if hd.next_seq < want.next_seq => format!(
                        "the chain ends before batch {}: the newest batches are missing",
                        hd.next_seq
                    ),
                    _ => "it is not on the verified chain".to_string(),
                };
                global_problem(
                    &mut r,
                    format!("expected head {}:{short} not reached: {why}", want.next_seq),
                );
            }
        }
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
            .map(|p| {
                (
                    p.file_name().unwrap().to_string_lossy().into_owned(),
                    fs::read(p).unwrap(),
                )
            })
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
        assert_eq!(
            (r.batches, r.records, r.first_seq, r.head_seq),
            (3, 7, Some(0), Some(3))
        );
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
        assert!(r
            .problems
            .iter()
            .any(|p| p.seq == Some(2) && p.what.contains("sequence 2 where 1")));
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
        let t = sign_batch(&other, head, &forged, 1);
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
        let flipped = if &text[sig_at..sig_at + 1] == "0" {
            "1"
        } else {
            "0"
        };
        segs[0].1 = format!("{}{}{}", &text[..sig_at], flipped, &text[sig_at + 1..]).into_bytes();
        assert!(verify_segments(&segs, None).problems[0]
            .what
            .contains("signature"));

        let other = AuditKey::from_seed([1; 32]).public_key();
        assert!(!verify_dir(&dir, Some(other)).unwrap().ok());
        let _ = fs::remove_dir_all(&dir);
    }

    /// Files of lines set aside by `recover`, in name order.
    fn set_aside(dir: &Path) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.to_string_lossy().contains(DISCARDED_MARK))
            .collect();
        out.sort();
        out
    }

    #[test]
    fn reopening_continues_the_chain_and_sets_leftovers_aside() {
        let dir = tempdir("reopen");
        let mut w = write(&dir, 4);
        // An unsealed record and a torn line, as after a crash mid-batch.
        w.append(&json!({"class_uid": 4001, "n": "late"})).unwrap();
        w.out.flush().unwrap();
        std::mem::forget(w);
        let newest = segments(&dir).unwrap().pop().unwrap();
        let mut f = OpenOptions::new().append(true).open(&newest).unwrap();
        f.write_all(b"{\"class_uid\":40").unwrap();
        drop(f);

        let w = Writer::open(&dir, AuditKey::from_seed([5; 32]), opts()).unwrap();
        assert_eq!(w.discarded().len(), 1, "{:?}", w.discarded());
        assert_eq!(w.discarded()[0].lines, 1);
        drop(w);
        drop(write(&dir, 2));
        let r = verify_dir(&dir, None).unwrap();
        assert!(r.ok(), "{:?}", r.problems);
        assert_eq!(r.segments, 2);
        assert_eq!(r.recovered_batches, 0);
        // The crashed writer's open batch is not part of the chain.
        assert_eq!(r.records, 6);
        assert!(r.warnings.iter().any(|w| w.contains("set aside")));
        let aside = set_aside(&dir);
        assert_eq!(aside.len(), 1);
        let kept = fs::read_to_string(&aside[0]).unwrap();
        assert!(kept.contains("\"late\"") && kept.ends_with("{\"class_uid\":40"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn recovery_does_not_sign_appended_records() {
        let dir = tempdir("oracle");
        drop(write(&dir, 3));
        // Someone who can write the log appends a record of their own after
        // the last sealed batch, then waits for the writer to restart.
        let newest = segments(&dir).unwrap().pop().unwrap();
        let forged = "{\"class_uid\":4001,\"forged\":true}\n";
        let mut f = OpenOptions::new().append(true).open(&newest).unwrap();
        f.write_all(forged.as_bytes()).unwrap();
        drop(f);

        let w = Writer::open(&dir, AuditKey::from_seed([5; 32]), opts()).unwrap();
        assert_eq!(w.discarded().len(), 1);
        drop(w);
        for seg in segments(&dir).unwrap() {
            let text = fs::read_to_string(&seg).unwrap();
            assert!(!text.contains("forged"), "{}: {text}", seg.display());
        }
        assert_eq!(fs::read_to_string(&set_aside(&dir)[0]).unwrap(), forged);
        let r = verify_dir(&dir, None).unwrap();
        assert!(r.ok(), "{:?}", r.problems);
        assert_eq!((r.records, r.unsealed_tail), (3, 0));

        // Restarting again, after another crash mid-batch, does not wedge:
        // the chain keeps verifying and every set-aside file is kept.
        let mut w = Writer::open(&dir, AuditKey::from_seed([5; 32]), opts()).unwrap();
        w.append(&json!({"class_uid": 4001, "n": "crash"})).unwrap();
        w.out.flush().unwrap();
        std::mem::forget(w);
        drop(write(&dir, 3));
        let r = verify_dir(&dir, None).unwrap();
        assert!(r.ok(), "{:?}", r.problems);
        assert_eq!(r.records, 6);
        assert_eq!(set_aside(&dir).len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_audit_dir_fails_verification() {
        let dir = tempdir("empty");
        fs::create_dir_all(&dir).unwrap();
        let r = verify_dir(&dir, None).unwrap();
        assert!(!r.ok());
        assert!(r.problems[0].what.contains("no audit segments"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn signing_key_change_fails_unless_both_keys_are_pinned() {
        let dir = tempdir("keychange");
        let first = write(&dir, 3);
        let old = first.public_key();
        drop(first);
        // A segment started under another key continues the chain.
        let mut w = Writer::open(&dir, AuditKey::from_seed([6; 32]), opts()).unwrap();
        let new = w.public_key();
        w.append(&json!({"class_uid": 4001, "n": "spliced"}))
            .unwrap();
        drop(w);

        let r = verify_dir(&dir, None).unwrap();
        assert!(!r.ok());
        assert!(r
            .problems
            .iter()
            .any(|p| p.what.contains("signing key changed")));
        assert!(!verify_dir(&dir, Some(old)).unwrap().ok());
        assert!(!verify_dir(&dir, Some(new)).unwrap().ok());
        let rotated = Expect {
            keys: vec![old, new],
            ..Expect::default()
        };
        let r = verify_dir_with(&dir, &rotated).unwrap();
        assert!(r.ok(), "{:?}", r.problems);
        assert_eq!(r.records, 4);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn expected_head_must_be_on_the_chain() {
        let dir = tempdir("anchor");
        let w = write(&dir, 6);
        let head = w.head();
        drop(w);
        assert_eq!(head.next_seq, 2);
        let text = format!("{}:{}", head.next_seq, hex::encode(head.hash));
        assert_eq!(Head::parse(&text).unwrap(), head);
        assert!(Head::parse("2").is_err());
        assert!(Head::parse("x:00").is_err());

        let expect = |h: Head| Expect {
            head: Some(h),
            ..Expect::default()
        };
        // The chain grew past the anchor: it still passes through it.
        drop(write(&dir, 3));
        let r = verify_dir_with(&dir, &expect(head)).unwrap();
        assert!(r.ok() && r.head_anchored, "{:?}", r.problems);

        // The newest batches removed: the anchor is beyond the end.
        let later = Head {
            next_seq: 9,
            hash: head.hash,
        };
        let r = verify_dir_with(&dir, &expect(later)).unwrap();
        assert!(!r.ok() && !r.head_anchored);
        assert!(r.problems[0].what.contains("newest batches are missing"));

        // A rewritten chain reaches the same position with another hash.
        let mut other = head;
        other.hash[0] ^= 1;
        let r = verify_dir_with(&dir, &expect(other)).unwrap();
        assert!(!r.ok());
        assert!(r.problems[0].what.contains("rewritten"));
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
        assert!(r
            .problems
            .iter()
            .any(|p| p.what.contains("does not continue the chain")));
        // Removing the oldest fails, unless the verifier is told the log
        // was pruned on purpose.
        let r = verify_segments(&segs[1..], None);
        assert!(!r.ok());
        assert!(r.problems[0].what.contains("chain starts at batch 1"));
        let pruned = Expect {
            allow_pruned: true,
            ..Expect::default()
        };
        let r = verify_segments_with(&segs[1..], &pruned);
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
