//! Validating decoder for records read from `events_ringbuf`.
//!
//! Wire format (see `rk-bpf/include/rk_abi.h` and `docs/abi.md`):
//! `rk_hdr | u32 payload_len | u32 _reserved | payload[payload_len]`.
//!
//! Every malformed record is rejected with a typed [`DecodeError`]; the decoder
//! never panics and contains no `unsafe`. Strings are returned as raw bytes
//! because Linux paths and argv are not guaranteed to be UTF-8.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use rk_ebpf_common::{
    rk_event_type, rk_hdr, rk_payload_exec, rk_payload_file, rk_payload_net, rk_verdict,
    RK_ABI_VERSION, RK_ENVELOPE_LEN, RK_SCRATCH_PAYLOAD_MAX,
};

const HDR_LEN: usize = core::mem::size_of::<rk_hdr>();
const MAX_PAYLOAD: usize = RK_SCRATCH_PAYLOAD_MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    TooShort { needed: usize, provided: usize },
    AbiMismatch { expected: u32, found: u8 },
    ReservedNonZero(u32),
    PayloadTooLarge(usize),
    LengthMismatch { expected: usize, found: usize },
    UnknownType(u16),
    UnknownVerdict(u8),
    BodyTooShort { needed: usize, provided: usize },
    MalformedStrings,
    TrailingBytes(usize),
}

impl DecodeError {
    pub const KINDS: usize = 10;

    /// Stable metric label for this error kind.
    pub fn kind(&self) -> &'static str {
        Self::KIND_NAMES[self.kind_index()]
    }

    pub const KIND_NAMES: [&'static str; Self::KINDS] = [
        "too_short",
        "abi_mismatch",
        "reserved_non_zero",
        "payload_too_large",
        "length_mismatch",
        "unknown_type",
        "unknown_verdict",
        "body_too_short",
        "malformed_strings",
        "trailing_bytes",
    ];

    fn kind_index(&self) -> usize {
        match self {
            DecodeError::TooShort { .. } => 0,
            DecodeError::AbiMismatch { .. } => 1,
            DecodeError::ReservedNonZero(_) => 2,
            DecodeError::PayloadTooLarge(_) => 3,
            DecodeError::LengthMismatch { .. } => 4,
            DecodeError::UnknownType(_) => 5,
            DecodeError::UnknownVerdict(_) => 6,
            DecodeError::BodyTooShort { .. } => 7,
            DecodeError::MalformedStrings => 8,
            DecodeError::TrailingBytes(_) => 9,
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::TooShort { needed, provided } => {
                write!(f, "record too short: need {needed} bytes, got {provided}")
            }
            DecodeError::AbiMismatch { expected, found } => {
                write!(f, "ABI version {found}, expected {expected}")
            }
            DecodeError::ReservedNonZero(v) => write!(f, "reserved field is {v:#x}, expected 0"),
            DecodeError::PayloadTooLarge(n) => {
                write!(f, "payload_len {n} exceeds maximum {MAX_PAYLOAD}")
            }
            DecodeError::LengthMismatch { expected, found } => {
                write!(f, "record is {found} bytes, header declares {expected}")
            }
            DecodeError::UnknownType(t) => write!(f, "unknown event type {t}"),
            DecodeError::UnknownVerdict(v) => write!(f, "unknown verdict {v}"),
            DecodeError::BodyTooShort { needed, provided } => {
                write!(f, "event body too short: need {needed} bytes, got {provided}")
            }
            DecodeError::MalformedStrings => f.write_str("string tail is truncated or malformed"),
            DecodeError::TrailingBytes(n) => write!(f, "{n} unexpected trailing bytes"),
        }
    }
}

impl std::error::Error for DecodeError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event<'a> {
    pub hdr: rk_hdr,
    pub payload: Payload<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Payload<'a> {
    Exec {
        body: rk_payload_exec,
        strings: Strings<'a>,
    },
    File {
        body: rk_payload_file,
        strings: Strings<'a>,
    },
    Net {
        body: rk_payload_net,
    },
    /// Event types whose body is not defined yet (unlink, rename, fork, exit,
    /// tamper). Bytes are passed through for logging only.
    Raw {
        data: &'a [u8],
    },
}

/// A validated `[u16 len][bytes]` string tail. Iteration cannot fail: the
/// whole tail was checked when the record was decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Strings<'a> {
    data: &'a [u8],
    remaining: u16,
}

impl<'a> Strings<'a> {
    pub fn len(&self) -> usize {
        usize::from(self.remaining)
    }

    pub fn is_empty(&self) -> bool {
        self.remaining == 0
    }

    fn validate(data: &'a [u8], count: u16) -> Result<Self, DecodeError> {
        let strings = Strings {
            data,
            remaining: count,
        };
        let mut rest = data;
        for _ in 0..count {
            let (_, tail) = split_str(rest).ok_or(DecodeError::MalformedStrings)?;
            rest = tail;
        }
        if !rest.is_empty() {
            return Err(DecodeError::TrailingBytes(rest.len()));
        }
        Ok(strings)
    }
}

impl<'a> Iterator for Strings<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        if self.remaining == 0 {
            return None;
        }
        let (s, rest) = split_str(self.data)?;
        self.data = rest;
        self.remaining -= 1;
        Some(s)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len(), Some(self.len()))
    }
}

/// Splits one `[u16 len][bytes]` string off the front of `data`.
fn split_str(data: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = data.split_first_chunk::<2>()?;
    let len = usize::from(u16::from_ne_bytes(*len));
    if len > rest.len() {
        return None;
    }
    Some(rest.split_at(len))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let chunk = bytes.get(offset..offset + 4)?;
    Some(u32::from_ne_bytes(chunk.try_into().ok()?))
}

/// Reads a fixed-size Pod body from the front of `payload`.
fn read_body<T: bytemuck::Pod>(payload: &[u8]) -> Result<(T, &[u8]), DecodeError> {
    let size = core::mem::size_of::<T>();
    if payload.len() < size {
        return Err(DecodeError::BodyTooShort {
            needed: size,
            provided: payload.len(),
        });
    }
    let (body, rest) = payload.split_at(size);
    Ok((bytemuck::pod_read_unaligned(body), rest))
}

/// Decodes and validates one ring-buffer record.
pub fn decode(bytes: &[u8]) -> Result<Event<'_>, DecodeError> {
    if bytes.len() < RK_ENVELOPE_LEN {
        return Err(DecodeError::TooShort {
            needed: RK_ENVELOPE_LEN,
            provided: bytes.len(),
        });
    }

    let hdr: rk_hdr = bytemuck::pod_read_unaligned(&bytes[..HDR_LEN]);
    if u32::from(hdr.abi) != RK_ABI_VERSION {
        return Err(DecodeError::AbiMismatch {
            expected: RK_ABI_VERSION,
            found: hdr.abi,
        });
    }

    let too_short = DecodeError::TooShort {
        needed: RK_ENVELOPE_LEN,
        provided: bytes.len(),
    };
    let payload_len = read_u32(bytes, HDR_LEN).ok_or(too_short)? as usize;
    let reserved = read_u32(bytes, HDR_LEN + 4).ok_or(too_short)?;
    if reserved != 0 {
        return Err(DecodeError::ReservedNonZero(reserved));
    }
    if payload_len > MAX_PAYLOAD {
        return Err(DecodeError::PayloadTooLarge(payload_len));
    }
    if RK_ENVELOPE_LEN + payload_len != bytes.len() {
        return Err(DecodeError::LengthMismatch {
            expected: RK_ENVELOPE_LEN + payload_len,
            found: bytes.len(),
        });
    }

    match u32::from(hdr.verdict) {
        rk_verdict::RK_VERDICT_ALLOW
        | rk_verdict::RK_VERDICT_DENY
        | rk_verdict::RK_VERDICT_AUDIT_WOULD_DENY => {}
        _ => return Err(DecodeError::UnknownVerdict(hdr.verdict)),
    }

    let payload = &bytes[RK_ENVELOPE_LEN..];
    let payload = match u32::from(hdr.type_) {
        rk_event_type::RK_EV_EXEC => {
            let (body, tail) = read_body::<rk_payload_exec>(payload)?;
            let strings = Strings::validate(tail, body.str_count)?;
            Payload::Exec { body, strings }
        }
        rk_event_type::RK_EV_FILE_OPEN => {
            let (body, tail) = read_body::<rk_payload_file>(payload)?;
            let strings = Strings::validate(tail, body.str_count)?;
            Payload::File { body, strings }
        }
        rk_event_type::RK_EV_NET_CONNECT | rk_event_type::RK_EV_SENDMSG => {
            let (body, tail) = read_body::<rk_payload_net>(payload)?;
            if !tail.is_empty() {
                return Err(DecodeError::TrailingBytes(tail.len()));
            }
            Payload::Net { body }
        }
        rk_event_type::RK_EV_UNLINK
        | rk_event_type::RK_EV_RENAME
        | rk_event_type::RK_EV_FORK
        | rk_event_type::RK_EV_EXIT
        | rk_event_type::RK_EV_TAMPER => Payload::Raw { data: payload },
        _ => return Err(DecodeError::UnknownType(hdr.type_)),
    };

    Ok(Event { hdr, payload })
}

/// Counters for decoded and rejected records, one per [`DecodeError`] kind.
#[derive(Debug, Default)]
pub struct DecodeStats {
    decoded: AtomicU64,
    errors: [AtomicU64; DecodeError::KINDS],
}

impl DecodeStats {
    pub fn record<T>(&self, result: &Result<T, DecodeError>) {
        let counter = match result {
            Ok(_) => &self.decoded,
            Err(e) => &self.errors[e.kind_index()],
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decoded(&self) -> u64 {
        self.decoded.load(Ordering::Relaxed)
    }

    pub fn rejected(&self) -> u64 {
        self.errors.iter().map(|c| c.load(Ordering::Relaxed)).sum()
    }

    /// `(kind, count)` for every error kind, in a stable order.
    pub fn rejected_by_kind(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        DecodeError::KIND_NAMES
            .iter()
            .zip(self.errors.iter())
            .map(|(name, c)| (*name, c.load(Ordering::Relaxed)))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use bytemuck::Zeroable;
    use proptest::prelude::*;

    pub(crate) fn hdr(type_: u32, verdict: u32) -> rk_hdr {
        rk_hdr {
            ts_ns: 1,
            cgroup_id: 42,
            policy_gen: 7,
            pid: 100,
            tgid: 100,
            uid: 1000,
            gid: 1000,
            type_: type_ as u16,
            verdict: verdict as u8,
            abi: RK_ABI_VERSION as u8,
            rule_id: 3,
        }
    }

    /// Encodes a record exactly as `rk_emit` does in the kernel.
    pub(crate) fn record(hdr: &rk_hdr, payload: &[u8]) -> Vec<u8> {
        let mut out = bytemuck::bytes_of(hdr).to_vec();
        out.extend_from_slice(&(payload.len() as u32).to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn string_tail(strings: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for s in strings {
            out.extend_from_slice(&(s.len() as u16).to_ne_bytes());
            out.extend_from_slice(s);
        }
        out
    }

    fn exec_payload(strings: &[&[u8]]) -> Vec<u8> {
        let body = rk_payload_exec {
            file_dev: (8 << 20) | 1,
            file_ino: 1234,
            flags: 0,
            str_count: strings.len() as u16,
            _pad: 0,
        };
        let mut out = bytemuck::bytes_of(&body).to_vec();
        out.extend(string_tail(strings));
        out
    }

    #[test]
    fn decodes_exec_with_strings() {
        let h = hdr(rk_event_type::RK_EV_EXEC, rk_verdict::RK_VERDICT_DENY);
        let rec = record(&h, &exec_payload(&[b"bash", b"/bin/bash", b"-c"]));
        let ev = decode(&rec).unwrap();
        assert_eq!(ev.hdr, h);
        let Payload::Exec { body, strings } = ev.payload else {
            panic!("expected exec payload");
        };
        assert_eq!(body.file_ino, 1234);
        assert_eq!(strings.collect::<Vec<_>>(), vec![&b"bash"[..], b"/bin/bash", b"-c"]);
    }

    #[test]
    fn decodes_non_utf8_path() {
        let body = rk_payload_file {
            str_count: 1,
            ..Zeroable::zeroed()
        };
        let mut payload = bytemuck::bytes_of(&body).to_vec();
        payload.extend(string_tail(&[b"\xff\xfe.txt"]));
        let rec = record(&hdr(rk_event_type::RK_EV_FILE_OPEN, 0), &payload);
        let Payload::File { mut strings, .. } = decode(&rec).unwrap().payload else {
            panic!("expected file payload");
        };
        assert_eq!(strings.next(), Some(&b"\xff\xfe.txt"[..]));
        assert_eq!(strings.next(), None);
    }

    #[test]
    fn decodes_net() {
        let mut body: rk_payload_net = Zeroable::zeroed();
        body.daddr_v6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1];
        body.dport = 9;
        let rec = record(&hdr(rk_event_type::RK_EV_NET_CONNECT, 1), bytemuck::bytes_of(&body));
        assert_eq!(decode(&rec).unwrap().payload, Payload::Net { body });
    }

    #[test]
    fn rejects_short_record() {
        assert_eq!(
            decode(&[0u8; 10]),
            Err(DecodeError::TooShort {
                needed: 56,
                provided: 10
            })
        );
    }

    #[test]
    fn rejects_abi_mismatch() {
        let mut h = hdr(rk_event_type::RK_EV_EXEC, 0);
        h.abi = 2;
        let rec = record(&h, &exec_payload(&[]));
        assert!(matches!(decode(&rec), Err(DecodeError::AbiMismatch { found: 2, .. })));
    }

    #[test]
    fn rejects_reserved_non_zero() {
        let mut rec = record(&hdr(rk_event_type::RK_EV_EXEC, 0), &exec_payload(&[]));
        rec[52] = 1;
        assert!(matches!(decode(&rec), Err(DecodeError::ReservedNonZero(_))));
    }

    #[test]
    fn rejects_oversized_payload_len() {
        let mut rec = record(&hdr(rk_event_type::RK_EV_EXEC, 0), &[]);
        rec[48..52].copy_from_slice(&(MAX_PAYLOAD as u32 + 1).to_ne_bytes());
        assert_eq!(decode(&rec), Err(DecodeError::PayloadTooLarge(MAX_PAYLOAD + 1)));
    }

    #[test]
    fn rejects_length_mismatch() {
        let mut rec = record(&hdr(rk_event_type::RK_EV_EXEC, 0), &exec_payload(&[]));
        rec.push(0);
        assert!(matches!(decode(&rec), Err(DecodeError::LengthMismatch { .. })));
    }

    #[test]
    fn rejects_unknown_type_and_none() {
        let rec = record(&hdr(rk_event_type::RK_EV_NONE, 0), &[]);
        assert_eq!(decode(&rec), Err(DecodeError::UnknownType(0)));
        let rec = record(&hdr(999, 0), &[]);
        assert_eq!(decode(&rec), Err(DecodeError::UnknownType(999)));
    }

    #[test]
    fn rejects_unknown_verdict() {
        let rec = record(&hdr(rk_event_type::RK_EV_EXEC, 7), &exec_payload(&[]));
        assert_eq!(decode(&rec), Err(DecodeError::UnknownVerdict(7)));
    }

    #[test]
    fn rejects_short_body() {
        let rec = record(&hdr(rk_event_type::RK_EV_NET_CONNECT, 0), &[0u8; 39]);
        assert_eq!(
            decode(&rec),
            Err(DecodeError::BodyTooShort {
                needed: 40,
                provided: 39
            })
        );
    }

    #[test]
    fn rejects_string_count_beyond_tail() {
        let mut payload = exec_payload(&[b"a"]);
        payload[20..22].copy_from_slice(&2u16.to_ne_bytes()); // claims 2 strings
        let rec = record(&hdr(rk_event_type::RK_EV_EXEC, 0), &payload);
        assert_eq!(decode(&rec), Err(DecodeError::MalformedStrings));
    }

    #[test]
    fn rejects_truncated_string() {
        let mut payload = exec_payload(&[b"abc"]);
        payload.pop();
        let rec = record(&hdr(rk_event_type::RK_EV_EXEC, 0), &payload);
        assert_eq!(decode(&rec), Err(DecodeError::MalformedStrings));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut payload = exec_payload(&[b"abc"]);
        payload.push(0);
        let rec = record(&hdr(rk_event_type::RK_EV_EXEC, 0), &payload);
        assert_eq!(decode(&rec), Err(DecodeError::TrailingBytes(1)));

        let mut net = vec![0u8; 40];
        net.push(0);
        let rec = record(&hdr(rk_event_type::RK_EV_NET_CONNECT, 0), &net);
        assert_eq!(decode(&rec), Err(DecodeError::TrailingBytes(1)));
    }

    #[test]
    fn stats_count_every_kind() {
        let stats = DecodeStats::default();
        stats.record(&decode(&[0u8; 1]));
        stats.record(&decode(&record(&hdr(1, 0), &exec_payload(&[]))));
        assert_eq!(stats.decoded(), 1);
        assert_eq!(stats.rejected(), 1);
        let by_kind: Vec<_> = stats.rejected_by_kind().collect();
        assert_eq!(by_kind.len(), DecodeError::KINDS);
        assert_eq!(by_kind[0], ("too_short", 1));
    }

    #[test]
    fn kind_names_are_unique() {
        let mut names = DecodeError::KIND_NAMES.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), DecodeError::KINDS);
    }

    proptest! {
        #[test]
        fn exec_strings_round_trip(
            strings in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..64), 0..16)
        ) {
            let refs: Vec<&[u8]> = strings.iter().map(Vec::as_slice).collect();
            let rec = record(&hdr(rk_event_type::RK_EV_EXEC, 0), &exec_payload(&refs));
            let ev = decode(&rec).unwrap();
            let Payload::Exec { strings: got, .. } = ev.payload else {
                panic!("expected exec payload");
            };
            prop_assert_eq!(got.len(), refs.len());
            prop_assert_eq!(got.collect::<Vec<_>>(), refs);
        }

        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = decode(&bytes);
        }

        #[test]
        fn arbitrary_payload_with_valid_envelope_never_panics(
            type_ in 0u32..12,
            payload in proptest::collection::vec(any::<u8>(), 0..256)
        ) {
            let _ = decode(&record(&hdr(type_, 0), &payload));
        }
    }
}
