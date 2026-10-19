// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * decoder.rs — Validating userspace event decoder
 * Unpacks variable-length event envelopes from BPF ring buffer
 * using read_unaligned and bytemuck with explicit length checks.
 */

use rk_ebpf_common::*;

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    BufferTooShort { needed: usize, provided: usize },
    AbiMismatch { expected: u8, found: u8 },
    ReservedNonZero(u32),
    InvalidEventType(u16),
    PayloadLengthMismatch { expected: usize, found: usize },
    FixedBodyTooShort { needed: usize, provided: usize },
    InvalidUtf8,
    MalformedStringLength,
}

#[derive(Debug)]
pub enum RkDecodedPayload<'a> {
    Exec {
        body: rk_payload_exec,
        strings: &'a [&'a str],
    },
    FileOpen {
        body: rk_payload_file,
        path: &'a str,
    },
    Net {
        body: rk_payload_net,
    },
    Generic {
        type_: rk_event_type,
        data: &'a [u8],
    },
}

#[derive(Debug)]
pub struct RkDecodedEvent<'a> {
    pub hdr: rk_hdr,
    pub payload: RkDecodedPayload<'a>,
}

pub fn decode_event<'a>(bytes: &'a [u8], str_buf: &'a mut [&'a str]) -> Result<RkDecodedEvent<'a>, DecodeError> {
    const HDR_LEN: usize = core::mem::size_of::<rk_hdr>();
    const MIN_MSG_LEN: usize = 56; // sizeof(rk_hdr) (48) + payload_len (4) + _reserved (4)

    if bytes.len() < MIN_MSG_LEN {
        return Err(DecodeError::BufferTooShort {
            needed: MIN_MSG_LEN,
            provided: bytes.len(),
        });
    }

    // Read fixed rk_hdr via read_unaligned
    let hdr: rk_hdr = unsafe {
        core::ptr::read_unaligned(bytes.as_ptr() as *const rk_hdr)
    };

    if hdr.abi != RK_ABI_VERSION {
        return Err(DecodeError::AbiMismatch {
            expected: RK_ABI_VERSION,
            found: hdr.abi,
        });
    }

    // Read payload_len and _reserved
    let payload_len = unsafe {
        core::ptr::read_unaligned(bytes.as_ptr().add(48) as *const u32)
    } as usize;

    let reserved = unsafe {
        core::ptr::read_unaligned(bytes.as_ptr().add(52) as *const u32)
    };

    if reserved != 0 {
        return Err(DecodeError::ReservedNonZero(reserved));
    }

    // Exact length check: slice must match exactly 56 + payload_len
    if 56 + payload_len != bytes.len() {
        return Err(DecodeError::PayloadLengthMismatch {
            expected: 56 + payload_len,
            found: bytes.len(),
        });
    }

    let payload_bytes = &bytes[56..];

    // Decode by event type
    let payload = match hdr.type_ {
        0 => return Err(DecodeError::InvalidEventType(0)), // RK_EV_NONE is rejected

        1 => {
            // RK_EV_EXEC: 24 bytes fixed body + str_count * (__u16 len + str)
            const EXEC_BODY_LEN: usize = core::mem::size_of::<rk_payload_exec>();
            if payload_bytes.len() < EXEC_BODY_LEN {
                return Err(DecodeError::FixedBodyTooShort {
                    needed: EXEC_BODY_LEN,
                    provided: payload_bytes.len(),
                });
            }

            let body: rk_payload_exec = unsafe {
                core::ptr::read_unaligned(payload_bytes.as_ptr() as *const rk_payload_exec)
            };

            let mut offset = EXEC_BODY_LEN;
            let count = (body.str_count as usize).min(str_buf.len());
            for i in 0..count {
                if offset + 2 > payload_bytes.len() {
                    return Err(DecodeError::MalformedStringLength);
                }
                let s_len = unsafe {
                    core::ptr::read_unaligned(payload_bytes.as_ptr().add(offset) as *const u16)
                } as usize;
                offset += 2;
                if offset + s_len > payload_bytes.len() {
                    return Err(DecodeError::MalformedStringLength);
                }
                let s = core::str::from_utf8(&payload_bytes[offset..offset + s_len])
                    .map_err(|_| DecodeError::InvalidUtf8)?;
                str_buf[i] = s;
                offset += s_len;
            }

            RkDecodedPayload::Exec {
                body,
                strings: &str_buf[..count],
            }
        }

        2 => {
            // RK_EV_FILE_OPEN: 32 bytes fixed body + 1 * (__u16 len + path)
            const FILE_BODY_LEN: usize = core::mem::size_of::<rk_payload_file>();
            if payload_bytes.len() < FILE_BODY_LEN {
                return Err(DecodeError::FixedBodyTooShort {
                    needed: FILE_BODY_LEN,
                    provided: payload_bytes.len(),
                });
            }

            let body: rk_payload_file = unsafe {
                core::ptr::read_unaligned(payload_bytes.as_ptr() as *const rk_payload_file)
            };

            let mut path = "";
            if payload_bytes.len() >= FILE_BODY_LEN + 2 {
                let s_len = unsafe {
                    core::ptr::read_unaligned(payload_bytes.as_ptr().add(FILE_BODY_LEN) as *const u16)
                } as usize;
                let start = FILE_BODY_LEN + 2;
                if start + s_len <= payload_bytes.len() {
                    path = core::str::from_utf8(&payload_bytes[start..start + s_len])
                        .map_err(|_| DecodeError::InvalidUtf8)?;
                }
            }

            RkDecodedPayload::FileOpen { body, path }
        }

        3 | 9 => {
            // RK_EV_NET_CONNECT | RK_EV_SENDMSG: 40 bytes fixed body
            const NET_BODY_LEN: usize = core::mem::size_of::<rk_payload_net>();
            if payload_bytes.len() < NET_BODY_LEN {
                return Err(DecodeError::FixedBodyTooShort {
                    needed: NET_BODY_LEN,
                    provided: payload_bytes.len(),
                });
            }

            let body: rk_payload_net = unsafe {
                core::ptr::read_unaligned(payload_bytes.as_ptr() as *const rk_payload_net)
            };

            RkDecodedPayload::Net { body }
        }

        4..=8 => RkDecodedPayload::Generic {
            type_: match hdr.type_ {
                4 => rk_event_type::RK_EV_UNLINK,
                5 => rk_event_type::RK_EV_RENAME,
                6 => rk_event_type::RK_EV_FORK,
                7 => rk_event_type::RK_EV_EXIT,
                8 => rk_event_type::RK_EV_TAMPER,
                _ => unreachable!(),
            },
            data: payload_bytes,
        },

        other => return Err(DecodeError::InvalidEventType(other)),
    };

    Ok(RkDecodedEvent { hdr, payload })
}
