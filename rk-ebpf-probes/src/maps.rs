use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, RingBuf};

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
pub static EVENT_DROPS: Array<u64> = Array::with_max_entries(1, 0);
