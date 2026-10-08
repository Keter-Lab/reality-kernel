use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, RingBuf};

#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
pub static EVENT_DROPS: Array<u64> = Array::with_max_entries(1, 0);

#[map]
pub static MONITORED_CGROUPS: HashMap<u64, u32> = HashMap::with_max_entries(1024, 0);

#[map]
pub static MONITORED_PIDS: HashMap<u32, u32> = HashMap::with_max_entries(4096, 0);

#[map]
pub static FILTER_MODE: Array<u32> = Array::with_max_entries(1, 0);

