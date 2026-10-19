#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut str_buf = [""; 32];
    let _ = rk_sensor::decoder::decode_event(data, &mut str_buf);
});
